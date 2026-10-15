package httpapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/Taminum/RemnaScope/internal/auth"
	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/store"
)

// A backup file is "RSAWGB1\n" + salt(16) + nonce(12) + AES-256-GCM(JSON of the files). The key comes from the
// passphrase by argon2id. The files hold the server's private key and every device's preshared key, so the file
// is useless without the passphrase, and nothing of it is kept here.
const (
	awgBackupMagic      = "RSAWGB1\n"
	minBackupPassphrase = 10
	maxRestoreBody      = 1 << 20
)

func awgBackupGCM(pass string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(pass), salt, 2, 64*1024, 2, 32)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func awgBackupSeal(files []ingestproto.AWGFile, pass string) ([]byte, error) {
	plain, err := json.Marshal(files)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm, err := awgBackupGCM(pass, salt)
	if err != nil {
		return nil, err
	}
	out := append([]byte(awgBackupMagic), salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, []byte(awgBackupMagic)), nil
}

func awgBackupOpen(blob []byte, pass string) ([]ingestproto.AWGFile, error) {
	n := len(awgBackupMagic)
	if len(blob) < n+16+12+16 || string(blob[:n]) != awgBackupMagic {
		return nil, errors.New("this is not a RemnaScope backup")
	}
	salt, nonce, ct := blob[n:n+16], blob[n+16:n+28], blob[n+28:]
	gcm, err := awgBackupGCM(pass, salt)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(awgBackupMagic))
	if err != nil {
		return nil, errors.New("wrong passphrase or damaged file")
	}
	var files []ingestproto.AWGFile
	if json.Unmarshal(plain, &files) != nil || len(files) == 0 || len(files) > len(ingestproto.AWGFileNames) {
		return nil, errors.New("this is not a RemnaScope backup")
	}
	return files, nil
}

// awgExport asks the host that owns an instance for its container's files.
func (s *Server) awgExport(ctx context.Context, w http.ResponseWriter, r *http.Request, a auth.Actor, instID, action string) ([]ingestproto.AWGFile, bool) {
	agentID, container, _, err := s.Store.AWGInstanceTarget(ctx, a.Scope(), instID)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such server")
		return nil, false
	}
	if !awgContainerRe.MatchString(container) {
		s.writeErr(w, r, http.StatusConflict, "not_removable", "only containers in the Amnezia layout can be backed up here")
		return nil, false
	}
	if !s.AWGOps.ContainerAdmin(agentID) {
		s.writeErr(w, r, http.StatusConflict, "container_admin_off", "this host has not opted in to container operations")
		return nil, false
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	res, err := s.AWGOps.Do(c, agentID, ingestproto.AWGOp{Op: "export", Container: container})
	ok := err == nil && res.Status == "ok" && len(res.Files) > 0
	s.audit(r, a, "", action, "awg_instance", instID, map[string]any{"container": container, "ok": ok})
	if !ok {
		if err == nil && res.Status == "ok" {
			res.Status, res.Code = "error", "bad_helper_output"
		}
		s.awgOpFailure(w, r, err, res)
		return nil, false
	}
	return res.Files, true
}

// awgBackup returns an encrypted backup of one container, once. Nothing is stored.
func (s *Server) awgBackup(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	var in struct {
		Passphrase string `json:"passphrase"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	if len(in.Passphrase) < minBackupPassphrase {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "weak_passphrase", "the passphrase must be at least 10 characters")
		return
	}
	files, ok := s.awgExport(r.Context(), w, r, a, r.PathValue("id"), "awg.container.backup")
	if !ok {
		return
	}
	blob, err := awgBackupSeal(files, in.Passphrase)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="amnezia-awg-backup.rsawg"`)
	_, _ = w.Write(blob)
}

func (s *Server) awgRestoreOn(ctx context.Context, w http.ResponseWriter, r *http.Request, a auth.Actor, hostID, container string, files []ingestproto.AWGFile, action string) {
	if !awgContainerRe.MatchString(container) {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "invalid_container", "the container name must be amnezia-awg or amnezia-awg followed by up to two digits")
		return
	}
	agentID, err := s.Store.AWGHostAgent(ctx, a.Scope(), hostID)
	if err != nil {
		s.writeErr(w, r, http.StatusNotFound, "not_found", "no such host")
		return
	}
	if !s.AWGOps.ContainerAdmin(agentID) {
		s.writeErr(w, r, http.StatusConflict, "container_admin_off", "this host has not opted in to creating containers")
		return
	}
	c, cancel := context.WithTimeout(ctx, 13*time.Minute)
	defer cancel()
	res, err := s.AWGOps.Do(c, agentID, ingestproto.AWGOp{Op: "restore", Container: container, Files: files})
	ok := err == nil && res.Status == "ok"
	meta := map[string]any{"container": container, "ok": ok}
	if !ok {
		code := res.Code
		if err != nil {
			code = "agent"
		}
		meta["code"] = code
		s.audit(r, a, "", action, "agent", agentID, meta)
		s.awgOpFailure(w, r, err, res)
		return
	}
	s.audit(r, a, "", action, "agent", agentID, meta)
	writeJSON(w, http.StatusCreated, map[string]any{"container": container, "port": res.Port, "server_key_short": shortKey(res.Key)})
}

// awgRestore creates a container from an uploaded backup on a host that opted in.
func (s *Server) awgRestore(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	var in struct {
		Container  string `json:"container"`
		Passphrase string `json:"passphrase"`
		Backup     string `json:"backup"`
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.writeErr(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRestoreBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		s.writeErr(w, r, http.StatusBadRequest, "invalid_body", "request body is not valid for this endpoint")
		return
	}
	blob, err := base64.StdEncoding.DecodeString(in.Backup)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "bad_backup", "this is not a RemnaScope backup")
		return
	}
	files, err := awgBackupOpen(blob, in.Passphrase)
	if err != nil {
		s.writeErr(w, r, http.StatusUnprocessableEntity, "bad_backup", err.Error())
		return
	}
	s.awgRestoreOn(r.Context(), w, r, a, r.PathValue("id"), in.Container, files, "awg.container.restore")
}

// awgTransfer moves a container's configuration to another host: the files go from one agent to the other
// through this server and are neither stored nor returned.
func (s *Server) awgTransfer(w http.ResponseWriter, r *http.Request, a auth.Actor, _ store.Session) {
	if !s.awgOwner(w, r, a) {
		return
	}
	var in struct {
		HostID    string `json:"host_id"`
		Container string `json:"container"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	files, ok := s.awgExport(r.Context(), w, r, a, r.PathValue("id"), "awg.container.transfer.export")
	if !ok {
		return
	}
	s.awgRestoreOn(r.Context(), w, r, a, in.HostID, in.Container, files, "awg.container.transfer.restore")
}
