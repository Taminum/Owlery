// Package selfupdate fetches and checks a new agent. It trusts nothing it was handed: the program comes from the
// project's GitHub release, the list of hashes of that release must carry a signature made by the release key, and the
// program must match its hash in the list. The server only says which version; it can name neither an address nor a hash.
package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Taminum/Owlery/internal/relsign"
)

// ReleaseBase is where the project's releases are downloaded from.
const ReleaseBase = "https://github.com/Taminum/Owlery/releases/download"

const (
	maxProgram = 64 << 20
	maxSmall   = 1 << 20
)

var versionRe = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// ValidVersion says whether s is a release tag of the form v1.2.3.
func ValidVersion(s string) bool { return versionRe.MatchString(s) }

func parse(v string) (n [3]int, ok bool) {
	m := versionRe.FindStringSubmatch(v)
	if m == nil {
		return n, false
	}
	for i := 0; i < 3; i++ {
		n[i], _ = strconv.Atoi(m[i+1])
	}
	return n, true
}

// Newer says whether candidate is a later release than current. A build that is not a release ("dev") is never replaced,
// and a version that is not a release tag is never newer.
func Newer(candidate, current string) bool {
	c, ok1 := parse(candidate)
	o, ok2 := parse(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if c[i] != o[i] {
			return c[i] > o[i]
		}
	}
	return false
}

// AssetName is the name of the security agent in a release for this system.
func AssetName(goos, goarch string) (string, error) {
	if goarch != "amd64" && goarch != "arm64" {
		return "", fmt.Errorf("selfupdate: no program for the processor %q", goarch)
	}
	switch goos {
	case "linux":
		return "remnascope-secagent-linux-" + goarch, nil
	case "windows":
		return "remnascope-secagent-windows-" + goarch + ".exe", nil
	}
	return "", fmt.Errorf("selfupdate: no program for the system %q", goos)
}

// Staged files, in one directory.
const (
	FileProgram = "program"
	FileSums    = "SHA256SUMS"
	FileSig     = "SHA256SUMS.sig"
	FileVersion = "version"
)

type Fetcher struct {
	Client    *http.Client
	Base      string // ReleaseBase unless a test says otherwise
	PublicKey string // relsign.ReleaseKey unless a test says otherwise
}

func (f *Fetcher) base() string {
	if f.Base != "" {
		return f.Base
	}
	return ReleaseBase
}

func (f *Fetcher) key() string {
	if f.PublicKey != "" {
		return f.PublicKey
	}
	return relsign.ReleaseKey
}

func (f *Fetcher) client() *http.Client {
	c := f.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Minute}
	}
	copied := *c
	copied.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("selfupdate: too many redirects")
		}
		if req.URL.Scheme != "https" && f.Base == "" { // a release is never fetched in the clear
			return errors.New("selfupdate: a redirect to a plain address")
		}
		return nil
	}
	return &copied
}

func (f *Fetcher) get(ctx context.Context, name, version string, limit int64) ([]byte, error) {
	u, err := url.JoinPath(f.base(), version, name)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("selfupdate: %s answered %d", name, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("selfupdate: %s is larger than allowed", name)
	}
	return b, nil
}

// Fetch downloads the release of version, checks it, and leaves the program with the files that prove it in dir. Nothing is
// left in dir when a check fails.
func (f *Fetcher) Fetch(ctx context.Context, version, goos, goarch, dir string) error {
	if !ValidVersion(version) {
		return errors.New("selfupdate: not a release version")
	}
	asset, err := AssetName(goos, goarch)
	if err != nil {
		return err
	}
	sums, err := f.get(ctx, FileSums, version, maxSmall)
	if err != nil {
		return err
	}
	sig, err := f.get(ctx, FileSig, version, maxSmall)
	if err != nil {
		return err
	}
	if err := relsign.Verify(f.key(), sums, string(sig)); err != nil {
		return err
	}
	want, err := relsign.HashFor(sums, asset)
	if err != nil {
		return err
	}
	prog, err := f.get(ctx, asset, version, maxProgram)
	if err != nil {
		return err
	}
	if got := sha256.Sum256(prog); hex.EncodeToString(got[:]) != want {
		return errors.New("selfupdate: the program does not match its hash in the signed list")
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{FileSums: sums, FileSig: sig, FileProgram: prog, FileVersion: []byte(version)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
	}
	return nil
}

// VerifyStaged checks, from the files alone, what Fetch left: the signature, the hash, that the version it names is a later one
// than current, and that the program says the same about itself. It is what a root helper runs before it installs anything,
// so a staged file that somebody else wrote does not pass. run asks the program for its version; nil runs it.
func VerifyStaged(dir, pubKey, current, goos, goarch string, run func(path string) (string, error)) (string, error) {
	if pubKey == "" {
		pubKey = relsign.ReleaseKey
	}
	read := func(name string, limit int64) ([]byte, error) {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("selfupdate: %s is too large", name)
		}
		return b, nil
	}
	verb, err := read(FileVersion, 64)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(verb))
	if !ValidVersion(version) {
		return "", errors.New("selfupdate: the staged version is not a release version")
	}
	if !Newer(version, current) {
		return "", fmt.Errorf("selfupdate: %s is not later than %s", version, current)
	}
	asset, err := AssetName(goos, goarch)
	if err != nil {
		return "", err
	}
	sums, err := read(FileSums, maxSmall)
	if err != nil {
		return "", err
	}
	sig, err := read(FileSig, maxSmall)
	if err != nil {
		return "", err
	}
	if err := relsign.Verify(pubKey, sums, string(sig)); err != nil {
		return "", err
	}
	want, err := relsign.HashFor(sums, asset)
	if err != nil {
		return "", err
	}
	prog, err := read(FileProgram, maxProgram)
	if err != nil {
		return "", err
	}
	if got := sha256.Sum256(prog); hex.EncodeToString(got[:]) != want {
		return "", errors.New("selfupdate: the staged program does not match its hash in the signed list")
	}
	// A signed list of an older release would pass the checks above with a version file that lies; the program tells the truth.
	if run == nil {
		run = ProgramVersion
	}
	said, err := run(filepath.Join(dir, FileProgram))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(said) != version {
		return "", fmt.Errorf("selfupdate: the program says it is %q, not %s", strings.TrimSpace(said), version)
	}
	return version, nil
}

// ProgramVersion runs a program with -version and returns what it prints.
func ProgramVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "-version")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("selfupdate: the staged program does not run: %w", err)
	}
	return out.String(), nil
}
