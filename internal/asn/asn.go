// Package asn maps an IP address to the network that announces it (autonomous system number and
// organisation name) using the DB-IP "IP to ASN Lite" table (CC BY 4.0, see NOTICE.txt), embedded in
// the program. It names the owner of an address range; it does not say what a connection to it was
// for, so it is shown as "owner", never as a service.
package asn

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/csv"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"sync"
)

//go:embed dbip-asn-lite.csv.gz
var data []byte

type v4 struct {
	start, end uint32
	asn        uint32
	org        uint32 // index into DB.orgs
}

type v6 struct {
	start, end [16]byte
	asn        uint32
	org        uint32
}

type DB struct {
	v4   []v4
	v6   []v6
	orgs []string
}

var (
	once sync.Once
	def  *DB
)

// Default parses the embedded table once and returns it.
func Default() *DB {
	once.Do(func() { def, _ = parse(data) })
	if def == nil {
		def = &DB{}
	}
	return def
}

func u32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func parse(gz []byte) (*DB, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	r := csv.NewReader(zr)
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	db := &DB{}
	orgIdx := map[string]uint32{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return db, err
		}
		if len(rec) != 4 {
			continue
		}
		n, err := strconv.ParseUint(rec[2], 10, 32)
		a, e1 := netip.ParseAddr(rec[0])
		b, e2 := netip.ParseAddr(rec[1])
		if err != nil || n == 0 || e1 != nil || e2 != nil {
			continue // ASN 0 is "none" in the table
		}
		oi, ok := orgIdx[rec[3]]
		if !ok {
			oi = uint32(len(db.orgs))
			orgIdx[rec[3]] = oi
			db.orgs = append(db.orgs, rec[3])
		}
		if a.Is4() {
			x, y := a.As4(), b.As4()
			db.v4 = append(db.v4, v4{u32(x), u32(y), uint32(n), oi})
		} else {
			db.v6 = append(db.v6, v6{a.As16(), b.As16(), uint32(n), oi})
		}
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].start < db.v4[j].start })
	sort.Slice(db.v6, func(i, j int) bool { return bytes.Compare(db.v6[i].start[:], db.v6[j].start[:]) < 0 })
	return db, nil
}

// Owner is the network an address belongs to.
type Owner struct {
	ASN uint32
	Org string
}

// Lookup returns the owner of a public address; ok is false for a private, local or unknown one.
func (d *DB) Lookup(ip netip.Addr) (Owner, bool) {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return Owner{}, false
	}
	if ip.Is4() {
		x := u32(ip.As4())
		i := sort.Search(len(d.v4), func(i int) bool { return d.v4[i].start > x }) - 1
		if i >= 0 && x <= d.v4[i].end {
			return Owner{d.v4[i].asn, d.orgs[d.v4[i].org]}, true
		}
		return Owner{}, false
	}
	x := ip.As16()
	i := sort.Search(len(d.v6), func(i int) bool { return bytes.Compare(d.v6[i].start[:], x[:]) > 0 }) - 1
	if i >= 0 && bytes.Compare(x[:], d.v6[i].end[:]) <= 0 {
		return Owner{d.v6[i].asn, d.orgs[d.v6[i].org]}, true
	}
	return Owner{}, false
}
