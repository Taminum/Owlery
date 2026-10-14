// Package geoip maps an IP address to a country code using the DB-IP "IP to Country Lite" table
// (CC BY 4.0, see NOTICE.txt), embedded in the program. It is a lookup of the address only: it
// says where the address is registered, not where a person is or what a site is about.
package geoip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

//go:embed dbip-country-lite.csv.gz
var data []byte

type v4 struct {
	start, end uint32
	cc         [2]byte
}

type v6 struct {
	start, end [16]byte
	cc         [2]byte
}

type DB struct {
	v4 []v4
	v6 []v6
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

func parse(gz []byte) (*DB, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	db := &DB{}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ",")
		if len(f) != 3 || len(f[2]) != 2 || f[2] == "ZZ" {
			continue // ZZ is "unknown" in the table
		}
		a, e1 := netip.ParseAddr(f[0])
		b, e2 := netip.ParseAddr(f[1])
		if e1 != nil || e2 != nil {
			continue
		}
		cc := [2]byte{f[2][0], f[2][1]}
		if a.Is4() {
			x, y := a.As4(), b.As4()
			db.v4 = append(db.v4, v4{u32(x), u32(y), cc})
		} else {
			db.v6 = append(db.v6, v6{a.As16(), b.As16(), cc})
		}
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].start < db.v4[j].start })
	sort.Slice(db.v6, func(i, j int) bool { return bytes.Compare(db.v6[i].start[:], db.v6[j].start[:]) < 0 })
	return db, sc.Err()
}

func u32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Country returns the two-letter code for an address, or "" for a private, local or unknown one.
func (d *DB) Country(ip netip.Addr) string {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return ""
	}
	if ip.Is4() {
		x := u32(ip.As4())
		i := sort.Search(len(d.v4), func(i int) bool { return d.v4[i].start > x }) - 1
		if i >= 0 && x <= d.v4[i].end {
			return string(d.v4[i].cc[:])
		}
		return ""
	}
	x := ip.As16()
	i := sort.Search(len(d.v6), func(i int) bool { return bytes.Compare(d.v6[i].start[:], x[:]) > 0 }) - 1
	if i >= 0 && bytes.Compare(x[:], d.v6[i].end[:]) <= 0 {
		return string(d.v6[i].cc[:])
	}
	return ""
}

// Name is the country's name in Russian, falling back to the code.
func Name(code string) string {
	r, err := language.ParseRegion(strings.ToUpper(code))
	if err != nil {
		return code
	}
	if n := display.Russian.Regions().Name(r); n != "" {
		return n
	}
	return code
}
