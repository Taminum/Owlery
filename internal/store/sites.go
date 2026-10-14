package store

import (
	"context"
	"net/netip"

	"github.com/Taminum/RemnaScope/internal/geoip"
	"github.com/Taminum/RemnaScope/internal/site"
)

// BackfillSites fills the site column on rows stored before it existed (or by an older
// build). It works through the distinct hosts in batches and is safe to run repeatedly: rows
// that already have a site are never touched. It returns how many rows it updated.
func (s *Store) BackfillSites(ctx context.Context) (int64, error) {
	var total int64
	for _, tbl := range []string{"connection_events", "device_connections"} {
		for {
			rs, err := s.pool.Query(ctx, `SELECT DISTINCT destination_host FROM `+tbl+` WHERE site IS NULL AND destination_host IS NOT NULL LIMIT 500`)
			if err != nil {
				return total, err
			}
			var hosts, sites []string
			for rs.Next() {
				var h string
				if err := rs.Scan(&h); err != nil {
					rs.Close()
					return total, err
				}
				hosts = append(hosts, h)
				sites = append(sites, site.Of(h))
			}
			rs.Close()
			if len(hosts) == 0 {
				break
			}
			tag, err := s.pool.Exec(ctx, `UPDATE `+tbl+` t SET site = v.s FROM unnest($1::text[], $2::text[]) AS v(h, s)
				WHERE t.site IS NULL AND t.destination_host = v.h`, hosts, sites)
			if err != nil {
				return total, err
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() == 0 {
				break // defensive: never loop on rows that cannot be updated
			}
		}
	}
	return total, nil
}

// UnknownCountry marks an address that is private or that the table does not know.
const UnknownCountry = "ZZ"

// BackfillCountries sets the country on rows stored before the column existed. Rows with an IP
// but no table entry get "ZZ", so they are never looked at again. It returns the rows updated.
func (s *Store) BackfillCountries(ctx context.Context) (int64, error) {
	var total int64
	for _, tbl := range []string{"connection_events", "device_connections"} {
		for {
			rs, err := s.pool.Query(ctx, `SELECT DISTINCT host(destination_ip) FROM `+tbl+` WHERE country IS NULL AND destination_ip IS NOT NULL LIMIT 1000`)
			if err != nil {
				return total, err
			}
			var ips, ccs []string
			for rs.Next() {
				var ip string
				if err := rs.Scan(&ip); err != nil {
					rs.Close()
					return total, err
				}
				cc := UnknownCountry
				if a, err := netip.ParseAddr(ip); err == nil {
					if c := geoip.Default().Country(a); c != "" {
						cc = c
					}
				}
				ips, ccs = append(ips, ip), append(ccs, cc)
			}
			rs.Close()
			if len(ips) == 0 {
				break
			}
			tag, err := s.pool.Exec(ctx, `UPDATE `+tbl+` t SET country = v.c FROM unnest($1::text[], $2::text[]) AS v(ip, c)
				WHERE t.country IS NULL AND host(t.destination_ip) = v.ip`, ips, ccs)
			if err != nil {
				return total, err
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() == 0 {
				break
			}
		}
	}
	return total, nil
}
