package dnsmap

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func mxRR(name string, pref uint16, host string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeMX, 300), Body: &dnsmessage.MXResource{Pref: pref, MX: nm(host)}}
}

func nsRR(name, host string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeNS, 300), Body: &dnsmessage.NSResource{NS: nm(host)}}
}

func soaRR(name string, serial uint32) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeSOA, 300), Body: &dnsmessage.SOAResource{NS: nm("ns1.example.com"), MBox: nm("h.example.com"), Serial: serial, Refresh: 1, Retry: 1, Expire: 1, MinTTL: 1}}
}

func txtRR(name string, s string) dnsmessage.Resource {
	return dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeTXT, 300), Body: &dnsmessage.TXTResource{TXT: []string{s}}}
}

// zone is what a healthy example.com looks like to every server in these tests.
func zone() map[string]spec {
	return map[string]spec{
		"example.com|A":          {answers: []dnsmessage.Resource{rrA("example.com", "93.184.216.34", 300)}},
		"example.com|MX":         {answers: []dnsmessage.Resource{mxRR("example.com", 10, "mail.example.com")}},
		"example.com|NS":         {answers: []dnsmessage.Resource{nsRR("example.com", "ns1.example.com")}},
		"example.com|SOA":        {aa: true, answers: []dnsmessage.Resource{soaRR("example.com", 100)}},
		"example.com|TXT":        {answers: []dnsmessage.Resource{txtRR("example.com", "v=spf1 -all")}},
		"_dmarc.example.com|TXT": {answers: []dnsmessage.Resource{txtRR("_dmarc.example.com", "v=DMARC1; p=none")}},
		"www.example.com|A":      {answers: []dnsmessage.Resource{rrCNAME("www.example.com", "cdn.example.com", 60), rrA("cdn.example.com", "198.51.100.7", 60)}},
		"ns1.example.com|A":      {answers: []dnsmessage.Resource{rrA("ns1.example.com", "127.0.0.1", 300)}},
	}
}

func cfgFor(c *Client, resolvers ...*fakeDNS) Config {
	var rs []netip.AddrPort
	for _, r := range resolvers {
		rs = append(rs, r.addr)
	}
	return Config{Domain: "example.com", Resolvers: rs, Client: c, Retry: 10 * time.Millisecond}
}

func find(res RunResult, name, typ string) (Rec, bool) {
	for _, r := range res.Recs {
		if r.Name == name && r.Type == typ {
			return r, true
		}
	}
	return Rec{}, false
}

func TestAHealthyRunIsConfirmedByTwoResolversAndSaysWhatItCovered(t *testing.T) {
	a, c := newFake(t, zone())
	b, _ := newFake(t, zone())
	auth, _ := newFake(t, zone())
	cfg := cfgFor(c, a, b)
	cfg.AuthPort = auth.addr.Port()
	cfg.ExtraNames = []string{"api.example.com"}
	res := Run(context.Background(), cfg)

	if res.Status != "ok" {
		t.Fatalf("status %s, failures %d, unconfirmed %d", res.Status, res.Coverage.Failures, res.Coverage.Unconfirmed)
	}
	mx, ok := find(res, "example.com", TypeMX)
	if !ok || !mx.Confirmed || mx.Values[0] != "10 mail.example.com" || mx.TTL != 300 || len(mx.Views) != 2 {
		t.Fatalf("%+v", mx)
	}
	// The www alias: the CNAME, and the address at its target, are both there.
	cn, ok := find(res, "www.example.com", TypeCNAME)
	if !ok || cn.Values[0] != "cdn.example.com" {
		t.Fatalf("%+v", cn)
	}
	if tgt, ok := find(res, "cdn.example.com", TypeA); !ok || tgt.Values[0] != "198.51.100.7" {
		t.Fatalf("%+v", tgt)
	}
	// A name with no address record of its own is "nodata", not an empty answer.
	if www, ok := find(res, "www.example.com", TypeA); !ok || www.Result != OutcomeNoData {
		t.Fatalf("%+v", www)
	}
	// The map says how it knows each name, and does not claim to know the whole zone.
	prov := map[string]string{}
	for _, n := range res.Names {
		prov[n.Name] = n.Provenance
	}
	if prov["example.com"] != ProvApex || prov["www.example.com"] != ProvWWW || prov["api.example.com"] != ProvManual || prov["cdn.example.com"] != ProvCNAMETaget {
		t.Fatalf("%v", prov)
	}
	cov := res.Coverage
	if cov.Discovery != "known_names" || cov.DNSSEC != "not_checked" || cov.AuthoritativeAsked != 1 || len(cov.Resolvers) != 2 || cov.NamesChecked != 3 {
		t.Fatalf("%+v", cov)
	}
	if len(res.Auth) != 1 || res.Auth[0].NS != "ns1.example.com" || res.Auth[0].Answers[TypeSOA].Outcome != OutcomeAnswer || !res.Auth[0].Answers[TypeSOA].AA {
		t.Fatalf("%+v", res.Auth)
	}
	if len(res.Mismatch) != 0 {
		t.Fatalf("%v", res.Mismatch)
	}
}

func TestAnUnconfirmedAnswerIsKeptButNotTrusted(t *testing.T) {
	a, c := newFake(t, zone())
	other := zone()
	other["example.com|A"] = spec{answers: []dnsmessage.Resource{rrA("example.com", "203.0.113.99", 300)}} // a resolver that has not caught up
	b, _ := newFake(t, other)
	res := Run(context.Background(), cfgFor(c, a, b))
	rec, ok := find(res, "example.com", TypeA)
	if !ok || rec.Confirmed || res.Coverage.Unconfirmed == 0 {
		t.Fatalf("%+v unconfirmed %d", rec, res.Coverage.Unconfirmed)
	}
	if len(rec.Views) != 2 || rec.Views[0].Values[0] == rec.Views[1].Values[0] {
		t.Fatalf("both resolvers' answers are kept: %+v", rec.Views)
	}
	// And the diff, fed this run, ignores it.
	prev := map[Key]State{{"example.com", TypeA}: {Values: []string{"93.184.216.34"}, Result: OutcomeAnswer}}
	if ch := Diff(prev, []Obs{rec.Obs}, false); len(ch) != 0 {
		t.Fatalf("%v", ch)
	}
}

func TestOneResolverDownIsNotConfirmedAndNothingIsLost(t *testing.T) {
	a, c := newFake(t, zone())
	dead := zone()
	for k := range dead {
		dead[k] = spec{silent: true}
	}
	b, _ := newFake(t, dead)
	res := Run(context.Background(), cfgFor(c, a, b))
	rec, ok := find(res, "example.com", TypeMX)
	if !ok || rec.Confirmed || rec.Result != OutcomeAnswer || len(rec.Values) == 0 {
		t.Fatalf("what the working resolver said is kept, unconfirmed: %+v", rec)
	}
	if res.Status == "failed" {
		t.Fatalf("one resolver is enough to read; the run is %s", res.Status)
	}
}

func TestWhenNothingAnswersTheRunFailsAndInventsNothing(t *testing.T) {
	silent := map[string]spec{}
	for k := range zone() {
		silent[k] = spec{silent: true}
	}
	// A fake answers "no such name" to a question it has no entry for, so every question asked is listed.
	for _, ty := range apexTypes {
		silent["example.com|"+ty] = spec{silent: true}
	}
	for _, ty := range hostTypes {
		silent["www.example.com|"+ty] = spec{silent: true}
	}
	a, c := newFake(t, silent)
	b, _ := newFake(t, silent)
	res := Run(context.Background(), cfgFor(c, a, b))
	if res.Status != "failed" || res.Coverage.Failures == 0 {
		t.Fatalf("%s %+v", res.Status, res.Coverage)
	}
	for _, r := range res.Recs {
		if r.Result == OutcomeAnswer || len(r.Values) > 0 || r.Confirmed {
			t.Fatalf("a failed run produced data: %+v", r)
		}
	}
	// None of it can become a change.
	prev := map[Key]State{{"example.com", TypeA}: {Values: []string{"93.184.216.34"}, Result: OutcomeAnswer}}
	var obs []Obs
	for _, r := range res.Recs {
		obs = append(obs, r.Obs)
	}
	if ch := Diff(prev, obs, false); len(ch) != 0 {
		t.Fatalf("%v", ch)
	}
}

func TestNamesOutsideTheDomainAreDroppedAndTheNumberIsBounded(t *testing.T) {
	a, c := newFake(t, zone())
	cfg := cfgFor(c, a, a)
	cfg.ExtraNames = []string{"evil.org", "EXAMPLE.com.evil.org", "ok.example.com", "ok.example.com", "bad name.example.com"}
	for i := 0; i < 100; i++ {
		cfg.CTNames = append(cfg.CTNames, "h"+itoa(i)+".example.com")
	}
	cfg.MaxNames = 10
	names, dropped := cfg.planNames()
	if len(names) != 10 || dropped < 90 {
		t.Fatalf("%d names, %d dropped", len(names), dropped)
	}
	for _, n := range names {
		if !strings.HasSuffix(n.Name, "example.com") || strings.Contains(n.Name, "evil") {
			t.Fatalf("%+v", n)
		}
	}
	if names[2].Name != "ok.example.com" || names[2].Provenance != ProvManual || names[3].Provenance != ProvExisting {
		t.Fatalf("%+v", names[:4])
	}
}

func TestAuthoritativeServersThatDisagreeAreNoted(t *testing.T) {
	a, c := newFake(t, zone())
	b, _ := newFake(t, zone())
	other := zone()
	other["example.com|MX"] = spec{answers: []dnsmessage.Resource{mxRR("example.com", 10, "mail.other.example.net")}}
	other["example.com|SOA"] = spec{aa: true, answers: []dnsmessage.Resource{soaRR("example.com", 99)}}
	auth, _ := newFake(t, other)
	cfg := cfgFor(c, a, b)
	cfg.AuthPort = auth.addr.Port()
	res := Run(context.Background(), cfg)
	if got := strings.Join(res.Mismatch, ","); !strings.Contains(got, "MX") {
		t.Fatalf("the authoritative server disagrees with the resolvers about MX: %v", res.Mismatch)
	}
}

func TestAnAuthoritativeServerAtAPrivateAddressIsNotAsked(t *testing.T) {
	z := zone()
	z["ns1.example.com|A"] = spec{answers: []dnsmessage.Resource{rrA("ns1.example.com", "10.0.0.53", 300)}}
	a, c := newFake(t, z)
	b, _ := newFake(t, z)
	res := Run(context.Background(), cfgFor(c, a, b))
	if len(res.Auth) != 1 || res.Auth[0].Skipped != "not_public" || res.Auth[0].Addr != "" || res.Coverage.AuthoritativeAsked != 0 {
		t.Fatalf("%+v", res.Auth)
	}
}
