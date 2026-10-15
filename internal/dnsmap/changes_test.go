package dnsmap

import (
	"strings"
	"testing"
)

func st(result string, v ...string) State { return State{Values: v, Result: result} }

func obs(name, typ, result string, confirmed bool, v ...string) Obs {
	return Obs{Name: name, Type: typ, Result: result, Values: v, Confirmed: confirmed}
}

func kinds(cs []Change) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Name+" "+c.Type+" "+c.Kind)
	}
	return strings.Join(out, "; ")
}

func TestTheFirstRunExplainsNothing(t *testing.T) {
	if got := Diff(nil, []Obs{obs("example.com", TypeA, OutcomeAnswer, true, "1.1.1.1")}, true); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestAddedRemovedAndChangedRecords(t *testing.T) {
	prev := map[Key]State{
		{"example.com", TypeA}:     st(OutcomeAnswer, "1.1.1.1", "2.2.2.2"),
		{"example.com", TypeMX}:    st(OutcomeAnswer, "10 mail.example.com"),
		{"example.com", TypeNS}:    st(OutcomeAnswer, "ns1.example.net", "ns2.example.net"),
		{"example.com", TypeSOA}:   st(OutcomeAnswer, "ns1 h 1 7200 900 1209600 300"),
		{"www.example.com", TypeA}: st(OutcomeAnswer, "3.3.3.3"),
	}
	cur := []Obs{
		obs("example.com", TypeA, OutcomeAnswer, true, "1.1.1.1", "4.4.4.4"),
		obs("example.com", TypeMX, OutcomeAnswer, true, "20 other.example.org"),
		obs("example.com", TypeNS, OutcomeAnswer, true, "ns1.example.net", "ns3.example.net"),
		obs("example.com", TypeSOA, OutcomeAnswer, true, "ns1 h 2 7200 900 1209600 300"),
		obs("www.example.com", TypeA, OutcomeNXDomain, true),
		obs("new.example.com", TypeA, OutcomeAnswer, true, "5.5.5.5"),
	}
	got := kinds(Diff(prev, cur, false))
	for _, want := range []string{"example.com A dns.record_added", "example.com A dns.record_removed", "example.com MX dns.mx_changed", "example.com NS dns.ns_changed",
		"example.com SOA dns.value_changed", "www.example.com A dns.record_removed", "new.example.com A dns.record_added"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}
}

func TestAFailureAnUnconfirmedAnswerAndAnUnaskedRecordAreNeverAChange(t *testing.T) {
	prev := map[Key]State{{"example.com", TypeA}: st(OutcomeAnswer, "1.1.1.1"), {"example.com", TypeMX}: st(OutcomeAnswer, "10 m.example.com")}
	for _, o := range []Obs{
		obs("example.com", TypeA, OutcomeTimeout, true),
		obs("example.com", TypeA, OutcomeServFail, true),
		obs("example.com", TypeA, OutcomeRefused, true),
		obs("example.com", TypeA, OutcomeError, true),
		obs("example.com", TypeA, OutcomeNXDomain, false),          // one resolver's word is not enough to delete a record
		obs("example.com", TypeA, OutcomeAnswer, false, "9.9.9.9"), // nor to add one
	} {
		if got := Diff(prev, []Obs{o}, false); len(got) != 0 {
			t.Errorf("%+v produced %v", o, got)
		}
	}
	// MX was not asked about at all: it is left as it was, not "removed".
	if got := Diff(prev, []Obs{obs("example.com", TypeA, OutcomeAnswer, true, "1.1.1.1")}, false); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestTheSameRecordsInAnotherOrderAreNoChange(t *testing.T) {
	prev := map[Key]State{{"example.com", TypeA}: st(OutcomeAnswer, "1.1.1.1", "2.2.2.2")}
	if got := Diff(prev, []Obs{obs("example.com", TypeA, OutcomeAnswer, true, "2.2.2.2", "1.1.1.1")}, false); len(got) != 0 {
		t.Fatalf("round-robin order is not a change: %v", got)
	}
}

func TestSPFAndDMARCAreRecognisedWithoutBeingCalledCorrect(t *testing.T) {
	prev := map[Key]State{
		{"example.com", TypeTXT}:        st(OutcomeAnswer, "v=spf1 include:a.example -all", "google-site-verification=abc"),
		{"_dmarc.example.com", TypeTXT}: st(OutcomeAnswer, "v=DMARC1; p=none"),
	}
	cur := []Obs{
		obs("example.com", TypeTXT, OutcomeAnswer, true, "v=spf1 include:b.example ~all", "google-site-verification=abc"),
		obs("_dmarc.example.com", TypeTXT, OutcomeAnswer, true, "v=DMARC1; p=reject"),
	}
	got := Diff(prev, cur, false)
	if k := kinds(got); !strings.Contains(k, "example.com TXT dns.spf_changed") || !strings.Contains(k, "_dmarc.example.com TXT dns.dmarc_changed") {
		t.Fatalf("%s", k)
	}
	for _, c := range got {
		if c.Kind == ChangeAdded || c.Kind == ChangeRemoved {
			t.Errorf("an unrelated TXT value did not change: %+v", c)
		}
	}
	// An ordinary TXT record added is an addition, not an SPF change.
	got = Diff(prev, []Obs{obs("example.com", TypeTXT, OutcomeAnswer, true, "v=spf1 include:a.example -all", "google-site-verification=abc", "new-token=1")}, false)
	if len(got) != 1 || got[0].Kind != ChangeAdded || got[0].After[0] != "new-token=1" {
		t.Fatalf("%v", got)
	}
}

func TestANameThatHadNothingAndStillHasNothingIsQuiet(t *testing.T) {
	if got := Diff(nil, []Obs{obs("x.example.com", TypeAAAA, OutcomeNoData, true)}, false); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	prev := map[Key]State{{"x.example.com", TypeAAAA}: st(OutcomeNoData)}
	if got := Diff(prev, []Obs{obs("x.example.com", TypeAAAA, OutcomeNXDomain, true)}, false); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	// And a record that comes back after being absent is an addition.
	if got := Diff(prev, []Obs{obs("x.example.com", TypeAAAA, OutcomeAnswer, true, "2001:db8::1")}, false); len(got) != 1 || got[0].Kind != ChangeAdded {
		t.Fatalf("%v", got)
	}
}

func TestWhichChangesRaiseAnAlert(t *testing.T) {
	for k, want := range map[string]bool{ChangeNS: true, ChangeMX: true, ChangeSPF: true, ChangeDMARC: true, ChangeRemoved: true, ChangeValue: true, ChangeAdded: false, ChangeCheckFailed: false} {
		if Important(k) != want {
			t.Errorf("%s: %v", k, !want)
		}
	}
}
