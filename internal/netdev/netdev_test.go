package netdev

import "testing"

func TestParseReadsStatsInterfacesAndClientsAndIgnoresJunk(t *testing.T) {
	r, err := Parse("board=hAP ax3\nversion=7.16 (stable)\nuptime=1w2d03:04:05\ncpu=7\nmem_free=500\nmem_total=1000\ntemp=47\nif=ether1,100,200,true\nif=bad,x,1,true\nif=ether2,1,2,false\nclient=192.168.88.20,aa:bb:cc:dd:ee:01,home-pc\nclient=999.1.1.1,aa:bb:cc:dd:ee:02\nclient=192.168.88.21,zz\nrandom text\n")
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasStats || r.Board != "hAP ax3" || r.UptimeSec != 7*86400+2*86400+3*3600+4*60+5 || r.CPU != 7 || r.MemTotal != 1000 || r.Temp == nil || *r.Temp != 47 {
		t.Fatalf("%+v", r)
	}
	if len(r.Ifaces) != 2 || r.Ifaces[0].RX != 100 || !r.Ifaces[0].Up || r.Ifaces[1].Up {
		t.Fatalf("%+v", r.Ifaces)
	}
	if len(r.Clients) != 1 || r.Clients[0].MAC != "AA:BB:CC:DD:EE:01" || r.Clients[0].Host != "home-pc" {
		t.Fatalf("%+v", r.Clients)
	}
}

func TestParseRefusesNothingUsableAndBadNumbers(t *testing.T) {
	if _, err := Parse("hello\nworld"); err == nil {
		t.Fatal("junk must be an error")
	}
	r, err := Parse("cpu=900\nboard=x")
	if err != nil || r.HasStats {
		t.Fatalf("an impossible load is not stats: %+v %v", r, err)
	}
	if s, ok := ParseUptime("03:04:05"); !ok || s != 11045 {
		t.Fatal(s, ok)
	}
	if _, ok := ParseUptime("soon"); ok {
		t.Fatal("not an uptime")
	}
}
