package remnawave

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTorrentReportsReadWhicheverNamesThePanelUses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node-plugins/torrent-blocker" {
			t.Errorf("asked %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"response":{"total":3,"records":[
			{"id":4,"userId":12,"nodeName":"Steal","createdAt":"2026-11-13T10:00:00.000Z"},
			{"userUuid":"abc","node":{"name":"Helsinki"},"reportedAt":"2026-11-13T09:00:00Z"},
			{"userId":13}]}}`))
	}))
	defer srv.Close()
	p, err := NewV3(srv.URL, "tok", plainGetter{}).TorrentReports(context.Background(), 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 3 || len(p.Reports) != 2 {
		t.Fatalf("got %+v", p)
	}
	if a, b := p.Reports[0], p.Reports[1]; a.ID != 4 || a.User != "12" || a.Node != "Steal" || b.User != "abc" || b.Node != "Helsinki" || b.ID == 0 {
		t.Fatalf("reports %+v", p.Reports)
	}
}

func TestHWIDDevicesReadAndAnUnknownShapeIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("start") == "5" {
			_, _ = w.Write([]byte(`{"response":{"devices":[{"foo":1}],"total":9}}`))
			return
		}
		_, _ = w.Write([]byte(`{"response":{"total":2,"devices":[{"hwid":"a1","userId":7},{"hwid":"b2","userUuid":"7"},{"hwid":"","userId":7}]}}`))
	}))
	defer srv.Close()
	a := NewV3(srv.URL, "tok", plainGetter{})
	p, err := a.HWIDDevices(context.Background(), 0, 200)
	if err != nil || p.Total != 2 || len(p.Devices) != 2 || p.Devices[0].User != "7" || p.Devices[1].HWID != "b2" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := a.HWIDDevices(context.Background(), 5, 200); ErrorCode(err) != CodeIncompatible {
		t.Fatalf("got %v", err)
	}
}

func TestAnEmptyListIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"records":[],"total":0}}`))
	}))
	defer srv.Close()
	p, err := NewV3(srv.URL, "tok", plainGetter{}).TorrentReports(context.Background(), 0, 200)
	if err != nil || len(p.Reports) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
}
