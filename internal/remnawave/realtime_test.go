package remnawave

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNodesRealtimeReadsSpeedsAndSkipsRowsWithoutIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/bandwidth-stats/nodes/realtime" || r.Header.Get("Authorization") != "Bearer "+token {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"response":[
			{"nodeUuid":"b","nodeName":"Steal","downloadSpeedBps":2500,"uploadSpeedBps":"bad"},
			{"nodeUuid":"a","nodeName":"Helsinki","downloadSpeedBps":1000,"uploadSpeedBps":300},
			{"nodeName":"no identity","downloadSpeedBps":9}]}`))
	}))
	defer srv.Close()
	rates, err := NewV3(srv.URL, token, plainGetter{}).NodesRealtime(context.Background())
	if err != nil || len(rates) != 2 {
		t.Fatalf("%v %+v", err, rates)
	}
	if rates[0].Name != "Helsinki" || rates[0].DownBps != 1000 || rates[0].UpBps != 300 || rates[1].DownBps != 2500 || rates[1].UpBps != 0 {
		t.Fatalf("%+v", rates)
	}
}

func TestUsersCarryTheEndDateAndTheLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"total":2,"users":[
			{"id":7,"username":"u7","status":"ACTIVE","expireAt":"2026-11-20T10:00:00.000Z","trafficLimitBytes":1073741824,"userTraffic":{"usedTrafficBytes":5}},
			{"id":8,"username":"u8","status":"ACTIVE","expireAt":"not a date","trafficLimitBytes":0}]}}`))
	}))
	defer srv.Close()
	pg, err := NewV3(srv.URL, token, plainGetter{}).ListUsers(context.Background(), 0, 50)
	if err != nil || len(pg.Users) != 2 {
		t.Fatalf("%v %+v", err, pg)
	}
	u := pg.Users[0]
	if u.ExpireAt == nil || u.ExpireAt.Format("2006-01-02") != "2026-11-20" || u.LimitBytes == nil || *u.LimitBytes != 1<<30 || *u.UsedBytes != 5 {
		t.Fatalf("%+v", u)
	}
	if v := pg.Users[1]; v.ExpireAt != nil || v.LimitBytes == nil || *v.LimitBytes != 0 {
		t.Fatalf("an unreadable date is not invented: %+v", v)
	}
}
