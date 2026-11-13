package remnawave

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubscriptionHistoryReadsRecordsAndSkipsRowsWithoutIdentity(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Path + "?" + r.URL.RawQuery
		_, _ = w.Write([]byte(`{"response":{"total":3,"records":[
			{"id":7,"userId":12,"requestAt":"2026-11-13T10:00:00.000Z","requestIp":"46.1.2.3","userAgent":"Hiddify/2.0","srrRuleName":null},
			{"id":6,"userId":12,"requestAt":"2026-11-13T09:00:00Z","requestIp":null,"userAgent":null},
			{"id":0,"userId":12,"requestAt":"2026-11-13T08:00:00Z"},
			{"id":5,"userId":"12","requestAt":"2026-11-13T07:00:00Z"}]}}`))
	}))
	defer srv.Close()
	h, err := NewV3(srv.URL, "tok", plainGetter{}).SubscriptionHistory(context.Background(), 0, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "/api/subscription-request-history?size=1000&start=0" {
		t.Fatalf("asked %s", gotQuery)
	}
	if h.Total != 3 || len(h.Records) != 2 || h.Skipped != 2 {
		t.Fatalf("got %+v", h)
	}
	r := h.Records[0]
	if r.ID != 7 || r.UserID != "12" || r.IP != "46.1.2.3" || r.Agent != "Hiddify/2.0" || r.At.Hour() != 10 {
		t.Fatalf("record %+v", r)
	}
	if h.Records[1].IP != "" || h.Records[1].Agent != "" {
		t.Fatalf("null fields should be empty: %+v", h.Records[1])
	}
}

func TestSubscriptionHistoryRefusesAnUnknownShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":{"records":[{"foo":1}],"total":1}}`))
	}))
	defer srv.Close()
	if _, err := NewV3(srv.URL, "tok", plainGetter{}).SubscriptionHistory(context.Background(), 0, 10); ErrorCode(err) != CodeIncompatible {
		t.Fatalf("got %v", err)
	}
}
