package store

import (
	"encoding/json"
	"testing"

	"github.com/Taminum/Owlery/internal/secproto"
)

func TestDockerSnapshotHashIgnoresTheLoad(t *testing.T) {
	parse := func(s string) (string, error) {
		_, _, h, err := ParseSnapshotData(secproto.CatDocker, secproto.StatusOK, json.RawMessage(s))
		return h, err
	}
	base := `{"containers":[{"id":"aaaaaaaaaaaa","name":"nginx","image":"nginx","state":"running","restarts":2,"restarts_1h":0,"cpu":1.5,"mem":1000,"ports":["80"]}]}`
	busier := `{"containers":[{"id":"aaaaaaaaaaaa","name":"nginx","image":"nginx","state":"running","restarts":2,"restarts_1h":0,"cpu":40,"mem":9000,"ports":["80"]}]}`
	restarted := `{"containers":[{"id":"aaaaaaaaaaaa","name":"nginx","image":"nginx","state":"running","restarts":3,"restarts_1h":1,"cpu":1.5,"mem":1000,"ports":["80"]}]}`
	a, err := parse(base)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := parse(busier); a != b {
		t.Error("load alone is not a change: the history would grow by a line every half minute")
	}
	if c, _ := parse(restarted); a == c {
		t.Error("a restart is a change")
	}
	for name, bad := range map[string]string{
		"short id":       `{"containers":[{"id":"abc","name":"x","image":"i","state":"running"}]}`,
		"no name":        `{"containers":[{"id":"aaaaaaaaaaaa","name":"","image":"i","state":"running"}]}`,
		"unknown":        `{"containers":[],"secret":"x"}`,
		"too many ports": `{"containers":[{"id":"aaaaaaaaaaaa","name":"x","image":"i","state":"running","ports":["1","2","3","4","5","6","7","8","9"]}]}`,
	} {
		if _, err := parse(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
