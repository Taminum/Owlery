package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
)

const sensorStream = "W\tc1\t1000\t1060\t3\t2\n" +
	"F\t10.8.1.2\t6\t1.2.3.4\t443\t100\t9000\tsite.example\tsni\n" +
	"F\t10.8.1.2\t17\t9.9.9.9\t53\t50\t50\t\t\n" +
	"F\tbroken line\n" +
	"F\t10.8.1.2\tx\t1.2.3.4\t443\t1\t1\t\t\n" + // bad protocol number: skipped
	"E\n" +
	"F\t10.8.1.2\t6\t1.1.1.1\t443\t1\t1\t\t\n" + // outside a window: ignored
	"W\tother\t1060\t1120\t0\t0\n" + // a container nobody asked for: the whole report is ignored
	"F\t10.8.1.2\t6\t8.8.8.8\t443\t1\t1\t\t\n" +
	"E\n" +
	"W\tc1\t1120\t1180\t0\t0\n" +
	"E\n"

func TestSensorReportsBecomeFramesAndGarbageAndStrangersAreIgnored(t *testing.T) {
	got := make(chan ingestproto.AWGFlows, 4)
	src := &AWGSensorSource{Containers: []string{"c1"}, Emit: func(f ingestproto.AWGFlows) { got <- f }}
	src.consume(strings.NewReader(sensorStream))
	close(got)
	var frames []ingestproto.AWGFlows
	for f := range got {
		frames = append(frames, f)
	}
	if len(frames) != 2 {
		t.Fatalf("%d frames: %+v", len(frames), frames)
	}
	a := frames[0]
	if a.Container != "c1" || a.Start != 1000 || a.End != 1060 || a.Dropped != 3 || a.Left != 2 || len(a.Flows) != 2 {
		t.Fatalf("%+v", a)
	}
	if f := a.Flows[0]; f.Client != "10.8.1.2" || f.Port != 443 || f.Up != 100 || f.Down != 9000 || f.Name != "site.example" || f.How != "sni" {
		t.Fatalf("%+v", f)
	}
	if frames[1].Start != 1120 || len(frames[1].Flows) != 0 {
		t.Fatalf("%+v", frames[1])
	}
}

func TestSensorsReportThroughTheAgentSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "s")
	if err != nil {
		t.Skip("no temp dir")
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "sensor.sock")
	got := make(chan ingestproto.AWGFlows, 4)
	src := &AWGSensorSource{Socket: sock, Containers: []string{"c1"}, Emit: func(f ingestproto.AWGFlows) { got <- f }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx)
	var c net.Conn
	for i := 0; i < 100; i++ {
		if c, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Skip("unix sockets are not available here: " + err.Error())
	}
	defer c.Close()
	_, _ = c.Write([]byte(sensorStream))
	select {
	case f := <-got:
		if f.Container != "c1" || len(f.Flows) != 2 {
			t.Fatalf("%+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no report arrived through the socket")
	}
}
