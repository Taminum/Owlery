// Command demodata fills a DEVELOPMENT database with invented traffic so the analyzer pages
// (sites, domains, AmneziaWG) have something to show in screenshots and demos. Never run it
// against a real installation: it creates a panel called "Demo VPN" and thousands of fake rows.
//
//	DATABASE_URL=postgres://… demodata -dev-database
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Taminum/RemnaScope/internal/ingestproto"
	"github.com/Taminum/RemnaScope/internal/site"
	"github.com/Taminum/RemnaScope/internal/store"
)

const panelID = "33333333-3333-4333-8333-333333333333"

var sites = []struct {
	weight int
	hosts  []string
}{
	{20, []string{"www.google.com", "mtalk.google.com", "accounts.google.com", "www.gstatic.com"}},
	{16, []string{"rr1.googlevideo.com", "www.youtube.com", "i.ytimg.com"}},
	{9, []string{"api.telegram.org", "web.telegram.org", "t.me"}},
	{8, []string{"github.com", "api.github.com", "raw.githubusercontent.com"}},
	{7, []string{"cdn.discordapp.com", "discord.com", "gateway.discord.gg"}},
	{6, []string{"api.openai.com", "chatgpt.com"}},
	{6, []string{"open.spotify.com", "api.spotify.com"}},
	{5, []string{"www.reddit.com", "oauth.reddit.com"}},
	{5, []string{"en.wikipedia.org", "upload.wikimedia.org"}},
	{4, []string{"www.twitch.tv", "usher.ttvnw.net"}},
	{4, []string{"store.steampowered.com", "steamcommunity.com"}},
	{3, []string{"www.netflix.com", "occ-0-1.nflxvideo.net"}},
	{3, []string{"www.cloudflare.com", "one.one.one.one"}},
	{2, []string{"habr.com", "vk.com", "ya.ru"}},
	{2, []string{"unknown-tracker.example.net", "metrics.sample-cdn.example.org"}},
}

var awgHosts = [][]string{
	{"www.youtube.com", "rr3.googlevideo.com"}, {"www.google.com"}, {"api.telegram.org"}, {"open.spotify.com"},
	{"github.com"}, {"www.reddit.com"}, {"www.netflix.com", "occ-0-2.nflxvideo.net"}, {"discord.com"}, {"en.wikipedia.org"},
}

var remotes = []string{"142.250.74.14", "142.250.185.206", "140.82.121.4", "151.101.1.69", "104.16.132.229", "149.154.167.99", "162.159.135.232", "199.232.69.194"}

func main() {
	ok := flag.Bool("dev-database", false, "confirm that DATABASE_URL is a development database")
	flag.Parse()
	if !*ok || os.Getenv("DATABASE_URL") == "" {
		log.Fatal("refusing to run: set DATABASE_URL and pass -dev-database (this writes fake data)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	s := store.New(pool)
	rng := mrand.New(mrand.NewSource(7))
	now := time.Now().UTC()
	all := store.Scope{All: true}

	if _, err := s.GetPanel(ctx, all, panelID); errors.Is(err, store.ErrNotFound) {
		if _, err := s.CreatePanel(ctx, panelID, store.PanelInput{Name: "Demo VPN", BaseURL: "https://panel.example.com", Status: "active"}, nil); err != nil {
			log.Fatal(err)
		}
	} else if err != nil {
		log.Fatal(err)
	} else {
		log.Fatal("the demo panel already exists; remove it first (this tool is meant to run once)")
	}
	must(s.UpsertNodes(ctx, panelID, now, []store.NodeRecord{{RemoteUUID: "n1", Name: "node-fra"}, {RemoteUUID: "n2", Name: "node-ams"}}))
	must(s.UpsertUsers(ctx, panelID, now, []store.UserRecord{{RemoteUUID: "2", Username: "anna", Status: "ACTIVE"}, {RemoteUUID: "3", Username: "boris", Status: "ACTIVE"}, {RemoteUUID: "4", Username: "clara", Status: "ACTIVE"}}))
	nodes, err := s.ListNodes(ctx, all, panelID, false)
	check(err)
	users, _, err := s.ListUsers(ctx, all, panelID, "", 10)
	check(err)

	agents := map[string]string{}
	for _, n := range nodes {
		a, err := s.CreateAgent(ctx, all, panelID, n.ID, "agent-"+n.Name, "node", "", store.HashAgentSecret(token()))
		check(err)
		_, err = s.AgentHello(ctx, a.ID, "demo", "0.1", "demo")
		check(err)
		agents[n.ID] = a.ID
	}

	// connections of the last 24 hours, busier in the evening
	total := 0
	for i := 0; i < 9000; i++ {
		ts := now.Add(-time.Duration(rng.Int63n(int64(24 * time.Hour))))
		if rng.Float64() > 0.35+0.65*diurnal(ts.Hour()) {
			continue
		}
		st := pickSite(rng)
		host := st.hosts[rng.Intn(len(st.hosts))]
		n := nodes[rng.Intn(len(nodes))]
		u := users[rng.Intn(len(users))]
		fp := make([]byte, 16)
		_, _ = rand.Read(fp)
		inbound := "Steal"
		if rng.Intn(4) == 0 {
			inbound = "XHTTP-TW"
		}
		var siteName any
		if v := site.Of(host); v != "" {
			siteName = v
		}
		_, err := pool.Exec(ctx, `INSERT INTO connection_events (event_id, panel_id, node_id, agent_id, ts, client_ip, destination_host, destination_port, protocol, inbound_tag, outbound_tag, xray_email, user_id, raw_fingerprint, site)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5::inet, $6, 443, $7, $8, 'DIRECT', $9, $10, $11, $12)`,
			panelID, n.ID, agents[n.ID], ts, fmt.Sprintf("198.51.100.%d", 1+rng.Intn(40)), host, map[bool]string{true: "udp", false: "tcp"}[rng.Intn(14) == 0], inbound, u.RemoteUUID, u.ID, fp, siteName)
		check(err)
		total++
	}
	log.Printf("connections: %d", total)

	// an AmneziaWG server with four devices
	awgNode := nodes[0]
	ag, err := s.CreateAgent(ctx, all, panelID, awgNode.ID, "awg-demo", "awg", "", store.HashAgentSecret(token()))
	check(err)
	keys := []string{key(), key(), key(), key()}
	names := []string{"anna-phone", "boris-laptop", "living-room-tv", "home-router"}
	rx := []int64{0, 0, 0, 0}
	tx := []int64{0, 0, 0, 0}
	for h := 24; h >= 0; h-- {
		at := now.Add(-time.Duration(h) * time.Hour)
		peers := make([]ingestproto.AWGPeer, 0, 4)
		for i := range keys {
			grow := int64((rng.Intn(40) + 5) << 20)
			rx[i] += grow * int64(4-i) / 2
			tx[i] += grow * int64(i+1) / 3
			hs := at.Add(-time.Duration(rng.Intn(600)) * time.Second).Unix()
			if i == 3 && h < 0 {
				hs = 0
			}
			peers = append(peers, ingestproto.AWGPeer{Key: keys[i], Name: names[i], IP: fmt.Sprintf("10.8.1.%d/32", i+2), RX: rx[i], TX: tx[i], Handshake: hs})
		}
		check(s.SaveAWG(ctx, ag, ingestproto.AWG{Type: "awg", Instances: []ingestproto.AWGInstance{{Container: "amnezia-awg", Interface: "awg0", Port: 51820, Fields: []string{"Jc", "S3", "S4", "H1"}, Peers: peers}}}, at))
		flows := []ingestproto.AWGFlow{}
		for i := range keys {
			for k := 0; k < 6; k++ {
				set := awgHosts[rng.Intn(len(awgHosts))]
				flows = append(flows, ingestproto.AWGFlow{Client: fmt.Sprintf("10.8.1.%d", i+2), Proto: 6, Remote: remotes[rng.Intn(len(remotes))], Port: 443,
					Up: uint64(rng.Intn(400) << 10), Down: uint64((rng.Intn(9000) + 200) << 10), Name: set[rng.Intn(len(set))], How: "sni", New: 1})
			}
		}
		check(s.SaveAWGFlows(ctx, ag, ingestproto.AWGFlows{Type: "awg_flows", Container: "amnezia-awg", Start: at.Unix() - 60, End: at.Unix(), Flows: flows}, at))
	}
	log.Print("done: open the dashboard and pick the panel \"Demo VPN\"")
}

func diurnal(h int) float64 { // 0..1, evening peak (UTC+5 viewer)
	d := float64((h+5)%24) - 20
	if d < 0 {
		d = -d
	}
	if d > 12 {
		d = 24 - d
	}
	return 1 - d/12
}

func pickSite(r *mrand.Rand) (out struct {
	weight int
	hosts  []string
}) {
	sum := 0
	for _, s := range sites {
		sum += s.weight
	}
	n := r.Intn(sum)
	for _, s := range sites {
		if n < s.weight {
			return s
		}
		n -= s.weight
	}
	return sites[0]
}

func token() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func key() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func must[T any](_ T, err error) { check(err) }
