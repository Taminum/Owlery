// Package secfw reads the text of a firewall ruleset (nftables or iptables-save, already canonicalised by
// the agent) into a small structured model for the screen, and compares two rulesets line by line.
//
// It is a reader, not an interpreter. It does not decide what a rule allows or blocks, and nothing here
// can say that a port is open or closed: rules can be shadowed, bypassed or applied in another namespace.
package secfw

import (
	"strings"
)

// Chain is one chain with its rules as the lines were written.
type Chain struct {
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`     // filter | nat | route, nftables base chains
	Hook     string   `json:"hook,omitempty"`     // input | output | forward | prerouting | postrouting
	Priority string   `json:"priority,omitempty"` // as written
	Policy   string   `json:"policy,omitempty"`   // accept | drop, when the chain has one
	Rules    []string `json:"rules"`
}

type Table struct {
	Family string   `json:"family"`
	Name   string   `json:"name"`
	Chains []Chain  `json:"chains"`
	Other  []string `json:"other,omitempty"` // sets, maps and flowtables, by their first line
}

type Model struct {
	Backend string  `json:"backend"`
	Tables  []Table `json:"tables"`
	Rules   int     `json:"rules"`
}

// Parse reads rules text. Anything it does not understand stays in the text; the model is a convenience
// and the text is the record.
func Parse(backend, text string) Model {
	m := Model{Backend: backend, Tables: []Table{}}
	switch backend {
	case "iptables":
		m.Tables = parseIptables(text)
	default:
		m.Tables = parseNft(text)
	}
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			m.Rules += len(c.Rules)
		}
	}
	return m
}

func parseNft(text string) []Table {
	var out []Table
	var t *Table
	var c *Chain
	depth := 0
	var other string
	var otherDepth int
	flushOther := func() {
		if t != nil && other != "" {
			t.Other = append(t.Other, other)
		}
		other = ""
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case t == nil:
			f := strings.Fields(strings.TrimSuffix(line, "{"))
			if len(f) >= 3 && f[0] == "table" && strings.HasSuffix(line, "{") {
				out = append(out, Table{Family: f[1], Name: f[2], Chains: []Chain{}})
				t = &out[len(out)-1]
				depth = 1
			}
		case other != "":
			// Inside a set, map or flowtable: skip to its closing brace.
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= otherDepth {
				flushOther()
			}
		case c == nil:
			switch {
			case line == "}":
				t, depth = nil, 0
			case strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{"):
				t.Chains = append(t.Chains, Chain{Name: strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{")), Rules: []string{}})
				c = &t.Chains[len(t.Chains)-1]
				depth = 2
			case strings.HasSuffix(line, "{"):
				other = strings.TrimSpace(strings.TrimSuffix(line, "{"))
				otherDepth = depth
				depth++
			}
		default:
			if line == "}" {
				c, depth = nil, 1
				continue
			}
			if strings.HasPrefix(line, "type ") && strings.Contains(line, " hook ") {
				f := strings.Fields(strings.ReplaceAll(line, ";", " "))
				for i := 0; i+1 < len(f); i++ {
					switch f[i] {
					case "type":
						c.Type = f[i+1]
					case "hook":
						c.Hook = f[i+1]
					case "priority":
						// "priority filter - 1" has up to three words; take until "policy".
						j := i + 1
						var p []string
						for j < len(f) && f[j] != "policy" {
							p = append(p, f[j])
							j++
						}
						c.Priority = strings.Join(p, " ")
					case "policy":
						c.Policy = f[i+1]
					}
				}
				continue
			}
			c.Rules = append(c.Rules, line)
		}
	}
	return out
}

func parseIptables(text string) []Table {
	var out []Table
	var t *Table
	idx := map[string]int{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "*"):
			out = append(out, Table{Family: "ip", Name: strings.TrimPrefix(line, "*"), Chains: []Chain{}})
			t = &out[len(out)-1]
			idx = map[string]int{}
		case line == "COMMIT":
			t = nil
		case t == nil:
		case strings.HasPrefix(line, ":"):
			f := strings.Fields(strings.TrimPrefix(line, ":"))
			if len(f) >= 2 {
				ch := Chain{Name: f[0], Rules: []string{}}
				if f[1] != "-" {
					ch.Policy = strings.ToLower(f[1])
				}
				idx[f[0]] = len(t.Chains)
				t.Chains = append(t.Chains, ch)
			}
		case strings.HasPrefix(line, "-A "):
			f := strings.Fields(line)
			if len(f) >= 2 {
				i, ok := idx[f[1]]
				if !ok {
					idx[f[1]] = len(t.Chains)
					t.Chains = append(t.Chains, Chain{Name: f[1], Rules: []string{}})
					i = len(t.Chains) - 1
				}
				t.Chains[i].Rules = append(t.Chains[i].Rules, strings.TrimSpace(strings.TrimPrefix(line, "-A "+f[1])))
			}
		}
	}
	return out
}

// Line is one line of a comparison. Op is " " for context, "+" for a line only in the newer text, "-" for
// one only in the older.
type Line struct {
	Op   string `json:"op"`
	Text string `json:"text"`
}

// Diff lists what differs between two ruleset texts, with a little context around each change. It
// returns nothing when the texts are equal and caps its output at max lines (truncated reports it).
func Diff(a, b string, context, max int) (lines []Line, added, removed int, truncated bool) {
	x, y := split(a), split(b)
	n, m := len(x), len(y)
	// Longest common subsequence by dynamic programming; rulesets are bounded (64 KiB), so this is small.
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max32(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var full []Line
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			full = append(full, Line{" ", x[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			full = append(full, Line{"-", x[i]})
			removed++
			i++
		default:
			full = append(full, Line{"+", y[j]})
			added++
			j++
		}
	}
	for ; i < n; i++ {
		full = append(full, Line{"-", x[i]})
		removed++
	}
	for ; j < m; j++ {
		full = append(full, Line{"+", y[j]})
		added++
	}
	if added+removed == 0 {
		return nil, 0, 0, false
	}
	keep := make([]bool, len(full))
	for k, l := range full {
		if l.Op != " " {
			for d := -context; d <= context; d++ {
				if k+d >= 0 && k+d < len(full) {
					keep[k+d] = true
				}
			}
		}
	}
	gap := false
	for k, l := range full {
		if !keep[k] {
			gap = true
			continue
		}
		if gap && len(lines) > 0 {
			lines = append(lines, Line{"…", ""})
		}
		gap = false
		if len(lines) >= max {
			return lines, added, removed, true
		}
		lines = append(lines, l)
	}
	return lines, added, removed, false
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
