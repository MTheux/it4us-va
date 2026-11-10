// Package vacheck is the non-intrusive Vulnerability Assessment check library.
// Each check parses one scanner's raw output into normalized finding Candidates.
// Parsers here are pure: no network, no shell-out, no filesystem access beyond
// the bytes they are given. That purity is what makes them unit-testable and is
// a hard constraint (see the plan's Global Constraints). Live orchestration of
// scanners, CVE feeds, the asset graph and db.DBFinding persistence belong to a
// later layer, not to this package.
package vacheck

import (
	"sort"
	"sync"
)

// Asset is the host/service a Candidate is about.
type Asset struct {
	Host    string
	IP      string
	Port    int
	Proto   string // tcp/udp
	Service string
}

// Candidate is a normalized, non-intrusive VA finding produced by a check
// parser, decoupled from the AI and from DB persistence.
type Candidate struct {
	Check     string   // check id, e.g. "nmap.service"
	Title     string   // readable pt-BR title
	VulnClass string   // taxonomy key (maps to db.DBFinding.VulnClass)
	Severity  string   // one of db.Severity* constants
	Asset     Asset    // host/service the finding is about
	Summary   string   // pt-BR one-paragraph
	Evidence  string   // raw scanner excerpt (read-only capture)
	Tags      []string // coverage tags, e.g. "foresea:ad-hygiene"
	Refs      []string // CVE ids / references
}

// Parser turns one scanner's raw output into zero or more Candidates. It must be
// pure (no I/O, no network) so it is unit-testable from fixtures.
type Parser func(raw []byte) ([]Candidate, error)

// Check is the static, non-intrusive definition of a VA check.
type Check struct {
	ID           string   // "nmap.service"
	Title        string   // pt-BR
	Tool         string   // "nmap"
	ReadOnlyArgs []string // the only args the orchestrator may use (asserted non-intrusive)
	ForeSea      string   // which ForeSea area it derives from
	Parse        Parser
}

var (
	regMu    sync.RWMutex
	registry = map[string]Check{}
)

// Register adds a check to the global registry. It panics on duplicate ID so a
// collision is caught at init time, not silently shadowed.
func Register(c Check) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[c.ID]; dup {
		panic("vacheck: ID de check duplicado: " + c.ID)
	}
	registry[c.ID] = c
}

// All returns every registered check, ordered by ID.
func All() []Check {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns the check with the given ID.
func Get(id string) (Check, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	c, ok := registry[id]
	return c, ok
}
