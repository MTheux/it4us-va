package server

import (
	"testing"

	"github.com/MTheux/it4us-va/db"
)

func TestNewTaskIPScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope []db.ScopeInput
		isErr bool
	}{
		{name: "empty", scope: nil},
		{name: "IPs and CIDR", scope: []db.ScopeInput{{Kind: "ip", Value: "192.0.2.10"}, {Kind: "cidr", Value: "198.51.100.0/24"}}},
		{name: "invalid IP", scope: []db.ScopeInput{{Kind: "ip", Value: "999.1.1.1"}}, isErr: true},
		{name: "oversized CIDR", scope: []db.ScopeInput{{Kind: "cidr", Value: "10.0.0.0/8"}}, isErr: true},
		{name: "domain disallowed", scope: []db.ScopeInput{{Kind: "domain", Value: "example.com"}}, isErr: true},
		{name: "automatic classification disallowed", scope: []db.ScopeInput{{Value: "192.0.2.10"}}, isErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNewTaskIPScope(tc.scope)
			if (err != nil) != tc.isErr {
				t.Fatalf("validateNewTaskIPScope() error = %v, want error %t", err, tc.isErr)
			}
		})
	}
}

func TestNewTaskIPScopeCreatesAllowRules(t *testing.T) {
	inputs := []db.ScopeInput{{Kind: "ip", Value: "192.0.2.10"}, {Kind: "cidr", Value: "198.51.100.0/24"}}
	rules := newTaskIPAllowRules(inputs)
	if len(rules) != 2 || rules[0].Action != "allow" || rules[0].Kind != "exact_ip" || rules[0].Pattern != "192.0.2.10" ||
		rules[1].Action != "allow" || rules[1].Kind != "cidr" || rules[1].Pattern != "198.51.100.0/24" {
		t.Fatalf("unexpected task scope gates: %+v", rules)
	}
	allow := []db.AssetInterceptRule{
		{Enabled: true, Kind: rules[0].Kind, Pattern: rules[0].Pattern},
		{Enabled: true, Kind: rules[1].Kind, Pattern: rules[1].Pattern},
	}
	if !db.EvaluateAssetGate(nil, allow, nil, []string{"198.51.100.42"}, nil).Allowed {
		t.Fatal("IP in the imported CIDR was blocked")
	}
	if db.EvaluateAssetGate(nil, allow, nil, []string{"203.0.113.5"}, nil).Allowed {
		t.Fatal("IP outside the imported scope was allowed")
	}
}
