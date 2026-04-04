package tests

import (
	"github.com/leonardomb1/pulse/node"
	"testing"
)

func TestPortRangeContains(t *testing.T) {
	tests := []struct {
		pr   node.PortRange
		port uint16
		want bool
	}{
		{node.PortRange{Low: 22}, 22, true},
		{node.PortRange{Low: 22}, 23, false},
		{node.PortRange{Low: 80, High: 443}, 80, true},
		{node.PortRange{Low: 80, High: 443}, 443, true},
		{node.PortRange{Low: 80, High: 443}, 200, true},
		{node.PortRange{Low: 80, High: 443}, 79, false},
		{node.PortRange{Low: 80, High: 443}, 444, false},
	}
	for _, tt := range tests {
		got := tt.pr.Contains(tt.port)
		if got != tt.want {
			t.Errorf("PortRange{%d,%d}.Contains(%d) = %v, want %v", tt.pr.Low, tt.pr.High, tt.port, got, tt.want)
		}
	}
}

func TestParsePortRanges(t *testing.T) {
	tests := []struct {
		input string
		want  int
		err   bool
	}{
		{"22", 1, false},
		{"22,80,443", 3, false},
		{"8000-9000", 1, false},
		{"22,80,8000-9000", 3, false},
		{"", 0, false},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := node.ParsePortRanges(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ParsePortRanges(%q): err=%v, wantErr=%v", tt.input, err, tt.err)
		}
		if len(got) != tt.want {
			t.Errorf("ParsePortRanges(%q): got %d ranges, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestMatchesNode(t *testing.T) {
	meta := node.NodeMeta{Name: "db-server", Tags: []string{"prod", "infra"}}
	tests := []struct {
		pattern string
		nodeID  string
		meta    node.NodeMeta
		want    bool
	}{
		{"*", "abc123", node.NodeMeta{}, true},
		{"", "abc123", node.NodeMeta{}, true},
		{"abc*", "abc123", node.NodeMeta{}, true},
		{"abc*", "xyz123", node.NodeMeta{}, false},
		{"tag:prod", "abc123", meta, true},
		{"tag:dev", "abc123", meta, false},
		{"tag:infra", "abc123", meta, true},
		{"db-server", "abc123", meta, true},
		{"web-server", "abc123", meta, false},
		{"abc123", "abc123", node.NodeMeta{}, true},
	}
	for _, tt := range tests {
		got := node.MatchesNode(tt.pattern, tt.nodeID, tt.meta)
		if got != tt.want {
			t.Errorf("MatchesNode(%q, %q) = %v, want %v", tt.pattern, tt.nodeID, got, tt.want)
		}
	}
}

func TestNodeACLCheck(t *testing.T) {
	lookup := func(nodeID string) node.NodeMeta {
		switch nodeID {
		case "dev1":
			return node.NodeMeta{Tags: []string{"dev"}}
		case "prod1":
			return node.NodeMeta{Tags: []string{"prod"}}
		}
		return node.NodeMeta{}
	}

	acl := node.NodeACL{
		NodeID: "dev1",
		Allow: []node.ACLRule{
			{Action: "allow", SrcPattern: "tag:dev", DstPattern: "*", Ports: []node.PortRange{{Low: 22}}},
			{Action: "deny", SrcPattern: "tag:dev", DstPattern: "tag:prod"},
			{Action: "allow", DstPattern: "*"},
		},
	}

	tests := []struct {
		name    string
		src     string
		dst     string
		port    uint16
		wantErr bool
	}{
		{"dev SSH allowed", "dev1", "prod1", 22, false},
		{"dev HTTP denied", "dev1", "prod1", 80, true},
		{"other allowed", "other", "prod1", 80, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := acl.Check(tt.src, tt.dst, tt.port, lookup)
			if (err != nil) != tt.wantErr {
				t.Errorf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}

	// Empty ACL = allow all.
	empty := node.NodeACL{NodeID: "x"}
	if err := empty.Check("x", "y", 0, lookup); err != nil {
		t.Errorf("empty ACL should allow all: %v", err)
	}
}
