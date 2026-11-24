package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

// Aguara v0.29 alignment regressions. v0.29.0 moves MCP_009 to the
// mcp-capability analyzer and reports explicit Kubernetes SETUID/SETGID
// requests as LOW K8S_IDENTITY_CAPABILITIES_001 (kube-policy,
// container-security) instead of HIGH SUPPLY_007. These tests pin the
// finding fields MCP clients receive and keep the explain_rule tool
// description in step with the analyzers the catalog actually exposes.

func TestV029_CapabilityFindingContract(t *testing.T) {
	cases := []struct {
		name, filename, content                     string
		rule, severity, analyzer, category, verdict string
	}{
		{"kubernetes-setuid", "pod.yaml",
			"apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      capabilities: {add: [SETUID]}\n",
			"K8S_IDENTITY_CAPABILITIES_001", "LOW", "kube-policy", "container-security", "flag"},
		{"kubernetes-setgid", "pod.yaml",
			"apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      capabilities: {add: [SETGID]}\n",
			"K8S_IDENTITY_CAPABILITIES_001", "LOW", "kube-policy", "container-security", "flag"},
		{"mcp-capability-grant", "config.json", `{"capabilities":{"add":["ALL"]}}`,
			"MCP_009", "HIGH", "mcp-capability", "mcp-attack", "block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, isError := toolResponseText(t, handleScanContent(false), map[string]any{"content": tc.content, "filename": tc.filename})
			if isError {
				t.Fatal("scan returned an error")
			}
			var result struct {
				Verdict  string `json:"verdict"`
				Findings []struct {
					RuleID   string `json:"rule_id"`
					Severity string `json:"severity"`
					Analyzer string `json:"analyzer"`
					Category string `json:"category"`
				} `json:"findings"`
			}
			if err := json.Unmarshal([]byte(text), &result); err != nil {
				t.Fatal(err)
			}
			if result.Verdict != tc.verdict {
				t.Errorf("verdict = %q, want %q", result.Verdict, tc.verdict)
			}
			found := false
			for _, f := range result.Findings {
				if f.RuleID == "SUPPLY_007" {
					t.Errorf("SUPPLY_007 reported for a structured capability request")
				}
				if f.RuleID != tc.rule {
					continue
				}
				found = true
				if f.Severity != tc.severity || f.Analyzer != tc.analyzer || f.Category != tc.category {
					t.Errorf("%s = (%s, %s, %s), want (%s, %s, %s)", tc.rule,
						f.Severity, f.Analyzer, f.Category, tc.severity, tc.analyzer, tc.category)
				}
			}
			if !found {
				t.Fatalf("%s not reported", tc.rule)
			}
		})
	}
}

func TestV029_ExplainRuleDescriptionNamesCatalogAnalyzers(t *testing.T) {
	// The description spells some analyzers for readers (NLP, toxic-flow,
	// rug-pull); compare without case or hyphens.
	normalize := func(s string) string { return strings.ReplaceAll(strings.ToLower(s), "-", "") }
	desc := normalize(explainRuleTool().Description)
	seen := make(map[string]bool)
	for _, r := range aguara.ListRules() {
		if r.Analyzer == "" || seen[r.Analyzer] {
			continue
		}
		seen[r.Analyzer] = true
		if !strings.Contains(desc, normalize(r.Analyzer)) {
			t.Errorf("explain_rule description does not name cataloged analyzer %q", r.Analyzer)
		}
	}
	if len(seen) == 0 {
		t.Fatal("catalog lists no analyzer-emitted rules")
	}
}
