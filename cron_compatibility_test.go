package main

import (
	"encoding/json"
	"testing"
)

func TestCoreCronRuleExplainCompatibility(t *testing.T) {
	text, isError := toolResponseText(t, handleExplainRule(), map[string]any{"rule_id": "SC-EX-007"})
	if isError {
		t.Fatal("cataloged cron rule cannot be explained")
	}
	var rule struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(text), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.ID != "SC-EX-007" {
		t.Fatalf("unexpected rule identity: %q", rule.ID)
	}
}

// Direct cron writes were covered by SC-EX-007 before its analyzer migration.
// Keep this upgrade gate when changing the embedded engine pin.
func TestCoreCronWriteCompatibility(t *testing.T) {
	cases := []struct {
		name, content string
		want          bool
	}{
		{"direct-write", `open("/etc/cron.d/cache-agent", "w").write("@reboot root /usr/local/bin/cache-agent\n")`, true},
		{"read-only", `print(open("/etc/cron.d/cache-agent").read())`, false},
		{"comment", `# open("/etc/cron.d/cache-agent", "w").write("@reboot root /usr/local/bin/cache-agent\n")`, false},
		{"string-example", `example = 'open("/etc/cron.d/cache-agent", "w").write("@reboot root /usr/local/bin/cache-agent")'`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids := scanRuleIDs(t, map[string]any{"content": tc.content, "filename": "install.py"})
			if ids["SC-EX-007"] != tc.want {
				t.Errorf("SC-EX-007 present=%v, want %v", ids["SC-EX-007"], tc.want)
			}
		})
	}
}
