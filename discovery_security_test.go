package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/discover"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func isolatedDiscoveryHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"} {
		t.Setenv(key, home)
	}
	return home
}

func toolResponseText(t *testing.T, handler mcp.ToolHandler, args map[string]any) (string, bool) {
	t.Helper()
	var response struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(callHandler(t, handler, args)), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Content) != 1 {
		t.Fatalf("expected one text response, got %d", len(response.Content))
	}
	return response.Content[0].Text, response.IsError
}

func TestDiscoveryInventoryConfidentiality(t *testing.T) {
	home := isolatedDiscoveryHome(t)
	const secret = "synthetic-discovery-secret-92ab"
	config := map[string]any{"mcpServers": map[string]any{
		secret: map[string]any{
			"command": "sh -c " + secret,
			"args":    []string{"--token", secret, "--token=" + secret, "https://user:" + secret + "@example.invalid/?key=" + secret, `{"password":"` + secret + `"}`, secret},
			"env":     map[string]string{"API_TOKEN": secret, "ORDINARY_SETTING": secret, secret: "value"},
		},
	}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	for _, debug := range []bool{false, true} {
		var out string
		logs := captureDiscoveryStderr(t, func() {
			out = callHandler(t, handleDiscoverMCP(debug), map[string]any{})
		})
		for _, private := range []string{secret, home, "API_TOKEN", "ORDINARY_SETTING", "--token"} {
			if strings.Contains(out+logs, private) {
				t.Errorf("discovery disclosed a private field (debug=%v)", debug)
			}
		}
	}
	text, isError := toolResponseText(t, handleDiscoverMCP(false), map[string]any{})
	if isError {
		t.Fatal("discovery returned an error")
	}
	var inventory struct {
		Kind       string `json:"kind"`
		Redacted   bool   `json:"redacted"`
		ScanStatus string `json:"scan_status"`
		Clients    []struct {
			Client  string `json:"client"`
			Servers []struct {
				ArgumentCount    int `json:"argument_count"`
				EnvironmentCount int `json:"environment_count"`
			} `json:"servers"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(text), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Kind != "aguara.discovery-inventory" || !inventory.Redacted || inventory.ScanStatus != "not_scanned" {
		t.Error("discovery must identify itself as redacted inventory, not a scan")
	}
	if len(inventory.Clients) != 1 || inventory.Clients[0].Client != "cursor" || len(inventory.Clients[0].Servers) != 1 {
		t.Fatalf("expected one Cursor config with one server")
	}
	server := inventory.Clients[0].Servers[0]
	if server.ArgumentCount != 6 || server.EnvironmentCount != 3 {
		t.Error("inventory lost structural counts")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(data) {
		t.Fatal("discovery modified the source config")
	}
	_, isError = toolResponseText(t, handleCheckMCPConfig(false), map[string]any{"config": text})
	if !isError {
		t.Error("redacted inventory must not be accepted as an original MCP config")
	}
}

func captureDiscoveryStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	defer func() { os.Stderr = original; _ = r.Close(); _ = w.Close() }()
	os.Stderr = w
	f()
	os.Stderr = original
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDiscoveryProjectionWithholdsUnknownFields(t *testing.T) {
	const secret = "private-field-92ab"
	source := &discover.Result{Clients: []discover.ClientResult{{
		Client: secret, Path: secret,
		Servers: []discover.MCPServer{{Name: secret, Command: secret, Args: []string{secret}, Env: map[string]string{secret: secret}}},
	}}}
	before, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	projection := discoveryInventory(source)
	out, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), secret) {
		t.Fatal("untrusted field escaped inventory projection")
	}
	if projection.Clients[0].Client != "other" {
		t.Fatal("unknown client must get a fixed label")
	}
	after, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("projection mutated the original discovery data")
	}
}

func TestDiscoveryEmptyInventoryIsNotCleanScan(t *testing.T) {
	isolatedDiscoveryHome(t)
	text, isError := toolResponseText(t, handleDiscoverMCP(false), map[string]any{})
	if isError {
		t.Fatal("empty discovery returned an error")
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		t.Fatal(err)
	}
	if result["scan_status"] != "not_scanned" {
		t.Error("empty discovery must not imply a clean scan")
	}
	clients, ok := result["clients"].([]any)
	if !ok || len(clients) != 0 {
		t.Error("empty inventory must have an empty clients array")
	}
}

func TestCheckMCPConfigRejectsDiscoveryInventory(t *testing.T) {
	_, isError := toolResponseText(t, handleCheckMCPConfig(false), map[string]any{
		"config": `{"kind":"aguara.discovery-inventory","redacted":true,"scan_status":"not_scanned","clients":[]}`,
	})
	if !isError {
		t.Fatal("inventory accepted as a scan input")
	}
}
