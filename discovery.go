package main

import (
	"fmt"

	"github.com/garagon/aguara/discover"
)

type discoveryServerInventory struct {
	ID               string `json:"id"`
	CommandPresent   bool   `json:"command_present"`
	ArgumentCount    int    `json:"argument_count"`
	EnvironmentCount int    `json:"environment_count"`
}

type discoveryClientInventory struct {
	ID      string                     `json:"id"`
	Client  string                     `json:"client"`
	Servers []discoveryServerInventory `json:"servers"`
}

type discoveryInventoryResult struct {
	Kind       string                     `json:"kind"`
	Redacted   bool                       `json:"redacted"`
	ScanStatus string                     `json:"scan_status"`
	Notice     string                     `json:"notice"`
	Clients    []discoveryClientInventory `json:"clients"`
}

// Project only structural metadata. Any config string, including a name or an
// environment key, can contain credentials or instructions for the MCP client.
func discoveryInventory(result *discover.Result) discoveryInventoryResult {
	out := discoveryInventoryResult{
		Kind: "aguara.discovery-inventory", Redacted: true, ScanStatus: "not_scanned",
		Notice:  "Best-effort inventory, not a security scan. Unreadable or unsupported configs may be skipped. IDs are response-local. Original configuration is required for scanning.",
		Clients: make([]discoveryClientInventory, 0, len(result.Clients)),
	}
	for i, client := range result.Clients {
		item := discoveryClientInventory{
			ID: fmt.Sprintf("config-%d", i+1), Client: discoveryClientName(client.Client),
			Servers: make([]discoveryServerInventory, 0, len(client.Servers)),
		}
		for j, server := range client.Servers {
			item.Servers = append(item.Servers, discoveryServerInventory{
				ID: fmt.Sprintf("server-%d", j+1), CommandPresent: server.Command != "",
				ArgumentCount: len(server.Args), EnvironmentCount: len(server.Env),
			})
		}
		out.Clients = append(out.Clients, item)
	}
	return out
}

func discoveryClientName(name string) string {
	switch name {
	case "claude-desktop", "cursor", "vscode", "cline", "windsurf", "openclaw",
		"opencode", "zed", "amp", "gemini-cli", "copilot-cli", "amazon-q",
		"claude-code", "roo-code", "kilo-code", "boltai", "jetbrains":
		return name
	default:
		return "other"
	}
}
