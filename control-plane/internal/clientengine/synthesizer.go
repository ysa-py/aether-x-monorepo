package clientengine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ClientDiscoveryEngine autonomously detects unknown client User-Agents
// hitting /sub/{subToken} and synthesizes new schema entries — zero-code,
// zero-redeploy. Uses pattern matching on UA structure to infer platform
// and generate a fallback scheme. Entries are atomically hot-reloaded.
type ClientDiscoveryEngine struct {
	mu       sync.RWMutex
	engine   *Engine // the existing scheme engine
	filePath string  // path to clients_schema.json for persistence
	count    int64   // total auto-discovered clients
}

// NewClientDiscovery wraps an existing Engine with autonomous discovery.
func NewClientDiscovery(engine *Engine, schemaPath string) *ClientDiscoveryEngine {
	return &ClientDiscoveryEngine{
		engine:   engine,
		filePath: schemaPath,
	}
}

// InspectRequest is called on every /sub/{subToken} request. If the
// User-Agent is NOT matched in the existing schema, it synthesizes a new
// entry and hot-reloads the registry. Returns true if a new client was
// discovered and added.
func (d *ClientDiscoveryEngine) InspectRequest(r *http.Request) bool {
	ua := r.UserAgent()
	if ua == "" || len(ua) < 4 {
		return false
	}

	// Check if UA matches any known client.
	if d.isKnownUA(ua) {
		return false
	}

	// Unknown UA → synthesize a new entry.
	entry := d.synthesizeFromUA(ua)
	if entry == nil {
		return false
	}

	// Validate before insertion.
	if err := ValidateScheme(entry); err != nil {
		return false // invalid → don't add, fall back to QR
	}

	// Atomic hot-reload: add to in-memory registry + persist to JSON.
	d.mu.Lock()
	defer d.mu.Unlock()

	d.engine.mu.Lock()
	// Check again under lock to prevent duplicates.
	for _, c := range d.engine.scheme.Clients {
		if strings.EqualFold(c.Name, entry.Name) {
			d.engine.mu.Unlock()
			return false // already added by another goroutine
		}
	}
	d.engine.scheme.Clients = append(d.engine.scheme.Clients, entry.ClientScheme)
	d.engine.mu.Unlock()

	d.count++

	// Persist to JSON file (best-effort; non-blocking in production).
	if d.filePath != "" {
		go d.persistToFile()
	}

	return true
}

// isKnownUA checks if the User-Agent matches any registered client.
func (d *ClientDiscoveryEngine) isKnownUA(ua string) bool {
	uaLower := strings.ToLower(ua)
	d.engine.mu.RLock()
	defer d.engine.mu.RUnlock()
	for _, c := range d.engine.scheme.Clients {
		nameLower := strings.ToLower(c.Name)
		// Check if the client name appears in the UA.
		if strings.Contains(uaLower, nameLower) {
			return true
		}
		// Also check common abbreviations.
		abbrevs := uaAbbreviations(c.Name)
		for _, abbr := range abbrevs {
			if strings.Contains(uaLower, abbr) {
				return true
			}
		}
	}
	return false
}

// uaAbbreviations returns common short forms of a client name.
func uaAbbreviations(name string) []string {
	name = strings.ToLower(name)
	switch {
	case strings.Contains(name, "sing-box"):
		return []string{"singbox", "sfa"}
	case strings.Contains(name, "v2rayng"):
		return []string{"v2ray"}
	case strings.Contains(name, "clash"):
		return []string{"mihomo", "flclash"}
	case strings.Contains(name, "shadowrocket"):
		return []string{"shadow"}
	default:
		return nil
	}
}

// synthesizeFromUA generates a ClientScheme from an unknown User-Agent.
// Uses structural analysis: extracts app name, detects platform, generates
// a universal fallback scheme.
func (d *ClientDiscoveryEngine) synthesizeFromUA(ua string) *DiscoveredClient {
	// Extract app name from UA (first token before slash/space).
	appName := extractAppName(ua)
	if appName == "" || len(appName) > 50 {
		return nil
	}

	platform := detectPlatformFromUA(ua)

	return &DiscoveredClient{
		ClientScheme: ClientScheme{
			Name:     appName,
			Platform: platform,
			URI:      "", // no known scheme → QR/copy-link fallback
			Icon:     "📦",
			Priority: 99, // low priority (bottom of list)
		},
		Status:          "auto-discovered",
		SourceCheckedAt: time.Now().Format("2006-01-02"),
		Note:            fmt.Sprintf("Auto-discovered from UA: %s", truncateUA(ua)),
	}
}

// DiscoveredClient extends ClientScheme with discovery metadata.
type DiscoveredClient struct {
	ClientScheme
	Status          string `json:"status"`
	SourceCheckedAt string `json:"sourceCheckedAt"`
	Note            string `json:"note,omitempty"`
}

// ValidateScheme checks that a client scheme is well-formed and safe.
// Prevents injection attacks by verifying URI template variables.
func ValidateScheme(c *DiscoveredClient) error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(c.Name) > 100 {
		return fmt.Errorf("name too long")
	}
	// URI can be empty (QR fallback) — that's valid.
	if c.URI != "" {
		// Check for injection: only allow known template variables.
		allowed := []string{"{{SUB_URL_ENCODED}}", "{{SUB_URL_BASE64}}", "{{REMARK}}"}
		temp := c.URI
		for _, a := range allowed {
			temp = strings.ReplaceAll(temp, a, "")
		}
		// After removing known vars, remaining {{...}} patterns are suspicious.
		if strings.Contains(temp, "{{") || strings.Contains(temp, "}}") {
			return fmt.Errorf("unknown template variable in URI")
		}
		// Check for javascript: or data: schemes.
		uriLower := strings.ToLower(c.URI)
		if strings.HasPrefix(uriLower, "javascript:") || strings.HasPrefix(uriLower, "data:") {
			return fmt.Errorf("dangerous URI scheme")
		}
	}
	return nil
}

// persistToFile atomically writes the full client schema to JSON.
func (d *ClientDiscoveryEngine) persistToFile() {
	d.engine.mu.RLock()
	data := struct {
		Version string         `json:"version"`
		Clients []ClientScheme `json:"clients"`
	}{
		Version: d.engine.scheme.Version,
		Clients: d.engine.scheme.Clients,
	}
	d.engine.mu.RUnlock()

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	// Atomic write: write to temp file then rename.
	tmp := d.filePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	os.Rename(tmp, d.filePath)
}

// DiscoveryCount returns the total number of auto-discovered clients.
func (d *ClientDiscoveryEngine) DiscoveryCount() int64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.count
}

// --- Helpers ---

func extractAppName(ua string) string {
	// Try to extract the product name: "ProductName/1.0" pattern.
	if idx := strings.IndexByte(ua, '/'); idx > 0 {
		name := ua[:idx]
		name = strings.TrimSpace(name)
		// Filter out common browser tokens.
		lower := strings.ToLower(name)
		if lower == "mozilla" || lower == "okhttp" || lower == "java" || lower == "curl" || lower == "wget" {
			return ""
		}
		// Capitalize first letter.
		if len(name) > 0 {
			name = strings.ToUpper(name[:1]) + name[1:]
		}
		return name
	}
	return ""
}

func detectPlatformFromUA(ua string) string {
	uaLower := strings.ToLower(ua)
	switch {
	case strings.Contains(uaLower, "android"):
		return "android"
	case strings.Contains(uaLower, "iphone"), strings.Contains(uaLower, "ipad"), strings.Contains(uaLower, "ios"):
		return "ios"
	case strings.Contains(uaLower, "mac"), strings.Contains(uaLower, "darwin"):
		return "macos"
	case strings.Contains(uaLower, "win"), strings.Contains(uaLower, "windows"):
		return "windows"
	case strings.Contains(uaLower, "linux"):
		return "linux"
	default:
		return "all"
	}
}

func truncateUA(ua string) string {
	if len(ua) > 120 {
		return ua[:120] + "..."
	}
	return ua
}
