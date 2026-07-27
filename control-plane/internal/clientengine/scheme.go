// Package clientengine provides a zero-code client scheme engine that loads
// client URI templates from an external JSON file and supports dynamic variable
// substitution. New clients can be added by editing clients_schema.json — no
// code changes required.
package clientengine

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// ClientScheme defines a single VPN client's import URL template.
type ClientScheme struct {
	Name     string `json:"name"`
	Platform string `json:"platform"` // "android", "ios", "windows", "macos", "linux", "all"
	URI      string `json:"uri"`      // template with {{SUB_URL_ENCODED}}, {{SUB_URL_BASE64}}, {{REMARK}}
	Icon     string `json:"icon"`
	Priority int    `json:"priority"`
}

// SchemeFile is the JSON structure of clients_schema.json.
type SchemeFile struct {
	Version string         `json:"version"`
	Clients []ClientScheme `json:"clients"`
}

// Engine is the thread-safe client scheme engine.
type Engine struct {
	mu     sync.RWMutex
	scheme SchemeFile
}

// New loads the client scheme from a JSON file path.
func New(path string) (*Engine, error) {
	e := &Engine{}
	if err := e.Load(path); err != nil {
		return nil, err
	}
	return e, nil
}

// Default returns a pre-populated engine with the built-in client schemes.
func Default() *Engine {
	return &Engine{
		scheme: SchemeFile{
			Version: "1.0",
			Clients: builtinClients(),
		},
	}
}

// Load reads (or re-reads) the client scheme from a JSON file. Thread-safe;
// safe to call at runtime for hot-reload.
func (e *Engine) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var s SchemeFile
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	e.mu.Lock()
	e.scheme = s
	e.mu.Unlock()
	return nil
}

// ClientsForPlatform returns all client schemes matching the given platform
// (or "all"), sorted by priority (lower first).
func (e *Engine) ClientsForPlatform(platform string) []ClientScheme {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var out []ClientScheme
	pLower := strings.ToLower(platform)
	for _, c := range e.scheme.Clients {
		cp := strings.ToLower(c.Platform)
		if cp == "all" || cp == pLower {
			out = append(out, c)
		}
	}
	return out
}

// RenderURI substitutes template variables in a client URI template.
// Supported: {{SUB_URL_ENCODED}}, {{SUB_URL_BASE64}}, {{REMARK}}.
func (e *Engine) RenderURI(template, subURL, remark string) string {
	r := strings.NewReplacer(
		"{{SUB_URL_ENCODED}}", urlEncode(subURL),
		"{{SUB_URL_BASE64}}", base64Encode(subURL),
		"{{REMARK}}", remark,
	)
	return r.Replace(template)
}

// Version returns the schema version.
func (e *Engine) Version() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.scheme.Version
}

// Count returns the total number of registered client schemes.
func (e *Engine) Count() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.scheme.Clients)
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteRune(c)
		} else {
			b.WriteString(percentEncode(byte(c)))
		}
	}
	return b.String()
}

func percentEncode(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{'%', hex[b>>4], hex[b&0xF]})
}

func base64Encode(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	data := []byte(s)
	var b strings.Builder
	for i := 0; i < len(data); i += 3 {
		b0 := data[i]
		b1 := byte(0)
		b2 := byte(0)
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}
		b.WriteByte(table[b0>>2])
		b.WriteByte(table[((b0&0x03)<<4)|(b1>>4)])
		if i+1 < len(data) {
			b.WriteByte(table[((b1&0x0F)<<2)|(b2>>6)])
		} else {
			b.WriteByte('=')
		}
		if i+2 < len(data) {
			b.WriteByte(table[b2&0x3F])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}

// builtinClients contains convenience launch templates. They are not external
// client compatibility attestations: this repository does not execute these
// URIs in the named applications. Operators must validate a pinned client
// version before exposing a template to subscribers.
func builtinClients() []ClientScheme {
	return []ClientScheme{
		{Name: "Sing-box", Platform: "all", URI: "sing-box://import-remote-profile?url={{SUB_URL_ENCODED}}&name={{REMARK}}", Icon: "singbox", Priority: 10},
		{Name: "v2rayNG", Platform: "android", URI: "v2rayng://install-sub?url={{SUB_URL_ENCODED}}&name={{REMARK}}", Icon: "v2rayng", Priority: 20},
		{Name: "Shadowrocket", Platform: "ios", URI: "shadowrocket://add/sub://{{SUB_URL_BASE64}}", Icon: "shadowrocket", Priority: 15},
		{Name: "Streisand", Platform: "ios", URI: "streisand://import/{{SUB_URL_ENCODED}}", Icon: "streisand", Priority: 25},
		{Name: "FlClash", Platform: "all", URI: "clash://install-config?url={{SUB_URL_ENCODED}}&name={{REMARK}}", Icon: "flclash", Priority: 30},
		{Name: "Hiddify", Platform: "all", URI: "hiddify://import/{{SUB_URL_BASE64}}", Icon: "hiddify", Priority: 35},
		{Name: "NekoBox", Platform: "android", URI: "nekobox://addprofile/{{SUB_URL_ENCODED}}", Icon: "nekobox", Priority: 40},
		{Name: "Karing", Platform: "all", URI: "karing://add-profile?url={{SUB_URL_ENCODED}}", Icon: "karing", Priority: 45},
	}
}
