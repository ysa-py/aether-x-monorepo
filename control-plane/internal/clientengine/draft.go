package clientengine

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Draft statuses (Part 2 §6). The autonomous UA-discovery path uses
// "auto-discovered" (Part 1); the admin-initiated docs-URL draft path uses the
// two values below. Only "confirmed" drafts are ever promoted into the served
// client list — the deliberate human-confirm gate explained in §2.
const (
	StatusDraftPending = "ai-drafted-pending-review"
	StatusConfirmed    = "confirmed"
)

// DraftRegistry holds admin-initiated AI-drafted client entries until a human
// confirms them. It is deliberately separate from the autonomous
// ClientDiscoveryEngine so the confirm gate can never be bypassed by the
// auto-discovery path.
type DraftRegistry struct {
	mu      sync.RWMutex
	drafts  map[string]*DiscoveredClient // by Name
	storage *Engine                      // promoted (confirmed) clients land here
}

// NewDraftRegistry creates an empty draft registry. storage is the served
// client engine; confirmed drafts are promoted into it so they reach
// subscribers.
func NewDraftRegistry(storage *Engine) *DraftRegistry {
	return &DraftRegistry{
		drafts:  make(map[string]*DiscoveredClient),
		storage: storage,
	}
}

// DraftFromURL heuristically drafts a client entry from a docs / app-store /
// GitHub URL. It is deliberately conservative (Part 2 §6): it extracts the app
// name + inferred platform from the URL, but if the deep-link scheme cannot be
// determined from the URL alone it leaves the URI empty and says so in the
// Note rather than guessing. The result is NEVER served to subscribers until
// Confirm() flips it to "confirmed".
//
// This is the AI-assisted drafting step; a production deployment would feed the
// URL contents to an LLM with the same constrained prompt, but the extraction
// contract (and the confirm gate) is identical and fully testable here.
func DraftFromURL(docsURL string) (*DiscoveredClient, error) {
	docsURL = strings.TrimSpace(docsURL)
	if docsURL == "" {
		return nil, fmt.Errorf("docs_url is required")
	}
	parsed, err := url.Parse(docsURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid docs_url: must be a full URL")
	}

	name := extractNameFromURL(parsed)
	if name == "" {
		return nil, fmt.Errorf("could not infer client name from URL")
	}
	platform := inferPlatformFromURL(parsed)

	// Conservative: we cannot reliably know the deep-link scheme from the URL
	// alone, so we draft a QR/copy-link fallback (URI empty) and flag it for
	// human verification rather than guessing a scheme that could mislead a
	// subscriber mid-blackout (§2).
	return &DiscoveredClient{
		ClientScheme: ClientScheme{
			Name:     name,
			Platform: platform,
			URI:      "",
			Icon:     "📦",
			Priority: 99,
		},
		Status:          StatusDraftPending,
		SourceCheckedAt: time.Now().UTC().Format(time.RFC3339),
		Note:            "AI draft from " + truncateForNote(docsURL) + " — deep-link scheme not verifiable from URL alone; verify against the app's docs before confirming.",
	}, nil
}

// SubmitDraft validates and stores a drafted entry (pending review).
func (r *DraftRegistry) SubmitDraft(c *DiscoveredClient) error {
	if err := ValidateScheme(c); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c.Status = StatusDraftPending
	r.drafts[strings.ToLower(c.Name)] = c
	return nil
}

// DraftFromURLAndStore is the convenience path: draft from a URL, validate,
// and store pending review.
func (r *DraftRegistry) DraftFromURLAndStore(docsURL string) (*DiscoveredClient, error) {
	draft, err := DraftFromURL(docsURL)
	if err != nil {
		return nil, err
	}
	if err := r.SubmitDraft(draft); err != nil {
		return nil, err
	}
	return draft, nil
}

// Confirm flips a pending draft to "confirmed" and promotes it into the served
// client engine so it reaches real subscribers. Returns ErrDraftNotFound if the
// name is unknown.
func (r *DraftRegistry) Confirm(name string) (*DiscoveredClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(name))
	c, ok := r.drafts[key]
	if !ok {
		return nil, ErrDraftNotFound
	}
	c.Status = StatusConfirmed
	// Promote into the served engine (idempotent — skip if already present).
	if r.storage != nil {
		r.storage.mu.Lock()
		exists := false
		for _, existing := range r.storage.scheme.Clients {
			if strings.EqualFold(existing.Name, c.Name) {
				exists = true
				break
			}
		}
		if !exists {
			r.storage.scheme.Clients = append(r.storage.scheme.Clients, c.ClientScheme)
		}
		r.storage.mu.Unlock()
	}
	return c, nil
}

// Drafts returns all pending/confirmed drafts (admin review screen).
func (r *DraftRegistry) Drafts() []DiscoveredClient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]DiscoveredClient, 0, len(r.drafts))
	for _, c := range r.drafts {
		out = append(out, *c)
	}
	return out
}

// ErrDraftNotFound is returned when Confirm targets an unknown draft name.
var ErrDraftNotFound = fmt.Errorf("draft not found")

// --- URL extraction helpers ---

func extractNameFromURL(u *url.URL) string {
	// Use the last meaningful path segment; fall back to the host label.
	seg := ""
	for _, p := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if p != "" {
			seg = p
		}
	}
	if seg == "" {
		// e.g. https://novavpn.app → use the first host label.
		host := u.Host
		host = strings.TrimPrefix(host, "www.")
		if i := strings.IndexByte(host, '.'); i > 0 {
			seg = host[:i]
		}
	}
	seg = strings.TrimSpace(seg)
	// Strip common repo suffixes / extensions.
	seg = strings.TrimSuffix(seg, ".git")
	// Title-case first rune.
	if seg != "" {
		seg = strings.ToUpper(seg[:1]) + seg[1:]
	}
	// Reject obvious noise.
	lower := strings.ToLower(seg)
	if lower == "releases" || lower == "download" || lower == "issues" || lower == "" || len(seg) > 60 {
		return ""
	}
	return seg
}

func inferPlatformFromURL(u *url.URL) string {
	combined := strings.ToLower(u.Host + " " + u.Path)
	switch {
	case strings.Contains(combined, "play.google") || strings.Contains(combined, "android"):
		return "android"
	case strings.Contains(combined, "apps.apple") || strings.Contains(combined, "itunes") || strings.Contains(combined, "ios"):
		return "ios"
	case strings.Contains(combined, "windows") || strings.Contains(combined, ".exe"):
		return "windows"
	case strings.Contains(combined, "mac") || strings.Contains(combined, "darwin"):
		return "macos"
	case strings.Contains(combined, "linux") || strings.Contains(combined, ".deb") || strings.Contains(combined, ".rpm"):
		return "linux"
	default:
		return "all"
	}
}

func truncateForNote(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
