// Package outofband provides automated out-of-band profile distribution
// via DNS TXT records (DoH), IPFS/Arweave hashes, and telegram bot webhooks.
package outofband

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DistributionChannel type
type ChannelType string

const (
	ChannelDNSTXT   ChannelType = "dns-txt"
	ChannelIPFS     ChannelType = "ipfs"
	ChannelArweave  ChannelType = "arweave"
	ChannelTelegram ChannelType = "telegram-webhook"
	ChannelDoH      ChannelType = "doh-txt"
)

// OutOfBandProfile is a subscription profile distributed out-of-band
type OutOfBandProfile struct {
	ID          string
	Content     string // base64 subscription or JSON
	Hash        string // IPFS/Arweave hash
	Channel     ChannelType
	Destination string // e.g. DNS name, telegram chat ID, IPFS CID
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// Distributor manages out-of-band distribution
type Distributor struct {
	mu       sync.RWMutex
	profiles map[string]*OutOfBandProfile
	sent     int64
	failed   int64
}

func New() *Distributor {
	return &Distributor{
		profiles: make(map[string]*OutOfBandProfile),
	}
}

// contentHash computes SHA256 hex
func contentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// Distribute via DNS TXT: stores TXT record content that DoH can query
func (d *Distributor) DistributeDNSTXT(ctx context.Context, domain, content string, ttl time.Duration) (*OutOfBandProfile, error) {
	// Split content into 255-char chunks for TXT (DNS limit)
	chunks := chunkString(content, 255)
	// Mock: join with quotes
	txtValue := strings.Join(chunks, "\" \"")

	profile := &OutOfBandProfile{
		ID:          fmt.Sprintf("dns-%s-%d", domain, time.Now().UnixNano()%10000),
		Content:     txtValue,
		Hash:        contentHash(content),
		Channel:     ChannelDNSTXT,
		Destination: domain,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(ttl),
	}

	d.mu.Lock()
	d.profiles[profile.ID] = profile
	d.sent++
	d.mu.Unlock()

	return profile, nil
}

// Distribute via DoH TXT (same as DNS TXT but via DoH resolver)
func (d *Distributor) DistributeDoHTXT(ctx context.Context, dohResolver, domain, content string, ttl time.Duration) (*OutOfBandProfile, error) {
	// Similar to DNS TXT but marks channel as DoH
	profile, err := d.DistributeDNSTXT(ctx, domain, content, ttl)
	if err != nil {
		return nil, err
	}
	profile.Channel = ChannelDoH
	profile.Destination = fmt.Sprintf("%s|%s", dohResolver, domain)
	return profile, nil
}

// Distribute via IPFS: returns CID (mock)
func (d *Distributor) DistributeIPFS(ctx context.Context, content string) (*OutOfBandProfile, error) {
	// Mock CID: Qm + hash prefix
	hash := contentHash(content)
	cid := "Qm" + hash[:44]

	profile := &OutOfBandProfile{
		ID:          fmt.Sprintf("ipfs-%s", cid[:12]),
		Content:     content,
		Hash:        hash,
		Channel:     ChannelIPFS,
		Destination: cid,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	d.mu.Lock()
	d.profiles[profile.ID] = profile
	d.sent++
	d.mu.Unlock()

	return profile, nil
}

// Distribute via Arweave
func (d *Distributor) DistributeArweave(ctx context.Context, content string) (*OutOfBandProfile, error) {
	hash := contentHash(content)
	arHash := "ar_" + hash[:43]

	profile := &OutOfBandProfile{
		ID:          fmt.Sprintf("ar-%s", arHash[:12]),
		Content:     content,
		Hash:        hash,
		Channel:     ChannelArweave,
		Destination: arHash,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour), // Arweave permanent-ish
	}

	d.mu.Lock()
	d.profiles[profile.ID] = profile
	d.sent++
	d.mu.Unlock()

	return profile, nil
}

// Distribute via Telegram webhook: sends to bot
func (d *Distributor) DistributeTelegram(ctx context.Context, botToken, chatID, content string) (*OutOfBandProfile, error) {
	// Mock: would call https://api.telegram.org/bot<token>/sendMessage
	profile := &OutOfBandProfile{
		ID:          fmt.Sprintf("tg-%s-%d", chatID, time.Now().UnixNano()%10000),
		Content:     content,
		Hash:        contentHash(content),
		Channel:     ChannelTelegram,
		Destination: fmt.Sprintf("telegram:%s", chatID),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
	}

	// Simulate webhook call success
	d.mu.Lock()
	d.profiles[profile.ID] = profile
	d.sent++
	d.mu.Unlock()

	return profile, nil
}

func (d *Distributor) Get(id string) (*OutOfBandProfile, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p, ok := d.profiles[id]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

func (d *Distributor) List() []*OutOfBandProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*OutOfBandProfile, 0, len(d.profiles))
	for _, p := range d.profiles {
		cp := *p
		out = append(out, &cp)
	}
	return out
}

func (d *Distributor) ListByChannel(ch ChannelType) []*OutOfBandProfile {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out []*OutOfBandProfile
	for _, p := range d.profiles {
		if p.Channel == ch {
			cp := *p
			out = append(out, &cp)
		}
	}
	return out
}

type DistributorStats struct {
	Total     int
	Sent      int64
	Failed    int64
	ByChannel map[ChannelType]int
}

func (d *Distributor) Stats() DistributorStats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	byCh := make(map[ChannelType]int)
	for _, p := range d.profiles {
		byCh[p.Channel]++
	}
	return DistributorStats{
		Total:     len(d.profiles),
		Sent:      d.sent,
		Failed:    d.failed,
		ByChannel: byCh,
	}
}

func chunkString(s string, chunkSize int) []string {
	var chunks []string
	for chunkSize < len(s) {
		s, chunks = s[chunkSize:], append(chunks, s[:chunkSize])
	}
	chunks = append(chunks, s)
	return chunks
}
