package subendpoint

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aether-x/control-plane/internal/telemetry"
)

// DefaultCatalogReloadInterval bounds automatic catalog refreshes while keeping
// updates responsive. The service keeps serving its last validated catalog
// during a bad update instead of disrupting every standard client at once.
const DefaultCatalogReloadInterval = 30 * time.Second

// CatalogReloadResult describes one refresh attempt without exposing catalog
// endpoint material or subscriber data.
type CatalogReloadResult struct {
	Changed  bool
	Accepted bool
	Err      error
}

// CatalogReloadStatus is a safe operational snapshot. It contains catalog
// version/timing/counters only; node addresses and credentials remain private.
type CatalogReloadStatus struct {
	ActiveVersion string
	LoadedAt      time.Time
	LastAttemptAt time.Time
	LastError     string
	Accepted      uint64
	Rejected      uint64
}

type catalogFileFingerprint struct {
	digest [sha256.Size]byte
}

// ReloadingCatalogSubscriptionService atomically swaps an immutable catalog
// only after the complete replacement file passes the same strict validation as
// startup. Invalid, partial, deleted, or unreadable replacements leave the
// last known-good catalog active.
type ReloadingCatalogSubscriptionService struct {
	path     string
	interval time.Duration

	mu          sync.RWMutex
	catalog     *NodeCatalog
	fingerprint catalogFileFingerprint
	status      CatalogReloadStatus
}

// NewReloadingCatalogSubscriptionService loads the initial catalog. Unlike a
// later refresh, an invalid initial catalog is a configuration error because
// there is no safe known-good state to serve.
func NewReloadingCatalogSubscriptionService(
	path string,
	interval time.Duration,
) (*ReloadingCatalogSubscriptionService, error) {
	if path == "" {
		return nil, errors.New("verified node catalog path is required")
	}
	if interval <= 0 {
		interval = DefaultCatalogReloadInterval
	}
	if interval < time.Second {
		return nil, errors.New("catalog reload interval must be at least 1s")
	}
	contents, fingerprint, err := readCatalogFileSnapshot(path)
	if err != nil {
		return nil, err
	}
	catalog, err := decodeNodeCatalog(contents)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &ReloadingCatalogSubscriptionService{
		path:        path,
		interval:    interval,
		catalog:     catalog,
		fingerprint: fingerprint,
		status: CatalogReloadStatus{
			ActiveVersion: catalog.Version(),
			LoadedAt:      now,
			LastAttemptAt: now,
			Accepted:      1,
		},
	}, nil
}

// BuildGeoRouted snapshots one immutable catalog pointer, so a reload can
// never produce a half-old/half-new subscription response.
func (s *ReloadingCatalogSubscriptionService) BuildGeoRouted(
	_ context.Context,
	sub *SubscriptionData,
	userAgent string,
	_ string,
	format string,
) (*GeoRoutedProfileResult, error) {
	return buildCatalogSubscription(
		s.snapshotCatalog(),
		sub,
		DetectClientContext(userAgent, ""),
		format,
	)
}

// BuildGeoRoutedWithContext renders against one immutable catalog snapshot.
func (s *ReloadingCatalogSubscriptionService) BuildGeoRoutedWithContext(
	_ context.Context,
	sub *SubscriptionData,
	client telemetry.ClientContext,
	format string,
) (*GeoRoutedProfileResult, error) {
	return buildCatalogSubscription(s.snapshotCatalog(), sub, client, format)
}

func (s *ReloadingCatalogSubscriptionService) snapshotCatalog() *NodeCatalog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.catalog
}

// Reload checks the file content fingerprint and atomically accepts a complete
// validated replacement. Failed refreshes retain the previous catalog.
func (s *ReloadingCatalogSubscriptionService) Reload() CatalogReloadResult {
	contents, fingerprint, err := readCatalogFileSnapshot(s.path)
	if err != nil {
		s.recordRejected(err)
		return CatalogReloadResult{Changed: true, Err: err}
	}

	s.mu.RLock()
	unchanged := fingerprint == s.fingerprint
	s.mu.RUnlock()
	if unchanged {
		s.recordAttempt()
		return CatalogReloadResult{}
	}

	catalog, err := decodeNodeCatalog(contents)
	if err != nil {
		s.recordRejected(err)
		return CatalogReloadResult{Changed: true, Err: err}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if fingerprint == s.fingerprint {
		s.status.LastAttemptAt = time.Now().UTC()
		return CatalogReloadResult{}
	}
	now := time.Now().UTC()
	s.catalog = catalog
	s.fingerprint = fingerprint
	s.status.ActiveVersion = catalog.Version()
	s.status.LoadedAt = now
	s.status.LastAttemptAt = now
	s.status.LastError = ""
	s.status.Accepted++
	return CatalogReloadResult{Changed: true, Accepted: true}
}

// Run polls for catalog updates until the supplied service context is done.
// It is safe to call in a single background goroutine from the control plane.
func (s *ReloadingCatalogSubscriptionService) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Reload()
		}
	}
}

// Status returns a copy safe for logs, health endpoints, or future MCP tools.
func (s *ReloadingCatalogSubscriptionService) Status() CatalogReloadStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *ReloadingCatalogSubscriptionService) recordAttempt() {
	s.mu.Lock()
	s.status.LastAttemptAt = time.Now().UTC()
	s.mu.Unlock()
}

func (s *ReloadingCatalogSubscriptionService) recordRejected(err error) {
	s.mu.Lock()
	s.status.LastAttemptAt = time.Now().UTC()
	s.status.LastError = err.Error()
	s.status.Rejected++
	s.mu.Unlock()
}

func readCatalogFileSnapshot(path string) ([]byte, catalogFileFingerprint, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, catalogFileFingerprint{}, fmt.Errorf("stat node catalog: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, catalogFileFingerprint{}, errors.New("node catalog path must be a regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, catalogFileFingerprint{}, fmt.Errorf("read node catalog: %w", err)
	}
	return contents, catalogFileFingerprint{
		digest: sha256.Sum256(contents),
	}, nil
}

// Compile-time assertion: reloading retains the same public subscription
// contract as the immutable catalog service.
var _ interface {
	BuildGeoRouted(context.Context, *SubscriptionData, string, string, string) (*GeoRoutedProfileResult, error)
} = (*ReloadingCatalogSubscriptionService)(nil)
