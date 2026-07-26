// Package ipscanner provides a high-throughput concurrent clean-IP scanner
// that probes target ranges with TLS 1.3 ClientHello packets, measures RTT /
// jitter / packet loss, detects Iranian ISP TCP RST injection, and exposes a
// thread-safe GetBestCleanIP API. When a config is filtered, TriggerRescan
// fires automatically so the autoheal engine can rotate to a clean IP with
// zero downtime.
package ipscanner

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// IPProbe holds the result of a single IP probe.
type IPProbe struct {
	IP          string
	RTT         time.Duration
	Jitter      time.Duration
	PacketLoss  float64
	RSTDetected bool
	Clean       bool
	ProbedAt    time.Time
}

// Prober is the probe seam — production uses a real TLS 1.3 socket; tests use
// a mock. This decouples the scanner from network I/O for hermetic testing.
type Prober interface {
	Probe(ctx context.Context, ip string) (*IPProbe, error)
}

// Scanner is a concurrent worker-pool IP scanner. Thread-safe.
type Scanner struct {
	prober      Prober
	workers     int
	mu          sync.RWMutex
	results     map[string][]*IPProbe // ispID -> probes sorted by RTT
	rescanCount atomic.Int64
	log         *slog.Logger
}

// NewScanner constructs a scanner with `workers` concurrent probe goroutines.
func NewScanner(prober Prober, workers int, log *slog.Logger) *Scanner {
	if workers <= 0 {
		workers = 16
	}
	if log == nil {
		log = slog.Default()
	}
	return &Scanner{
		prober:  prober,
		workers: workers,
		results: make(map[string][]*IPProbe),
		log:     log,
	}
}

// Scan probes every IP in `ips` concurrently and stores results for `ispID`.
// It blocks until all probes complete or ctx is cancelled.
func (s *Scanner) Scan(ctx context.Context, ips []string, ispID string) {
	jobs := make(chan string, len(ips))
	results := make(chan *IPProbe, len(ips))

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				probe, err := s.prober.Probe(ctx, ip)
				if err != nil || probe == nil {
					probe = &IPProbe{IP: ip, Clean: false, ProbedAt: time.Now()}
				}
				results <- probe
			}
		}()
	}

	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	close(results)

	collected := make([]*IPProbe, 0, len(ips))
	for p := range results {
		collected = append(collected, p)
	}
	// Sort by RTT ascending (clean IPs first, lowest latency first).
	sort.Slice(collected, func(i, j int) bool {
		if collected[i].Clean != collected[j].Clean {
			return collected[i].Clean
		}
		return collected[i].RTT < collected[j].RTT
	})

	s.mu.Lock()
	s.results[ispID] = collected
	s.mu.Unlock()
}

// GetBestCleanIP returns the lowest-latency, unblocked IP for `ispID`, or "" if
// none is clean. Thread-safe; safe for concurrent callers.
func (s *Scanner) GetBestCleanIP(ispID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	probes, ok := s.results[ispID]
	if !ok {
		return ""
	}
	for _, p := range probes {
		if p.Clean {
			return p.IP
		}
	}
	return ""
}

// Results returns a copy of the latest probes for `ispID`.
func (s *Scanner) Results(ispID string) []*IPProbe {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src, ok := s.results[ispID]
	if !ok {
		return nil
	}
	out := make([]*IPProbe, len(src))
	copy(out, src)
	return out
}

// TriggerRescan launches an asynchronous rescan of `ips` for `ispID`. This is
// called automatically when the autoheal engine detects blocking (packet loss >
// threshold or RST injection). Non-blocking; safe to call repeatedly.
func (s *Scanner) TriggerRescan(ctx context.Context, ips []string, ispID string) {
	s.rescanCount.Add(1)
	go func() {
		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		s.Scan(scanCtx, ips, ispID)
		s.log.Info("ip rescan complete", "isp", ispID, "best_clean", s.GetBestCleanIP(ispID))
	}()
}

// RescanCount returns the total number of triggered rescans (for metrics).
func (s *Scanner) RescanCount() int64 { return s.rescanCount.Load() }

// ExpandCIDR returns all host IPs in a CIDR range (capped at `max` to bound
// large ranges). Useful for feeding Scan.
func ExpandCIDR(cidr string, max int) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := network.IP.Mask(network.Mask); network.Contains(ip) && len(ips) < max; incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
