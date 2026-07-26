package telemetry

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
	"github.com/aether-x/control-plane/internal/metrics"
)

// StreamEvent is the JSON payload broadcast to SSE/WS clients. It carries the
// minimal live signal the dashboard needs to animate the topology.
type StreamEvent struct {
	NodeID     string    `json:"node_id"`
	Protocol   string    `json:"protocol"`
	Isp        string    `json:"isp"`
	Kind       string    `json:"kind"`
	LatencyMs  int32     `json:"latency_ms"`
	PacketLoss bool      `json:"packet_loss"`
	Rst        bool      `json:"rst"`
	TS         time.Time `json:"ts"`
}

// Broadcaster is a thread-safe pub/sub hub. Each subscriber gets its own
// buffered channel; broadcasts are NON-BLOCKING (a slow client is dropped, not
// allowed to back-pressure the hot telemetry path), which is what lets it scale
// to many thousands of concurrent UI clients with bounded memory.
type Broadcaster struct {
	mu          sync.RWMutex
	subs        map[uint64]chan []byte
	nextID      uint64
	bufPerSub   int
	dropped     atomic.Int64 // telemetry of dropped events (slow clients)
	broadcasted atomic.Int64
}

// NewBroadcaster constructs a hub with a per-subscriber buffer of `bufPerSub`.
func NewBroadcaster(bufPerSub int) *Broadcaster {
	if bufPerSub <= 0 {
		bufPerSub = 64
	}
	return &Broadcaster{
		subs:      make(map[uint64]chan []byte),
		bufPerSub: bufPerSub,
	}
}

// Subscribe returns a receive channel plus an unsubscribe function.
func (b *Broadcaster) Subscribe() (<-chan []byte, func()) {
	id := atomic.AddUint64(&b.nextID, 1)
	ch := make(chan []byte, b.bufPerSub)
	b.mu.Lock()
	b.subs[id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.mu.Unlock()
	}
}

// Subscribers returns the current subscriber count.
func (b *Broadcaster) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Broadcast fans `payload` out to every subscriber, non-blocking.
func (b *Broadcaster) Broadcast(payload []byte) {
	b.broadcasted.Add(1)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- payload:
		default:
			b.dropped.Add(1) // slow client: drop, never block
		}
	}
}

// WriteBatch implements telemetry.Writer so the Broadcaster can sit in the
// MultiWriter pipeline and mirror every event to live UI clients.
func (b *Broadcaster) WriteBatch(_ context.Context, events []Event) error {
	for _, ev := range events {
		metrics.TelemetryEventsTotal.WithLabelValues(ispName(ev.ISP), ev.ProtocolID).Inc()
		payload, err := json.Marshal(toStreamEvent(ev))
		if err != nil {
			continue
		}
		b.Broadcast(payload)
	}
	return nil
}

// Dropped returns the count of events dropped to slow clients (for observability/tests).
func (b *Broadcaster) Dropped() int64 { return b.dropped.Load() }

// Broadcasted returns the total events fanned out.
func (b *Broadcaster) Broadcasted() int64 { return b.broadcasted.Load() }

func toStreamEvent(ev Event) StreamEvent {
	return StreamEvent{
		NodeID:     ev.NodeID,
		Protocol:   ev.ProtocolID,
		Isp:        ispName(ev.ISP),
		Kind:       ev.Kind.String(),
		LatencyMs:  ev.RTTms,
		PacketLoss: !ev.Success,
		Rst:        ev.Kind == telemetrypb.EventKind_EVENT_TCP_RST_INJECTED,
		TS:         ev.TS,
	}
}

// ---- tests -----------------------------------------------------------------

func TestBroadcasterFanout(t *testing.T) {
	b := NewBroadcaster(8)
	ch1, _ := b.Subscribe()
	ch2, _ := b.Subscribe()
	b.Broadcast([]byte("hello"))

	if got := <-ch1; string(got) != "hello" {
		t.Fatalf("sub1 got %q", got)
	}
	if got := <-ch2; string(got) != "hello" {
		t.Fatalf("sub2 got %q", got)
	}
	if b.Subscribers() != 2 {
		t.Fatalf("expected 2 subs, got %d", b.Subscribers())
	}
}

func TestBroadcasterUnsubscribeClosesChannel(t *testing.T) {
	b := NewBroadcaster(2)
	ch, unsub := b.Subscribe()
	unsub()
	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after unsubscribe")
	}
	if b.Subscribers() != 0 {
		t.Fatalf("expected 0 subs, got %d", b.Subscribers())
	}
}

func TestBroadcasterDropsSlowClientWithoutBlocking(t *testing.T) {
	b := NewBroadcaster(1)    // tiny buffer
	_, unsub := b.Subscribe() // slow client: registered but never drains
	defer unsub()
	// Flood past the buffer; a slow (never-draining) client must NOT block the
	// broadcaster and should be reflected in Dropped().
	for i := 0; i < 100; i++ {
		b.Broadcast([]byte("x"))
	}
	if b.Dropped() == 0 {
		t.Fatalf("expected some drops for slow client, got 0")
	}
}

func TestBroadcasterConcurrent(t *testing.T) {
	// Hammer subscribe/unsubscribe/broadcast concurrently; -race must be clean.
	b := NewBroadcaster(16)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// broadcasters
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					b.Broadcast([]byte("p"))
				}
			}
		}()
	}
	// subscribers churning
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ch, unsub := b.Subscribe()
					// drain a little
					select {
					case <-ch:
					default:
					}
					unsub()
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
