package featurizer

import (
	"testing"
	"time"

	telemetrypb "github.com/aether-x/control-plane/api/gen/go/aether/telemetry/v1"
	"github.com/aether-x/control-plane/internal/telemetry"
)

func ev(kind telemetrypb.EventKind, isp telemetrypb.IspId, proto string, ts time.Time, rtt int32) telemetry.Event {
	return telemetry.Event{
		ISP:        isp,
		ProtocolID: proto,
		Kind:       kind,
		TS:         ts,
		RTTms:      rtt,
	}
}

func TestHealthyWindow(t *testing.T) {
	a := New(time.Minute)
	base := time.UnixMilli(10_000)
	for i := 0; i < 10; i++ {
		a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_SUCCESS, telemetrypb.IspId_ISP_ID_MCI, "reality-vision", base, 40+int32(i)))
	}
	fp, ok := a.Feature(telemetrypb.IspId_ISP_ID_MCI, "reality-vision")
	if !ok {
		t.Fatal("expected feature point")
	}
	if fp.SampleCount != 10 || fp.SuccessRate != 1.0 {
		t.Fatalf("unexpected: %+v", fp)
	}
	if fp.MedianRTTms < 40 {
		t.Fatalf("median too low: %d", fp.MedianRTTms)
	}
}

func TestRstStormLowerSuccessRate(t *testing.T) {
	a := New(time.Minute)
	base := time.UnixMilli(20_000)
	for i := 0; i < 8; i++ {
		a.Observe(ev(telemetrypb.EventKind_EVENT_TCP_RST_INJECTED, telemetrypb.IspId_ISP_ID_IRANCELL, "reality-vision", base, -1))
	}
	for i := 0; i < 2; i++ {
		a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_SUCCESS, telemetrypb.IspId_ISP_ID_IRANCELL, "reality-vision", base, 30))
	}
	fp, _ := a.Feature(telemetrypb.IspId_ISP_ID_IRANCELL, "reality-vision")
	if fp.SuccessRate != 0.2 {
		t.Fatalf("success rate = %v, want 0.2", fp.SuccessRate)
	}
	if fp.RstRate != 0.8 {
		t.Fatalf("rst rate = %v, want 0.8", fp.RstRate)
	}
}

func TestEvictionDropsOldSamples(t *testing.T) {
	a := New(10 * time.Second) // 10s window
	t0 := time.UnixMilli(0)
	t1 := time.UnixMilli(15_000) // 15s later
	a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_SUCCESS, telemetrypb.IspId_ISP_ID_MCI, "tuic-v5", t0, 50))
	a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_FAIL, telemetrypb.IspId_ISP_ID_MCI, "tuic-v5", t1, -1))
	fp, _ := a.Feature(telemetrypb.IspId_ISP_ID_MCI, "tuic-v5")
	if fp.SampleCount != 1 {
		t.Fatalf("expected 1 after eviction, got %d", fp.SampleCount)
	}
	if fp.SuccessRate != 0.0 {
		t.Fatalf("expected 0 success after eviction, got %v", fp.SuccessRate)
	}
}

func TestIspsAreIsolated(t *testing.T) {
	a := New(time.Minute)
	base := time.UnixMilli(0)
	a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_SUCCESS, telemetrypb.IspId_ISP_ID_MCI, "hysteria2", base, 20))
	a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_FAIL, telemetrypb.IspId_ISP_ID_SHATEL, "hysteria2", base, -1))
	mci, _ := a.Feature(telemetrypb.IspId_ISP_ID_MCI, "hysteria2")
	if mci.SuccessRate != 1.0 {
		t.Fatalf("MCI not isolated: %+v", mci)
	}
}

func TestSnapshotSortedAndComplete(t *testing.T) {
	a := New(time.Minute)
	base := time.UnixMilli(0)
	a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_SUCCESS, telemetrypb.IspId_ISP_ID_SHATEL, "z", base, 10))
	a.Observe(ev(telemetrypb.EventKind_EVENT_CONNECT_SUCCESS, telemetrypb.IspId_ISP_ID_MCI, "a", base, 10))
	snap := a.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 points, got %d", len(snap))
	}
	// Sorted by ISP then protocol: MCI(a) before SHATEL(z).
	if snap[0].ISP != telemetrypb.IspId_ISP_ID_MCI {
		t.Fatalf("snapshot not sorted: %+v", snap)
	}
}
