package hedged

import (
	"context"
	"testing"
)

func TestHedgedSendAndAck(t *testing.T) {
	r := New()
	ctx := context.Background()

	packet := r.SendHedged(ctx, "handshake-001", []byte("client hello"), []Protocol{ProtocolQUIC, ProtocolReality, ProtocolICMP})
	if packet == nil {
		t.Fatal("packet nil")
	}
	if len(packet.Protocols) != 3 {
		t.Error("protocols")
	}

	// Ack via QUIC wins
	ok := r.Ack("handshake-001", ProtocolQUIC)
	if !ok {
		t.Error("ack should succeed")
	}

	if !r.IsDuplicate("handshake-001") {
		t.Error("should be duplicate after ack")
	}

	stats := r.Stats()
	if stats.Sent != 1 || stats.Acked != 1 {
		t.Errorf("stats wrong %+v", stats)
	}
	if stats.Deduped != 2 {
		t.Errorf("deduped should be 2 (other protocols), got %d", stats.Deduped)
	}
}

func TestDuplicateAck(t *testing.T) {
	r := New()
	ctx := context.Background()
	r.SendHedged(ctx, "pkt-1", []byte("data"), []Protocol{ProtocolQUIC, ProtocolGRPC})
	r.Ack("pkt-1", ProtocolQUIC)

	// Second ack should fail (already acked, eBPF deduped)
	ok := r.Ack("pkt-1", ProtocolGRPC)
	if ok {
		t.Error("second ack should fail")
	}
}
