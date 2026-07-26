package outofband

import (
	"context"
	"testing"
)

func TestDNSTXT(t *testing.T) {
	d := New()
	ctx := context.Background()
	profile, err := d.DistributeDNSTXT(ctx, "aether-x.example", "vless://...", 3600)
	if err != nil {
		t.Fatalf("dns txt failed: %v", err)
	}
	if profile.Channel != ChannelDNSTXT {
		t.Error("channel")
	}
	if profile.Destination != "aether-x.example" {
		t.Error("dest")
	}
}

func TestIPFS(t *testing.T) {
	d := New()
	ctx := context.Background()
	profile, err := d.DistributeIPFS(ctx, "test content for ipfs")
	if err != nil {
		t.Fatalf("ipfs failed: %v", err)
	}
	if len(profile.Destination) < 10 {
		t.Error("cid too short")
	}
	if profile.Channel != ChannelIPFS {
		t.Error("channel")
	}
}

func TestArweave(t *testing.T) {
	d := New()
	ctx := context.Background()
	profile, _ := d.DistributeArweave(ctx, "arweave content")
	if profile.Channel != ChannelArweave {
		t.Error("channel")
	}
}

func TestTelegram(t *testing.T) {
	d := New()
	ctx := context.Background()
	profile, err := d.DistributeTelegram(ctx, "bot-token", "chat123", "sub link")
	if err != nil {
		t.Fatalf("telegram failed: %v", err)
	}
	if profile.Channel != ChannelTelegram {
		t.Error("channel")
	}
}

func TestListByChannel(t *testing.T) {
	d := New()
	ctx := context.Background()
	d.DistributeDNSTXT(ctx, "a.example", "c1", 3600)
	d.DistributeIPFS(ctx, "c2")
	d.DistributeIPFS(ctx, "c3")

	list := d.ListByChannel(ChannelIPFS)
	if len(list) != 2 {
		t.Errorf("expected 2 ipfs, got %d", len(list))
	}
	stats := d.Stats()
	if stats.Total != 3 {
		t.Errorf("total %d", stats.Total)
	}
}
