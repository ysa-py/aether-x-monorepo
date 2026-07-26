// Package oob implements out-of-band subscription delivery via DNS TXT (DoH), IPFS/Arweave, Telegram
// This file is the spec-named oob_distributor.go wrapping outofband package
package oob

import (
	"context"
	"time"

	"github.com/aether-x/control-plane/internal/outofband"
)

// Distributor wraps outofband.Distributor to satisfy spec naming oob_distributor.go
type Distributor struct {
	inner *outofband.Distributor
}

func New() *Distributor {
	return &Distributor{inner: outofband.New()}
}

func (d *Distributor) DistributeDNSTXT(ctx context.Context, domain, content string, ttl time.Duration) (*outofband.OutOfBandProfile, error) {
	return d.inner.DistributeDNSTXT(ctx, domain, content, ttl)
}

func (d *Distributor) DistributeDoHTXT(ctx context.Context, resolver, domain, content string, ttl time.Duration) (*outofband.OutOfBandProfile, error) {
	return d.inner.DistributeDoHTXT(ctx, resolver, domain, content, ttl)
}

func (d *Distributor) DistributeIPFS(ctx context.Context, content string) (*outofband.OutOfBandProfile, error) {
	return d.inner.DistributeIPFS(ctx, content)
}

func (d *Distributor) DistributeArweave(ctx context.Context, content string) (*outofband.OutOfBandProfile, error) {
	return d.inner.DistributeArweave(ctx, content)
}

func (d *Distributor) DistributeTelegram(ctx context.Context, botToken, chatID, content string) (*outofband.OutOfBandProfile, error) {
	return d.inner.DistributeTelegram(ctx, botToken, chatID, content)
}

func (d *Distributor) List() []*outofband.OutOfBandProfile {
	return d.inner.List()
}

func (d *Distributor) Stats() outofband.DistributorStats {
	return d.inner.Stats()
}
