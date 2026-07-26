// Command aether-control is the Aether-X control plane (management) binary.
// It serves the REST/MCP API and drains telemetry from one or more Core
// Supervisors into the feature store.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aether-x/control-plane/internal/antiforgeryclient"
	"github.com/aether-x/control-plane/internal/api"
	"github.com/aether-x/control-plane/internal/auth"
	"github.com/aether-x/control-plane/internal/config"
	"github.com/aether-x/control-plane/internal/featurizer"
	"github.com/aether-x/control-plane/internal/grpcclient"
	"github.com/aether-x/control-plane/internal/mcp"
	"github.com/aether-x/control-plane/internal/mcpbridge"
	"github.com/aether-x/control-plane/internal/store"
	"github.com/aether-x/control-plane/internal/subendpoint"
	"github.com/aether-x/control-plane/internal/telemetry"

	supervisorpb "github.com/aether-x/control-plane/api/gen/go/aether/supervisor/v1"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.FromEnv()
	if err != nil {
		log.Error("config error", "err", err)
		os.Exit(2)
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	readyChecks := make([]api.ReadinessCheck, 0, 3)

	// 1. Dial the supervisor (mTLS in prod).
	supTLS := grpcclient.TLSConfig{
		Enabled:    cfg.MTLSEnabled,
		Cert:       cfg.SupervisorCert,
		Key:        cfg.SupervisorKey,
		CA:         cfg.SupervisorCA,
		ServerName: cfg.SupervisorServerName,
	}
	sup, err := grpcclient.New(rootCtx, cfg.SupervisorAddr, supTLS)
	if err != nil {
		log.Error("supervisor dial failed", "err", err)
		os.Exit(1)
	}
	defer sup.Close()

	// 1b. Dial the anti-forgery gRPC service (Rust bridge) for signed tokens.
	// Its transport is mutually authenticated in every non-loopback deployment.
	afTLS := antiforgeryclient.TLSConfig{
		Enabled:    cfg.AntiforgeryMTLSEnabled,
		Cert:       cfg.AntiforgeryCert,
		Key:        cfg.AntiforgeryKey,
		CA:         cfg.AntiforgeryCA,
		ServerName: cfg.AntiforgeryServerName,
	}
	afc, err := antiforgeryclient.New(rootCtx, cfg.AntiforgeryAddr, afTLS)
	if err != nil {
		log.Warn("anti-forgery service unreachable; /v1/subscriptions disabled", "addr", cfg.AntiforgeryAddr, "err", err)
	} else {
		defer afc.Close()
	}

	// 2. Start the telemetry ingester (drains StreamTelemetry -> feature store).
	//    The MultiWriter fans events out to BOTH the (future) persistence sink
	//    AND the live per-(ISP,protocol) featurizer that feeds the AI feature
	//    store, with no duplicated aggregation logic.
	nodeID := getenv("AETHER_NODE_ID", "node-local")
	agg := featurizer.New(2 * time.Minute)
	broadcaster := telemetry.NewBroadcaster(128)

	// Sinks: no-op (placeholder persistence), the live featurizer, the
	// real-time SSE broadcaster, and (if configured) the ClickHouse writer.
	sinks := []telemetry.Writer{noOpWriter{}, &aggregatorSink{agg: agg}, broadcaster}
	if cfg.ClickHouseDSN != "" {
		chSink, chErr := telemetry.NewClickHouseSink(rootCtx, cfg.ClickHouseDSN)
		if chErr != nil {
			log.Warn("clickhouse sink disabled", "err", chErr)
			readyChecks = append(readyChecks, api.ReadinessCheck{
				Name: "clickhouse",
				Check: func(context.Context) error {
					return errors.New("ClickHouse telemetry sink is unavailable")
				},
			})
		} else {
			schemaErr := telemetry.EnsureSchema(rootCtx, chSink)
			if schemaErr != nil {
				log.Warn("clickhouse schema ensure failed", "err", schemaErr)
			}
			readyChecks = append(readyChecks, api.ReadinessCheck{
				Name: "clickhouse",
				Check: func(ctx context.Context) error {
					if schemaErr != nil {
						return schemaErr
					}
					return chSink.Ping(ctx)
				},
			})
			spool, _ := telemetry.NewDiskSpool(getenv("AETHER_TELEMETRY_SPOOL", "/tmp/aether-telemetry-spool.jsonl"))
			chWriter := telemetry.NewClickHouseWriter(chSink, spool, telemetry.DefaultClickHouseOptions(), log)
			sinks = append(sinks, chWriter)
			go func() { <-rootCtx.Done(); chWriter.Close() }()
			log.Info("clickhouse telemetry writer enabled")
		}
	}

	ing := telemetry.New(
		&supervisorSource{sup: sup},
		telemetry.NewMultiWriter(sinks...),
		nodeID,
		cfg.TelemetryFlush,
		log,
	)
	go func() {
		if err := ing.Run(rootCtx); err != nil {
			log.Warn("ingester exited", "err", err)
		}
	}()

	// 3. Build the HTTP API + the embedded MCP server (tools/resources/prompts
	//    backed by the real supervisor client and featurizer).
	mcpSrv := mcp.New(mcpbridge.NewSupervisor(sup), agg)

	// 3b. Standard-client subscriptions are published only from an
	// operator-validated node catalog. The older telemetry optimizer remains an
	// advisory library until it has a real score reader; it must not fabricate
	// endpoint addresses from mock node IDs in a production response.
	var dynamicSvc api.DynamicSubProvider
	if !cfg.SubscriptionDelivery {
		log.Info("verified subscription delivery is disabled")
	} else {
		service, serviceErr := subendpoint.NewReloadingCatalogSubscriptionService(
			cfg.NodeCatalogFile,
			cfg.NodeCatalogReloadInterval,
		)
		if serviceErr != nil {
			log.Error("verified node catalog rejected", "err", serviceErr)
			os.Exit(2)
		}
		dynamicSvc = service
		status := service.Status()
		log.Info(
			"verified standard-client node catalog enabled",
			"version", status.ActiveVersion,
			"reload_interval", cfg.NodeCatalogReloadInterval,
		)
		go service.Run(rootCtx)

		if cfg.TelemetryScoring {
			scoreReader, scoreErr := telemetry.NewProductionNodeScoreReader(rootCtx, cfg.ClickHouseDSN)
			if scoreErr != nil {
				log.Error("production telemetry score reader unavailable", "err", scoreErr)
				os.Exit(2)
			}
			cachedScoreReader, cacheErr := subendpoint.NewCachingCatalogScoreReader(
				scoreReader,
				subendpoint.DefaultScoreCacheOptions(),
			)
			if cacheErr != nil {
				_ = scoreReader.Close()
				log.Error("telemetry score cache unavailable", "err", cacheErr)
				os.Exit(2)
			}
			scoredService, scoredErr := subendpoint.NewTelemetryCatalogSubscriptionService(service, cachedScoreReader)
			if scoredErr != nil {
				_ = scoreReader.Close()
				log.Error("telemetry catalog service unavailable", "err", scoredErr)
				os.Exit(2)
			}
			dynamicSvc = scoredService
			go func() {
				<-rootCtx.Done()
				if closeErr := scoreReader.Close(); closeErr != nil {
					log.Warn("close telemetry score reader", "err", closeErr)
				}
			}()
			log.Info("aggregate ClickHouse telemetry scoring enabled")
		}
	}

	// 3c. Network attribution is accepted only from explicitly trusted ingress
	// CIDRs. Without this configuration, subscriptions use capability-only
	// client context and never guess an ISP from a user-controlled header.
	var networkResolver api.ClientNetworkContextResolver
	if len(cfg.TrustedProxyCIDRs) > 0 {
		resolver, resolverErr := api.NewTrustedNetworkContextResolver(cfg.TrustedProxyCIDRs)
		if resolverErr != nil {
			log.Error("trusted proxy CIDR configuration rejected", "err", resolverErr)
			os.Exit(2)
		}
		networkResolver = resolver
		log.Info("trusted proxy network attribution enabled", "cidrs", len(cfg.TrustedProxyCIDRs))
	}

	// 3d. Session manager: PostgreSQL is the production source of truth and
	// Redis is the short-latency cache. Development may fall back to the locked
	// in-memory store when the local data layer is deliberately absent.
	var sessionStore store.SessionStore = store.NewMemSessionStore()
	if cfg.PostgresDSN != "" {
		storeCtx, cancelStore := context.WithTimeout(rootCtx, 5*time.Second)
		pgStore, pgErr := store.NewPgStore(storeCtx, cfg.PostgresDSN)
		cancelStore()
		if pgErr != nil {
			if !cfg.Development {
				log.Error("PostgreSQL session store unavailable", "err", pgErr)
				os.Exit(2)
			}
			log.Warn("development session store falling back to memory", "err", pgErr)
		} else {
			migrateCtx, cancelMigrate := context.WithTimeout(rootCtx, 10*time.Second)
			migrateErr := pgStore.Migrate(migrateCtx)
			cancelMigrate()
			if migrateErr != nil {
				pgStore.Close()
				if !cfg.Development {
					log.Error("PostgreSQL session migration failed", "err", migrateErr)
					os.Exit(2)
				}
				log.Warn("development session store falling back to memory", "err", migrateErr)
			} else {
				sessionStore = pgStore
				readyChecks = append(readyChecks, api.ReadinessCheck{
					Name:  "postgres",
					Check: pgStore.Ping,
				})
				defer pgStore.Close()
				log.Info("PostgreSQL session store enabled")
			}
		}
	}
	sessionManager := store.NewSessionManager(cfg.RedisAddr, sessionStore)
	defer func() {
		if closeErr := sessionManager.Close(); closeErr != nil {
			log.Warn("close Redis session cache", "err", closeErr)
		}
	}()
	readyChecks = append(readyChecks, api.ReadinessCheck{
		Name:  "redis",
		Check: sessionManager.RedisPing,
	})

	jwtIssuer, jwtErr := auth.NewKeyring(
		cfg.JWTKeyID,
		cfg.JWTSecret,
		cfg.JWTPreviousKeys,
		15*time.Minute,
	)
	if jwtErr != nil {
		log.Error("JWT keyring configuration rejected", "err", jwtErr)
		os.Exit(2)
	}

	apiSrv := &api.Server{
		SupervisorCores: func() (*supervisorpb.ListCoresResponse, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return sup.ListCores(ctx)
		},
		ReadyChecks: readyChecks,
		Issuer:                          jwtIssuer,
		AllowUnauthenticatedDevelopment: cfg.Development,
		Build:                           "0.1.0",
		MCP:                    mcpSrv,
		DynamicSubs:            dynamicSvc,
		NetworkContextResolver: networkResolver,
		Sessions:               sessionManager,
	}
	if afc != nil {
		apiSrv.Antiforgery = afc.Raw()
	}
	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           apiSrv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Info("control plane listening", "addr", cfg.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server error", "err", err)
		}
	}()

	<-rootCtx.Done()
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
}

// supervisorSource adapts grpcclient.Client to telemetry.Source. The gRPC
// stream client already satisfies telemetry.Sink (its Recv returns
// *telemetrypb.TelemetryBatch), so we return it directly.
type supervisorSource struct{ sup *grpcclient.Client }

func (s *supervisorSource) Open(ctx context.Context, nodeID string) (telemetry.Sink, error) {
	return s.sup.StreamTelemetry(ctx, nodeID)
}

// noOpWriter discards events until the ClickHouse writer exists.
type noOpWriter struct{}

func (noOpWriter) WriteBatch(context.Context, []telemetry.Event) error { return nil }

// aggregatorSink adapts a featurizer.Aggregator to the telemetry.Writer
// interface so the ingester can feed the AI feature store in parallel with
// persistence, without the telemetry package depending on featurizer (which
// would create an import cycle).
type aggregatorSink struct {
	agg *featurizer.Aggregator
}

func (a *aggregatorSink) WriteBatch(_ context.Context, events []telemetry.Event) error {
	for _, e := range events {
		a.agg.Observe(e)
	}
	return nil
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}
