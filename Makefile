# Aether-X monorepo tasks. Requires rustup, go, and buf on PATH.
# In this sandbox they are absent; these targets run in a real dev env.

PROTO_DIR := api/proto
GEN_DIR   := api/gen

.PHONY: help buf buf-check rust rust-test rust-clippy go go-test compose-up compose-down ci coverage clean

help:
	@echo "Aether-X targets:"
	@echo "  make ci         - run the WHOLE verification pipeline locally (rust + go gates)"
	@echo "  make coverage   - collect + print coverage reports (best-effort)"
	@echo "  make buf        - regenerate Go + Rust proto stubs into $(GEN_DIR)"
	@echo "  make buf-check  - lint protos (buf lint)"
	@echo "  make rust       - build the data plane (release)"
	@echo "  make rust-test  - test + clippy (-D warnings) the data plane"
	@echo "  make go         - build the control plane"
	@echo "  make go-test    - test + lint the control plane"
	@echo "  make compose-up - local dev stack (postgres/clickhouse/redis)"

# ---- Protos --------------------------------------------------------------

buf:
	cd $(PROTO_DIR) && buf generate

buf-check:
	cd $(PROTO_DIR) && buf lint

# ---- Whole-pipeline verification (mirrors .github/workflows/ci.yml) -------

# ci runs every hard gate locally. Rust gates run at the workspace root; Go
# gates run inside control-plane/. Fails fast on the first failing gate.
ci: rust-ci go-ci
	@echo "==============================="
	@echo "Aether-X pipeline: ALL GATES OK"
	@echo "==============================="

rust-ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace --all-features --no-fail-fast

go-ci:
	cd control-plane && go mod download
	cd control-plane && go vet ./...
	cd control-plane && go test -race ./...
	@out=$$(cd control-plane && gofmt -l .); \
	if [ -n "$$out" ]; then echo ":: gofmt issues: $$out"; exit 1; fi

# coverage is best-effort: tools (cargo-llvm-cov) may be absent; never fail `ci`.
coverage:
	-cargo llvm-cov --workspace --all-features || cargo test --workspace --all-features
	cd control-plane && go test -cover ./... || true

# ---- Rust crates (workspace: core-supervisor + antiforgery) --------------

rust:
	cargo build --release --workspace

rust-test:
	cargo test --workspace --all-features --no-fail-fast

rust-clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

# ---- Go control plane ----------------------------------------------------

go:
	cd control-plane && go build ./...

go-test:
	cd control-plane && go test -race ./...

# ---- Local dev stack -----------------------------------------------------

compose-up:
	docker compose -f deploy/compose/docker-compose.yml up -d

compose-down:
	docker compose -f deploy/compose/docker-compose.yml down -v

clean:
	rm -rf $(GEN_DIR)

# ---- Next.js NOC dashboard -------------------------------------------------

web:
	cd aether-x-dashboard && npm install --no-audit --no-fund && npm run dev

web-build:
	cd aether-x-dashboard && npm install --no-audit --no-fund && npm run build

web-typecheck:
	cd aether-x-dashboard && npx tsc --noEmit

# ---- Helm chart (Kubernetes) -----------------------------------------------

helm-lint:
	helm lint deploy/helm/aether-x

helm-template:
	helm template aether-x deploy/helm/aether-x

# ---- OpenAPI spec + frontend SDK codegen -----------------------------------

openapi-gen:
	@mkdir -p docs
	@cp control-plane/internal/api/openapi.yaml docs/openapi.yaml
	@python3 -c "import yaml,json; d=yaml.safe_load(open('control-plane/internal/api/openapi.yaml')); json.dump(d, open('docs/openapi.json','w'), indent=2); print('docs/openapi.json valid')"
	@echo "OpenAPI spec -> docs/openapi.{yaml,json}"
	@echo "Frontend types: cd aether-x-dashboard && npm run generate:api"

# ---- Playwright E2E (headless Chromium + Firefox) -------------------------

web-e2e:
	cd aether-x-dashboard && npm install --no-audit --no-fund
	cd aether-x-dashboard && npx playwright install chromium firefox
	cd aether-x-dashboard && npm run test:e2e

# ---- k6 load & stress tests (hermetic; stub control plane) -----------------

load-test:
	@echo ">> starting stub control plane on :8090"
	@python3 tests/load/stub.py & echo $$! > /tmp/aether-stub.pid
	@sleep 1
	@echo ">> REST API benchmark"; k6 run ./tests/load/rest-api.js
	@echo ">> SSE stream stress";   k6 run ./tests/load/sse-stream.js
	@kill $$(cat /tmp/aether-stub.pid) 2>/dev/null || true

# ---- Coverage-guided fuzzing (cargo-fuzz / libFuzzer) ----------------------

fuzz-check:
	@echo '==> Building cargo-fuzz targets...'
	cargo fuzz build
	@echo '==> Running sanity fuzz iterations...'
	cargo fuzz run fuzz_ech_client_hello -- -runs=1000
	cargo fuzz run fuzz_tls_fragmenter -- -runs=1000
	cargo fuzz run fuzz_route_resolver -- -runs=1000
	cargo fuzz run fuzz_antiforgery_proofs -- -runs=1000
	@echo '==> All fuzz targets compiled and verified cleanly.'

# ---- Terraform IaC validation ----------------------------------------------

tf-validate:
	terraform fmt -check -recursive infra/terraform/
	@for d in infra/terraform/modules/*/; do 		(cd $$d && terraform init -backend=false && terraform validate) || exit 1; 	done
	cd infra/terraform/environments/prod && terraform init -backend=false && terraform validate

# ---- Monitoring (Grafana + Prometheus) -------------------------------------

monitoring-validate:
	jq . deploy/monitoring/grafana/dashboards/aether_noc_overview.json > /dev/null
	@for f in deploy/monitoring/grafana/provisioning/datasources/datasources.yaml deploy/monitoring/grafana/provisioning/dashboards/dashboards.yaml deploy/monitoring/prometheus.yml deploy/monitoring/docker-compose.monitoring.yml; do 		python3 -c "import yaml; yaml.safe_load(open('$$f'))" || exit 1; 	done
	@echo 'Monitoring config validated'


# ---- eBPF/XDP bytecode compilation -----------------------------------------

ebpf-build:
	@mkdir -p ebpf/bin
	clang -O2 -g -target bpf -Wall -I/usr/include/x86_64-linux-gnu 		-c ebpf/xdp_rst_dropper.c -o ebpf/bin/xdp_rst_dropper.o
	@echo 'eBPF bytecode compiled: ebpf/bin/xdp_rst_dropper.o'
