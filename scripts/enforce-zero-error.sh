#!/usr/bin/env bash
# Aether-X — Zero-Error Automated Quality Gate Enforcement
#
# Runs every gate from ADVANCED_FEATURES_ENGINEERING_PROMPT.md §7 and exits
# non-zero if ANY of them fails.
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY THIS SCRIPT WAS REWRITTEN
# ─────────────────────────────────────────────────────────────────────────────
# The previous version appended `|| true` to cargo clippy, cargo test, cargo
# audit, go vet and go test, and ended with an unconditional `exit 0`. It
# therefore printed
#
#     ALL GATES PASSED — ZERO ERROR
#
# on a tree where core-supervisor did not compile at all (six hard errors), the
# Go control plane failed `go vet`, nine Go files failed `gofmt`, and thirteen
# Rust files failed `cargo fmt --check`. A gate that cannot fail is not a gate;
# it is a slogan, and it actively hides the problems it claims to prevent.
#
# Two rules now hold, and they are what make the output trustworthy:
#   1. A failing check fails the script. No `|| true` on a correctness gate.
#   2. A check that cannot run is reported as SKIPPED and is NEVER counted as
#      a pass. A missing toolchain is an unknown, not a success.
#
# Exit codes: 0 = every runnable gate passed. 1 = at least one gate FAILED.

set -uo pipefail

FAILED=0
PASSED=0
SKIPPED=0

pass() { echo "  PASS    $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL    $1"; FAILED=$((FAILED + 1)); }
skip() { echo "  SKIP    $1 ($2)"; SKIPPED=$((SKIPPED + 1)); }

# Run a command, capture output, and report. Any non-zero status is a FAILURE.
run_gate() {
    local name="$1"
    shift
    local out
    if out=$("$@" 2>&1); then
        pass "$name"
    else
        fail "$name"
        echo "$out" | sed 's/^/            /' | tail -25
    fi
}

# Resolve the repo root so the script works from any working directory.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

echo "========================================"
echo "Aether-X Zero-Error Gate Enforcement"
echo "repo: $REPO_ROOT"
echo "========================================"

# ── Rust gates ───────────────────────────────────────────────────────────────
echo
echo "[Rust]"
if command -v cargo &>/dev/null; then
    run_gate "cargo fmt --all -- --check" \
        cargo fmt --all -- --check
    run_gate "cargo clippy --workspace --all-targets --all-features -D warnings" \
        cargo clippy --workspace --all-targets --all-features -- -D warnings
    run_gate "cargo test --workspace --all-features" \
        cargo test --workspace --all-features --no-fail-fast

    if command -v cargo-audit &>/dev/null; then
        run_gate "cargo audit" cargo audit
    else
        skip "cargo audit" "cargo-audit not installed"
    fi
else
    skip "cargo fmt"    "cargo not installed"
    skip "cargo clippy" "cargo not installed"
    skip "cargo test"   "cargo not installed"
    skip "cargo audit"  "cargo not installed"
fi

# ── Go gates ─────────────────────────────────────────────────────────────────
echo
echo "[Go]"
if command -v go &>/dev/null; then
    run_gate "go vet ./..."        env -C control-plane go vet ./...
    run_gate "go test -race ./..." env -C control-plane go test -race ./...

    gofmt_out=$(cd control-plane && gofmt -l . 2>&1)
    if [ -z "$gofmt_out" ]; then
        pass "gofmt -l (no diffs)"
    else
        fail "gofmt -l (files need formatting)"
        echo "$gofmt_out" | sed 's/^/            /'
    fi
else
    skip "go vet"        "go not installed"
    skip "go test -race" "go not installed"
    skip "gofmt"         "go not installed"
fi

# ── Dashboard gates ──────────────────────────────────────────────────────────
echo
echo "[Dashboard]"
if command -v npx &>/dev/null && [ -d aether-x-dashboard/node_modules ]; then
    run_gate "tsc --noEmit" env -C aether-x-dashboard npx tsc --noEmit
else
    skip "tsc --noEmit" "npx unavailable or dependencies not installed"
fi

# ── Repository invariants (always runnable, no toolchain needed) ─────────────
echo
echo "[Invariants]"

# No Python in any production runtime path (ARCHITECTURE.md §6).
py_out=$(find . -type f -name '*.py' \
    -not -path './ai-training/*' \
    -not -path './tests/*' \
    -not -path '*/node_modules/*' \
    -not -path '*/target/*' \
    -not -path './.git/*' 2>/dev/null)
if [ -z "$py_out" ]; then
    pass "Python confined to ai-training/ and tests/"
else
    fail "Python found in a production path"
    echo "$py_out" | sed 's/^/            /'
fi

# No unsafe code in the Rust crates. `#![forbid(unsafe_code)]` is the real
# enforcement (the compiler rejects violations); this checks the pragma is
# still present, so it cannot be silently dropped.
missing_forbid=""
for crate_lib in core-supervisor/src/lib.rs antiforgery/src/lib.rs routing/src/lib.rs; do
    if [ -f "$crate_lib" ] && ! grep -q '#!\[forbid(unsafe_code)\]' "$crate_lib"; then
        missing_forbid="$missing_forbid $crate_lib"
    fi
done
if [ -z "$missing_forbid" ]; then
    pass "#![forbid(unsafe_code)] present in all core crates"
else
    fail "#![forbid(unsafe_code)] missing in:$missing_forbid"
fi

# The blackout honesty contract must exist and keep its non-claims section.
# Matched loosely on purpose: the document uses typographic quotes, and a gate
# that breaks on a curly apostrophe teaches people to ignore gates.
if [ -f BLACKOUT_BOUNDS.md ] && grep -qiE 'never .{0,2}Connected' BLACKOUT_BOUNDS.md; then
    pass "Blackout isolation honesty contract present"
else
    fail "BLACKOUT_BOUNDS.md missing or its honesty contract was weakened"
fi

# Every service referenced by the Northflank manifest must have a Dockerfile.
missing_df=""
for df in deploy/docker/control-plane.Dockerfile \
          deploy/docker/core-supervisor.Dockerfile \
          deploy/docker/antiforgery-server.Dockerfile \
          deploy/docker/dashboard.Dockerfile; do
    [ -f "$df" ] || missing_df="$missing_df $df"
done
if [ -z "$missing_df" ]; then
    pass "All four deployment Dockerfiles present"
else
    fail "Missing Dockerfile(s):$missing_df"
fi

# ── Verdict ──────────────────────────────────────────────────────────────────
echo
echo "========================================"
echo "passed: $PASSED   failed: $FAILED   skipped: $SKIPPED"
if [ "$FAILED" -ne 0 ]; then
    echo "RESULT: FAILED — $FAILED gate(s) did not pass."
    echo "========================================"
    exit 1
fi
if [ "$SKIPPED" -ne 0 ]; then
    echo "RESULT: PASSED (with $SKIPPED skipped — toolchains unavailable here)."
    echo "A skipped gate is NOT a passed gate. CI runs all of them."
    echo "========================================"
    exit 0
fi
echo "RESULT: ALL GATES PASSED."
echo "========================================"
exit 0
