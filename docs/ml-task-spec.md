# ML task specification: network-event classification

**Status:** task definition locked before model or heuristic implementation

**Date:** 2026-07-27

## Objective

Classify an observed network measurement window into one of the following
operational categories:

1. `normal` — configured control target reached and protocol transaction
   succeeded within the operator threshold;
2. `path_failure` — timeout, refused connection, route loss, or independently
   confirmed target outage;
3. `dns_anomaly` — configured DNS query did not match the authorized reference
   answer or DNS transaction failed while independent control paths succeeded;
4. `tls_anomaly` — configured TLS transaction failed after TCP success, with an
   authorized control receiver ruling out a target outage;
5. `inconclusive` — insufficient independent evidence.

The classifier must not label a network event as censorship solely from a reset,
EOF, timeout, destination failure, or packet feature. Attribution requires an
authorized control receiver and deployment-specific ground truth.

## Input features

One sample is an immutable, time-bounded measurement window from the production
live-signal collector. The minimum feature vector is:

| Feature | Type | Source | Privacy/validity constraint |
| --- | --- | --- | --- |
| TCP success fraction | float `[0,1]` | configured real TCP probes | aggregate only; no user destinations |
| TCP connection RTT p50/p95 | milliseconds | `tokio::time::Instant` measurements | omit if fewer than the configured minimum samples |
| TCP timeout/refusal/other-IO fractions | float `[0,1]` | typed real connector errors | aggregate by configured control target only |
| TLS success fraction and handshake duration p50 | float/milliseconds | configured TLS control probes | valid only with a configured trust anchor |
| DNS success fraction and answer mismatch fraction | float `[0,1]` | configured UDP DNS/DoH control probes | reference answer must be operator-owned/authorized |
| independent control-target availability | boolean/fraction | authorized independent receiver | required before anomaly attribution |
| collection-window count and duration | integer/milliseconds | collector | preserves sample-quality context |

No packet payload, user identifier, subscription token, SNI, raw IP address, or
application request body is a model input.

## Labels and ground truth

Labels must come from an authorized measurement campaign, not from a heuristic
applied to the same features:

- `normal`: campaign control receiver reports healthy and real client probe
  succeeds;
- `path_failure`: a planned route/target failure or independently observed
  receiver outage is recorded;
- `dns_anomaly` / `tls_anomaly`: an authorized test environment introduces a
  known DNS/TLS fault while an independent control receiver remains healthy;
- `inconclusive`: default where those facts are absent.

A field observation without an authorized receiver is retained only as
`inconclusive`, never promoted into a censorship training label.

## Evaluation protocol

A trained model requires a dataset manifest with capture time, target class,
operator, software version, controlled-fault identifier, and SHA-256 for every
input file. Split by campaign/day, never random rows from the same event, to
avoid leakage.

Required reported metrics:

- macro F1 and per-class precision/recall, including `inconclusive`;
- confusion matrix on a held-out campaign;
- p50/p95 inference latency and peak resident memory on the target runtime;
- false-positive rate for `dns_anomaly` and `tls_anomaly`.

Promotion requires an operator-defined threshold recorded with the dataset
manifest; no accuracy target is invented in source code.

## Current data status and fallback

No labeled, authorized, real campaign dataset is present in this repository.
The checked-in `.onnx` files are zero-byte placeholders and are not a model.
Therefore no trained-model accuracy, latency, or resource metric can honestly
be reported today.

Until a manifest-backed dataset and independently repeatable `ort` inference
run exist, the only shippable behavior is an explicitly named
`HeuristicDpiClassifier`. It is a transparent rule-based **advisory** classifier
that emits `inconclusive` without independent control evidence; it must not be
called an ML model or an AI censorship detector.

## Non-claims

This task cannot establish Iran-wide DPI detection, ISP attribution, automatic
bypass, speed, uninterrupted connectivity, or Internet reachability during an
international routing blackout. Those require authorized carrier measurements
and independently deployed paths.
