# External core operation contract

Aether-X does not claim that a binary is running simply because an adapter was
constructed. The default data-plane build uses deterministic mock adapters so
tests and local control-plane development have no hidden dependency on a proxy
binary.

A production operator may opt into the managed external-core path only when all
of these conditions are met:

1. Build the supervisor with the `real_cores` Cargo feature.
2. Set `AETHER_EXTERNAL_CORE_MODE=true` deliberately. A binary built without
   that feature fails closed at startup if this variable is enabled; it never
   silently substitutes a mock adapter.
3. Make an audited Xray and/or sing-box executable available in the workload.
   The default executable names are `xray` and `sing-box`; override only with
   `AETHER_XRAY_BIN` or `AETHER_SING_BOX_BIN`.
4. Pass an **absolute, read-only** native-core JSON config path through
   `opaque_config.config_path`.
5. Set `protocol.listen_addr` to the core's actual, non-zero local listener.
   The adapter normalizes wildcard addresses to loopback and performs a bounded
   TCP listener probe. A running PID with no accepting listener is reported as
   `Degraded`, not `Running`.
6. Keep the platform ingress closed until the actual core is healthy and has a
   separately authorized staging test.

The adapter emits only the fixed command shape below; it does not interpolate
opaque values into shell commands and it does not accept config bytes through
stdin:

```text
<operator-selected binary> run -c <reviewed absolute config path>
```

## Deliberate limits

- The generic subprocess adapter cannot truthfully promise graceful TCP stream
  migration, native API drain, connection counters, or memory metrics. It
  returns a conservative error for a requested drain rather than pretending a
  drain occurred.
- It does not download executables and the repository's default Docker image
  intentionally contains no Xray or sing-box binary. Supply a reviewed,
  version-pinned binary in a separately maintained production image.
- A positive TCP listener probe only proves local readiness. It does not prove
  an international route, a successful subscriber handshake, or a Blackout
  escape path.

This keeps standard clients possible without creating a custom client while
preventing a deployment from advertising nonexistent proxy ingress.
