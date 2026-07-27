# Test-only TLS material

These PEM files are deliberately public, non-production fixtures used only by
`live_signals` loopback tests. `probe-key.pem` is not a deployment secret and
must never be copied into a probe configuration or production image. Real
operators mount their own CA bundle outside Git.
