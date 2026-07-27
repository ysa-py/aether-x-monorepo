# Sealed store-and-forward spool

`core-supervisor/src/store_and_forward.rs` persists telemetry only through a
real `SpoolSealer`. The built-in production sealer is AES-256-GCM from `ring`,
which is already the rustls cryptographic provider used by the workspace.

## Production configuration

A disk-backed spool requires both variables:

```text
AETHER_SUPERVISOR_SPOOL=/var/lib/aether/supervisor.spool
AETHER_SUPERVISOR_SPOOL_KEY=<64 hexadecimal characters, 32 random bytes>
```

Generate and store the key in the deployment secret manager; do not place it
in Git, a node catalog, application logs, or a user subscription:

```text
openssl rand -hex 32
```

If `AETHER_SUPERVISOR_SPOOL` is set but the key is absent or invalid, the
supervisor logs a warning and uses the bounded in-memory queue. It **does not**
write a plaintext fallback spool.

## On-disk contract

The file begins with a format marker, followed by JSON envelopes containing a
format version, a random 96-bit nonce, and AES-256-GCM ciphertext. Queue IDs,
priorities, and payload bytes are all inside the authenticated ciphertext.

- Each append/rewrite gets a fresh nonce.
- A wrong key or authentication failure refuses opening the spool and leaves
  the existing file untouched.
- A legacy plaintext JSONL spool is rejected rather than automatically read or
  overwritten. Migrate it under an explicit operator-controlled process; do
  not silently expose its payload.
- A torn final record from a crash is skipped. Non-trailing malformed or
  unauthenticated records are fatal, preventing an incorrect key from looking
  like an empty spool.

## Tested boundary

The Rust tests read the actual spool file after persistence and assert that a
unique plaintext payload and the `QueuedItem.data` field name are absent from
disk bytes. They then reopen the same spool with the same key and recover the
payload. Separate tests prove wrong-key and legacy-plaintext spool attempts
fail without changing the on-disk bytes.

This is encryption at rest. It does not protect a live process that already has
the key, an unlocked host, backups copied before migration, or an operator who
puts the key in an insecure environment variable manager.
