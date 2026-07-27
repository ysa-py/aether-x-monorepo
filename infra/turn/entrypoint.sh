#!/bin/sh
set -eu

runtime_dir=/run/aether-turn
umask 077
mkdir -p "$runtime_dir"
random_hex() { od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'; }
username="${TURN_USERNAME:-aether-$(random_hex 8)}"
password="${TURN_PASSWORD:-$(random_hex 24)}"
realm="${TURN_REALM:-aether-x.test}"
printf 'TURN_USERNAME=%s\nTURN_PASSWORD=%s\nTURN_REALM=%s\n' \
  "$username" "$password" "$realm" >"$runtime_dir/credentials.env"
chmod 0600 "$runtime_dir/credentials.env"

exec turnserver \
  --no-cli \
  --no-tls \
  --no-dtls \
  --fingerprint \
  --lt-cred-mech \
  --realm="$realm" \
  --user="$username:$password" \
  --min-port=49160 \
  --max-port=49200 \
  --log-file=stdout \
  --simple-log
