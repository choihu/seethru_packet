#!/bin/sh
set -e

: "${TLS_LISTEN_PORT:?TLS_LISTEN_PORT not provided}"
: "${TLS_PLAINTEXT_PORT:?TLS_PLAINTEXT_PORT not provided}"
: "${MITM_SCRIPT_PATH:?MITM_SCRIPT_PATH not provided}"
: "${MITM_UPSTREAM_MODE:?MITM_UPSTREAM_MODE not provided}"
: "${TLS_UPSTREAM_PORT:?TLS_UPSTREAM_PORT not provided}"
: "${UPSTREAM_HOST:?UPSTREAM_HOST not provided}"
: "${UPSTREAM_PORT:?UPSTREAM_PORT not provided}"
: "${UPSTREAM_TYPE:?UPSTREAM_TYPE not provided}"
UPSTREAM_SNI="${UPSTREAM_SNI:-}"

CERT_PATH="${CUSTOM_CERT_PATH:-/certs/custom.pem}"

if [ ! -f "$CERT_PATH" ]; then
  echo "[ERROR] TLS certificate bundle not found at: $CERT_PATH" >&2
  exit 1
fi

if ! command -v socat >/dev/null 2>&1; then
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache socat >/dev/null
  elif command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update >/dev/null
    apt-get install -y socat >/dev/null
  else
    echo "[ERROR] socat binary unavailable in mitmproxy container" >&2
    exit 1
  fi
fi

SOCAT_SUPPORTS_SNI=0
if socat -h 2>&1 | grep -qi 'sni'; then
  SOCAT_SUPPORTS_SNI=1
fi

TCP_HOSTS_PATTERN="${TCP_HOSTS_PATTERN:-}"
CONNECTION_STRATEGY="${MITM_CONNECTION_STRATEGY:-}"

socat \
  openssl-listen:${TLS_LISTEN_PORT},reuseaddr,fork,cert=${CERT_PATH},key=${CERT_PATH},verify=0 \
  tcp:127.0.0.1:${TLS_PLAINTEXT_PORT} &
SOCAT_IN_PID=$!

if [ "$UPSTREAM_TYPE" = "tls" ]; then
  OPENSSL_DEST="openssl-connect:${UPSTREAM_HOST}:${UPSTREAM_PORT},verify=0"
  if [ -n "$UPSTREAM_SNI" ] && [ "$SOCAT_SUPPORTS_SNI" -eq 1 ]; then
    OPENSSL_DEST="${OPENSSL_DEST},sni=${UPSTREAM_SNI}"
  elif [ -n "$UPSTREAM_SNI" ] && [ "$SOCAT_SUPPORTS_SNI" -eq 0 ]; then
    echo "[WARN] socat binary does not support SNI parameter, continuing without it" >&2
  fi

  socat -d -d -x \
    tcp-listen:${TLS_UPSTREAM_PORT},reuseaddr,fork \
    "$OPENSSL_DEST" &
else
  socat -d -d -x \
    tcp-listen:${TLS_UPSTREAM_PORT},reuseaddr,fork \
    tcp:${UPSTREAM_HOST}:${UPSTREAM_PORT} &
fi
SOCAT_OUT_PID=$!

cleanup() {
  kill "$SOCAT_IN_PID" "$SOCAT_OUT_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

set -- mitmdump \
  --listen-host 127.0.0.1 \
  --listen-port "${TLS_PLAINTEXT_PORT}" \
  -s "${MITM_SCRIPT_PATH}" \
  --mode "${MITM_UPSTREAM_MODE}" \
  --set ssl_insecure=true \
  --set keep_host_header=true

if [ -n "$TCP_HOSTS_PATTERN" ]; then
  set -- "$@" --set "tcp_hosts=${TCP_HOSTS_PATTERN}"
fi

if [ -n "$CONNECTION_STRATEGY" ]; then
  set -- "$@" --set "connection_strategy=${CONNECTION_STRATEGY}"
fi

exec "$@"
