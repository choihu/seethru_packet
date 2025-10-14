#!/bin/bash

# ===================================================================
# ===               PROXY CONFIGURATION - MODIFY HERE               ===
# ===================================================================

# 1. The port on your VM that the proxy will listen on.
#    Your client (browser, curl, etc.) will connect to this port.
LISTENING_PORT=9999

# 2. The type of traffic. Use one of: "http", "https", "tcp", "tls".
PROXY_TYPE="http"

# 3. The name of the target service inside the docker-compose stack.
#    (Check the service name in the wargame's docker-compose.yml)
TARGET_SERVICE="my_web_service"

# 4. The port that the target service is listening on INSIDE the Docker network.
TARGET_PORT=8080

# 5. The name of the Docker network the wargame stack is running on.
#    (Usually this is <wargame_directory_name>_default)
NETWORK_NAME="my_wargame_default"

# 6. (OPTIONAL) Path to a custom certificate (.pem file) to use for HTTPS.
#    If set, mitmproxy will use this cert instead of its own, and you won't
#    need to install the mitmproxy CA on the client.
#    The path should be relative to the MITM_PROXY directory.
CUSTOM_CERT_PATH=""

BASE_DIR="$( cd "$( dirname "$0" )" && pwd -P )"
# ===================================================================
# ===                  END OF CONFIGURATION                       ===
# ===================================================================


# --- Internal Script Logic (Do not modify below) ---
set -e

# Determine mitmproxy mode and script based on PROXY_TYPE
CLIENT_SCHEME="$PROXY_TYPE"
EXTRA_MITM_ARGS=""
MITM_LISTEN_HOST="0.0.0.0"
MITM_LISTEN_PORT="$LISTENING_PORT"
TCP_HOSTS_PATTERN=""
MITM_CONNECTION_STRATEGY=""
USE_TLS_WRAPPER=0
TLS_PLAINTEXT_PORT=""
TLS_UPSTREAM_PORT=""
UPSTREAM_HOST=""
UPSTREAM_PORT=""
UPSTREAM_TYPE=""
UPSTREAM_SNI=""

if [ "$PROXY_TYPE" == "http" ]; then
  MODE="reverse:http://127.0.0.1:${TARGET_PORT}"
  SCRIPT="/scripts/monitor_http.py"
  LOG_FILE="log_http_${TARGET_SERVICE}_${TARGET_PORT}"
  LEAK_LOG_FILE="leak_http_${TARGET_SERVICE}_${TARGET_PORT}"
elif [ "$PROXY_TYPE" == "https" ]; then
  MODE="reverse:https://127.0.0.1:${TARGET_PORT}"
  SCRIPT="/scripts/monitor_http.py"
  LOG_FILE="log_https_${TARGET_SERVICE}_${TARGET_PORT}"
  LEAK_LOG_FILE="leak_https_${TARGET_SERVICE}_${TARGET_PORT}"
elif [ "$PROXY_TYPE" == "tcp" ]; then
  MODE="reverse:tcp://127.0.0.1:${TARGET_PORT}"
  SCRIPT="/scripts/monitor_tcp.py"
  LOG_FILE="log_tcp_${TARGET_SERVICE}_${TARGET_PORT}"
  LEAK_LOG_FILE="leak_tcp_${TARGET_SERVICE}_${TARGET_PORT}"
  TCP_HOSTS_PATTERN="127\\.0\\.0\\.1"
  MITM_CONNECTION_STRATEGY="lazy"
  EXTRA_MITM_ARGS=" --set tcp_hosts=${TCP_HOSTS_PATTERN} --set connection_strategy=${MITM_CONNECTION_STRATEGY}"
elif [ "$PROXY_TYPE" == "tls" ]; then
  TLS_PLAINTEXT_PORT=$((LISTENING_PORT + 1))
  TLS_UPSTREAM_PORT=$((LISTENING_PORT + 2))
  MODE="reverse:tcp://127.0.0.1:${TLS_UPSTREAM_PORT}"
  SCRIPT="/scripts/monitor_tcp.py"
  LOG_FILE="log_tls_${TARGET_SERVICE}_${TARGET_PORT}"
  LEAK_LOG_FILE="leak_tls_${TARGET_SERVICE}_${TARGET_PORT}"
  TCP_HOSTS_PATTERN="127\\.0\\.0\\.1"
  MITM_CONNECTION_STRATEGY="lazy"
  MITM_LISTEN_HOST="127.0.0.1"
  MITM_LISTEN_PORT=$TLS_PLAINTEXT_PORT
  UPSTREAM_HOST="127.0.0.1"
  UPSTREAM_PORT="$TARGET_PORT"
  UPSTREAM_TYPE="tls"
  UPSTREAM_SNI="$TARGET_SERVICE"
  USE_TLS_WRAPPER=1
else
  echo "[ERROR] Invalid PROXY_TYPE: must be http, https, tcp, or tls"
  exit 1
fi

# Create unique container name
CONTAINER_NAME="mitmproxy_${TARGET_SERVICE}_${TARGET_PORT}"


# --- Build docker and mitmproxy commands ---

# Base docker command
DOCKER_ARGS="-d --name $CONTAINER_NAME --net=host -v $BASE_DIR:/scripts/ -e LOG_FILE=$LOG_FILE -e LEAK_LOG_FILE=$LEAK_LOG_FILE"

# Base mitmproxy command
MITM_ARGS="mitmdump --listen-host $MITM_LISTEN_HOST --listen-port $MITM_LISTEN_PORT -s $SCRIPT --mode $MODE --set ssl_insecure=true --set keep_host_header=true"
if [ "$USE_TLS_WRAPPER" -eq 0 ] && [ -n "$EXTRA_MITM_ARGS" ]; then
  MITM_ARGS+="$EXTRA_MITM_ARGS"
fi

# Add custom certificate if provided
# Need Modify
if [ -n "$CUSTOM_CERT_PATH" ]; then
  if [ ! -f "$CUSTOM_CERT_PATH" ]; then
    echo "[ERROR] Custom certificate file not found at: $CUSTOM_CERT_PATH"
    exit 1
  fi
  echo "[INFO] Using custom certificate: $CUSTOM_CERT_PATH"
  DOCKER_ARGS+=" -v $BASE_DIR/$CUSTOM_CERT_PATH:/certs/custom.pem:ro"
  if [ "$USE_TLS_WRAPPER" -eq 0 ]; then
    MITM_ARGS+=" --certs *=/certs/custom.pem"
  fi
fi

# --- Announce and Run ---
echo "--- Preparing Proxy ---"
echo "  Container: $CONTAINER_NAME"
echo "  Network:   $NETWORK_NAME"
echo "  Log File:  $LOG_FILE"
echo ""
echo "--- Proxying --- "
echo "  Clients connect to  ==> ${CLIENT_SCHEME}://<your_vm_ip>:${LISTENING_PORT}"
echo "  Proxy forwards to   ==> ${MODE}"
echo ""

echo "[INFO] Stopping and removing old container if it exists..."
docker stop $CONTAINER_NAME >/dev/null 2>&1 || true
docker rm $CONTAINER_NAME >/dev/null 2>&1 || true

echo "[INFO] Starting new proxy container..."

if [ "$USE_TLS_WRAPPER" -eq 1 ]; then
  if [ -z "$CUSTOM_CERT_PATH" ]; then
    echo "[ERROR] TLS mode requires CUSTOM_CERT_PATH pointing to a PEM file with both cert and key" >&2
    exit 1
  fi

  DOCKER_ARGS+=" -e TLS_LISTEN_PORT=$LISTENING_PORT"
  DOCKER_ARGS+=" -e TLS_PLAINTEXT_PORT=$MITM_LISTEN_PORT"
  DOCKER_ARGS+=" -e TLS_UPSTREAM_PORT=$TLS_UPSTREAM_PORT"
  DOCKER_ARGS+=" -e MITM_SCRIPT_PATH=$SCRIPT"
  DOCKER_ARGS+=" -e MITM_UPSTREAM_MODE=$MODE"
  DOCKER_ARGS+=" -e TCP_HOSTS_PATTERN=$TCP_HOSTS_PATTERN"
  DOCKER_ARGS+=" -e MITM_CONNECTION_STRATEGY=$MITM_CONNECTION_STRATEGY"
  DOCKER_ARGS+=" -e UPSTREAM_HOST=$UPSTREAM_HOST"
  DOCKER_ARGS+=" -e UPSTREAM_PORT=$UPSTREAM_PORT"
  DOCKER_ARGS+=" -e UPSTREAM_TYPE=$UPSTREAM_TYPE"
  DOCKER_ARGS+=" -e UPSTREAM_SNI=$UPSTREAM_SNI"
  DOCKER_ARGS+=" -e CUSTOM_CERT_PATH=/certs/custom.pem"

  if [ ! -f "$BASE_DIR/tls_wrapper.sh" ]; then
    echo "[ERROR] Missing tls_wrapper.sh in $BASE_DIR. Re-run configure_proxy_docker.py to refresh service files." >&2
    exit 1
  fi

  docker run $DOCKER_ARGS --entrypoint /scripts/tls_wrapper.sh mitmproxy/mitmproxy
else
  docker run $DOCKER_ARGS mitmproxy/mitmproxy $MITM_ARGS
fi

echo "[SUCCESS] Proxy container '$CONTAINER_NAME' started."
echo "Add iptables rules: sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport $TARGET_PORT -j REDIRECT --to-ports $LISTENING_PORT"

if [ "$PROXY_TYPE" == "https" ]; then
  echo "Set .pem file: cat cert.key cert.crt > cert.pem"
if [ "$PROXY_TYPE" == "tls" ]; then
  echo "Set .pem file: cat cert.crt cert.key > cert.pem"