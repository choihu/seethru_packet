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

HOST_KEY_ALGORITHM=""

SERVER_KEY_PATH=""

CLIENT_KEY_PATH=""

AUTH_USERNAME="remote"

ENV_NAME="my_docker_environment"

BASE_DIR="$( cd "$( dirname "$0" )" && pwd -P )"
PROJECT_ROOT=$(dirname "$BASE_DIR")

CONTAINER_NAME="sshmitm_${TARGET_SERVICE}_${TARGET_PORT}"

IMAGE_NAME="sshmitm_${TARGET_SERVICE}_image"

FLAG_DIR="$PROJECT_ROOT/flags/$ENV_NAME"
# ===================================================================
# ===                  END OF CONFIGURATION                       ===
# ===================================================================


# --- Internal Script Logic (Do not modify below) ---
set -euo pipefail

# Determine mitmproxy mode and script based on PROXY_TYPE

LOG_FILE="log_${TARGET_SERVICE}_${TARGET_PORT}"
LEAK_LOG_FILE="leak_${TARGET_SERVICE}_${TARGET_PORT}"

# Create unique container name

# --- Build docker and mitmproxy commands ---

# Base docker command
DOCKER_ARGS=" -d --name $CONTAINER_NAME --net=host -v $BASE_DIR:/opt/ssh-mitm/ -v $FLAG_DIR:/flags -e LOG_FILE=$LOG_FILE -e LEAK_LOG_FILE=$LEAK_LOG_FILE"
DOCKER_ARGS+=" -v $BASE_DIR/$SERVER_KEY_PATH:/opt/ssh-mitm/server.key:ro"
DOCKER_ARGS+=" -v $BASE_DIR/$CLIENT_KEY_PATH:/opt/ssh-mitm/client.key:ro"

# --- Announce and Run ---
echo "--- Preparing Proxy ---"
echo "  Container: $CONTAINER_NAME"
echo "  Network:   $NETWORK_NAME"
echo "  Log File:  $LOG_FILE"
echo ""
echo "--- Proxying --- "
echo ""

echo "[INFO] Stopping and removing old container if it exists..."
docker stop $CONTAINER_NAME >/dev/null 2>&1 || true
docker rm $CONTAINER_NAME >/dev/null 2>&1 || true
docker image rm "$IMAGE_NAME" >/dev/null 2>&1 || true

echo "[INFO] Starting new proxy container..."

docker build -t "$IMAGE_NAME" .

docker run \
    --rm \
    $DOCKER_ARGS \
    $IMAGE_NAME \
      ssh-mitm server \
        --listen-port $LISTENING_PORT \
        --remote-host 127.0.0.1 \
        --remote-port $TARGET_PORT \
        --host-key /opt/ssh-mitm/server.key \
        --host-key-algorithm $HOST_KEY_ALGORITHM \
        --auth-username $AUTH_USERNAME \
        --auth-key /opt/ssh-mitm/client.key \
        --ssh-interface seethru

echo "[SUCCESS] Proxy container '$CONTAINER_NAME' started."
echo "Add iptables rules: sudo iptables -t nat -A MITM -p tcp \! -s 127.0.0.0/24 --dport $TARGET_PORT -j REDIRECT --to-ports $LISTENING_PORT"

