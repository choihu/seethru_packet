#!/usr/bin/env bash

# Turn on debugging mode
set -x

# Set variables
REMOTE_CONN=$1
REMOTE_PATH=$2

# Check arguments
if [ -z "$REMOTE_CONN" ] || [ -z "$REMOTE_PATH" ]; then
  echo "Invalid remote configurations"
  echo "Usage: $0 [Host] [Path]"
  echo "  - Host: [user]@[IP address]"
  echo "  - Path: Remote dir path to place scripts"
  echo "Example: $0 player@192.168.0.100 /home/player/network"
  exit 1
fi

# Check connectivity
# timeout 3 ssh -T -q "$REMOTE_CONN" exit
# if [ $? -ne 0 ]; then
#   echo "Unable to connect $REMOTE_CONN via SSH"
#   echo "Make sure you've set the credentials right"
#   exit 1
# fi

# Make destination directory
ssh "$REMOTE_CONN" "/bin/sh -c 'mkdir -p $REMOTE_PATH'"
if [ $? -ne 0 ]; then
  echo "Failed: mkdir $REMOTE_PATH"
  echo "Check permissions"
  exit 1
fi

# Copy files to remote host
files_to_copy=(
  "configure_proxy_docker.py"
  "set_iptables_rules.sh"
  "settings.yml"
  "scripts"
  "src"
  "get-flag.py"
  "get_flag
)

for file in "${files_to_copy[@]}"; do
  scp -r "$file" "$REMOTE_CONN:$REMOTE_PATH/$file"
done