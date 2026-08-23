#!/bin/bash

# Stop script for notty service
# Provides 4-second grace period for graceful shutdown
# Kills all related processes including Next.js server and child processes

echo "Stopping notty service and all related processes..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Function to find all notty-related process PIDs
find_notty_pids() {
  {
    # Find processes matching specific notty scripts
    ps aux | grep -E "node.*(server\.js|scripts/dev-ui\.mjs)" | grep -v grep | awk '{print $2}'

    # Find Next.js dev server processes
    ps aux | grep -E "node.*next.*dev" | grep -v grep | awk '{print $2}'

    # Find next-server processes (the actual Next.js server)
    ps aux | grep -E "next-server" | grep -v grep | awk '{print $2}'

    # Find any node processes running from the project directory
    ps aux | grep -E "node.*$PROJECT_DIR" | grep -v grep | awk '{print $2}'
  } | sort -u
}

# Function to find all child PIDs of a given PID
find_children() {
  local PARENT_PID=$1
  pgrep -P "$PARENT_PID" 2>/dev/null || true
}

# Function to kill a process and all its children
kill_process_tree() {
  local PID=$1
  local SIGNAL=$2

  # Find all children first
  local CHILDREN=$(find_children "$PID")

  # Recursively kill children
  for CHILD in $CHILDREN; do
    kill_process_tree "$CHILD" "$SIGNAL"
  done

  # Kill the process itself
  if kill -0 "$PID" 2>/dev/null; then
    kill "$SIGNAL" "$PID" 2>/dev/null || true
  fi
}

# Find PIDs of running notty processes
PIDS=$(find_notty_pids)

if [ -z "$PIDS" ]; then
  echo "No running notty processes found."
  exit 0
fi

echo "Found process(es): $PIDS"

# Send SIGTERM for graceful shutdown (including children)
for PID in $PIDS; do
  if kill -0 "$PID" 2>/dev/null; then
    echo "Sending SIGTERM to process $PID and its children..."
    kill_process_tree "$PID" "-TERM"
  fi
done

# Wait up to 4 seconds for graceful shutdown
echo "Waiting 4 seconds for graceful shutdown..."
WAITED=0
ALL_STOPPED=false

while [ $WAITED -lt 4 ]; do
  sleep 1
  WAITED=$((WAITED + 1))

  # Check if any processes are still running
  STILL_RUNNING=$(find_notty_pids)

  if [ -z "$STILL_RUNNING" ]; then
    echo "Service stopped gracefully."
    ALL_STOPPED=true
    break
  fi

  echo "Still running... ($WAITED/4s)"
done

# Force kill if still running after grace period
if [ "$ALL_STOPPED" = false ]; then
  STILL_RUNNING=$(find_notty_pids)

  if [ -n "$STILL_RUNNING" ]; then
    echo "Grace period expired. Force killing process(es) and their children..."
    for PID in $STILL_RUNNING; do
      if kill -0 "$PID" 2>/dev/null; then
        echo "Sending SIGKILL to process $PID and its children..."
        kill_process_tree "$PID" "-KILL"
      fi
    done
    echo "Service forcefully stopped."
  else
    echo "Service stopped gracefully."
  fi
fi

# Final cleanup: use pkill as a last resort for any stragglers
pkill -f "next.*dev" 2>/dev/null || true
pkill -f "next-server" 2>/dev/null || true

echo "All notty-related processes have been stopped."
