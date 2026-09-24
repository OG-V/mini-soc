#!/bin/bash
# One-command launcher: brings up the Docker lab, starts the log collector,
# detection engine, API, and dashboard - each in the background with its
# own log file - then opens the dashboard in a browser. Ctrl+C stops
# everything cleanly.

set -e
cd "$(dirname "$0")"

mkdir -p .run

echo "Starting lab containers..."
docker compose up -d

echo "Starting log collector..."
(cd log-collector && source venv/bin/activate && python3 -u parser.py) > .run/parser.log 2>&1 &
PARSER_PID=$!

echo "Starting detection engine..."
(cd detection-engine && source venv/bin/activate && python3 -u detector.py) > .run/detector.log 2>&1 &
DETECTOR_PID=$!

echo "Starting API..."
(cd api && source venv/bin/activate && python3 -u -m uvicorn main:app --reload --port 8000) > .run/api.log 2>&1 &
API_PID=$!

echo "Starting dashboard..."
(cd dashboard && npm run dev) > .run/dashboard.log 2>&1 &
DASHBOARD_PID=$!

cleanup() {
    echo ""
    echo "Shutting down..."
    kill "$PARSER_PID" "$DETECTOR_PID" "$API_PID" "$DASHBOARD_PID" 2>/dev/null
    wait 2>/dev/null
    echo "Stopped. (Containers are still running - use 'docker compose down' to stop those too.)"
}
trap cleanup EXIT INT TERM

echo "Waiting for services to come up..."
sleep 5

URL="http://localhost:5173"
echo ""
echo "Mini SOC is running:"
echo "  Dashboard: $URL"
echo "  API docs:  http://localhost:8000/docs"
echo ""
echo "Logs: .run/*.log   |   Press Ctrl+C to stop"

# Best-effort auto-open across environments; falls back silently to just
# printing the URL above if none of these are available.
# WSL: appendWindowsPath is often disabled (see /etc/wsl.conf), so
# cmd.exe/wslview may not be on PATH even though interop works fine
# via full path - so that's checked first here.
CMD_EXE="/mnt/c/Windows/System32/cmd.exe"
if [ -x "$CMD_EXE" ]; then
    "$CMD_EXE" /c start "$URL" >/dev/null 2>&1 || true
elif command -v wslview >/dev/null 2>&1; then
    wslview "$URL" >/dev/null 2>&1 || true
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
    open "$URL" >/dev/null 2>&1 || true
fi

wait
