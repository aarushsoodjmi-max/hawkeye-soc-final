#!/bin/bash

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$ROOT/backend"

echo "🦅 Starting HawkEye SOC..."

# Backend Python
cd "$BACKEND"

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python -m venv venv
fi

source venv/bin/activate

echo "Installing backend dependencies..."
pip install -q -r requirements.txt

echo "Starting FastAPI backend..."
uvicorn app.main:app --host 0.0.0.0 --port 8001 > "$ROOT/backend.log" 2>&1 &
BACKEND_PID=$!

# Give backend time to start
sleep 3

# Frontend
cd "$ROOT"

if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

echo "Starting frontend..."
npm run dev -- --host 0.0.0.0 > "$ROOT/frontend.log" 2>&1 &
FRONTEND_PID=$!

sleep 5

echo ""
echo "🦅 HawkEye SOC is running!"
echo "Frontend: http://localhost:3000"
echo "Backend:  http://localhost:8001"
echo "API Docs: http://localhost:8001/docs"
echo ""

# Open browser
if command -v xdg-open >/dev/null 2>&1; then
    xdg-open http://localhost:3000 >/dev/null 2>&1 &
elif command -v firefox >/dev/null 2>&1; then
    firefox http://localhost:3000 >/dev/null 2>&1 &
fi

# Stop both servers when Ctrl+C
cleanup() {
    echo ""
    echo "Stopping HawkEye SOC..."
    kill "$FRONTEND_PID" "$BACKEND_PID" 2>/dev/null || true
    exit 0
}

trap cleanup INT TERM

wait
