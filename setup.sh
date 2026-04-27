#!/usr/bin/env bash
set -e

echo "=== IDOR Scanner Setup ==="

# 1. Copy .env if missing
if [ ! -f backend/.env ]; then
  cp .env.example backend/.env
  echo "[+] Created backend/.env from template — edit it with your OPENAI_API_KEY"
fi

# 2. Python backend
echo "[*] Setting up Python backend..."
cd backend
python -m venv venv 2>/dev/null || python3 -m venv venv
source venv/Scripts/activate 2>/dev/null || source venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
echo "[+] Backend ready"
cd ..

# 3. Install Playwright MCP server (npm)
echo "[*] Installing Playwright MCP server..."
npm install -g @playwright/mcp@latest
echo "[+] Playwright MCP installed"

# 4. React frontend
echo "[*] Setting up React frontend..."
cd frontend
npm install
echo "[+] Frontend ready"
cd ..

echo ""
echo "=== Setup complete ==="
echo ""
echo "To start:"
echo "  Terminal 1:  cd backend && source venv/Scripts/activate && python manage.py runserver"
echo "  Terminal 2:  cd frontend && npm run dev"
echo ""
echo "Then open http://localhost:3000"
