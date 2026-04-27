@echo off
echo === IDOR Scanner Setup ===

REM 1. Copy .env if missing
if not exist backend\.env (
    copy .env.example backend\.env
    echo [+] Created backend\.env from template — edit it with your ANTHROPIC_API_KEY
)

REM 2. Python backend
echo [*] Setting up Python backend...
cd backend
python -m venv venv
call venv\Scripts\activate.bat
pip install -r requirements.txt
python manage.py migrate
echo [+] Backend ready
cd ..

REM 3. Install Playwright MCP server
echo [*] Installing Playwright MCP server...
call npm install -g @playwright/mcp@latest
echo [+] Playwright MCP installed

REM 4. React frontend
echo [*] Setting up React frontend...
cd frontend
call npm install
echo [+] Frontend ready
cd ..

echo.
echo === Setup complete ===
echo.
echo To start:
echo   Terminal 1:  cd backend ^&^& venv\Scripts\activate ^&^& python manage.py runserver
echo   Terminal 2:  cd frontend ^&^& npm run dev
echo.
echo Then open http://localhost:3000
