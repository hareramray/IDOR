@echo off
setlocal
cd /d "%~dp0"

if not exist venv (
    echo Creating venv...
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call venv\Scripts\activate.bat
)

if not exist vulnvault.db (
    echo Seeding database...
    python -c "from app import init_db; init_db()"
)

echo.
echo VulnVault running at http://127.0.0.1:5050
echo Logins: alice/alicepass  bob/bobpass  admin/adminpass
echo.
python app.py
