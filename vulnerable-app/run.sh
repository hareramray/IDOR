#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
    echo "Creating venv..."
    python -m venv venv
    # shellcheck disable=SC1091
    source venv/Scripts/activate 2>/dev/null || source venv/bin/activate
    pip install -r requirements.txt
else
    # shellcheck disable=SC1091
    source venv/Scripts/activate 2>/dev/null || source venv/bin/activate
fi

if [ ! -f vulnvault.db ]; then
    echo "Seeding database..."
    python -c "from app import init_db; init_db()"
fi

echo
echo "VulnVault running at http://127.0.0.1:5050"
echo "Logins: alice/alicepass  bob/bobpass  admin/adminpass"
echo
python app.py
