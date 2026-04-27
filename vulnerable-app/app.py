"""
VulnVault — intentionally vulnerable web app for IDOR Tester.

DO NOT DEPLOY. Every "secure" check here is deliberately broken so the
IDOR scanner has something interesting to find.

Bug map (see README.md for full details):
  GET    /api/notes/<id>        — horizontal IDOR (no owner check)
  PUT    /api/notes/<id>        — unauthorized modification
  DELETE /api/notes/<id>        — unauthorized deletion
  GET    /api/users/<id>        — profile data leak
  GET    /api/invoices/<id>     — billing data leak
  GET    /api/admin/users       — vertical privilege escalation (trusts client header)
  GET    /api/secure/notes/<id> — properly secured (control endpoint)
"""

import os
import sqlite3
from flask import (
    Flask, g, request, session, redirect, url_for,
    render_template, jsonify, abort,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vulnvault.db")

app = Flask(__name__)
app.secret_key = "vulnvault-demo-key-do-not-use-in-prod"


# ── DB helpers ──────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create schema and seed alice/bob/admin with notes + invoices."""
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        DROP TABLE IF EXISTS invoices;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            full_name TEXT NOT NULL,
            ssn TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            description TEXT NOT NULL,
            card_last4 TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
    """)

    users = [
        ("alice", "alicepass", "alice@example.com", "Alice Anderson", "111-22-3333", 0),
        ("bob",   "bobpass",   "bob@example.com",   "Bob Brown",      "444-55-6666", 0),
        ("admin", "adminpass", "admin@example.com", "Site Admin",     "999-99-9999", 1),
    ]
    db.executemany(
        "INSERT INTO users (username, password, email, full_name, ssn, is_admin) "
        "VALUES (?, ?, ?, ?, ?, ?)", users,
    )

    notes = [
        # alice (id=1)
        (1, "Alice's grocery list",   "milk, eggs, bread"),
        (1, "Alice's diary",          "Today I learned about IDOR."),
        (1, "Alice's API key",        "sk-alice-secret-9f2c"),
        # bob (id=2)
        (2, "Bob's todo",             "fix the leaky faucet"),
        (2, "Bob's password hint",    "first dog's name + birth year"),
        # admin (id=3)
        (3, "Server credentials",     "root / hunter2"),
    ]
    db.executemany(
        "INSERT INTO notes (owner_id, title, content) VALUES (?, ?, ?)", notes,
    )

    invoices = [
        (1, 49.99,  "Pro plan — March",       "4242"),
        (1, 49.99,  "Pro plan — April",       "4242"),
        (2, 199.00, "Enterprise plan — Q1",   "5555"),
        (3, 0.00,   "Internal — admin comp",  "0000"),
    ]
    db.executemany(
        "INSERT INTO invoices (owner_id, amount, description, card_last4) "
        "VALUES (?, ?, ?, ?)", invoices,
    )

    db.commit()
    db.close()


# ── Auth ────────────────────────────────────────────────────────────────

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute(
        "SELECT * FROM users WHERE id = ?", (uid,),
    ).fetchone()


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


# ── Pages ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        if row:
            session["user_id"] = row["id"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    db = get_db()
    notes = db.execute(
        "SELECT id, title FROM notes WHERE owner_id = ?", (user["id"],),
    ).fetchall()
    invoices = db.execute(
        "SELECT id, amount, description FROM invoices WHERE owner_id = ?",
        (user["id"],),
    ).fetchall()
    return render_template(
        "dashboard.html", user=user, notes=notes, invoices=invoices,
    )


# ── API: Notes ──────────────────────────────────────────────────────────

@app.route("/api/notes/<int:note_id>", methods=["GET"])
@login_required
def get_note(note_id):
    """BUG: horizontal IDOR — does not check owner_id against session user."""
    row = get_db().execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@login_required
def update_note(note_id):
    """BUG: unauthorized modification — any logged-in user can edit any note."""
    data = request.get_json(silent=True) or {}
    db = get_db()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    db.execute(
        "UPDATE notes SET title = ?, content = ? WHERE id = ?",
        (data.get("title", row["title"]), data.get("content", row["content"]), note_id),
    )
    db.commit()
    updated = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return jsonify(dict(updated))


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    """BUG: unauthorized deletion — any logged-in user can delete any note."""
    db = get_db()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return jsonify({"deleted": note_id})


@app.route("/api/notes", methods=["GET"])
@login_required
def list_my_notes():
    user = current_user()
    rows = get_db().execute(
        "SELECT id, title FROM notes WHERE owner_id = ?", (user["id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── API: Users (profile leak) ───────────────────────────────────────────

@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
def get_user(user_id):
    """BUG: profile data leak — returns email, full name, SSN of any user."""
    row = get_db().execute(
        "SELECT id, username, email, full_name, ssn, is_admin FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ── API: Invoices ───────────────────────────────────────────────────────

@app.route("/api/invoices/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice(invoice_id):
    """BUG: billing data leak — exposes other users' invoices and card_last4."""
    row = get_db().execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ── API: Admin (vertical) ───────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    """
    BUG: vertical privilege escalation — checks an attacker-controlled
    header instead of the server-side session role.
    """
    if request.headers.get("X-Admin") != "true":
        return jsonify({"error": "forbidden"}), 403
    rows = get_db().execute(
        "SELECT id, username, email, full_name, ssn, is_admin FROM users",
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── API: Secure control endpoint ────────────────────────────────────────

@app.route("/api/secure/notes/<int:note_id>", methods=["GET"])
@login_required
def get_note_secure(note_id):
    """Properly secured: enforces owner_id == session user_id."""
    user = current_user()
    row = get_db().execute(
        "SELECT * FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user["id"]),
    ).fetchone()
    if not row:
        return jsonify({"error": "not found or forbidden"}), 404
    return jsonify(dict(row))


# ── Entry point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
