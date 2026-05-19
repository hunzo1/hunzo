import sqlite3
import os
from datetime import datetime
from config import Config

def get_db():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            is_verified INTEGER DEFAULT 0
        )
    """)

    # API keys table — encrypted storage
    c.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL DEFAULT 'groq',
            encrypted_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Checks history table
    c.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            code_snippet TEXT,
            code_language TEXT,
            trust_score INTEGER,
            risk_level TEXT,
            packages_status TEXT,
            logic_sound INTEGER,
            full_report TEXT,
            share_token TEXT UNIQUE,
            created_at TEXT NOT NULL
        )
    """)

    # Daily usage table
    c.execute("""
        CREATE TABLE IF NOT EXISTS daily_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            date TEXT NOT NULL,
            check_count INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

# ── User operations ──────────────────────────────────────
def create_user(email, password_hash):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email.lower(), password_hash, datetime.now().isoformat())
        )
        conn.commit()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower(),)
        ).fetchone()
        return dict(user)
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_email(email):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email.lower(),)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

# ── API Key operations ────────────────────────────────────
def save_api_key(user_id, encrypted_key, provider="groq"):
    conn = get_db()
    # Delete existing key for this provider
    conn.execute(
        "DELETE FROM api_keys WHERE user_id = ? AND provider = ?",
        (user_id, provider)
    )
    conn.execute(
        """INSERT INTO api_keys (user_id, provider, encrypted_key, created_at)
           VALUES (?, ?, ?, ?)""",
        (user_id, provider, encrypted_key, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def get_api_key(user_id, provider="groq"):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE user_id = ? AND provider = ?",
        (user_id, provider)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def update_api_key_last_used(user_id, provider="groq"):
    conn = get_db()
    conn.execute(
        "UPDATE api_keys SET last_used = ? WHERE user_id = ? AND provider = ?",
        (datetime.now().isoformat(), user_id, provider)
    )
    conn.commit()
    conn.close()

def delete_api_key(user_id, provider="groq"):
    conn = get_db()
    conn.execute(
        "DELETE FROM api_keys WHERE user_id = ? AND provider = ?",
        (user_id, provider)
    )
    conn.commit()
    conn.close()

# ── Checks operations ─────────────────────────────────────
def save_check(user_id, code, language, score, risk_level,
               packages_status, logic_sound, full_report, share_token):
    conn = get_db()
    conn.execute(
        """INSERT INTO checks
           (user_id, code_snippet, code_language, trust_score, risk_level,
            packages_status, logic_sound, full_report, share_token, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, code[:500], language, score, risk_level,
         packages_status, logic_sound, full_report, share_token,
         datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def get_user_checks(user_id, limit=50):
    conn = get_db()
    rows = conn.execute(
        """SELECT * FROM checks WHERE user_id = ?
           ORDER BY created_at DESC LIMIT ?""",
        (user_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_check_by_token(token):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM checks WHERE share_token = ?", (token,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_stats(user_id):
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) as count FROM checks WHERE user_id = ?",
        (user_id,)
    ).fetchone()["count"]

    avg_score = conn.execute(
        "SELECT AVG(trust_score) as avg FROM checks WHERE user_id = ?",
        (user_id,)
    ).fetchone()["avg"]

    today = datetime.now().strftime("%Y-%m-%d")
    today_count = conn.execute(
        """SELECT COUNT(*) as count FROM checks
           WHERE user_id = ? AND created_at LIKE ?""",
        (user_id, f"{today}%")
    ).fetchone()["count"]

    conn.close()
    return {
        "total_checks": total,
        "avg_score": round(avg_score) if avg_score else 0,
        "today_checks": today_count
    }

# ── Usage/Rate limiting ───────────────────────────────────
def get_daily_usage(user_id=None, ip=None):
    conn = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    if user_id:
        row = conn.execute(
            "SELECT * FROM daily_usage WHERE user_id = ? AND date = ?",
            (user_id, today)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM daily_usage WHERE ip_address = ? AND date = ?",
            (ip, today)
        ).fetchone()
    conn.close()
    return dict(row) if row else None

def increment_usage(user_id=None, ip=None):
    conn = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    existing = get_daily_usage(user_id, ip)
    if existing:
        if user_id:
            conn.execute(
                "UPDATE daily_usage SET check_count = check_count + 1 WHERE user_id = ? AND date = ?",
                (user_id, today)
            )
        else:
            conn.execute(
                "UPDATE daily_usage SET check_count = check_count + 1 WHERE ip_address = ? AND date = ?",
                (ip, today)
            )
    else:
        conn.execute(
            "INSERT INTO daily_usage (user_id, ip_address, date, check_count) VALUES (?, ?, ?, 1)",
            (user_id, ip, today)
        )
    conn.commit()
    conn.close()
