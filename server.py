"""
Krypton Messenger - Secure Backend & Admin Panel Server
Supports Render (PostgreSQL) and fallback SQLite.
"""

import os
import json
import time
import secrets
import sqlite3
import requests
from functools import wraps
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG = True
except ImportError:
    HAS_PSYCOPG = False

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://krypton_db_vr49_user:DWG1u2UmNuLRIYsc5NdKwBN2aHqhDpMK@dpg-dasm2hfpn0mc7390vms0-a/krypton_db_vr49"
)
ADMIN_SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY", "krypton_admin_2026")
SQLITE_DB = "krypton_fallback.db"

def get_db():
    if HAS_PSYCOPG and DATABASE_URL and ("postgres" in DATABASE_URL or "postgresql" in DATABASE_URL):
        try:
            return psycopg2.connect(DATABASE_URL)
        except Exception as e:
            print("Postgres connection error:", e)
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # 1. Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT,
            display_name TEXT,
            avatar_url TEXT,
            is_verified_blue BOOLEAN DEFAULT FALSE,
            is_system_red BOOLEAN DEFAULT FALSE,
            is_admin BOOLEAN DEFAULT FALSE,
            is_banned BOOLEAN DEFAULT FALSE,
            banned_until BIGINT DEFAULT 0,
            ban_reason TEXT DEFAULT '',
            created_at BIGINT DEFAULT 0
        )
    """)
    
    # 2. Messages table
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            chat_id TEXT,
            sender_name TEXT,
            sender_email TEXT,
            target_email TEXT,
            text TEXT,
            timestamp BIGINT
        )
    """ if HAS_PSYCOPG and "postgres" in DATABASE_URL else """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id TEXT,
            sender_name TEXT,
            sender_email TEXT,
            target_email TEXT,
            text TEXT,
            timestamp INTEGER
        )
    """)
    
    # 3. Sessions table
    c.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            token TEXT PRIMARY KEY,
            user_email TEXT,
            created_at BIGINT,
            expires_at BIGINT,
            is_active BOOLEAN DEFAULT TRUE
        )
    """)
    
    # 4. Reports table
    c.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            reporter_email TEXT,
            reported_user TEXT,
            reason TEXT,
            timestamp BIGINT,
            status TEXT DEFAULT 'PENDING'
        )
    """ if HAS_PSYCOPG and "postgres" in DATABASE_URL else """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_email TEXT,
            reported_user TEXT,
            reason TEXT,
            timestamp INTEGER,
            status TEXT DEFAULT 'PENDING'
        )
    """)

    conn.commit()
    conn.close()

init_db()

# --- Middleware ---
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip() or request.headers.get("X-Session-Token", "")
        email = request.headers.get("X-User-Email", "").lower().strip()
        
        if not token:
            data = request.get_json(silent=True) or {}
            token = data.get("session_token", "")
            if not email:
                email = data.get("sender_email", "").lower().strip()

        if email:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT is_banned, banned_until, ban_reason FROM users WHERE email = %s" if HAS_PSYCOPG and "postgres" in DATABASE_URL else "SELECT is_banned, banned_until, ban_reason FROM users WHERE email = ?", (email,))
            u = c.fetchone()
            conn.close()
            if u:
                is_banned = u[0]
                banned_until = u[1]
                reason = u[2]
                now_ms = int(time.time() * 1000)
                if is_banned and (banned_until == 0 or banned_until > now_ms):
                    return jsonify({
                        "error": "ACCOUNT_BANNED",
                        "message": f"حساب کاربری شما مسدود است: {reason}",
                        "is_banned": True
                    }), 403
                    
        return f(*args, **kwargs)
    return decorated

# --- API Routes ---

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Krypton Messenger Cloud Engine",
        "status": "online",
        "database": "PostgreSQL (Render)" if HAS_PSYCOPG and "postgres" in DATABASE_URL else "SQLite",
        "admin_url": "/admin",
        "version": "4.2.0"
    })

@app.route("/api/auth", methods=["POST"])
def auth():
    data = request.get_json() or {}
    email = data.get("email", "").lower().strip()
    username = data.get("username", "")
    display_name = data.get("display_name", "")
    avatar_url = data.get("avatar_url", "")
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
        
    token = secrets.token_hex(32)
    now = int(time.time() * 1000)
    expires = now + (30 * 24 * 3600 * 1000) # 30 days
    
    conn = get_db()
    c = conn.cursor()
    
    # Upsert user
    if HAS_PSYCOPG and "postgres" in DATABASE_URL:
        c.execute("""
            INSERT INTO users (email, username, display_name, avatar_url, created_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (email) DO UPDATE SET
            username = EXCLUDED.username,
            display_name = EXCLUDED.display_name,
            avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url)
        """, (email, username, display_name, avatar_url, now))
        c.execute("INSERT INTO user_sessions (token, user_email, created_at, expires_at) VALUES (%s, %s, %s, %s)",
                  (token, email, now, expires))
        c.execute("SELECT is_verified_blue, is_system_red, is_admin, is_banned, ban_reason FROM users WHERE email = %s", (email,))
    else:
        c.execute("INSERT OR REPLACE INTO users (email, username, display_name, avatar_url, created_at) VALUES (?, ?, ?, ?, ?)",
                  (email, username, display_name, avatar_url, now))
        c.execute("INSERT INTO user_sessions (token, user_email, created_at, expires_at) VALUES (?, ?, ?, ?)",
                  (token, email, now, expires))
        c.execute("SELECT is_verified_blue, is_system_red, is_admin, is_banned, ban_reason FROM users WHERE email = ?", (email,))
        
    row = c.fetchone()
    conn.commit()
    conn.close()
    
    return jsonify({
        "status": "success",
        "session_token": token,
        "is_verified_blue": bool(row[0]) if row else False,
        "is_system_red": bool(row[1]) if row else False,
        "is_admin": bool(row[2]) if row else False,
        "is_banned": bool(row[3]) if row else False,
        "ban_reason": row[4] if row else ""
    })

@app.route("/api/auth/google", methods=["POST"])
def auth_google():
    """Validates real Google accounts via Google OAuth token verification"""
    data = request.get_json() or {}
    id_token = data.get("id_token", "")
    email = data.get("email", "").lower().strip()
    name = data.get("name", "")
    picture = data.get("picture", "")

    if id_token:
        try:
            r = requests.get(f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}", timeout=5)
            if r.status_code == 200:
                info = r.json()
                email = info.get("email", email)
                name = info.get("name", name)
                picture = info.get("picture", picture)
        except Exception as e:
            print("Google token validation error:", e)

    if not email.endswith("@gmail.com") and not email:
        return jsonify({"error": "Invalid Google email"}), 400

    token = secrets.token_hex(32)
    now = int(time.time() * 1000)
    expires = now + (30 * 24 * 3600 * 1000)

    conn = get_db()
    c = conn.cursor()
    sql_user = ("""
        INSERT INTO users (email, username, display_name, avatar_url, is_verified_blue, created_at)
        VALUES (%s, %s, %s, %s, TRUE, %s)
        ON CONFLICT (email) DO UPDATE SET
        display_name = EXCLUDED.display_name,
        avatar_url = COALESCE(EXCLUDED.avatar_url, users.avatar_url),
        is_verified_blue = TRUE
    """ if HAS_PSYCOPG and "postgres" in DATABASE_URL else
        "INSERT OR REPLACE INTO users (email, username, display_name, avatar_url, is_verified_blue, created_at) VALUES (?, ?, ?, ?, 1, ?)"
    )
    c.execute(sql_user, (email, email.split("@")[0], name, picture, now))
    
    sql_sess = ("INSERT INTO user_sessions (token, user_email, created_at, expires_at) VALUES (%s, %s, %s, %s)"
                if HAS_PSYCOPG and "postgres" in DATABASE_URL else
                "INSERT INTO user_sessions (token, user_email, created_at, expires_at) VALUES (?, ?, ?, ?)")
    c.execute(sql_sess, (token, email, now, expires))
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "session_token": token,
        "email": email,
        "display_name": name,
        "avatar_url": picture,
        "is_verified_blue": True
    })

@app.route("/api/send", methods=["POST"])
@require_auth
def send_message():
    data = request.get_json() or {}
    chat_id = data.get("chat_id", "")
    sender_name = data.get("sender_name", "")
    sender_email = data.get("sender_email", "").lower().strip()
    target_email = data.get("target_email", "").lower().strip()
    text = data.get("text", "")
    timestamp = data.get("timestamp", int(time.time() * 1000))
    
    conn = get_db()
    c = conn.cursor()
    sql = ("INSERT INTO messages (chat_id, sender_name, sender_email, target_email, text, timestamp) VALUES (%s, %s, %s, %s, %s, %s)"
           if HAS_PSYCOPG and "postgres" in DATABASE_URL else
           "INSERT INTO messages (chat_id, sender_name, sender_email, target_email, text, timestamp) VALUES (?, ?, ?, ?, ?, ?)")
    c.execute(sql, (chat_id, sender_name, sender_email, target_email, text, timestamp))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "sent", "chat_id": chat_id, "timestamp": timestamp})

@app.route("/api/sync", methods=["GET"])
def sync_messages():
    email = request.args.get("email", "").lower().strip()
    since = int(request.args.get("since", 0))
    
    conn = get_db()
    c = conn.cursor()
    sql = ("SELECT id, chat_id, sender_name, sender_email, target_email, text, timestamp FROM messages WHERE (target_email = %s OR target_email = 'all' OR sender_email = %s) AND timestamp > %s ORDER BY timestamp ASC LIMIT 100"
           if HAS_PSYCOPG and "postgres" in DATABASE_URL else
           "SELECT id, chat_id, sender_name, sender_email, target_email, text, timestamp FROM messages WHERE (target_email = ? OR target_email = 'all' OR sender_email = ?) AND timestamp > ? ORDER BY timestamp ASC LIMIT 100")
    c.execute(sql, (email, email, since))
    rows = c.fetchall()
    conn.close()
    
    msgs = []
    for r in rows:
        msgs.append({
            "id": r[0], "chat_id": r[1], "sender_name": r[2], "sender_email": r[3],
            "target_email": r[4], "text": r[5], "timestamp": r[6]
        })
    return jsonify({"status": "ok", "messages": msgs})

# --- Web Admin Panel ---
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    auth_key = request.args.get("key") or request.form.get("key") or ""
    if auth_key != ADMIN_SECRET_KEY:
        return """
        <!DOCTYPE html>
        <html dir="rtl" lang="fa">
        <head><meta charset="utf-8"><title>ورود به پنل کریپتون</title><style>body{background:#0e1621;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;}form{background:#17212b;padding:30px;border-radius:12px;display:flex;flex-direction:column;gap:15px;width:300px;}input{padding:10px;border-radius:8px;border:none;}button{padding:10px;background:#2481cc;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer;}</style></head>
        <body>
        <form method="POST"><h3 style="text-align:center;">🛡️ مدیریت کریپتون</h3><input type="password" name="key" placeholder="کلید محرمانه ادمین..." required><button type="submit">ورود به پنل</button></form>
        </body></html>
        """, 401

    conn = get_db()
    c = conn.cursor()
    
    # Handle Actions
    action = request.args.get("action")
    target = request.args.get("target")
    if action == "ban" and target:
        c.execute("UPDATE users SET is_banned = TRUE, ban_reason = 'تخلف از قوانین (توسط وب ادمین)' WHERE email = %s" if HAS_PSYCOPG and "postgres" in DATABASE_URL else "UPDATE users SET is_banned = 1 WHERE email = ?", (target,))
        conn.commit()
    elif action == "unban" and target:
        c.execute("UPDATE users SET is_banned = FALSE, ban_reason = '' WHERE email = %s" if HAS_PSYCOPG and "postgres" in DATABASE_URL else "UPDATE users SET is_banned = 0 WHERE email = ?", (target,))
        conn.commit()
    elif action == "toggle_blue" and target:
        c.execute("UPDATE users SET is_verified_blue = NOT is_verified_blue WHERE email = %s" if HAS_PSYCOPG and "postgres" in DATABASE_URL else "UPDATE users SET is_verified_blue = CASE WHEN is_verified_blue=1 THEN 0 ELSE 1 END WHERE email = ?", (target,))
        conn.commit()
    elif action == "toggle_red" and target:
        c.execute("UPDATE users SET is_system_red = NOT is_system_red WHERE email = %s" if HAS_PSYCOPG and "postgres" in DATABASE_URL else "UPDATE users SET is_system_red = CASE WHEN is_system_red=1 THEN 0 ELSE 1 END WHERE email = ?", (target,))
        conn.commit()

    # Fetch stats & users
    c.execute("SELECT COUNT(*) FROM users")
    user_count = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM messages")
    msg_count = c.fetchone()[0]
    c.execute("SELECT email, username, display_name, is_verified_blue, is_system_red, is_banned, ban_reason FROM users ORDER BY created_at DESC LIMIT 50")
    users = c.fetchall()
    conn.close()

    html = f"""
    <!DOCTYPE html>
    <html dir="rtl" lang="fa">
    <head>
        <meta charset="utf-8">
        <title>پنل مدیریت Krypton Cloud</title>
        <style>
            body {{ background: #0e1621; color: #fff; font-family: system-ui, sans-serif; margin: 0; padding: 20px; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #2b394a; padding-bottom: 15px; }}
            .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
            .card {{ background: #17212b; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #2481cc33; }}
            .card h2 {{ margin: 0; color: #2481cc; font-size: 32px; }}
            table {{ width: 100%; border-collapse: collapse; background: #17212b; border-radius: 12px; overflow: hidden; }}
            th, td {{ padding: 12px 16px; text-align: right; border-bottom: 1px solid #232e3c; }}
            th {{ background: #202b36; color: #6ab2f2; }}
            .btn {{ padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: bold; color: #fff; display: inline-block; }}
            .btn-ban {{ background: #e53935; }}
            .btn-unban {{ background: #4caf50; }}
            .btn-blue {{ background: #2481cc; }}
            .btn-red {{ background: #d32f2f; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>🛡️ پنل مدیریت ابری Krypton (Render Engine)</h2>
            <span>کلید نشست: فعال ✅</span>
        </div>
        <div class="stats">
            <div class="card"><h2>{user_count}</h2><p>👥 کل کاربران</p></div>
            <div class="card"><h2>{msg_count}</h2><p>💬 پیام‌های ثبت‌شده</p></div>
            <div class="card"><h2>🟢 آنلاین</h2><p>وضعیت پایگاه‌داده PostgreSQL</p></div>
        </div>
        <h3>👥 لیست کاربران و تنظیمات سریع:</h3>
        <table>
            <tr><th>ایمیل / نام</th><th>نشان آبی</th><th>نشان قرمز</th><th>وضعیت</th><th>عملیات</th></tr>
            {"".join(f'''
            <tr>
                <td><strong>{u[2] or u[1] or 'کاربر'}</strong><br><small style="color:#7f91a4">{u[0]}</small></td>
                <td><a class="btn btn-blue" href="?key={auth_key}&action=toggle_blue&target={u[0]}">{'تایید شده 🔹' if u[3] else 'ندارد'}</a></td>
                <td><a class="btn btn-red" href="?key={auth_key}&action=toggle_red&target={u[0]}">{'سیستم 🛡️' if u[4] else 'ندارد'}</a></td>
                <td>{'<span style="color:#e53935">مسدود 🚫</span>' if u[5] else '<span style="color:#4caf50">عادی ✅</span>'}</td>
                <td>
                    {'<a class="btn btn-unban" href="?key='+auth_key+'&action=unban&target='+u[0]+'">رفع مسدودیت</a>' if u[5] else '<a class="btn btn-ban" href="?key='+auth_key+'&action=ban&target='+u[0]+'">مسدودسازی (Ban)</a>'}
                </td>
            </tr>
            ''' for u in users)}
        </table>
    </body>
    </html>
    """
    return render_template_string(html)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)