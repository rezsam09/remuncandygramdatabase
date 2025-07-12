import os
import psycopg2
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------- CONFIG ----------------------
app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("❌ DATABASE_URL environment variable is not set!")

# ---------------------- DB INIT ----------------------
def init_db():
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as c:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL
                    )
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS messages (
                        id SERIAL PRIMARY KEY,
                        sender TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        alias TEXT NOT NULL,
                        content TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
                print("✅ Database initialized.")
    except Exception as e:
        print("❌ Database initialization error:", e)

# ---------------------- AUTH ----------------------
@app.route("/auth", methods=["POST"])
def auth():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    action = data.get("action", "").lower()

    if not username:
        return jsonify(success=False, error="Username is required."), 400

    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as c:
                c.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
                row = c.fetchone()

                if action == "check":
                    return jsonify(success=True, taken=bool(row))

                elif action == "submit":
                    if row:
                        if not password:
                            return jsonify(success=False, error="Password is required."), 400
                        if check_password_hash(row[0], password):
                            return jsonify(success=True, message="Logged in.")
                        else:
                            return jsonify(success=False, error="Incorrect password."), 401
                    else:
                        if not password:
                            return jsonify(success=False, error="Password is required to register."), 400
                        hash_pw = generate_password_hash(password)
                        c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hash_pw))
                        conn.commit()
                        return jsonify(success=True, message="Account created.")
    except Exception as e:
        print("❌ /auth error:", e)
        return jsonify(success=False, error="Server error."), 500

    return jsonify(success=False, error="Unknown action."), 400

# ---------------------- SEND MESSAGE ----------------------
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json() or {}
    sender = data.get("from", "").strip().lower()
    recipient = data.get("to", "").strip().lower()
    alias = data.get("alias", "").strip()
    content = data.get("content", "").strip()

    if not all([sender, recipient, alias, content]):
        return jsonify(success=False, error="All fields are required."), 400

    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as c:
                c.execute("SELECT 1 FROM users WHERE username = %s", (sender,))
                if not c.fetchone():
                    return jsonify(success=False, error="Sender does not exist."), 404

                c.execute("SELECT 1 FROM users WHERE username = %s", (recipient,))
                if not c.fetchone():
                    return jsonify(success=False, error="Recipient does not exist."), 404

                c.execute("""
                    INSERT INTO messages (sender, recipient, alias, content)
                    VALUES (%s, %s, %s, %s)
                """, (sender, recipient, alias, content))
                conn.commit()

        return jsonify(success=True, message="Candygram sent!")
    except Exception as e:
        print("❌ /send error:", e)
        return jsonify(success=False, error="Failed to send message."), 500

# ---------------------- INBOX ----------------------
@app.route("/inbox/<username>", methods=["GET"])
def inbox(username):
    username = username.strip().lower()
    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as c:
                c.execute("""
                    SELECT alias, content, timestamp
                    FROM messages
                    WHERE recipient = %s
                    ORDER BY timestamp DESC
                """, (username,))
                rows = c.fetchall()

        messages = [
            {"alias": alias, "content": content, "timestamp": timestamp.isoformat()}
            for alias, content, timestamp in rows
        ]
        return jsonify(success=True, messages=messages)
    except Exception as e:
        print("❌ /inbox error:", e)
        return jsonify(success=False, error="Could not fetch inbox."), 500

# ---------------------- ADMIN VIEW ----------------------
@app.route("/admin/messages", methods=["GET"])
def view_all_messages():
    if request.args.get("key") != "remun2025":
        return jsonify(success=False, error="Unauthorized"), 401

    try:
        with psycopg2.connect(DATABASE_URL) as conn:
            with conn.cursor() as c:
                c.execute("""
                    SELECT id, sender, recipient, alias, content, timestamp
                    FROM messages
                    ORDER BY timestamp DESC
                """)
                rows = c.fetchall()

        messages = [{
            "id": row[0], "sender": row[1], "recipient": row[2],
            "alias": row[3], "content": row[4], "timestamp": row[5].isoformat()
        } for row in rows]

        return jsonify(success=True, messages=messages)
    except Exception as e:
        print("❌ /admin/messages error:", e)
        return jsonify(success=False, error="Failed to fetch messages."), 500

# ---------------------- RUN ----------------------
init_db()  # <-- ensure DB is initialized always

if __name__ == "__main__":
    app.run(debug=True)