import os
import psycopg2
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Load PostgreSQL database URL from environment variable
DATABASE_URL = os.environ.get("DATABASE_URL")

# ---------------------- DB INIT ----------------------
def init_db():
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as c:
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
            ''')

            c.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    alias TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        conn.commit()

# ---------------------- AUTH ----------------------
@app.route("/auth", methods=["POST"])
def auth():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    action = data.get("action", "").lower()

    if not username:
        return jsonify(success=False, error="Username is required."), 400

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
                    password_hash = generate_password_hash(password)
                    try:
                        c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
                        conn.commit()
                        return jsonify(success=True, message="Account created.")
                    except:
                        return jsonify(success=False, error="Username already exists."), 400

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
        return jsonify(success=False, error="All fields are required (from, to, alias, content)."), 400

    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as c:
            c.execute("SELECT 1 FROM users WHERE username = %s", (sender,))
            if not c.fetchone():
                return jsonify(success=False, error="Sender does not exist."), 404

            c.execute("SELECT 1 FROM users WHERE username = %s", (recipient,))
            if not c.fetchone():
                return jsonify(success=False, error="Recipient does not exist."), 404

            c.execute('''
                INSERT INTO messages (sender, recipient, alias, content)
                VALUES (%s, %s, %s, %s)
            ''', (sender, recipient, alias, content))
            conn.commit()

    return jsonify(success=True, message="Candygram sent!")

# ---------------------- INBOX ----------------------
@app.route("/inbox/<username>", methods=["GET"])
def inbox(username):
    username = username.strip().lower()

    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as c:
            c.execute('''
                SELECT alias, content, timestamp
                FROM messages
                WHERE recipient = %s
                ORDER BY timestamp DESC
            ''', (username,))
            messages = c.fetchall()

    result = [
        {"alias": alias, "content": content, "timestamp": timestamp.isoformat()} for alias, content, timestamp in messages
    ]
    return jsonify(success=True, messages=result)

# ---------------------- ADMIN VIEW ----------------------
@app.route("/admin/messages", methods=["GET"])
def view_all_messages():
    secret = request.args.get("key")
    if secret != "remun2025":
        return jsonify({"error": "Unauthorized"}), 401

    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as c:
            c.execute('''
                SELECT id, sender, recipient, alias, content, timestamp
                FROM messages
                ORDER BY timestamp DESC
            ''')
            rows = c.fetchall()

    return jsonify(success=True, messages=[{
        "id": r[0], "sender": r[1], "recipient": r[2], "alias": r[3], "content": r[4], "timestamp": r[5].isoformat()
    } for r in rows])

# ---------------------- RUN ----------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
