import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

DB_NAME = 'users.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Create Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')

    # Create Messages table
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            alias TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

# ---------------------- AUTH ----------------------
@app.route("/auth", methods=["POST"])
def auth():
    data = request.get_json()
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    action = data.get("action", "").lower()

    if not username:
        return jsonify(success=False, error="Username is required."), 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if action == "check":
        return jsonify(success=True, taken=bool(row))

    elif action == "submit":
        if row:
            # Login
            if not password:
                return jsonify(success=False, error="Password is required."), 400
            if check_password_hash(row[0], password):
                return jsonify(success=True, message="Logged in.")
            else:
                return jsonify(success=False, error="Incorrect password."), 401
        else:
            # Register
            if not password:
                return jsonify(success=False, error="Password is required to register."), 400
            password_hash = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            return jsonify(success=True, message="Account created.")

    return jsonify(success=False, error="Unknown action."), 400

# ---------------------- SEND MESSAGE ----------------------
@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json()

    sender = data.get("from", "").strip().lower()
    recipient = data.get("to", "").strip().lower()
    alias = data.get("alias", "").strip()
    content = data.get("content", "").strip()

    if not all([sender, recipient, alias, content]):
        return jsonify(success=False, error="All fields are required (from, to, alias, content)."), 400

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Validate sender
    c.execute("SELECT 1 FROM users WHERE username = ?", (sender,))
    if not c.fetchone():
        conn.close()
        return jsonify(success=False, error="Sender does not exist."), 404

    # Validate recipient
    c.execute("SELECT 1 FROM users WHERE username = ?", (recipient,))
    if not c.fetchone():
        conn.close()
        return jsonify(success=False, error="Recipient does not exist."), 404

    # Store message
    c.execute('''
        INSERT INTO messages (sender, recipient, alias, content)
        VALUES (?, ?, ?, ?)
    ''', (sender, recipient, alias, content))

    conn.commit()
    conn.close()
    return jsonify(success=True, message="Candygram sent!")

# ---------------------- INBOX ----------------------
@app.route("/inbox/<username>", methods=["GET"])
def inbox(username):
    username = username.strip().lower()
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute('''
        SELECT alias, content, timestamp
        FROM messages
        WHERE recipient = ?
        ORDER BY timestamp DESC
    ''', (username,))
    messages = c.fetchall()
    conn.close()

    result = [
        {
            "alias": row[0],
            "content": row[1],
            "timestamp": row[2]
        }
        for row in messages
    ]

    return jsonify(success=True, messages=result)

# ---------------------- RUN ----------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
