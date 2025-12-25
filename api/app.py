from flask import Flask, request, jsonify
import sqlite3
import subprocess
import bcrypt
import os
import re

app = Flask(__name__)

DB_PATH = "users.db"

# ======================
# Utils
# ======================

def get_db():
    return sqlite3.connect(DB_PATH)

def validate_username(username: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9_]{3,30}", username))

def validate_host(host: str) -> bool:
    # Autorise IP ou hostname simple
    return bool(re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", host))


# ======================
# Routes
# ======================

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "").encode()

    if not validate_username(username):
        return jsonify({"error": "Invalid username"}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Requête paramétrée → anti SQL injection
    cursor.execute(
        "SELECT password FROM users WHERE username = ?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    stored_hash = row[0].encode()

    if bcrypt.checkpw(password, stored_hash):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/ping", methods=["POST"])
def ping():
    data = request.get_json(force=True)
    host = data.get("host", "")

    if not validate_host(host):
        return jsonify({"error": "Invalid host"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=True
        )
        return jsonify({"output": result.stdout})
    except subprocess.CalledProcessError:
        return jsonify({"error": "Ping failed"}), 500


@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json(force=True)
    pwd = data.get("password", "").encode()

    if len(pwd) < 8:
        return jsonify({"error": "Password too short"}), 400

    hashed = bcrypt.hashpw(pwd, bcrypt.gensalt())
    return jsonify({"bcrypt": hashed.decode()})


@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Secure DevSecOps API"})


# ======================
# Main
# ======================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
