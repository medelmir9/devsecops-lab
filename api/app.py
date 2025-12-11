from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import re
import json

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "fallback-dev-key")  # plus de hardcode


# ---------------------------
#  SECURE DATABASE FUNCTION
# ---------------------------
def get_db_connection():
    return sqlite3.connect("users.db")


# ---------------------------
#  LOGIN (Fix SQL Injection)
# ---------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = get_db_connection()
    cursor = conn.cursor()

    # PARAMETERIZED QUERY instead of f-string
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))

    result = cursor.fetchone()
    conn.close()

    if result:
        return {"status": "success", "user": username}
    return {"status": "error", "message": "Invalid credentials"}


# ---------------------------
#  PING (Fix Command Injection)
# ---------------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # simple whitelist regex
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        return {"error": "Invalid host"}, 400

    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", host],
            stderr=subprocess.STDOUT,
        )
        return {"output": output.decode()}
    except subprocess.CalledProcessError as e:
        return {"error": e.output.decode()}, 400


# ---------------------------
#  COMPUTE (Remove eval → Safe Eval)
# ---------------------------
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "")

    # Allowed math only
    if not re.match(r"^[0-9\+\-\*/\(\)\.\s]+$", expression):
        return {"error": "Invalid expression"}, 400

    try:
        # eval with a restricted env
        result = eval(expression, {"__builtins__": {}}, {})
        return {"result": result}
    except Exception:
        return {"error": "Bad expression"}, 400


# ---------------------------
#  HASH (Replace MD5 → SHA256)
# ---------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
    hashed = hashlib.sha256(pwd.encode()).hexdigest()
    return {"sha256": hashed}


# ---------------------------
#  READFILE (Prevent LFI)
# ---------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "")

    # allow only local safe folder
    base_dir = "files/"
    safe_path = os.path.abspath(os.path.join(base_dir, filename))

    if not safe_path.startswith(os.path.abspath(base_dir)):
        return {"error": "Invalid file path"}, 400

    if not os.path.exists(safe_path):
        return {"error": "File not found"}, 404

    with open(safe_path, "r") as f:
        content = f.read()

    return {"content": content}


# ---------------------------
#  Remove debug leakage
# ---------------------------
@app.route("/debug", methods=["GET"])
def debug():
    return {"debug": False}


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps secure API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
