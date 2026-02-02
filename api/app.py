from flask import Flask, request, jsonify, session, abort
import sqlite3
import os
import subprocess
import logging
import requests
import json
import html
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ---------------- CONFIG ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

DB_PATH = "database.db"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("ADMIN_PASSWORD", "change-me")
)

UPLOAD_DIR = "/tmp/uploads"
ALLOWED_API_DOMAINS = {"api.github.com", "httpbin.org"}

logging.basicConfig(level=logging.INFO)

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------- HELPERS ----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            abort(401)
        return f(*args, **kwargs)
    return wrapper

def get_db():
    return sqlite3.connect(DB_PATH)

def is_safe_url(url):
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.netloc in ALLOWED_API_DOMAINS

# ---------------- ROUTES ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if not data:
        abort(400)

    username = data.get("username")
    password = data.get("password")

    if (
        username == ADMIN_USERNAME
        and check_password_hash(ADMIN_PASSWORD_HASH, password)
    ):
        session["user"] = username
        logging.info("Admin logged in")
        return "Login success"

    return "Login failed", 401


@app.route("/create-ticket", methods=["POST"])
@login_required
def create_ticket():
    data = request.json
    title = data.get("title")
    description = data.get("description")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tickets(title, description) VALUES (?, ?)",
        (title, description),
    )
    conn.commit()
    conn.close()

    return "Ticket created"


@app.route("/search", methods=["GET"])
@login_required
def search():
    keyword = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM tickets WHERE title LIKE ?",
        (f"%{keyword}%",),
    )
    data = cursor.fetchall()
    conn.close()
    return jsonify(data)


@app.route("/ping", methods=["GET"])
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.check_output(
        ["ping", "-c", "1", host],
        stderr=subprocess.STDOUT,
        timeout=3,
        text=True,
    )
    return result


@app.route("/load-data", methods=["POST"])
@login_required
def load_data():
    data = request.json
    return jsonify(data)


@app.route("/external-api", methods=["GET"])
@login_required
def external_api():
    url = request.args.get("url")
    if not is_safe_url(url):
        abort(403)

    response = requests.get(url, timeout=5)
    return response.text


@app.route("/hello", methods=["GET"])
def hello():
    name = html.escape(request.args.get("name", "Guest"))
    return f"<h1>Hello {name}</h1>"


@app.route("/admin/delete", methods=["POST"])
@login_required
def delete_all():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tickets")
    conn.commit()
    conn.close()
    return "All tickets deleted"


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if not file:
        abort(400)

    filename = os.path.basename(file.filename)
    path = os.path.join(UPLOAD_DIR, filename)
    file.save(path)
    return "File uploaded"


@app.route("/config", methods=["GET"])
@login_required
def config():
    return {
        "db": DB_PATH
    }


# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
