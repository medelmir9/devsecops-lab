from flask import Flask, request, escape
import hashlib
import subprocess
import os

app = Flask(__name__)


ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change_me")
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    
    # Vérification sécurisée
    if username == "admin" and hash_password(password) == hash_password(ADMIN_PASSWORD):
        return "Logged in"
    return "Invalid credentials"

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    
    # Protection contre injection de commande
    try:
        result = subprocess.check_output(["ping", "-c", "1", host], text=True)
        return f"<pre>{result}</pre>"
    except subprocess.CalledProcessError:
        return "Ping failed"

@app.route("/hello")
def hello():
    name = request.args.get("name", "user")
    
    # Protection contre XSS
    return f"<h1>Hello {escape(name)}</h1>"

if __name__ == "__main__":
    # Désactiver debug en production
    app.run(debug=False)