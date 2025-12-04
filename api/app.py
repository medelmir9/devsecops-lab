from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Fixed: Use parameterized queries instead of f-strings
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    
    conn.close()
    
    if result:
        return {"status": "success", "user": username}
    return {"status": "error", "message": "Invalid credentials"}

if __name__ == "__main__":
    app.run()