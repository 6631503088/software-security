"""
Tiny sample web app for Week 1 threat modeling.
You will NOT exploit this in Week 1 — you will draw a data-flow diagram
and apply STRIDE to its components (web client, app, SQLite DB, /upload).
"""
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import sqlite3, os

app = Flask(__name__)
DB = "notes.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    con.commit(); con.close()

@app.route("/notes", methods=["GET", "POST"])
def notes():
    con = sqlite3.connect(DB)
    if request.method == "POST":
        owner = request.json.get("owner", "anon")
        body = request.json.get("body", "")
        con.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (owner, body))
        con.commit()
    rows = con.execute("SELECT id, owner, body FROM notes").fetchall()
    con.close()
    return jsonify(rows)

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    original_name = f.filename or ""
    safe_name = secure_filename(original_name)
    if not safe_name or original_name != os.path.basename(original_name) or safe_name != original_name:
        return jsonify(error="invalid filename"), 400
    f.save(os.path.join(UPLOAD_DIR, safe_name))
    return {"saved": safe_name}

@app.route("/files/<name>")
def files(name):
    return send_from_directory(UPLOAD_DIR, name)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
