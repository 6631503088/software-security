"""Small Flask sample remediated as part of the Week 2 secure-SDLC lab."""
import ipaddress
import os
import sqlite3
import subprocess

import bcrypt
from flask import Flask, request

app = Flask(__name__)

# Credentials are injected by the deployment environment, never committed.
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    rows = con.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
    con.close()
    return str(rows)

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return "host must be an IP address", 400
    return subprocess.check_output(["ping", "-c", "1", host])

def store_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

if __name__ == "__main__":
    app.run(debug=False)
