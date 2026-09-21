from flask import Flask, request, jsonify, render_template_string
import sqlite3
import secrets
import string
from datetime import datetime, timedelta

app = Flask(__name__)
DB = "keys.db"

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            expiry TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)
    con.commit()
    return con

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key = str(data.get("key", "")).strip().upper()

    con = db()
    row = con.execute(
        "SELECT * FROM keys WHERE key = ?", (key,)
    ).fetchone()
    con.close()

    if not row:
        return jsonify(valid=False)

    if not row["active"]:
        return jsonify(valid=False)

    try:
        if datetime.now() >= datetime.fromisoformat(row["expiry"]):
            return jsonify(valid=False)
    except Exception:
        return jsonify(valid=False)

    return jsonify(valid=True, expiry=row["expiry"])

@app.route("/")
def home():
    return jsonify(status="online")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
