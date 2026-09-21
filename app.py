from flask import Flask, request, jsonify, render_template_string, redirect, session
import sqlite3
import secrets
import string
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DB = "keys.db"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            expiry TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created TEXT NOT NULL
        )
    """)
    con.commit()
    return con


def logged_in():
    return session.get("admin") is True


LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Key Manager</title>

<style>
body {
    background:#0d1117;
    color:white;
    font-family:Arial;
    display:flex;
    justify-content:center;
    align-items:center;
    min-height:100vh;
    margin:0;
}

.box {
    background:#161b22;
    padding:30px;
    border-radius:15px;
    width:320px;
}

.login-image {
    display:block;
    width:60%;
    height:150px;
    object-fit:cover;
    object-position:center 18%;
    margin:12px auto 20px auto;
    border-radius:10px;
}

input, button {
    box-sizing:border-box;
    width:100%;
    padding:13px;
    margin-top:10px;
    border-radius:8px;
    border:1px solid #30363d;
}

input {
    background:#0d1117;
    color:white;
}

button {
    background:#238636;
    color:white;
    border:0;
    font-weight:bold;
}

.error {
    color:#ff6b6b;
}
</style>
</head>

<body>

<div class="box">

<h2>Key Manager</h2>

<img
    class="login-image"
    src="/image"
    alt="Key Manager"
>

<p>Admin Login</p>

{% if error %}
<p class="error">{{ error }}</p>
{% endif %}

<form method="POST">
<input
    type="password"
    name="password"
    placeholder="Password"
    required
>

<button type="submit">Login</button>
</form>

</div>

</body>
</html>
"""


PANEL_HTML = """
<!DOCTYPE html>
<html>
<head>

<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Key Manager</title>

<style>

body {
    background:#0d1117;
    color:#fff;
    font-family:Arial;
    margin:0;
    padding:20px;
}

.container {
    max-width:900px;
    margin:auto;
}

.card {
    background:#161b22;
    border:1px solid #30363d;
    border-radius:12px;
    padding:18px;
    margin-bottom:18px;
}

input, button {
    padding:10px;
    border-radius:7px;
    border:1px solid #30363d;
    margin:4px;
}

input {
    background:#0d1117;
    color:white;
}

button {
    background:#238636;
    color:white;
    cursor:pointer;
}

.red {
    background:#da3633;
}

.orange {
    background:#9e6a03;
}

.blue {
    background:#1f6feb;
}

table {
    width:100%;
    border-collapse:collapse;
}

th, td {
    padding:10px;
    border-bottom:1px solid #30363d;
    text-align:left;
}

.active {
    color:#3fb950;
}

.banned {
    color:#f85149;
}

a {
    color:#58a6ff;
}

</style>

</head>

<body>

<div class="container">

<h1>Key Manager</h1>

<p>
<a href="/logout">Logout</a>
</p>


<div class="card">

<h3>Generate Key</h3>

<form action="/generate" method="POST">

<input
    type="number"
    name="days"
    value="30"
    min="1"
    required
>

<button type="submit">
Generate
</button>

</form>

</div>


<div class="card">

<h3>Add Custom Key</h3>

<form action="/add" method="POST">

<input
    name="key"
    placeholder="Custom key"
    required
>

<input
    type="number"
    name="days"
    value="30"
    min="1"
    required
>

<button type="submit">
Add Key
</button>

</form>

</div>


<div class="card">

<h3>Keys</h3>

<table>

<tr>
<th>Key</th>
<th>Expiry</th>
<th>Status</th>
<th>Actions</th>
</tr>

{% for k in keys %}

<tr>

<td>
{{ k["key"] }}
</td>

<td>
{{ k["expiry"] }}
</td>

<td>

{% if k["active"] %}

<span class="active">
ACTIVE
</span>

{% else %}

<span class="banned">
BANNED
</span>

{% endif %}

</td>


<td>

{% if k["active"] %}

<form
    action="/ban/{{ k['key'] }}"
    method="POST"
    style="display:inline"
>

<button class="orange">
Ban
</button>

</form>

{% else %}

<form
    action="/unban/{{ k['key'] }}"
    method="POST"
    style="display:inline"
>

<button class="blue">
Unban
</button>

</form>

{% endif %}


<form
    action="/delete/{{ k['key'] }}"
    method="POST"
    style="display:inline"
>

<button class="red">
Delete
</button>

</form>

</td>

</tr>

{% endfor %}

</table>

</div>

</div>

</body>
</html>
"""


@app.route("/image")
def image():
    from flask import send_from_directory

    return send_from_directory(
        os.path.dirname(os.path.abspath(__file__)),
        "-5877288279722364578_121.jpg"
    )


@app.route("/", methods=["GET", "POST"])
def home():

    if not logged_in():

        error = None

        if request.method == "POST":

            password = request.form.get(
                "password",
                ""
            )

            if ADMIN_PASSWORD and secrets.compare_digest(
                password,
                ADMIN_PASSWORD
            ):
                session["admin"] = True
                return redirect("/")

            error = "Wrong password"

        return render_template_string(
            LOGIN_HTML,
            error=error
        )

    con = db()

    keys = con.execute(
        "SELECT * FROM keys ORDER BY created DESC"
    ).fetchall()

    con.close()

    return render_template_string(
        PANEL_HTML,
        keys=keys
    )


@app.route("/generate", methods=["POST"])
def generate():

    if not logged_in():
        return redirect("/")

    try:
        days = max(
            1,
            int(request.form.get("days", 30))
        )

    except ValueError:
        days = 30

    alphabet = (
        string.ascii_uppercase
        + string.digits
    )

    con = db()

    while True:

        key = "".join(
            secrets.choice(alphabet)
            for _ in range(12)
        )

        exists = con.execute(
            "SELECT 1 FROM keys WHERE key=?",
            (key,)
        ).fetchone()

        if not exists:
            break

    expiry = (
        datetime.utcnow()
        + timedelta(days=days)
    ).isoformat()

    created = datetime.utcnow().isoformat()

    con.execute(
        """
        INSERT INTO keys
        (key, expiry, active, created)
        VALUES (?, ?, 1, ?)
        """,
        (
            key,
            expiry,
            created
        )
    )

    con.commit()
    con.close()

    return redirect("/")


@app.route("/add", methods=["POST"])
def add_key():

    if not logged_in():
        return redirect("/")

    key = request.form.get(
        "key",
        ""
    ).strip().upper()

    if not key:
        return redirect("/")

    try:

        days = max(
            1,
            int(request.form.get("days", 30))
        )

    except ValueError:
        days = 30

    expiry = (
        datetime.utcnow()
        + timedelta(days=days)
    ).isoformat()

    created = datetime.utcnow().isoformat()

    con = db()

    con.execute(
        """
        INSERT OR REPLACE INTO keys
        (key, expiry, active, created)
        VALUES (?, ?, 1, ?)
        """,
        (
            key,
            expiry,
            created
        )
    )

    con.commit()
    con.close()

    return redirect("/")


@app.route("/ban/<key>", methods=["POST"])
def ban(key):

    if not logged_in():
        return redirect("/")

    con = db()

    con.execute(
        "UPDATE keys SET active=0 WHERE key=?",
        (key,)
    )

    con.commit()
    con.close()

    return redirect("/")


@app.route("/unban/<key>", methods=["POST"])
def unban(key):

    if not logged_in():
        return redirect("/")

    con = db()

    con.execute(
        "UPDATE keys SET active=1 WHERE key=?",
        (key,)
    )

    con.commit()
    con.close()

    return redirect("/")


@app.route("/delete/<key>", methods=["POST"])
def delete(key):

    if not logged_in():
        return redirect("/")

    con = db()

    con.execute(
        "DELETE FROM keys WHERE key=?",
        (key,)
    )

    con.commit()
    con.close()

    return redirect("/")


@app.route("/verify", methods=["POST"])
def verify():

    data = request.get_json(
        silent=True
    ) or {}

    key = str(
        data.get("key", "")
    ).strip().upper()

    if not key:
        return jsonify(valid=False)

    con = db()

    row = con.execute(
        "SELECT * FROM keys WHERE key=?",
        (key,)
    ).fetchone()

    con.close()

    if not row:
        return jsonify(valid=False)

    if not row["active"]:
        return jsonify(valid=False)

    try:
        expiry = datetime.fromisoformat(
            row["expiry"]
        )

    except ValueError:
        return jsonify(valid=False)

    if datetime.utcnow() >= expiry:
        return jsonify(valid=False)

    return jsonify(
        valid=True,
        expiry=row["expiry"]
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                10000
            )
        )
    )
