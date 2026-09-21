from flask import Flask, request, jsonify, render_template_string, redirect, session, send_from_directory
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


def remaining(expiry_text):
    try:
        expiry = datetime.fromisoformat(expiry_text)
        seconds = max(0, int((expiry - datetime.utcnow()).total_seconds()))
    except Exception:
        return "0D-0h-0m-0s"

    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{days}D-{hours}h-{minutes}m-{seconds}s"


LOGIN_HTML = r"""
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Manager</title>
<style>
*{box-sizing:border-box} body{margin:0;min-height:100vh;background:#03050b;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;overflow:hidden}
body:before{content:"";position:fixed;inset:-25%;background:radial-gradient(circle at 25% 20%,#21104f66,transparent 28%),radial-gradient(circle at 80% 70%,#40101d55,transparent 30%);filter:blur(40px);animation:bg 8s ease-in-out infinite alternate}
@keyframes bg{to{transform:scale(1.12) rotate(3deg)}}
.box{position:relative;width:min(390px,90vw);padding:2px;border-radius:22px;background:linear-gradient(90deg,#ff315f,#ffba37,#43ff7c,#42c8ff,#8b5cff,#ff315f);background-size:300% 100%;animation:ring 5s linear infinite;box-shadow:0 0 45px #6b48ff33}
@keyframes ring{to{background-position:300% 0}}
.inner{background:#080b13ee;border-radius:20px;padding:28px;backdrop-filter:blur(18px)}
h2{margin:0 0 6px;font-size:29px}.sub{color:#838ba4;margin:0 0 18px}
input,button{width:100%;padding:14px;border-radius:11px;margin-top:10px;font-size:15px}
input{background:#050810;color:#fff;border:1px solid #252b3b;outline:none} input:focus{border-color:#7258ff;box-shadow:0 0 0 3px #7258ff22}
button{border:0;color:#fff;font-weight:800;background:linear-gradient(90deg,#733dff,#a54cff);box-shadow:0 8px 25px #7d45ff44}
.error{color:#ff647e}
</style>
</head>
<body>
<div class="box"><div class="inner">
<div style="font-size:11px;letter-spacing:3px;color:#737b95;margin-bottom:9px">MIDNIGHT CONTROL</div>
<h2>Key Manager</h2><p class="sub">Admin Login</p>
{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="password" name="password" placeholder="Password" required><button>LOGIN</button></form>
</div></div>
</body></html>
"""


PANEL_HTML = r"""
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Manager</title>
<style>
*{box-sizing:border-box} :root{--bg:#03050b;--panel:#080c14;--line:#1a2130;--muted:#747d96;--purple:#7447ff}
body{margin:0;background:radial-gradient(circle at 15% 0,#17113b55,transparent 26%),radial-gradient(circle at 95% 15%,#38101d44,transparent 28%),var(--bg);color:#f5f7ff;font-family:Arial,sans-serif;min-height:100vh}
.wrap{max-width:1180px;margin:auto;padding:26px 18px 70px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #111827;padding-bottom:22px;margin-bottom:24px}
.eyebrow{font-size:11px;letter-spacing:3px;color:#737b95}.title{font-size:31px;font-weight:900;margin-top:7px}.logout{color:#a8afc2;text-decoration:none}
.hero-shell,.rainbow{position:relative;padding:2px;border-radius:18px;background:linear-gradient(90deg,#ff315f,#ffb52f,#47f777,#42c8ff,#885cff,#ff315f);background-size:300% 100%;animation:ring 6s linear infinite;box-shadow:0 0 30px #673eff22}
@keyframes ring{to{background-position:300% 0}}
.hero{height:240px;border-radius:16px;overflow:hidden;background:#080c14}.hero img{width:100%;height:100%;object-fit:cover;display:block}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:20px}.rainbow{animation-duration:7s}.card{height:100%;background:linear-gradient(145deg,#090d16,#060910);border-radius:16px;padding:23px}
.card h3{margin:0 0 5px;font-size:20px}.hint{color:var(--muted);font-size:13px;margin-bottom:19px}
.fields{display:grid;grid-template-columns:1fr 1fr;gap:10px}.custom{grid-template-columns:1.4fr .7fr .7fr}
input,button{border-radius:10px;border:1px solid #20283a;padding:13px;font-size:14px}input{width:100%;background:#050810;color:#fff;outline:none}input:focus{border-color:#714dff;box-shadow:0 0 0 3px #714dff1f}
.primary{width:100%;margin-top:13px;color:#fff;border:0;font-weight:800;background:linear-gradient(90deg,#6a3dff,#9b43ff);box-shadow:0 8px 24px #6e3cff2b;cursor:pointer}
.keys{margin-top:22px;background:#060a12;border:1px solid var(--line);border-radius:17px;overflow:hidden}.keys-head{padding:22px 20px;border-bottom:1px solid var(--line)}.keys-head h3{margin:0;font-size:21px}
table{width:100%;border-collapse:collapse}th{font-size:11px;letter-spacing:2px;color:#737b95;text-align:left;padding:16px 18px}td{padding:17px 18px;border-top:1px solid #121827;vertical-align:middle}
.keycell{display:flex;align-items:center;gap:13px;font-weight:800}.keyorb{width:42px;height:42px;flex:0 0 42px;border-radius:50%;display:grid;place-items:center;font-size:20px;border:1px solid;box-shadow:0 0 18px currentColor}.keyorb.active{color:#36f38b;background:#08291d}.keyorb.bad{color:#ff526f;background:#2a0b14}
.status{display:inline-flex;gap:7px;align-items:center;padding:7px 11px;border-radius:999px;font-size:11px;font-weight:900}.status.active{color:#44ee94;background:#07251b}.status.bad{color:#ff6079;background:#2b0b14}.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.action{display:inline-block;margin:2px}.action button{cursor:pointer;font-weight:800;background:#0a0e17;color:#fff}.ban button{color:#ffb642;border-color:#6c4813;background:#241807}.unban button{color:#56a8ff;border-color:#205f9e;background:#071a2b}.delete button{color:#ff6079;border-color:#702033;background:#250a12}
.exp{font-family:monospace;color:#cbd2e5;white-space:nowrap}
@media(max-width:760px){.grid{grid-template-columns:1fr}.hero{height:185px}.custom,.fields{grid-template-columns:1fr 1fr}.custom input:first-child{grid-column:1/-1}.keys{overflow-x:auto}table{min-width:720px}.title{font-size:27px}}
</style>
</head>
<body><div class="wrap">
<div class="top"><div><div class="eyebrow">MIDNIGHT CONTROL</div><div class="title">Key Manager</div></div><a class="logout" href="/logout">Logout</a></div>

<div class="hero-shell"><div class="hero"><img src="/meer.jpg" alt="meer"></div></div>

<div class="grid">
<div class="rainbow"><div class="card">
<h3>⚡ Generate Key</h3><div class="hint">Create a new access key with a custom validity period.</div>
<form action="/generate" method="POST"><div class="fields">
<input type="number" name="days" value="30" min="0" placeholder="Days">
<input type="number" name="hours" value="0" min="0" max="23" placeholder="Hours">
</div><button class="primary">🔑 Generate Key</button></form>
</div></div>

<div class="rainbow"><div class="card">
<h3>✚ Add Custom Key</h3><div class="hint">Choose the key name, days and hours.</div>
<form action="/add" method="POST"><div class="fields custom">
<input name="key" placeholder="Custom key" required>
<input type="number" name="days" value="30" min="0" placeholder="Days">
<input type="number" name="hours" value="0" min="0" max="23" placeholder="Hours">
</div><button class="primary">＋ Add Key</button></form>
</div></div>
</div>

<div class="keys"><div class="keys-head"><h3>◉ Access Keys</h3></div>
<table><thead><tr><th>NAME / KEY</th><th>EXPIRY</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody>
{% for k in keys %}
{% set expired = k["expired"] %}
<tr>
<td><div class="keycell"><span class="keyorb {{'active' if k['active'] and not expired else 'bad'}}">🔑</span><span>{{k["key"]}}</span></div></td>
<td class="exp" data-expiry="{{k['expiry']}}">{{k["remaining"]}}</td>
<td>
{% if expired %}<span class="status bad"><i class="dot"></i>EXPIRED</span>
{% elif k["active"] %}<span class="status active"><i class="dot"></i>ACTIVE</span>
{% else %}<span class="status bad"><i class="dot"></i>BANNED</span>{% endif %}
</td>
<td>
{% if not expired %}
{% if k["active"] %}<form class="action ban" action="/ban/{{k['key']}}" method="POST"><button>Ban</button></form>
{% else %}<form class="action unban" action="/unban/{{k['key']}}" method="POST"><button>Unban</button></form>{% endif %}
{% endif %}
<form class="action delete" action="/delete/{{k['key']}}" method="POST"><button>Delete</button></form>
</td></tr>
{% endfor %}
</tbody></table></div>
</div>
<script>
function tick(){
 document.querySelectorAll("[data-expiry]").forEach(el=>{
  let t=new Date(el.dataset.expiry+"Z").getTime()-Date.now();
  t=Math.max(0,Math.floor(t/1000));
  let d=Math.floor(t/86400); t%=86400;
  let h=Math.floor(t/3600); t%=3600;
  let m=Math.floor(t/60),s=t%60;
  el.textContent=`${d}D-${h}h-${m}m-${s}s`;
 });
}
tick();setInterval(tick,1000);
</script>
</body></html>
"""


@app.route("/meer.jpg")
def meer_image():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "meer.jpg")


@app.route("/", methods=["GET", "POST"])
def home():
    if not logged_in():
        error = None
        if request.method == "POST":
            password = request.form.get("password", "")
            if ADMIN_PASSWORD and secrets.compare_digest(password, ADMIN_PASSWORD):
                session["admin"] = True
                return redirect("/")
            error = "Wrong password"
        return render_template_string(LOGIN_HTML, error=error)

    con = db()
    rows = con.execute("SELECT * FROM keys ORDER BY created DESC").fetchall()
    con.close()

    keys = []
    now = datetime.utcnow()
    for row in rows:
        item = dict(row)
        try:
            item["expired"] = now >= datetime.fromisoformat(item["expiry"])
        except Exception:
            item["expired"] = True
        item["remaining"] = remaining(item["expiry"])
        keys.append(item)
    return render_template_string(PANEL_HTML, keys=keys)


def get_duration():
    try:
        days = max(0, int(request.form.get("days", 0)))
    except ValueError:
        days = 0
    try:
        hours = max(0, int(request.form.get("hours", 0)))
    except ValueError:
        hours = 0
    # Allows hours as requested; 24+ hours are normalized naturally.
    if days == 0 and hours == 0:
        hours = 1
    return timedelta(days=days, hours=hours)


@app.route("/generate", methods=["POST"])
def generate():
    if not logged_in():
        return redirect("/")
    duration = get_duration()
    alphabet = string.ascii_uppercase + string.digits
    con = db()
    while True:
        key = "".join(secrets.choice(alphabet) for _ in range(12))
        if not con.execute("SELECT 1 FROM keys WHERE key=?", (key,)).fetchone():
            break
    expiry = (datetime.utcnow() + duration).isoformat()
    created = datetime.utcnow().isoformat()
    con.execute("INSERT INTO keys (key, expiry, active, created) VALUES (?, ?, 1, ?)",
                (key, expiry, created))
    con.commit(); con.close()
    return redirect("/")


@app.route("/add", methods=["POST"])
def add_key():
    if not logged_in():
        return redirect("/")
    key = request.form.get("key", "").strip().upper()
    if not key:
        return redirect("/")
    duration = get_duration()
    expiry = (datetime.utcnow() + duration).isoformat()
    created = datetime.utcnow().isoformat()
    con = db()
    con.execute("INSERT OR REPLACE INTO keys (key, expiry, active, created) VALUES (?, ?, 1, ?)",
                (key, expiry, created))
    con.commit(); con.close()
    return redirect("/")


@app.route("/ban/<key>", methods=["POST"])
def ban(key):
    if not logged_in(): return redirect("/")
    con=db(); con.execute("UPDATE keys SET active=0 WHERE key=?", (key,)); con.commit(); con.close()
    return redirect("/")


@app.route("/unban/<key>", methods=["POST"])
def unban(key):
    if not logged_in(): return redirect("/")
    con=db(); con.execute("UPDATE keys SET active=1 WHERE key=?", (key,)); con.commit(); con.close()
    return redirect("/")


@app.route("/delete/<key>", methods=["POST"])
def delete(key):
    if not logged_in(): return redirect("/")
    con=db(); con.execute("DELETE FROM keys WHERE key=?", (key,)); con.commit(); con.close()
    return redirect("/")


@app.route("/verify", methods=["POST"])
def verify():
    data=request.get_json(silent=True) or {}
    key=str(data.get("key","")).strip().upper()
    if not key: return jsonify(valid=False)
    con=db(); row=con.execute("SELECT * FROM keys WHERE key=?", (key,)).fetchone(); con.close()
    if not row or not row["active"]: return jsonify(valid=False)
    try: expiry=datetime.fromisoformat(row["expiry"])
    except ValueError: return jsonify(valid=False)
    if datetime.utcnow() >= expiry: return jsonify(valid=False)
    return jsonify(valid=True, expiry=row["expiry"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",10000)))
