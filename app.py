from flask import Flask, request, jsonify, render_template_string, redirect, session, send_from_directory
import sqlite3, secrets, string, os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = "keys.db"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
IMAGE_FILE = "-5877288279722364578_121.jpg"

def db():
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY, expiry TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL)""")
    con.commit(); return con

def logged_in(): return session.get("admin") is True

LOGIN_HTML = """
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Manager</title><style>
*{box-sizing:border-box}body{margin:0;height:100vh;overflow:hidden;color:#f5f7fb;font-family:Arial,sans-serif;background:#05070b}
.bg{position:fixed;inset:-50px;background:radial-gradient(circle at 20% 20%,#351a6b55,transparent 30%),radial-gradient(circle at 80% 75%,#8d153955,transparent 30%),linear-gradient(135deg,#05070b,#0a0d14,#05070b);filter:blur(5px);animation:bg 8s ease-in-out infinite alternate}
@keyframes bg{to{transform:scale(1.09) translate(-1%,1%)}}
.wrap{position:relative;z-index:2;height:100%;display:flex;align-items:center;justify-content:center;padding:18px}
.shell{position:relative;width:min(390px,93vw);padding:1px;border-radius:24px;overflow:hidden;box-shadow:0 30px 100px #000}
.shell:before{content:"";position:absolute;width:115px;height:115px;left:-40px;top:-40px;background:linear-gradient(90deg,#ff174f,#ff7200,#8b5cf6,#00d9ff);filter:blur(7px);animation:worm 5s linear infinite}
@keyframes worm{0%{left:-40px;top:-40px}25%{left:calc(100% - 75px);top:-40px}50%{left:calc(100% - 75px);top:calc(100% - 75px)}75%{left:-40px;top:calc(100% - 75px)}100%{left:-40px;top:-40px}}
.card{position:relative;z-index:2;padding:28px;background:#090c12f5;border:1px solid #ffffff12;border-radius:23px;backdrop-filter:blur(22px)}
.kicker{font-size:10px;letter-spacing:3px;color:#697383}.card h1{margin:7px 0 3px;font-size:29px}.sub{margin:0 0 15px;color:#8a94a4;font-size:14px}
.avatar{display:block;width:60%;max-width:205px;aspect-ratio:1/1;object-fit:cover;object-position:50% 16%;margin:14px auto 20px;border-radius:18px;border:1px solid #ffffff18;box-shadow:0 15px 40px #0009}
input{width:100%;padding:14px;border-radius:11px;border:1px solid #252c37;background:#05070b;color:#fff;outline:none}input:focus{border-color:#765cff;box-shadow:0 0 0 3px #765cff20}
button{width:100%;padding:14px;margin-top:11px;border:0;border-radius:11px;color:white;font-weight:bold;background:linear-gradient(100deg,#6847ff,#8b5cf6,#ff315f);background-size:200%;animation:glow 4s linear infinite}@keyframes glow{to{background-position:200%}}
.err{color:#ff829a;background:#ff264f12;border:1px solid #ff264f28;padding:9px;border-radius:9px;font-size:13px;margin-bottom:10px}
.foot{text-align:center;color:#4e5868;font-size:10px;letter-spacing:1px;margin-top:16px}
</style></head><body><div class="bg"></div><div class="wrap"><div class="shell"><div class="card">
<div class="kicker">SECURE ACCESS</div><h1>Key Manager</h1><p class="sub">Admin Login</p>
<img class="avatar" src="/asset-image" alt="Key Manager">
{% if error %}<div class="err">{{error}}</div>{% endif %}
<form method="post"><input type="password" name="password" placeholder="Enter admin password" required><button>ENTER DASHBOARD</button></form>
<div class="foot">MIDNIGHT CONTROL SYSTEM</div></div></div></div></body></html>
"""

PANEL_HTML = """
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Key Manager</title><style>
*{box-sizing:border-box}body{margin:0;background:#05070b;color:#edf1f7;font-family:Arial,sans-serif;min-height:100vh;background-image:radial-gradient(circle at 10% 0%,#5638d522,transparent 28%),radial-gradient(circle at 90% 10%,#ff315511,transparent 25%)}
.container{max-width:1150px;margin:auto;padding:28px 18px}.top{display:flex;justify-content:space-between;align-items:center;padding:8px 3px 24px;border-bottom:1px solid #151a23;margin-bottom:20px}.top small{color:#697383;letter-spacing:2px;font-size:9px}.top h1{margin:5px 0 0;font-size:27px}.logout{color:#8e98a8;text-decoration:none;font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px}.card{background:#090c12;border:1px solid #191f29;border-radius:15px;padding:18px;margin-bottom:16px;box-shadow:0 18px 45px #0003}.card h3{margin:0 0 13px;font-size:15px}
input{background:#05070b;color:white;border:1px solid #232a35;border-radius:9px;padding:11px;outline:none}button{padding:11px 14px;border:1px solid #2a3140;border-radius:9px;background:#111620;color:#eef2f8;font-weight:bold}.primary{background:#6f4cff;border-color:#6f4cff}
.tablecard{padding:0;overflow:hidden}.tablehead{padding:18px 20px;border-bottom:1px solid #171d26}table{width:100%;border-collapse:collapse}th{padding:13px 18px;text-align:left;color:#687283;font-size:10px;letter-spacing:1.3px;text-transform:uppercase}td{padding:17px 18px;border-top:1px solid #131820;font-size:14px}.expiry{color:#9099a8;font-size:12px}
.badge{display:inline-flex;align-items:center;gap:7px;padding:6px 9px;border-radius:99px;font-size:10px;font-weight:bold}.badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}.active{color:#42d392;background:#42d39212}.banned{color:#ff657a;background:#ff657a12}
.actions{white-space:nowrap}.actions form{display:inline}.actions button{padding:8px 10px;margin:2px;font-size:11px}.warn{color:#ffbd55;border-color:#ffbd5533;background:#ffbd5511}.blue{color:#8da9ff;border-color:#8da9ff33;background:#8da9ff11}.danger{color:#ff6d84;border-color:#ff6d8433;background:#ff6d8411}
@media(max-width:700px){.grid{grid-template-columns:1fr}.tablecard{overflow-x:auto}table{min-width:700px}}
</style></head><body><div class="container"><div class="top"><div><small>MIDNIGHT CONTROL</small><h1>Key Manager</h1></div><a class="logout" href="/logout">Logout</a></div>
<div class="grid"><div class="card"><h3>Generate Key</h3><form action="/generate" method="post"><input type="number" name="days" value="30" min="1" required><button class="primary">Generate</button></form></div>
<div class="card"><h3>Add Custom Key</h3><form action="/add" method="post"><input name="key" placeholder="Custom key" required><input type="number" name="days" value="30" min="1" required><button class="primary">Add Key</button></form></div></div>
<div class="card tablecard"><div class="tablehead"><h3>Access Keys</h3></div><table><tr><th>Name / Key</th><th>Expiry</th><th>Status</th><th>Action</th></tr>
{% for k in keys %}<tr><td><b>{{k["key"]}}</b></td><td class="expiry">{{k["expiry"]}}</td><td>{% if k["active"] %}<span class="badge active">ACTIVE</span>{% else %}<span class="badge banned">BANNED</span>{% endif %}</td><td class="actions">
{% if k["active"] %}<form action="/ban/{{k['key']}}" method="post"><button class="warn">Ban</button></form>{% else %}<form action="/unban/{{k['key']}}" method="post"><button class="blue">Unban</button></form>{% endif %}
<form action="/delete/{{k['key']}}" method="post"><button class="danger">Delete</button></form></td></tr>{% endfor %}</table></div></div></body></html>
"""

@app.route("/asset-image")
def asset_image():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), IMAGE_FILE)

@app.route("/", methods=["GET","POST"])
def home():
    if not logged_in():
        error=None
        if request.method=="POST":
            password=request.form.get("password","")
            if ADMIN_PASSWORD and secrets.compare_digest(password,ADMIN_PASSWORD):
                session["admin"]=True; return redirect("/")
            error="Wrong password"
        return render_template_string(LOGIN_HTML,error=error)
    con=db(); keys=con.execute("SELECT * FROM keys ORDER BY created DESC").fetchall(); con.close()
    return render_template_string(PANEL_HTML,keys=keys)

@app.route("/generate",methods=["POST"])
def generate():
    if not logged_in(): return redirect("/")
    try: days=max(1,int(request.form.get("days",30)))
    except ValueError: days=30
    alphabet=string.ascii_uppercase+string.digits; con=db()
    while True:
        key="".join(secrets.choice(alphabet) for _ in range(12))
        if not con.execute("SELECT 1 FROM keys WHERE key=?",(key,)).fetchone(): break
    expiry=(datetime.utcnow()+timedelta(days=days)).isoformat(); created=datetime.utcnow().isoformat()
    con.execute("INSERT INTO keys (key,expiry,active,created) VALUES (?,?,1,?)",(key,expiry,created)); con.commit(); con.close(); return redirect("/")

@app.route("/add",methods=["POST"])
def add_key():
    if not logged_in(): return redirect("/")
    key=request.form.get("key","").strip().upper()
    if not key: return redirect("/")
    try: days=max(1,int(request.form.get("days",30)))
    except ValueError: days=30
    expiry=(datetime.utcnow()+timedelta(days=days)).isoformat(); created=datetime.utcnow().isoformat(); con=db()
    con.execute("INSERT OR REPLACE INTO keys (key,expiry,active,created) VALUES (?,?,1,?)",(key,expiry,created)); con.commit(); con.close(); return redirect("/")

@app.route("/ban/<key>",methods=["POST"])
def ban(key):
    if not logged_in(): return redirect("/")
    con=db(); con.execute("UPDATE keys SET active=0 WHERE key=?",(key,)); con.commit(); con.close(); return redirect("/")

@app.route("/unban/<key>",methods=["POST"])
def unban(key):
    if not logged_in(): return redirect("/")
    con=db(); con.execute("UPDATE keys SET active=1 WHERE key=?",(key,)); con.commit(); con.close(); return redirect("/")

@app.route("/delete/<key>",methods=["POST"])
def delete(key):
    if not logged_in(): return redirect("/")
    con=db(); con.execute("DELETE FROM keys WHERE key=?",(key,)); con.commit(); con.close(); return redirect("/")

@app.route("/verify",methods=["POST"])
def verify():
    data=request.get_json(silent=True) or {}; key=str(data.get("key","")).strip().upper()
    if not key: return jsonify(valid=False)
    con=db(); row=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone(); con.close()
    if not row or not row["active"]: return jsonify(valid=False)
    try: expiry=datetime.fromisoformat(row["expiry"])
    except ValueError: return jsonify(valid=False)
    if datetime.utcnow()>=expiry: return jsonify(valid=False)
    return jsonify(valid=True,expiry=row["expiry"])

@app.route("/logout")
def logout():
    session.clear(); return redirect("/")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",10000)))
