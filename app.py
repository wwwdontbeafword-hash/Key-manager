from flask import Flask, request, jsonify, render_template_string, redirect, session, send_from_directory
import sqlite3, secrets, string, os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = "keys.db"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

LOGIN_IMAGE = "-5877288279722364578_121.jpg"
PANEL_IMAGE = "meer.jpg"

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS keys(
        key TEXT PRIMARY KEY,
        expiry TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created TEXT NOT NULL
    )""")
    cols = {r["name"] for r in con.execute("PRAGMA table_info(keys)").fetchall()}
    migrations = {
        "max_devices": "ALTER TABLE keys ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1",
        "paused_seconds": "ALTER TABLE keys ADD COLUMN paused_seconds INTEGER",
        "stopped": "ALTER TABLE keys ADD COLUMN stopped INTEGER NOT NULL DEFAULT 0"
    }
    for name, sql in migrations.items():
        if name not in cols:
            con.execute(sql)
    con.execute("""CREATE TABLE IF NOT EXISTS key_devices(
        key TEXT NOT NULL,
        device_id TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        PRIMARY KEY(key, device_id)
    )""")
    con.commit()
    return con

def logged_in():
    return session.get("admin") is True

def seconds_left(row):
    if row["stopped"] and row["paused_seconds"] is not None:
        return max(0, int(row["paused_seconds"]))
    try:
        return max(0, int((datetime.fromisoformat(row["expiry"]) - datetime.utcnow()).total_seconds()))
    except Exception:
        return 0

def pretty_time(seconds):
    seconds=max(0,int(seconds))
    d,seconds=divmod(seconds,86400)
    h,seconds=divmod(seconds,3600)
    m,s=divmod(seconds,60)
    return f"{d}D-{h}h-{m}m-{s}s"

def duration_from_form():
    try: days=max(0,int(request.form.get("days",0)))
    except: days=0
    try: hours=max(0,int(request.form.get("hours",0)))
    except: hours=0
    if days==0 and hours==0: hours=1
    return timedelta(days=days,hours=hours),days,hours

def max_devices_from_form():
    try: n=int(request.form.get("max_devices",1))
    except: n=1
    return max(1,min(100,n))

def random_key(days,hours):
    # Exactly 25 characters total, always starts with Cheto.
    if days:
        token=f"{days}D"
    else:
        token=f"{hours}H"
    alphabet=string.ascii_uppercase+string.digits
    room=25-len("Cheto")-len(token)
    room=max(2,room)
    left=room//2
    right=room-left
    result="Cheto"+"".join(secrets.choice(alphabet) for _ in range(left))+token+"".join(secrets.choice(alphabet) for _ in range(right))
    return result[:25]

LOGIN_HTML=r"""
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Manager</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#0d1117;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;overflow:hidden}
.bg{position:fixed;inset:-15%;background:radial-gradient(circle at 20% 20%,#25144c88,transparent 28%),radial-gradient(circle at 80% 80%,#47121e66,transparent 30%);filter:blur(30px);animation:bg 7s ease-in-out infinite alternate}
@keyframes bg{to{transform:scale(1.12) rotate(4deg)}}.shell{position:relative;width:min(390px,91vw);padding:2px;border-radius:20px;background:linear-gradient(90deg,#ff335f,#754cff,#2dd4ff,#ff335f);background-size:250%;animation:border 5s linear infinite;box-shadow:0 0 50px #744cff33}
@keyframes border{to{background-position:250%}}.box{background:#161b22;border-radius:18px;padding:27px}.box h2{margin:0 0 12px;font-size:28px}
.avatar{width:60%;aspect-ratio:1/1;margin:0 auto 17px;border-radius:15px;overflow:hidden;border:1px solid #30394a;box-shadow:0 0 28px #704cff25;animation:float 3.2s ease-in-out infinite}
.avatar img{width:100%;height:100%;object-fit:cover}@keyframes float{50%{transform:translateY(-5px)}}p{color:#b8beca}
input,button{width:100%;padding:13px;margin-top:10px;border-radius:9px}input{background:#0d1117;color:#fff;border:1px solid #394150;outline:none}button{border:0;color:#fff;font-weight:800;background:linear-gradient(90deg,#633bff,#a53cff);cursor:pointer;transition:.2s}button:active{transform:scale(.97)}.error{color:#ff637d}
</style></head><body><div class="bg"></div><div class="shell"><div class="box">
<h2>Key Manager</h2><div class="avatar"><img src="/login-image" alt=""></div><p>Admin Login</p>
{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input type="password" name="password" placeholder="Password" required><button>Login</button></form>
</div></div></body></html>
"""

PANEL_HTML=r"""
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Key Manager</title>
<style>
*{box-sizing:border-box}:root{--bg:#03050b;--panel:#080c14;--line:#192131;--muted:#788198}
body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 0,#17113b55,transparent 27%),radial-gradient(circle at 95% 10%,#3c101c44,transparent 27%),var(--bg);color:#f6f7fb;font-family:Arial,sans-serif}
body:after{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(110deg,transparent 35%,#6647ff08 50%,transparent 65%);animation:sweep 7s linear infinite}@keyframes sweep{from{transform:translateX(-60%)}to{transform:translateX(60%)}}
.wrap{max-width:1180px;margin:auto;padding:24px 16px 70px}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #121827;padding-bottom:20px}.eyebrow{font-size:10px;letter-spacing:3px;color:#747c92}.title{font-size:30px;font-weight:900;margin-top:6px}.logout{color:#aeb5c5;text-decoration:none}
.hero-border,.motion-border{position:relative;margin-top:18px;padding:2px;border-radius:17px;overflow:hidden;background:#101624}
.hero-border:before,.motion-border:before{content:"";position:absolute;width:42%;height:240%;left:-20%;top:-70%;background:linear-gradient(90deg,transparent,#5b7cff,#9b5cff,transparent);animation:orbit 3.5s linear infinite;transform-origin:170% 50%}
@keyframes orbit{to{transform:rotate(360deg)}}.hero,.card{position:relative;z-index:1;background:#070b13;border-radius:15px}
.hero{overflow:hidden}.hero img{display:block;width:100%;height:auto;max-height:430px;object-fit:contain}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}.motion-border{margin-top:0}.card{height:100%;padding:22px}.card h3{margin:0 0 6px;font-size:19px}.hint{color:var(--muted);font-size:12px;margin-bottom:16px}
.fields{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px}.custom{grid-template-columns:1.4fr .65fr .65fr .7fr}
input,button{padding:12px;border-radius:9px;border:1px solid #20293a;font-size:13px}input{width:100%;background:#050810;color:#fff;outline:none}input:focus{border-color:#6757ff;box-shadow:0 0 0 3px #6757ff1c}
.primary{width:100%;margin-top:12px;border:0;color:#fff;font-weight:900;background:linear-gradient(90deg,#653cff,#ad37f5);box-shadow:0 8px 28px #6b3cff30;cursor:pointer;transition:.25s}.primary:hover{filter:brightness(1.15);transform:translateY(-1px)}
.keys{margin-top:20px;background:#060a12;border:1px solid var(--line);border-radius:16px;overflow:hidden}.keys-head{padding:21px;border-bottom:1px solid var(--line)}.keys-head h3{margin:0}
table{width:100%;border-collapse:collapse}th{padding:15px 18px;text-align:left;font-size:10px;letter-spacing:2px;color:#737c94}td{padding:16px 18px;border-top:1px solid #111827}
.keycell{display:flex;align-items:center;gap:12px;font-weight:800}.keyicon{width:42px;height:42px;flex:0 0 42px;border-radius:50%;display:grid;place-items:center;border:1px solid currentColor;box-shadow:0 0 18px currentColor}
.keyicon svg{width:20px;height:20px;fill:currentColor}.keyicon.on{color:#39e88b;background:#06331f}.keyicon.off{color:#ff536f;background:#3a0b16}
.status{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:7px 10px;font-size:10px;font-weight:900}.status.on{color:#42ec92;background:#07271c}.status.off{color:#ff617a;background:#2b0b14}.dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.exp{font-family:monospace;color:#cbd2e3;white-space:nowrap}.devices{color:#aab3c7;white-space:nowrap}
.action{display:inline-block;margin:2px}.action button{font-weight:800;cursor:pointer;background:#0a0e17}.stop button{color:#ffb642;border-color:#684612;background:#241807}.start button{color:#4ef09a;border-color:#17623e;background:#06251a}.delete button{color:#ff617a;border-color:#6e2032;background:#260a12}
@media(max-width:760px){.grid{grid-template-columns:1fr}.hero img{max-height:none}.fields{grid-template-columns:1fr 1fr}.custom{grid-template-columns:1fr 1fr}.custom input:first-child{grid-column:1/-1}.keys{overflow-x:auto}table{min-width:820px}.title{font-size:27px}}
</style></head><body><div class="wrap">
<div class="top"><div><div class="eyebrow">MIDNIGHT CONTROL</div><div class="title">Key Manager</div></div><a class="logout" href="/logout">Logout</a></div>
<div class="hero-border"><div class="hero"><img src="/meer.jpg" alt="meer"></div></div>

<div class="grid">
<div class="motion-border"><div class="card"><h3>Generate Key</h3><div class="hint">Random 25-character Cheto key with days, hours and device limit.</div>
<form action="/generate" method="POST"><div class="fields">
<input type="number" name="days" value="30" min="0" placeholder="Days">
<input type="number" name="hours" value="0" min="0" placeholder="Hours">
<input type="number" name="max_devices" value="1" min="1" max="100" placeholder="Devices">
</div><button class="primary">Generate Key</button></form></div></div>

<div class="motion-border"><div class="card"><h3>Add Custom Key</h3><div class="hint">Custom key with days, hours and up to 100 devices.</div>
<form action="/add" method="POST"><div class="custom fields">
<input name="key" placeholder="Custom key" required>
<input type="number" name="days" value="30" min="0" placeholder="Days">
<input type="number" name="hours" value="0" min="0" placeholder="Hours">
<input type="number" name="max_devices" value="1" min="1" max="100" placeholder="Devices">
</div><button class="primary">Add Key</button></form></div></div>
</div>

<div class="keys"><div class="keys-head"><h3>Access Keys</h3></div><table>
<thead><tr><th>NAME / KEY</th><th>TIME LEFT</th><th>DEVICES</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody>
{% for k in keys %}<tr>
<td><div class="keycell"><span class="keyicon {{'on' if k['state']=='ACTIVE' else 'off'}}">
<svg viewBox="0 0 24 24"><path d="M7.5 14A5.5 5.5 0 1 1 12.7 6.7l8.1 0v3h-2v2h-3v2h-3.1A5.48 5.48 0 0 1 7.5 14Zm0-3A2.5 2.5 0 1 0 7.5 6a2.5 2.5 0 0 0 0 5Z"/></svg>
</span><span>{{k["key"]}}</span></div></td>
<td class="exp" data-seconds="{{k['seconds']}}" data-running="{{1 if k['state']=='ACTIVE' else 0}}">{{k["remaining"]}}</td>
<td class="devices">{{k["used_devices"]}} / {{k["max_devices"]}}</td>
<td><span class="status {{'on' if k['state']=='ACTIVE' else 'off'}}"><i class="dot"></i>{{k["state"]}}</span></td>
<td>
{% if k["state"] == "ACTIVE" %}<form class="action stop" action="/stop/{{k['key']}}" method="POST"><button>Stop</button></form>
{% elif k["state"] == "STOPPED" %}<form class="action start" action="/start/{{k['key']}}" method="POST"><button>Start</button></form>{% endif %}
<form class="action delete" action="/delete/{{k['key']}}" method="POST"><button>Delete</button></form>
</td></tr>{% endfor %}
</tbody></table></div></div>
<script>
setInterval(()=>document.querySelectorAll("[data-seconds]").forEach(el=>{
 let s=parseInt(el.dataset.seconds||0); if(el.dataset.running==="1"&&s>0){s--;el.dataset.seconds=s}
 let d=Math.floor(s/86400);s%=86400;let h=Math.floor(s/3600);s%=3600;let m=Math.floor(s/60),x=s%60;
 el.textContent=`${d}D-${h}h-${m}m-${x}s`;
}),1000);
</script></body></html>
"""

@app.route("/meer.jpg")
def meer_image():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), PANEL_IMAGE)

@app.route("/login-image")
def login_image():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), LOGIN_IMAGE)

@app.route("/",methods=["GET","POST"])
def home():
    if not logged_in():
        error=None
        if request.method=="POST":
            password=request.form.get("password","")
            if ADMIN_PASSWORD and secrets.compare_digest(password,ADMIN_PASSWORD):
                session["admin"]=True
                return redirect("/")
            error="Wrong password"
        return render_template_string(LOGIN_HTML,error=error)

    con=db()
    rows=con.execute("SELECT * FROM keys ORDER BY created DESC").fetchall()
    items=[]
    for r in rows:
        x=dict(r); sec=seconds_left(r)
        if sec<=0: state="EXPIRED"
        elif r["stopped"]: state="STOPPED"
        elif r["active"]: state="ACTIVE"
        else: state="STOPPED"
        x["state"]=state
        x["seconds"]=sec
        x["remaining"]=pretty_time(sec)
        x["used_devices"]=con.execute("SELECT COUNT(*) c FROM key_devices WHERE key=?",(r["key"],)).fetchone()["c"]
        items.append(x)
    con.close()
    return render_template_string(PANEL_HTML,keys=items)

@app.route("/generate",methods=["POST"])
def generate():
    if not logged_in(): return redirect("/")
    duration,days,hours=duration_from_form()
    limit=max_devices_from_form()
    con=db()
    while True:
        key=random_key(days,hours)
        if not con.execute("SELECT 1 FROM keys WHERE key=?",(key,)).fetchone(): break
    now=datetime.utcnow()
    con.execute("INSERT INTO keys(key,expiry,active,created,max_devices,paused_seconds,stopped) VALUES(?,?,?,?,?,NULL,0)",
                (key,(now+duration).isoformat(),1,now.isoformat(),limit))
    con.commit();con.close();return redirect("/")

@app.route("/add",methods=["POST"])
def add_key():
    if not logged_in(): return redirect("/")
    key=request.form.get("key","").strip().upper()
    if not key:return redirect("/")
    duration,_,_=duration_from_form();limit=max_devices_from_form();now=datetime.utcnow()
    con=db()
    con.execute("INSERT OR REPLACE INTO keys(key,expiry,active,created,max_devices,paused_seconds,stopped) VALUES(?,?,?,?,?,NULL,0)",
                (key,(now+duration).isoformat(),1,now.isoformat(),limit))
    con.execute("DELETE FROM key_devices WHERE key=?",(key,))
    con.commit();con.close();return redirect("/")

@app.route("/stop/<key>",methods=["POST"])
def stop(key):
    if not logged_in(): return redirect("/")
    con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if r:
        sec=seconds_left(r)
        con.execute("UPDATE keys SET active=0,stopped=1,paused_seconds=? WHERE key=?",(sec,key))
        con.commit()
    con.close();return redirect("/")

@app.route("/start/<key>",methods=["POST"])
def start(key):
    if not logged_in(): return redirect("/")
    con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if r:
        sec=max(0,int(r["paused_seconds"] or 0))
        con.execute("UPDATE keys SET active=1,stopped=0,paused_seconds=NULL,expiry=? WHERE key=?",
                    ((datetime.utcnow()+timedelta(seconds=sec)).isoformat(),key))
        con.commit()
    con.close();return redirect("/")

@app.route("/delete/<key>",methods=["POST"])
def delete(key):
    if not logged_in(): return redirect("/")
    con=db();con.execute("DELETE FROM key_devices WHERE key=?",(key,));con.execute("DELETE FROM keys WHERE key=?",(key,));con.commit();con.close()
    return redirect("/")

@app.route("/verify",methods=["POST"])
def verify():
    data=request.get_json(silent=True) or {}
    key=str(data.get("key","")).strip().upper()
    device_id=str(data.get("device_id","")).strip()
    if not key:return jsonify(valid=False,reason="invalid_key")
    con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if not r or not r["active"] or r["stopped"] or seconds_left(r)<=0:
        con.close();return jsonify(valid=False,reason="inactive")
    # Device limits are enforced when the client supplies a stable device_id.
    if device_id:
        known=con.execute("SELECT 1 FROM key_devices WHERE key=? AND device_id=?",(key,device_id)).fetchone()
        if not known:
            used=con.execute("SELECT COUNT(*) c FROM key_devices WHERE key=?",(key,)).fetchone()["c"]
            if used>=r["max_devices"]:
                con.close();return jsonify(valid=False,reason="device_limit")
            con.execute("INSERT INTO key_devices(key,device_id,first_seen) VALUES(?,?,?)",(key,device_id,datetime.utcnow().isoformat()))
            con.commit()
    con.close()
    return jsonify(valid=True,remaining_seconds=seconds_left(r),max_devices=r["max_devices"])

@app.route("/logout")
def logout():
    session.clear();return redirect("/")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",10000)))
