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
    con.execute("""CREATE TABLE IF NOT EXISTS server_state(
        id INTEGER PRIMARY KEY CHECK(id=1),
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        version INTEGER NOT NULL DEFAULT 0,
        updated TEXT NOT NULL
    )""")
    state_cols = {r["name"] for r in con.execute("PRAGMA table_info(server_state)").fetchall()}
    if "update_active" not in state_cols:
        con.execute("ALTER TABLE server_state ADD COLUMN update_active INTEGER NOT NULL DEFAULT 0")
    con.execute("""CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        detail TEXT NOT NULL,
        device TEXT NOT NULL,
        ip TEXT NOT NULL,
        created TEXT NOT NULL
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS log_cycle(
        id INTEGER PRIMARY KEY CHECK(id=1),
        reset_at TEXT NOT NULL
    )""")
    cycle = con.execute("SELECT reset_at FROM log_cycle WHERE id=1").fetchone()
    now_cycle = datetime.utcnow()
    if not cycle:
        con.execute("INSERT INTO log_cycle(id,reset_at) VALUES(1,?)",
                    ((now_cycle + timedelta(days=1)).isoformat(),))
    else:
        try:
            reset_at = datetime.fromisoformat(cycle["reset_at"])
        except Exception:
            reset_at = now_cycle
        if now_cycle >= reset_at:
            con.execute("DELETE FROM audit_logs")
            con.execute("UPDATE log_cycle SET reset_at=? WHERE id=1",
                        ((now_cycle + timedelta(days=1)).isoformat(),))
    if not con.execute("SELECT 1 FROM server_state WHERE id=1").fetchone():
        con.execute("INSERT INTO server_state(id,title,message,enabled,version,updated) VALUES(1,?,?,?,?,?)",
                    ("Error!","A new update is available. Please update to the latest version.",1,0,datetime.utcnow().isoformat()))
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

def client_device():
    ua=request.headers.get("User-Agent","Unknown device")
    if "Android" in ua: return "Android"
    if "iPhone" in ua or "iPad" in ua: return "iPhone / iPad"
    if "Windows" in ua: return "Windows"
    if "Macintosh" in ua: return "Mac"
    return ua[:55]

def add_log(con, action, detail):
    ip=(request.headers.get("X-Forwarded-For") or request.remote_addr or "Unknown").split(",")[0].strip()
    con.execute("INSERT INTO audit_logs(action,detail,device,ip,created) VALUES(?,?,?,?,?)",
                (action,detail,client_device(),ip,datetime.utcnow().isoformat()))

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

.toastStack{position:fixed;top:18px;left:50%;transform:translateX(-50%);z-index:100;width:min(430px,92vw);display:grid;gap:10px;pointer-events:none}.toast{position:relative;overflow:hidden;display:flex;gap:12px;align-items:center;padding:13px 14px;border:1px solid #293249;border-radius:14px;background:#090e18eF;backdrop-filter:blur(18px);box-shadow:0 18px 55px #000b,0 0 30px #7652ff25;animation:toastIn .48s cubic-bezier(.16,.9,.2,1),toastOut .45s ease 3.75s forwards}.toastIcon{width:42px;height:42px;flex:0 0 42px;border-radius:12px;display:grid;place-items:center;font-size:20px;background:linear-gradient(135deg,#5137d8,#a43ff1);box-shadow:0 0 20px #754cff55}.toast b{display:block}.toast small{display:block;color:#9da7ba;margin-top:3px}.toast:after{content:"";position:absolute;bottom:0;left:0;height:2px;width:100%;background:linear-gradient(90deg,#5d7cff,#c13cff,#3eea9b);animation:toastBar 4s linear forwards}@keyframes toastIn{from{opacity:0;transform:translateY(-28px) scale(.92)}}@keyframes toastOut{to{opacity:0;transform:translateY(-20px) scale(.96)}}@keyframes toastBar{to{width:0}}
.updateBadge{display:inline-flex;align-items:center;gap:8px;padding:8px 11px;border-radius:999px;font-size:11px;font-weight:900;border:1px solid #2c3448;background:#0b101a}.updateBadge.live{color:#ffc85a;border-color:#62491b;box-shadow:0 0 20px #ffb83d18}.updateBadge.clear{color:#5ceca0;border-color:#19573b}.miniDot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}.updateTop{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.cancelUpdate{width:100%;margin-top:9px;color:#ff7188;background:#260a13;border-color:#6b2031;font-weight:900;cursor:pointer}.logsPage{display:none;animation:sectionIn .5s ease}.logsPage.show{display:block}.logWrap{margin-top:22px;background:#070b13;border:1px solid #1b2434;border-radius:17px;overflow:hidden}.logHead{padding:22px;border-bottom:1px solid #182131}.logItem{display:grid;grid-template-columns:52px 1fr auto;gap:14px;align-items:center;padding:16px 20px;border-top:1px solid #121a28;transition:.25s}.logItem:hover{background:#0a101c;transform:translateX(3px)}.logIcon{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;font-size:19px;background:#10172a;border:1px solid #2b3650;box-shadow:0 0 18px #6b55ff18}.logTitle{font-weight:900}.logDetail{font-size:12px;color:#909bb0;margin-top:4px}.logMeta{text-align:right;font-size:11px;color:#747f95}.emptyLogs{text-align:center;color:#788198;padding:55px 20px}
.logTimer{margin:18px;padding:16px 18px;border:1px solid #28324a;border-radius:16px;background:linear-gradient(135deg,#0b1020,#070a12);position:relative;overflow:hidden;box-shadow:0 12px 40px #0006,0 0 24px #7658ff12}
.logTimer:before{content:"";position:absolute;inset:-2px;background:linear-gradient(90deg,transparent,#7658ff33,transparent);transform:translateX(-100%);animation:logSweep 3s linear infinite;pointer-events:none}
@keyframes logSweep{to{transform:translateX(100%)}}
.logTimerTop{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:15px}
.logTimerText b{display:block;font-size:13px;letter-spacing:.8px}.logTimerText small{display:block;color:#818ba1;margin-top:5px;line-height:1.4}
.logClock{display:flex;align-items:center;gap:6px;font-family:monospace}
.logClockBox{min-width:54px;padding:10px 8px;text-align:center;border-radius:11px;border:1px solid #39435f;background:#040813;color:#e6e2ff;font-size:18px;font-weight:900;box-shadow:inset 0 0 18px #7954ff12,0 0 15px #7954ff10}
.logClockSep{color:#706a96;font-weight:900}.logProgressTrack{position:relative;z-index:1;height:3px;margin-top:14px;border-radius:10px;background:#151b29;overflow:hidden}.logProgress{height:100%;width:100%;background:linear-gradient(90deg,#6758ff,#b548ff,#43e69b);box-shadow:0 0 10px #7954ff;transition:width 1s linear}
@media(max-width:600px){.logTimerTop{align-items:flex-start;flex-direction:column}.logClock{width:100%;justify-content:center}.logClockBox{min-width:49px}}
</style></head><body><div class="bg"></div><div class="shell"><div class="box">
<div style="display:flex;justify-content:flex-end;gap:6px;margin-bottom:8px">
<button type="button" onclick="setLang('en')" style="width:auto;margin:0;padding:6px 10px;font-size:11px">EN</button>
<button type="button" onclick="setLang('ar')" style="width:auto;margin:0;padding:6px 10px;font-size:11px">العربية</button>
</div><h2 data-en="Key Manager" data-ar="إدارة المفاتيح">Key Manager</h2><div class="avatar"><img src="/login-image" alt=""></div><p data-en="Admin Login" data-ar="تسجيل دخول المدير">Admin Login</p>
{% if error %}<p class="error">{{error}}</p>{% endif %}
<form method="POST"><input id="loginPass" type="password" name="password" placeholder="Password" required><button data-en="Login" data-ar="دخول">Login</button></form>
<script>
function setLang(l){localStorage.setItem("km_lang",l);document.documentElement.lang=l;document.documentElement.dir=l==="ar"?"rtl":"ltr";document.querySelectorAll("[data-"+l+"]").forEach(e=>e.textContent=e.dataset[l]);document.getElementById("loginPass").placeholder=l==="ar"?"كلمة المرور":"Password"}
setLang(localStorage.getItem("km_lang")||"en");
</script></div></div></body></html>
"""

PANEL_HTML=r"""
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Key Manager</title>
<style>
*{box-sizing:border-box}:root{--bg:#03050b;--panel:#080c14;--line:#192131;--muted:#788198;--purple:#7954ff}
html{scroll-behavior:smooth}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 0,#17113b55,transparent 27%),radial-gradient(circle at 95% 10%,#3c101c44,transparent 27%),var(--bg);color:#f6f7fb;font-family:Arial,sans-serif;overflow-x:hidden}
body:after{content:"";position:fixed;inset:0;pointer-events:none;background:linear-gradient(110deg,transparent 35%,#6647ff09 50%,transparent 65%);animation:sweep 6s linear infinite}@keyframes sweep{from{transform:translateX(-70%)}to{transform:translateX(70%)}}
.wrap{max-width:1180px;margin:auto;padding:24px 16px 70px;animation:pageIn .55s cubic-bezier(.2,.8,.2,1)}@keyframes pageIn{from{opacity:0;transform:translateY(13px) scale(.992)}}
.top{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid #121827;padding-bottom:20px}.eyebrow{font-size:10px;letter-spacing:3px;color:#747c92}.title{font-size:30px;font-weight:900;margin-top:6px}.topright{display:flex;align-items:flex-start;gap:12px}.logout{color:#aeb5c5;text-decoration:none;margin-top:8px}.menuBtn{width:42px;height:42px;border:1px solid #252d3d;background:#080c14;color:white;border-radius:12px;font-size:23px;cursor:pointer;transition:.25s}.menuBtn:hover{transform:rotate(5deg) scale(1.05);box-shadow:0 0 25px #7954ff35}
.lang{display:flex;gap:5px;margin-top:4px}.lang button{border:1px solid #252d3d;background:#080c14;color:#adb5c7;border-radius:8px;padding:6px 8px;cursor:pointer}
.drawerShade{position:fixed;inset:0;background:#0008;backdrop-filter:blur(4px);z-index:30;opacity:0;pointer-events:none;transition:.3s}.drawerShade.show{opacity:1;pointer-events:auto}
.drawer{position:fixed;z-index:31;top:0;right:0;width:min(25vw,330px);min-width:280px;height:100vh;background:#070b13;border-left:1px solid #242c3e;transform:translateX(105%);transition:.42s cubic-bezier(.2,.8,.2,1);padding:24px;box-shadow:-30px 0 70px #0009}.drawer.show{transform:none}.profile{text-align:center;padding:20px 0 25px;border-bottom:1px solid #192131}.avatar2{width:76px;height:76px;margin:auto;border-radius:50%;display:grid;place-items:center;font-size:30px;font-weight:900;background:linear-gradient(135deg,#6542ff,#bb38ee);box-shadow:0 0 30px #784cff55;animation:pulse 2.2s ease-in-out infinite}@keyframes pulse{50%{box-shadow:0 0 45px #a34cff88;transform:scale(1.035)}}.profile h3{margin:12px 0 0}.nav{margin-top:18px}.nav a{position:relative;display:flex;align-items:center;gap:10px;color:#c6ccda;text-decoration:none;padding:13px;border-radius:10px;margin:6px 0;transition:.25s}.nav a:hover{background:#101626;transform:translateX(-3px)}.nav a.active{background:#0b211a;color:#5cf0a2}.nav a.active:before{content:"";width:8px;height:8px;background:#42eb91;border-radius:50%;box-shadow:0 0 12px #42eb91}
.hero-border,.motion-border{position:relative;margin-top:18px;padding:2px;border-radius:17px;overflow:hidden;background:#101624}.hero-border:before,.motion-border:before{content:"";position:absolute;width:42%;height:240%;left:-20%;top:-70%;background:linear-gradient(90deg,transparent,#5b7cff,#9b5cff,transparent);animation:orbit 3.5s linear infinite;transform-origin:170% 50%}@keyframes orbit{to{transform:rotate(360deg)}}.hero,.card{position:relative;z-index:1;background:#070b13;border-radius:15px}.hero{overflow:hidden}.hero img{display:block;width:100%;height:auto;max-height:430px;object-fit:contain;transition:transform 7s ease}.hero:hover img{transform:scale(1.025)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}.motion-border{margin-top:0}.card{height:100%;padding:22px;transition:.3s}.card:hover{background:#090e18}.card h3{margin:0 0 6px;font-size:19px}.hint{color:var(--muted);font-size:12px;margin-bottom:16px}.fields{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px}.custom{grid-template-columns:1.4fr .65fr .65fr .7fr}
input,textarea,button{padding:12px;border-radius:9px;border:1px solid #20293a;font-size:13px}input,textarea{width:100%;background:#050810;color:#fff;outline:none;transition:.25s}input:focus,textarea:focus{border-color:#6757ff;box-shadow:0 0 0 3px #6757ff1c;transform:translateY(-1px)}.primary{width:100%;margin-top:12px;border:0;color:#fff;font-weight:900;background:linear-gradient(90deg,#653cff,#ad37f5);background-size:180%;box-shadow:0 8px 28px #6b3cff30;cursor:pointer;transition:.25s;animation:buttonGlow 3s linear infinite}@keyframes buttonGlow{50%{background-position:100%;box-shadow:0 8px 35px #9e3cff45}}.primary:hover{filter:brightness(1.15);transform:translateY(-2px)}
.keys{margin-top:20px;background:#060a12;border:1px solid var(--line);border-radius:16px;overflow:hidden}.keys-head{padding:21px;border-bottom:1px solid var(--line)}.keys-head h3{margin:0}table{width:100%;border-collapse:collapse}th{padding:15px 18px;text-align:left;font-size:10px;letter-spacing:2px;color:#737c94}td{padding:16px 18px;border-top:1px solid #111827}.keycell{display:flex;align-items:center;gap:12px;font-weight:800}.keyicon{width:42px;height:42px;flex:0 0 42px;border-radius:50%;display:grid;place-items:center;border:1px solid currentColor;box-shadow:0 0 18px currentColor}.keyicon svg{width:20px;height:20px;fill:currentColor}.keyicon.on{color:#39e88b;background:#06331f}.keyicon.off{color:#ff536f;background:#3a0b16}.status{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:7px 10px;font-size:10px;font-weight:900}.status.on{color:#42ec92;background:#07271c}.status.off{color:#ff617a;background:#2b0b14}.dot{width:6px;height:6px;border-radius:50%;background:currentColor}.exp{font-family:monospace;color:#cbd2e3;white-space:nowrap}.devices{color:#aab3c7;white-space:nowrap}.action{display:inline-block;margin:2px}.action button{font-weight:800;cursor:pointer;background:#0a0e17}.stop button{color:#ffb642;border-color:#684612;background:#241807}.start button{color:#4ef09a;border-color:#17623e;background:#06251a}.delete button{color:#ff617a;border-color:#6e2032;background:#260a12}
.server{display:none;animation:sectionIn .5s ease}.server.show,.keysPage.show{display:block}.keysPage.hide{display:none}@keyframes sectionIn{from{opacity:0;transform:translateX(18px)}}.serverGrid{display:grid;gap:20px;margin-top:22px}.serverCard{background:#070b13;border:1px solid #1c2535;border-radius:17px;padding:23px;box-shadow:0 15px 50px #0004;animation:cardBreath 4s ease-in-out infinite}@keyframes cardBreath{50%{border-color:#41366f;box-shadow:0 15px 60px #684cff12}}.serverCard h2{margin:0 0 6px}.serverCard textarea{min-height:72px;resize:vertical;margin-top:9px}.beam{height:2px;margin:27px 0;border-radius:10px;background:linear-gradient(90deg,transparent,#5d7cff,#b44cff,#5d7cff,transparent);background-size:200%;animation:beam 2.4s linear infinite;box-shadow:0 0 15px #785bff}@keyframes beam{to{background-position:200%}}.serverStatus{display:flex;align-items:center;justify-content:space-between;gap:20px}.lamp{width:62px;height:62px;border-radius:16px;background:#092c1d;border:1px solid #31e88b;box-shadow:0 0 25px #31e88b55;animation:lamp 1.7s ease-in-out infinite}.lamp.off{background:#360b15;border-color:#ff536f;box-shadow:0 0 25px #ff536f55}@keyframes lamp{50%{filter:brightness(1.45);transform:scale(1.04)}}.toggleServer{min-width:125px;font-weight:900;cursor:pointer}.flash{animation:flash .5s ease}@keyframes flash{50%{filter:brightness(1.8)}}
@media(max-width:760px){.grid{grid-template-columns:1fr}.hero img{max-height:none}.fields{grid-template-columns:1fr 1fr}.custom{grid-template-columns:1fr 1fr}.custom input:first-child{grid-column:1/-1}.keys{overflow-x:auto}table{min-width:820px}.title{font-size:27px}.drawer{width:75vw;min-width:0}}

.toastStack{position:fixed;top:18px;left:50%;transform:translateX(-50%);z-index:100;width:min(430px,92vw);display:grid;gap:10px;pointer-events:none}.toast{position:relative;overflow:hidden;display:flex;gap:12px;align-items:center;padding:13px 14px;border:1px solid #293249;border-radius:14px;background:#090e18eF;backdrop-filter:blur(18px);box-shadow:0 18px 55px #000b,0 0 30px #7652ff25;animation:toastIn .48s cubic-bezier(.16,.9,.2,1),toastOut .45s ease 3.75s forwards}.toastIcon{width:42px;height:42px;flex:0 0 42px;border-radius:12px;display:grid;place-items:center;font-size:20px;background:linear-gradient(135deg,#5137d8,#a43ff1);box-shadow:0 0 20px #754cff55}.toast b{display:block}.toast small{display:block;color:#9da7ba;margin-top:3px}.toast:after{content:"";position:absolute;bottom:0;left:0;height:2px;width:100%;background:linear-gradient(90deg,#5d7cff,#c13cff,#3eea9b);animation:toastBar 4s linear forwards}@keyframes toastIn{from{opacity:0;transform:translateY(-28px) scale(.92)}}@keyframes toastOut{to{opacity:0;transform:translateY(-20px) scale(.96)}}@keyframes toastBar{to{width:0}}
.updateBadge{display:inline-flex;align-items:center;gap:8px;padding:8px 11px;border-radius:999px;font-size:11px;font-weight:900;border:1px solid #2c3448;background:#0b101a}.updateBadge.live{color:#ffc85a;border-color:#62491b;box-shadow:0 0 20px #ffb83d18}.updateBadge.clear{color:#5ceca0;border-color:#19573b}.miniDot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 10px currentColor}.updateTop{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.cancelUpdate{width:100%;margin-top:9px;color:#ff7188;background:#260a13;border-color:#6b2031;font-weight:900;cursor:pointer}.logsPage{display:none;animation:sectionIn .5s ease}.logsPage.show{display:block}.logWrap{margin-top:22px;background:#070b13;border:1px solid #1b2434;border-radius:17px;overflow:hidden}.logHead{padding:22px;border-bottom:1px solid #182131}.logItem{display:grid;grid-template-columns:52px 1fr auto;gap:14px;align-items:center;padding:16px 20px;border-top:1px solid #121a28;transition:.25s}.logItem:hover{background:#0a101c;transform:translateX(3px)}.logIcon{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;font-size:19px;background:#10172a;border:1px solid #2b3650;box-shadow:0 0 18px #6b55ff18}.logTitle{font-weight:900}.logDetail{font-size:12px;color:#909bb0;margin-top:4px}.logMeta{text-align:right;font-size:11px;color:#747f95}.emptyLogs{text-align:center;color:#788198;padding:55px 20px}
.logTimer{margin:18px;padding:16px 18px;border:1px solid #28324a;border-radius:16px;background:linear-gradient(135deg,#0b1020,#070a12);position:relative;overflow:hidden;box-shadow:0 12px 40px #0006,0 0 24px #7658ff12}
.logTimer:before{content:"";position:absolute;inset:-2px;background:linear-gradient(90deg,transparent,#7658ff33,transparent);transform:translateX(-100%);animation:logSweep 3s linear infinite;pointer-events:none}
@keyframes logSweep{to{transform:translateX(100%)}}
.logTimerTop{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:15px}
.logTimerText b{display:block;font-size:13px;letter-spacing:.8px}.logTimerText small{display:block;color:#818ba1;margin-top:5px;line-height:1.4}
.logClock{display:flex;align-items:center;gap:6px;font-family:monospace}
.logClockBox{min-width:54px;padding:10px 8px;text-align:center;border-radius:11px;border:1px solid #39435f;background:#040813;color:#e6e2ff;font-size:18px;font-weight:900;box-shadow:inset 0 0 18px #7954ff12,0 0 15px #7954ff10}
.logClockSep{color:#706a96;font-weight:900}.logProgressTrack{position:relative;z-index:1;height:3px;margin-top:14px;border-radius:10px;background:#151b29;overflow:hidden}.logProgress{height:100%;width:100%;background:linear-gradient(90deg,#6758ff,#b548ff,#43e69b);box-shadow:0 0 10px #7954ff;transition:width 1s linear}
@media(max-width:600px){.logTimerTop{align-items:flex-start;flex-direction:column}.logClock{width:100%;justify-content:center}.logClockBox{min-width:49px}}
</style></head><body>
<div class="drawerShade" id="shade" onclick="menu(false)"></div><aside class="drawer" id="drawer"><div class="profile"><div class="avatar2">C</div><h3>Cheto_Admin</h3></div><nav class="nav">
<a href="#" id="navKeys" class="active" onclick="page('keys');return false"><span>⌘</span><b data-en="Keys Manager" data-ar="إدارة المفاتيح">Keys Manager</b></a>
<a href="#" id="navServer" onclick="page('server');return false"><span>◈</span><b data-en="Server Manager" data-ar="إدارة السيرفر">Server Manager</b></a>
<a href="#" id="navLogs" onclick="page('logs');return false"><span>≡</span><b data-en="Activity Logs" data-ar="سجل النشاط">Activity Logs</b></a></nav></aside>
<div class="wrap"><div class="top"><div><div class="eyebrow">MIDNIGHT CONTROL</div><div class="title" data-en="Key Manager" data-ar="إدارة المفاتيح">Key Manager</div></div>
<div class="topright"><div><a class="logout" href="/logout" data-en="Logout" data-ar="تسجيل الخروج">Logout</a><div class="lang"><button onclick="setLang('en')">EN</button><button onclick="setLang('ar')">عربي</button></div></div><button class="menuBtn" onclick="menu(true)">☰</button></div></div>

<section class="keysPage show" id="keysPage">
<div class="hero-border"><div class="hero"><img src="/meer.jpg" alt="meer"></div></div><div class="grid">
<div class="motion-border"><div class="card"><h3 data-en="Generate Key" data-ar="إنشاء مفتاح">Generate Key</h3><div class="hint" data-en="Random 25-character Cheto key with days, hours and device limit." data-ar="إنشاء مفتاح Cheto عشوائي مع تحديد الأيام والساعات وعدد الأجهزة.">Random 25-character Cheto key with days, hours and device limit.</div><form action="/generate" method="POST"><div class="fields"><input type="number" name="days" value="30" min="0" placeholder="Days"><input type="number" name="hours" value="0" min="0" placeholder="Hours"><input type="number" name="max_devices" value="1" min="1" max="100" placeholder="Devices"></div><button class="primary" data-en="Generate Key" data-ar="إنشاء المفتاح">Generate Key</button></form></div></div>
<div class="motion-border"><div class="card"><h3 data-en="Add Custom Key" data-ar="إضافة مفتاح مخصص">Add Custom Key</h3><div class="hint" data-en="Custom key with days, hours and up to 100 devices." data-ar="مفتاح مخصص مع الأيام والساعات وحتى 100 جهاز.">Custom key with days, hours and up to 100 devices.</div><form action="/add" method="POST"><div class="custom fields"><input name="key" placeholder="Custom key" required><input type="number" name="days" value="30" min="0" placeholder="Days"><input type="number" name="hours" value="0" min="0" placeholder="Hours"><input type="number" name="max_devices" value="1" min="1" max="100" placeholder="Devices"></div><button class="primary" data-en="Add Key" data-ar="إضافة المفتاح">Add Key</button></form></div></div></div>
<div class="keys"><div class="keys-head"><h3 data-en="Access Keys" data-ar="مفاتيح الوصول">Access Keys</h3></div><table><thead><tr><th data-en="NAME / KEY" data-ar="الاسم / المفتاح">NAME / KEY</th><th data-en="TIME LEFT" data-ar="الوقت المتبقي">TIME LEFT</th><th data-en="DEVICES" data-ar="الأجهزة">DEVICES</th><th data-en="STATUS" data-ar="الحالة">STATUS</th><th data-en="ACTION" data-ar="الإجراء">ACTION</th></tr></thead><tbody>
{% for k in keys %}<tr><td><div class="keycell"><span class="keyicon {{'on' if k['state']=='ACTIVE' else 'off'}}"><svg viewBox="0 0 24 24"><path d="M7.5 14A5.5 5.5 0 1 1 12.7 6.7l8.1 0v3h-2v2h-3v2h-3.1A5.48 5.48 0 0 1 7.5 14Zm0-3A2.5 2.5 0 1 0 7.5 6a2.5 2.5 0 0 0 0 5Z"/></svg></span><span>{{k["key"]}}</span></div></td><td class="exp" data-seconds="{{k['seconds']}}" data-running="{{1 if k['state']=='ACTIVE' else 0}}">{{k["remaining"]}}</td><td class="devices">{{k["used_devices"]}} / {{k["max_devices"]}}</td><td><span class="status {{'on' if k['state']=='ACTIVE' else 'off'}}"><i class="dot"></i>{{k["state"]}}</span></td><td>
{% if k["state"] == "ACTIVE" %}<form class="action stop" action="/stop/{{k['key']}}" method="POST"><button>STOP</button></form>{% elif k["state"] == "STOPPED" %}<form class="action start" action="/start/{{k['key']}}" method="POST"><button>START</button></form>{% endif %}<form class="action delete" action="/delete/{{k['key']}}" method="POST"><button data-en="Delete" data-ar="حذف">Delete</button></form></td></tr>{% endfor %}</tbody></table></div>
</section>

<section class="server" id="serverPage"><div class="serverGrid">
<div class="serverCard"><div class="updateTop"><div><h2 data-en="Send Updates Online" data-ar="إرسال التحديثات أونلاين">Send Updates Online</h2><div class="hint" data-en="Publish an update message to connected clients." data-ar="إرسال رسالة تحديث للعملاء المتصلين.">Publish an update message to connected clients.</div></div>
<span class="updateBadge {{'live' if server['update_active'] else 'clear'}}"><i class="miniDot"></i>{{"UPDATE LIVE" if server["update_active"] else "NO ACTIVE UPDATE"}}</span></div>
<form action="/server/update" method="POST"><input name="title" value="{{server['title']}}" required {% if server["update_active"] %}disabled{% endif %}><textarea name="message" required {% if server["update_active"] %}disabled{% endif %}>{{server["message"]}}</textarea><button class="primary" {% if server["update_active"] %}disabled style="opacity:.42;cursor:not-allowed"{% endif %} data-en="SEND UPDATE" data-ar="إرسال التحديث">SEND UPDATE</button></form>
{% if server["update_active"] %}<form action="/server/update/cancel" method="POST"><button class="cancelUpdate" data-en="CANCEL CURRENT UPDATE" data-ar="إلغاء التحديث الحالي">CANCEL CURRENT UPDATE</button></form>{% endif %}</div>
<div class="beam"></div>
<div class="serverCard"><div class="serverStatus"><div><h2 data-en="Hack Server Control" data-ar="التحكم بسيرفر الهاك">Hack Server Control</h2><div class="hint" data-en="Enable or completely stop key verification from the server." data-ar="تشغيل أو إيقاف التحقق من المفاتيح بالكامل من السيرفر.">Enable or completely stop key verification from the server.</div><b>{{"ONLINE" if server["enabled"] else "OFFLINE"}}</b></div><div class="lamp {{'' if server['enabled'] else 'off'}}"></div></div>
<form action="/server/toggle" method="POST"><button class="primary toggleServer">{{"STOP SERVER" if server["enabled"] else "START SERVER"}}</button></form></div></div></section>
<section class="logsPage" id="logsPage"><div class="logWrap"><div class="logHead"><h2 style="margin:0" data-en="Activity Logs" data-ar="سجل النشاط">Activity Logs</h2><div class="hint" data-en="Recent actions performed from this control panel." data-ar="آخر العمليات التي تمت من لوحة التحكم.">Recent actions performed from this control panel.</div></div>
<div class="logTimer">
  <div class="logTimerTop">
    <div class="logTimerText"><b data-en="24H AUTO CLEANUP" data-ar="الحذف التلقائي خلال 24 ساعة">24H AUTO CLEANUP</b><small data-en="When the countdown reaches zero, all activity logs are deleted automatically." data-ar="عندما يصل العداد إلى الصفر يتم حذف سجل النشاط تلقائياً.">When the countdown reaches zero, all activity logs are deleted automatically.</small></div>
    <div class="logClock"><span class="logClockBox" id="logH">24</span><span class="logClockSep">:</span><span class="logClockBox" id="logM">00</span><span class="logClockSep">:</span><span class="logClockBox" id="logS">00</span></div>
  </div>
  <div class="logProgressTrack"><div class="logProgress" id="logProgress"></div></div>
</div>
{% if logs %}{% for l in logs %}<div class="logItem"><div class="logIcon">{{l["icon"]}}</div><div><div class="logTitle">{{l["action"]}}</div><div class="logDetail">{{l["detail"]}}</div></div><div class="logMeta"><b>{{l["device"]}}</b><br>{{l["created_short"]}}</div></div>{% endfor %}{% else %}<div class="emptyLogs">No activity yet</div>{% endif %}</div></section>
<div class="toastStack" id="toastStack"></div>
</div>
<script>
function menu(x){document.getElementById("drawer").classList.toggle("show",x);document.getElementById("shade").classList.toggle("show",x)}
function page(p){let k=p==="keys",sv=p==="server",lg=p==="logs";document.getElementById("keysPage").classList.toggle("hide",!k);document.getElementById("serverPage").classList.toggle("show",sv);document.getElementById("logsPage").classList.toggle("show",lg);document.getElementById("navKeys").classList.toggle("active",k);document.getElementById("navServer").classList.toggle("active",sv);document.getElementById("navLogs").classList.toggle("active",lg);localStorage.setItem("km_page",p);menu(false)}
function toast(icon,msg){let t=document.createElement("div");t.className="toast";t.innerHTML=`<div class="toastIcon">${icon}</div><div><b>Cheto</b><small>${msg}</small></div>`;document.getElementById("toastStack").appendChild(t);setTimeout(()=>t.remove(),4300)}
{% if notice %}setTimeout(()=>toast({{notice_icon|tojson}},{{notice|tojson}}),250);{% endif %}
function setLang(l){localStorage.setItem("km_lang",l);document.documentElement.lang=l;document.documentElement.dir=l==="ar"?"rtl":"ltr";document.querySelectorAll("[data-"+l+"]").forEach(e=>e.textContent=e.dataset[l]);document.querySelectorAll('input[placeholder="Days"]').forEach(e=>e.placeholder=l==="ar"?"الأيام":"Days");document.querySelectorAll('input[placeholder="Hours"]').forEach(e=>e.placeholder=l==="ar"?"الساعات":"Hours");document.querySelectorAll('input[placeholder="Devices"]').forEach(e=>e.placeholder=l==="ar"?"الأجهزة":"Devices");document.querySelectorAll('input[placeholder="Custom key"]').forEach(e=>e.placeholder=l==="ar"?"مفتاح مخصص":"Custom key")}
setLang(localStorage.getItem("km_lang")||"en");
{% if force_keys %}
localStorage.setItem("km_page","keys");page("keys");
{% else %}
page(localStorage.getItem("km_page")||"keys");
{% endif %}
const LOG_RESET_AT = new Date({{ log_reset_at|tojson }} + "Z").getTime();
function updateLogCountdown(){
    let left = Math.max(0, Math.floor((LOG_RESET_AT - Date.now()) / 1000));
    const original = left;
    const h = Math.floor(left / 3600); left %= 3600;
    const m = Math.floor(left / 60);
    const sec = left % 60;
    const pad = n => String(n).padStart(2,"0");
    const eh=document.getElementById("logH"), em=document.getElementById("logM"), es=document.getElementById("logS");
    if(eh){
        eh.textContent=pad(h); em.textContent=pad(m); es.textContent=pad(sec);
        document.getElementById("logProgress").style.width=(Math.min(86400,original)/86400*100)+"%";
    }
    if(original<=0) setTimeout(()=>location.reload(),1200);
}
updateLogCountdown();
setInterval(updateLogCountdown,1000);
setInterval(()=>document.querySelectorAll("[data-seconds]").forEach(el=>{let s=parseInt(el.dataset.seconds||0);if(el.dataset.running==="1"&&s>0){s--;el.dataset.seconds=s}let d=Math.floor(s/86400);s%=86400;let h=Math.floor(s/3600);s%=3600;let m=Math.floor(s/60),x=s%60;el.textContent=`${d}D-${h}h-${m}m-${x}s`}),1000);
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
                session["open_keys_after_login"]=True
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
    server=con.execute("SELECT * FROM server_state WHERE id=1").fetchone()
    cycle=con.execute("SELECT reset_at FROM log_cycle WHERE id=1").fetchone()
    log_reset_at=cycle["reset_at"] if cycle else (datetime.utcnow()+timedelta(days=1)).isoformat()
    logrows=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 60").fetchall()
    icons={"KEY_CREATED":"✦","KEY_ADDED":"＋","KEY_STOPPED":"Ⅱ","KEY_STARTED":"▶","KEY_DELETED":"×","UPDATE_SENT":"↑","UPDATE_CANCELLED":"↶","SERVER_STOPPED":"■","SERVER_STARTED":"●"}
    logs=[]
    for lr in logrows:
        z=dict(lr);z["icon"]=icons.get(z["action"],"•")
        try:z["created_short"]=datetime.fromisoformat(z["created"]).strftime("%Y-%m-%d %H:%M:%S")
        except:z["created_short"]=z["created"]
        z["action"]=z["action"].replace("_"," ").title()
        logs.append(z)
    con.close()
    notice=session.pop("notice",None);notice_icon=session.pop("notice_icon","✓")
    force_keys=session.pop("open_keys_after_login",False)
    return render_template_string(PANEL_HTML,keys=items,server=server,logs=logs,notice=notice,notice_icon=notice_icon,log_reset_at=log_reset_at,force_keys=force_keys)

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
    add_log(con,"KEY_CREATED",f"Generated {key} • {days}D {hours}H • {limit} device(s)")
    con.commit();con.close();session["notice"]="New key generated successfully";session["notice_icon"]="✦";return redirect("/")

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
    add_log(con,"KEY_ADDED",f"Added custom key {key} • limit {limit} device(s)")
    con.commit();con.close();session["notice"]="Custom key added successfully";session["notice_icon"]="＋";return redirect("/")

@app.route("/stop/<key>",methods=["POST"])
def stop(key):
    if not logged_in(): return redirect("/")
    con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if r:
        sec=seconds_left(r)
        con.execute("UPDATE keys SET active=0,stopped=1,paused_seconds=? WHERE key=?",(sec,key))
        add_log(con,"KEY_STOPPED",f"Stopped key {key} with {pretty_time(sec)} remaining")
        con.commit()
    con.close();session["notice"]="Key stopped and timer paused";session["notice_icon"]="Ⅱ";return redirect("/")

@app.route("/start/<key>",methods=["POST"])
def start(key):
    if not logged_in(): return redirect("/")
    con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if r:
        sec=max(0,int(r["paused_seconds"] or 0))
        con.execute("UPDATE keys SET active=1,stopped=0,paused_seconds=NULL,expiry=? WHERE key=?",
                    ((datetime.utcnow()+timedelta(seconds=sec)).isoformat(),key))
        add_log(con,"KEY_STARTED",f"Started key {key} with {pretty_time(sec)} remaining")
        con.commit()
    con.close();session["notice"]="Key started and timer resumed";session["notice_icon"]="▶";return redirect("/")

@app.route("/delete/<key>",methods=["POST"])
def delete(key):
    if not logged_in(): return redirect("/")
    con=db();con.execute("DELETE FROM key_devices WHERE key=?",(key,));con.execute("DELETE FROM keys WHERE key=?",(key,));add_log(con,"KEY_DELETED",f"Deleted key {key}");con.commit();con.close()
    session["notice"]="Key deleted";session["notice_icon"]="×";return redirect("/")

@app.route("/verify",methods=["POST"])
def verify():
    data=request.get_json(silent=True) or {}
    key=str(data.get("key","")).strip().upper()
    device_id=str(data.get("device_id","")).strip()
    if not key:return jsonify(valid=False,reason="invalid_key")
    con=db();server=con.execute("SELECT * FROM server_state WHERE id=1").fetchone()
    if server and not server["enabled"]:
        con.close();return jsonify(valid=False,reason="server_offline")
    r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
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


@app.route("/server/status",methods=["GET"])
def server_status():
    con=db();s=con.execute("SELECT * FROM server_state WHERE id=1").fetchone();con.close()
    return jsonify(enabled=bool(s["enabled"]),update_active=bool(s["update_active"]),title=s["title"],message=s["message"],version=s["version"],updated=s["updated"])

@app.route("/server/update",methods=["POST"])
def server_update():
    if not logged_in(): return redirect("/")
    title=request.form.get("title","Error!").strip() or "Error!"
    message=request.form.get("message","").strip() or "A new update is available. Please update to the latest version."
    con=db();state=con.execute("SELECT update_active FROM server_state WHERE id=1").fetchone()
    if state and state["update_active"]:
        con.close();session["notice"]="An update is already active. Cancel it first.";session["notice_icon"]="!";return redirect("/#server")
    con.execute("UPDATE server_state SET title=?,message=?,update_active=1,version=version+1,updated=? WHERE id=1",(title,message,datetime.utcnow().isoformat()))
    add_log(con,"UPDATE_SENT",f"{title} — {message[:90]}")
    con.commit();con.close();session["notice"]="Update published successfully";session["notice_icon"]="↑"
    return redirect("/#server")

@app.route("/server/update/cancel",methods=["POST"])
def server_update_cancel():
    if not logged_in(): return redirect("/")
    con=db();state=con.execute("SELECT * FROM server_state WHERE id=1").fetchone()
    if state and state["update_active"]:
        con.execute("UPDATE server_state SET update_active=0,updated=? WHERE id=1",(datetime.utcnow().isoformat(),))
        add_log(con,"UPDATE_CANCELLED",f"Cancelled active update: {state['title']}")
        con.commit()
        session["notice"]="Current update cancelled";session["notice_icon"]="↶"
    con.close();return redirect("/#server")

@app.route("/server/toggle",methods=["POST"])
def server_toggle():
    if not logged_in(): return redirect("/")
    con=db();s=con.execute("SELECT enabled FROM server_state WHERE id=1").fetchone()
    new_state=0 if s["enabled"] else 1
    con.execute("UPDATE server_state SET enabled=?,updated=? WHERE id=1",(new_state,datetime.utcnow().isoformat()))
    add_log(con,"SERVER_STARTED" if new_state else "SERVER_STOPPED","Server verification switched "+("ONLINE" if new_state else "OFFLINE"))
    con.commit();con.close();session["notice"]="Server is now "+("ONLINE" if new_state else "OFFLINE");session["notice_icon"]="●" if new_state else "■"
    return redirect("/#server")

@app.route("/logout")
def logout():
    session.clear();return redirect("/")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",10000)))
