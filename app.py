from flask import Flask, request, jsonify, render_template_string, redirect, session, send_from_directory
import sqlite3, secrets, string, os, time
try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB = os.environ.get("SQLITE_PATH", "keys.db")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SESSION_HOURS = int(os.environ.get("SESSION_HOURS", "12"))
VERIFY_RATE_LIMIT = int(os.environ.get("VERIFY_RATE_LIMIT", "120"))
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE","1")=="1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS))

LOGIN_IMAGE = "-5877288279722364578_121.jpg"
PANEL_IMAGE = "meer.jpg"

class DBConnection:
    def __init__(self, con, postgres=False):
        self._con=con; self.postgres=postgres
    def execute(self, sql, params=()):
        if self.postgres:
            cur=self._con.cursor()
            cur.execute(sql.replace("?", "%s"), params)
            return cur
        return self._con.execute(sql, params)
    def commit(self): return self._con.commit()
    def close(self): return self._con.close()

def _connect():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("Install psycopg[binary] to use DATABASE_URL")
        return DBConnection(psycopg.connect(DATABASE_URL,row_factory=dict_row),True)
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row
    return DBConnection(con,False)

def _columns(con, table):
    if con.postgres:
        rows=con.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=?",(table,)).fetchall()
        return {r["column_name"] for r in rows}
    return {r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()}

def db():
    con=_connect()
    con.execute("""CREATE TABLE IF NOT EXISTS keys(
        key TEXT PRIMARY KEY, expiry TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL)""")
    cols=_columns(con,"keys")
    for name,sql in {
        "max_devices":"ALTER TABLE keys ADD COLUMN max_devices INTEGER NOT NULL DEFAULT 1",
        "paused_seconds":"ALTER TABLE keys ADD COLUMN paused_seconds INTEGER",
        "stopped":"ALTER TABLE keys ADD COLUMN stopped INTEGER NOT NULL DEFAULT 0",
        "duration_seconds":"ALTER TABLE keys ADD COLUMN duration_seconds INTEGER",
        "activated_at":"ALTER TABLE keys ADD COLUMN activated_at TEXT"}.items():
        if name not in cols: con.execute(sql)

    # Backfill original duration for keys created before activation-on-first-use existed.
    # Existing keys keep their current remaining time as their reset duration.
    for r in con.execute("SELECT * FROM keys WHERE duration_seconds IS NULL").fetchall():
        try: remaining=max(1,int((datetime.fromisoformat(r["expiry"])-datetime.utcnow()).total_seconds()))
        except Exception: remaining=3600
        con.execute("UPDATE keys SET duration_seconds=?, activated_at=? WHERE key=?",(remaining,r["created"],r["key"]))

    con.execute("""CREATE TABLE IF NOT EXISTS server_state(
        id INTEGER PRIMARY KEY, title TEXT NOT NULL, message TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 0, updated TEXT NOT NULL)""")
    if "update_active" not in _columns(con,"server_state"):
        con.execute("ALTER TABLE server_state ADD COLUMN update_active INTEGER NOT NULL DEFAULT 0")

    audit_id="BIGSERIAL PRIMARY KEY" if con.postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
    con.execute(f"""CREATE TABLE IF NOT EXISTS audit_logs(
        id {audit_id}, action TEXT NOT NULL, detail TEXT NOT NULL,
        device TEXT NOT NULL, ip TEXT NOT NULL, created TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS log_cycle(id INTEGER PRIMARY KEY,reset_at TEXT NOT NULL)""")

    cycle=con.execute("SELECT reset_at FROM log_cycle WHERE id=1").fetchone()
    now_cycle=datetime.utcnow()
    if not cycle:
        con.execute("INSERT INTO log_cycle(id,reset_at) VALUES(1,?)",((now_cycle+timedelta(days=1)).isoformat(),))
    else:
        try: reset_at=datetime.fromisoformat(cycle["reset_at"])
        except Exception: reset_at=now_cycle
        if now_cycle>=reset_at:
            con.execute("DELETE FROM audit_logs")
            con.execute("UPDATE log_cycle SET reset_at=? WHERE id=1",((now_cycle+timedelta(days=1)).isoformat(),))

    if not con.execute("SELECT 1 FROM server_state WHERE id=1").fetchone():
        con.execute("INSERT INTO server_state(id,title,message,enabled,version,updated) VALUES(1,?,?,?,?,?)",
                    ("Error!","A new update is available. Please update to the latest version.",1,0,datetime.utcnow().isoformat()))

    con.execute("""CREATE TABLE IF NOT EXISTS key_devices(
        key TEXT NOT NULL,device_id TEXT NOT NULL,first_seen TEXT NOT NULL,PRIMARY KEY(key,device_id))""")
    con.execute("""CREATE TABLE IF NOT EXISTS app_meta(name TEXT PRIMARY KEY,value TEXT NOT NULL)""")
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
    # A newly issued/reset key keeps its full duration until first successful verification.
    if "activated_at" in row.keys() and row["activated_at"] is None:
        return max(0, int(row["duration_seconds"] or 0))
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

_verify_hits={}
def _rate_ok():
    ip=(request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()
    now=time.time(); bucket=_verify_hits.setdefault(ip,[])
    bucket[:]=[x for x in bucket if now-x<60]
    if len(bucket)>=VERIFY_RATE_LIMIT:return False
    bucket.append(now);return True

def _stats(con):
    rows=con.execute("SELECT * FROM keys").fetchall();active=stopped=expired=0
    for r in rows:
        if seconds_left(r)<=0:expired+=1
        elif r["stopped"] or not r["active"]:stopped+=1
        else:active+=1
    devices=con.execute("SELECT COUNT(*) c FROM key_devices").fetchone()["c"]
    return {"total":len(rows),"active":active,"stopped":stopped,"expired":expired,"devices":devices}

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
<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#03040a"><title>Cheto • Secure Access</title>
<style>
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Inter,Arial,sans-serif;color:#f8f9ff}body{min-height:100vh;display:grid;place-items:center;overflow:hidden;background:#03040a}
.scene{position:fixed;inset:0;overflow:hidden;background:radial-gradient(circle at 16% 20%,#5225a944,transparent 28%),radial-gradient(circle at 84% 76%,#0b82a83a,transparent 29%),radial-gradient(circle at 55% 45%,#8b2e7930,transparent 25%),#03040a}
.orb{position:absolute;border-radius:50%;opacity:.55;animation:drift 12s ease-in-out infinite alternate}.o1{width:420px;height:420px;left:-180px;top:-110px;background:#6f38ff26;box-shadow:0 0 110px #6f38ff55}.o2{width:330px;height:330px;right:-130px;bottom:-90px;background:#15d9ff1d;box-shadow:0 0 120px #15d9ff44;animation-delay:-4s}@keyframes drift{to{transform:translate(45px,35px) scale(1.13) rotate(18deg)}}
.grid{position:absolute;inset:-30%;opacity:.14;background-image:linear-gradient(#8f85ff18 1px,transparent 1px),linear-gradient(90deg,#8f85ff18 1px,transparent 1px);background-size:48px 48px;transform:perspective(700px) rotateX(64deg) translateY(25%);animation:grid 14s linear infinite}@keyframes grid{to{background-position:0 96px,96px 0}}
.wrap{position:relative;z-index:2;width:min(940px,94vw);display:grid;grid-template-columns:1.02fr .98fr;border:1px solid #ffffff18;border-radius:30px;overflow:hidden;background:#090b14d9;backdrop-filter:blur(28px);box-shadow:0 35px 100px #000c,0 0 90px #6548ff16;animation:enter .85s cubic-bezier(.16,.85,.2,1)}@keyframes enter{from{opacity:0;transform:translateY(28px) scale(.965);filter:blur(10px)}}
.visual{position:relative;min-height:570px;padding:34px;overflow:hidden;background:linear-gradient(145deg,#111329,#070912)}.visual:before{content:"";position:absolute;inset:-80%;background:conic-gradient(from 0deg,transparent,#7654ff25,transparent 22%,#25d5ff18,transparent 43%);animation:spin 13s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.photo{position:relative;width:100%;height:100%;min-height:500px;border-radius:0;overflow:hidden;border:0;box-shadow:none;animation:float 5s ease-in-out infinite}@keyframes float{50%{transform:translateY(-7px) rotate(.25deg)}}.photo img{width:100%;height:100%;object-fit:cover;display:block;transform:scale(1.04);-webkit-mask-image:linear-gradient(to bottom,#000 0%,#000 80%,transparent 100%);mask-image:linear-gradient(to bottom,#000 0%,#000 80%,transparent 100%)}.photo:after{content:"";position:absolute;inset:0;background:linear-gradient(180deg,transparent 48%,#050710e8)}
.brand{position:absolute;left:57px;bottom:60px;z-index:3}.brand small{letter-spacing:4px;color:#a8a7bd;font-size:10px}.brand h1{font-size:34px;margin:7px 0}.live{display:inline-flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid #5df0ae35;border-radius:999px;background:#071912aa;color:#71efb6;font-size:10px;font-weight:900;letter-spacing:1.2px}.dot{width:7px;height:7px;border-radius:50%;background:#58f0a9;box-shadow:0 0 15px #58f0a9;animation:pulse 1.5s infinite}@keyframes pulse{50%{opacity:.3;transform:scale(.7)}}
.login{position:relative;padding:56px 52px;display:flex;flex-direction:column;justify-content:center;background:linear-gradient(155deg,#0d0f19e8,#070811f2)}.top{display:flex;justify-content:space-between;align-items:center;position:absolute;top:28px;left:52px;right:52px}.shield{font-size:10px;color:#838aa0;letter-spacing:1.4px}.lang{display:flex;padding:3px;border:1px solid #242a3a;border-radius:10px;background:#060811}.lang button{border:0;background:transparent;color:#747d91;padding:7px 9px;border-radius:7px;cursor:pointer;font-weight:800}.lang button:hover{background:#171b29;color:#fff}
.kicker{color:#8c7bff;font-size:10px;font-weight:900;letter-spacing:3.3px;margin-bottom:13px}.login h2{font-size:37px;line-height:1.05;margin:0;letter-spacing:-1.7px}.sub{color:#81899d;font-size:13px;line-height:1.65;margin:15px 0 27px}
.field{position:relative}.field input{width:100%;height:58px;border:1px solid #252c3c;border-radius:15px;background:#050711;color:#fff;padding:0 52px 0 17px;outline:none;font-size:14px;transition:.3s}.field input:focus{border-color:#7564ff;box-shadow:0 0 0 4px #765bff16,0 0 35px #765bff16;transform:translateY(-2px)}.eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);width:36px;height:36px;border:0;border-radius:10px;background:#111521;color:#8f98aa;cursor:pointer}
.submit{position:relative;width:100%;height:56px;margin-top:14px;border:0;border-radius:15px;color:#fff;font-weight:900;letter-spacing:.6px;cursor:pointer;overflow:hidden;background:linear-gradient(100deg,#6447ff,#a946f4,#287cf5);background-size:220%;box-shadow:0 14px 35px #6648ff2d;transition:.25s;animation:gradient 5s linear infinite}.submit:before{content:"";position:absolute;top:-100%;left:-35%;width:28%;height:300%;background:#ffffff36;transform:rotate(25deg);animation:shine 3.8s ease-in-out infinite}@keyframes shine{0%,55%{left:-40%}80%,100%{left:125%}}@keyframes gradient{50%{background-position:100%}}.submit:hover{transform:translateY(-3px);box-shadow:0 18px 45px #7654ff45}
.error{margin:0 0 13px;padding:11px 13px;border:1px solid #ff536f42;border-radius:12px;background:#3a0b162f;color:#ff7c91;font-size:12px;animation:shake .35s ease}@keyframes shake{25%{transform:translateX(-5px)}50%{transform:translateX(5px)}}.foot{margin-top:20px;color:#596176;font-size:10px}
.scan{position:absolute;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#7d6cffaa,transparent);box-shadow:0 0 16px #7d6cff;animation:scan 5.5s linear infinite;opacity:.35}@keyframes scan{from{top:0}to{top:100%}}
@media(max-width:760px){body{overflow:auto}.wrap{grid-template-columns:1fr;width:min(440px,93vw);margin:22px 0}.visual{min-height:270px;padding:18px}.photo{min-height:250px}.brand{left:38px;bottom:38px}.login{padding:76px 27px 36px}.top{left:27px;right:27px;top:25px}.login h2{font-size:32px}}

.loginIntel{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:13px}.intel{padding:9px 10px;border:1px solid #202a3a;border-radius:11px;background:#070b12}.intel b{display:block;font-size:9px;color:#dbe2ef;margin-bottom:3px}.intel span{font-size:7.5px;color:#707d93;line-height:1.35;display:block}.intel.wide{grid-column:1/-1}.loginStatusLine{display:flex;justify-content:space-between;align-items:center;margin:10px 0 0;padding:8px 10px;border:1px solid #1d2737;border-radius:10px;background:#060a11;font:800 8px monospace;color:#78859b}.loginStatusLine i{width:6px;height:6px;border-radius:50%;background:#4ce69a;box-shadow:0 0 10px #4ce69a;display:inline-block;margin-right:5px}.capsWarn{display:none;color:#ffb65e;font-size:9px;margin-top:7px}.capsWarn.show{display:block}.loginProgress{height:3px;background:#111827;border-radius:8px;overflow:hidden;margin-top:12px}.loginProgress i{display:block;height:100%;width:0;background:linear-gradient(90deg,#745cff,#ff4963);transition:.25s}.photo:after{content:"SECURE ADMIN NODE";position:absolute;left:12px;bottom:12px;padding:6px 8px;border-radius:8px;background:#050810cc;border:1px solid #29354a;color:#d7deed;font:900 8px monospace;letter-spacing:1px}.photo{position:relative}
.loginQuick{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin:14px 0 0}.loginQuick div{padding:9px 6px;text-align:center;border:1px solid #202a3a;border-radius:10px;background:#070b12}.loginQuick b{display:block;font:900 9px monospace;color:#e5e9f3}.loginQuick small{display:block;color:#69758a;font-size:7px;margin-top:3px}.loginNotice{margin-top:10px;padding:9px 11px;border-left:2px solid #755cff;background:#745cff0c;color:#8d98ac;font-size:8px;line-height:1.5}.loginPulse{display:inline-block;width:6px;height:6px;border-radius:50%;background:#55e99d;box-shadow:0 0 12px #55e99d;margin-right:6px;animation:pulse 1.5s infinite}@media(max-width:760px){.shell{width:min(94vw,680px)}.visual{min-height:430px}.photo{min-height:390px}.login{padding-top:76px;padding-bottom:30px}.loginQuick{grid-template-columns:repeat(3,1fr)}}
/* Login portrait: clean image + body-following red scanner */
.loginPortrait:after{content:none!important}
.loginPortrait{background:transparent!important;overflow:hidden!important}
.loginPortrait img{object-position:50% 50%!important}
.loginBodyTrace{position:absolute;z-index:4;left:17%;top:1.5%;width:66%;height:99%;overflow:visible;pointer-events:none}
.loginBodyTrace .traceBase{fill:none;stroke:#ff263f;stroke-width:.55;opacity:.22;vector-effect:non-scaling-stroke}
.loginBodyTrace .traceRunner{fill:none;stroke:#ff1738;stroke-width:2.2;stroke-linecap:round;stroke-dasharray:7 93;vector-effect:non-scaling-stroke;filter:drop-shadow(0 0 3px #ff1738) drop-shadow(0 0 8px #ff1738);animation:loginBodyRun 2.15s linear infinite}
@keyframes loginBodyRun{to{stroke-dashoffset:-100}}
</style></head><body>
<div class="scene"><div class="grid"></div><div class="orb o1"></div><div class="orb o2"></div></div>
<main class="wrap"><section class="visual"><div class="scan"></div><div class="photo loginPortrait"><img src="/login-image" alt="">
<svg class="loginBodyTrace" viewBox="0 0 100 150" preserveAspectRatio="none" aria-hidden="true">
 <path class="traceBase" d="M50 4 C39 5 35 14 36 23 C37 29 40 33 41 37 C35 40 27 43 22 51 C17 60 15 77 13 99 L10 147 L90 147 L87 99 C85 77 83 60 78 51 C73 43 65 40 59 37 C60 33 63 29 64 23 C65 14 61 5 50 4Z"/>
 <path class="traceRunner" d="M50 4 C39 5 35 14 36 23 C37 29 40 33 41 37 C35 40 27 43 22 51 C17 60 15 77 13 99 L10 147 L90 147 L87 99 C85 77 83 60 78 51 C73 43 65 40 59 37 C60 33 63 29 64 23 C65 14 61 5 50 4Z"/>
</svg></div><div class="brand"><small>CHETO // CONTROL</small><h1>Midnight Access</h1><span class="live"><i class="dot"></i>SYSTEM READY</span></div></section>
<section class="login"><div class="top"><span class="shield">◆ SECURE CONSOLE</span><div class="lang"><button type="button" onclick="setLang('en')">EN</button><button type="button" onclick="setLang('ar')">عربي</button></div></div><div class="kicker" data-en="ADMINISTRATION NODE" data-ar="بوابة الإدارة">ADMINISTRATION NODE</div><h2 data-en="Welcome back." data-ar="مرحباً بعودتك.">Welcome back.</h2><p class="sub" data-en="Authenticate to enter your private control environment." data-ar="سجّل الدخول للوصول إلى بيئة التحكم الخاصة بك.">Authenticate to enter your private control environment.</p>
{% if error %}<div class="error" data-en="Access denied • Check your password" data-ar="تم رفض الدخول • تحقق من كلمة المرور">Access denied • Check your password</div>{% endif %}
<form method="POST" id="loginForm"><div class="field"><input id="loginPass" type="password" name="password" placeholder="Admin password" autocomplete="current-password" required autofocus><button class="eye" type="button" onclick="togglePass()">◉</button></div><button class="submit" id="loginBtn" data-en="ENTER CONTROL" data-ar="دخول لوحة التحكم">ENTER CONTROL</button><div class="loginQuick"><div><b>LOCAL</b><small>device memory</small></div><div><b>LIVE</b><small>server notices</small></div><div><b>SECURE</b><small>admin session</small></div></div><div class="loginNotice"><span class="loginPulse"></span>Password memory is stored only in this browser. Server suspension and update notices are visible before login.</div></form><div class="foot" data-en="● Protected session • Authorized access only" data-ar="● جلسة محمية • وصول مصرح فقط">● Protected session • Authorized access only</div></section></main>
<script>
function setLang(l){localStorage.setItem("km_lang",l);document.documentElement.lang=l;document.documentElement.dir=l==="ar"?"rtl":"ltr";document.querySelectorAll("[data-"+l+"]").forEach(e=>e.textContent=e.dataset[l]);document.getElementById("loginPass").placeholder=l==="ar"?"كلمة مرور المدير":"Admin password"}
function togglePass(){let p=document.getElementById("loginPass");p.type=p.type==="password"?"text":"password"}
const savedPass=localStorage.getItem("km_admin_password");if(savedPass)document.getElementById("loginPass").value=savedPass;
document.getElementById("loginForm").addEventListener("submit",()=>{let p=document.getElementById("loginPass");localStorage.setItem("km_admin_password",p.value);let b=document.getElementById("loginBtn");b.textContent=document.documentElement.lang==="ar"?"جاري التحقق...":"AUTHENTICATING...";b.style.pointerEvents="none";b.style.opacity=".78"});setLang(localStorage.getItem("km_lang")||"en");
</script><script>
(function(){
 const p=document.querySelector('input[type="password"]');
 const bar=document.getElementById('loginProgressBar');
 const caps=document.getElementById('capsWarn');
 const clock=document.getElementById('loginClock');
 function tick(){if(clock)clock.textContent=new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});}
 tick();setInterval(tick,1000);
 if(p){
   const saved=localStorage.getItem("km_local_admin_password"); if(saved&&!p.value)p.value=saved;
   function update(e){if(bar)bar.style.width=Math.min(100,(p.value.length/12)*100)+"%";localStorage.setItem("km_local_admin_password",p.value);if(e&&e.getModifierState)caps.classList.toggle("show",e.getModifierState("CapsLock"))}
   p.addEventListener("input",update);p.addEventListener("keyup",update);update();
 }
})();
</script></body></html>
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
.keys{margin-top:20px;background:#060a12;border:1px solid var(--line);border-radius:16px;overflow:hidden}.keyTools{padding:16px 18px;border-bottom:1px solid #182131;background:linear-gradient(180deg,#090e18,#060a12)}.searchRow{display:grid;grid-template-columns:1fr auto auto;gap:9px;align-items:center}.searchBox{position:relative}.searchBox input{height:48px;padding-left:43px;padding-right:42px;border-radius:14px;background:#040812;border-color:#28334a;font-family:monospace}.searchBox:before{content:"⌕";position:absolute;left:15px;top:10px;font-size:23px;color:#7e89a4;z-index:2}.clearSearch{position:absolute;right:8px;top:7px;width:34px;height:34px;padding:0;border:0;background:#111827;color:#8d98ad;cursor:pointer}.toolBtn{height:48px;white-space:nowrap;background:#0b1120;color:#cbd4e8;border-color:#29344a;font-weight:900;cursor:pointer}.searchMeta{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-top:10px;color:#77839a;font-size:11px}.searchMeta b{color:#bfc9dd}.quickFilters{display:flex;gap:6px;flex-wrap:wrap}.filterChip{padding:6px 9px;border-radius:999px;background:#0a101b;color:#8490a7;border:1px solid #222d40;font-size:10px;font-weight:900;cursor:pointer}.filterChip.active{color:#fff;border-color:#6e59ff;background:#261d58}.keys-head{padding:21px;border-bottom:1px solid var(--line)}.keys-head h3{margin:0}table{width:100%;border-collapse:collapse}th{padding:15px 18px;text-align:left;font-size:10px;letter-spacing:2px;color:#737c94}td{padding:16px 18px;border-top:1px solid #111827}.keycell{display:flex;align-items:center;gap:12px;font-weight:800}.keyicon{position:relative;width:46px;height:46px;flex:0 0 46px;border-radius:14px;display:grid;place-items:center;border:1px solid #d6b96a66;background:radial-gradient(circle at 32% 25%,#fff2b633,transparent 24%),linear-gradient(145deg,#17140d,#07090e 72%);color:#e8cc79;box-shadow:inset 0 1px 0 #fff3bd2b,inset 0 -10px 22px #0008,0 8px 24px #0009,0 0 18px #cfa94d22;overflow:hidden}.keyicon:before{content:"";position:absolute;inset:2px;border-radius:11px;border:1px solid #fff3bd16;pointer-events:none}.keyicon:after{content:"";position:absolute;width:70%;height:180%;left:-85%;top:-40%;transform:rotate(22deg);background:linear-gradient(90deg,transparent,#fff4c65e,transparent);animation:keyLuxurySweep 4.8s ease-in-out infinite}.keyicon svg{position:relative;z-index:2;width:23px;height:23px;fill:currentColor;filter:drop-shadow(0 0 6px #e5c76f55)}.keyicon.on{color:#efd681;border-color:#d8b85b88;background:radial-gradient(circle at 30% 24%,#fff3b63b,transparent 25%),linear-gradient(145deg,#1b170d,#080a0e 72%)}.keyicon.off{color:#a88d5a;border-color:#6f5b3566;filter:saturate(.65);opacity:.78}@keyframes keyLuxurySweep{0%,68%{left:-90%}88%,100%{left:125%}}.status{display:inline-flex;align-items:center;gap:7px;border-radius:999px;padding:7px 10px;font-size:10px;font-weight:900}.status.on{color:#42ec92;background:#07271c}.status.off{color:#ff617a;background:#2b0b14}.dot{width:6px;height:6px;border-radius:50%;background:currentColor}.exp{font-family:monospace;color:#cbd2e3;white-space:nowrap}.devices{color:#aab3c7;white-space:nowrap}.action{display:inline-block;margin:2px}.action button{font-weight:800;cursor:pointer;background:#0a0e17}.stop button{color:#ffb642;border-color:#684612;background:#241807}.start button{color:#4ef09a;border-color:#17623e;background:#06251a}.delete button{color:#ff617a;border-color:#6e2032;background:#260a12}.edit button{position:relative;overflow:hidden;color:#c8bcff;border-color:#4b3a78;background:linear-gradient(145deg,#111525,#080b14);box-shadow:inset 0 1px 0 #ffffff0d,0 8px 22px #0008,0 0 18px #7654ff18;transition:.22s}.edit button:hover{color:#fff;border-color:#8468ff;transform:translateY(-1px);box-shadow:inset 0 0 16px #7954ff18,0 0 24px #7654ff42}.edit button:after{content:"";position:absolute;inset:-80% -45%;background:linear-gradient(105deg,transparent 43%,#b7a7ff55 50%,transparent 57%);transform:translateX(-80%);animation:editSweep 4.2s ease-in-out infinite}@keyframes editSweep{0%,72%{transform:translateX(-85%)}90%,100%{transform:translateX(85%)}}.editModal{position:fixed;inset:0;z-index:120;display:none;place-items:center;padding:18px;background:#02040be8;backdrop-filter:blur(18px)}.editModal.show{display:grid}.editCard{position:relative;overflow:hidden;width:min(520px,94vw);border:1px solid #41365f;border-radius:22px;padding:22px;background:radial-gradient(circle at 88% 0,#7954ff22,transparent 35%),radial-gradient(circle at 0 100%,#263e8a16,transparent 38%),linear-gradient(145deg,#0c101b,#060810);box-shadow:0 30px 90px #000e,0 0 55px #7654ff1f,inset 0 1px 0 #ffffff0a}.editCard:before{content:"";position:absolute;left:0;right:0;top:0;height:1px;background:linear-gradient(90deg,transparent,#8e75ff,#b54cff,#8e75ff,transparent);box-shadow:0 0 18px #7954ff88}.editTop .eyebrow{color:#8e7cff}.editTop h3{letter-spacing:-.3px}.editTop{display:flex;justify-content:space-between;align-items:center;margin-bottom:17px}.editTop h3{margin:0;font-size:19px}.editClose{width:38px;height:38px;padding:0;border-radius:11px;background:#0b0e15;color:#b8bfd0;border-color:#252c3b;cursor:pointer}.editFields{display:grid;grid-template-columns:1fr 1fr;gap:10px}.editFields label{display:block;color:#858fa3;font-size:10px;font-weight:900;letter-spacing:.7px}.editFields label:first-child{grid-column:1/-1}.editFields input{margin-top:6px}.editNote{margin:12px 0 0;color:#747f93;font-size:10px;line-height:1.5}
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
.dashboardPage{display:none;animation:sectionIn .5s ease}.dashboardPage.show{display:block}.dashGrid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:22px}.statCard{position:relative;overflow:hidden;background:linear-gradient(145deg,#0a0f1a,#060910);border:1px solid #202a3b;border-radius:17px;padding:20px;box-shadow:0 16px 45px #0005}.statCard:after{content:"";position:absolute;width:80px;height:80px;right:-25px;top:-25px;border-radius:50%;background:#7954ff18;box-shadow:0 0 45px #7954ff28}.statCard small{display:block;color:#7f899f;letter-spacing:1.5px;font-weight:900}.statCard strong{display:block;font-size:31px;margin:10px 0 5px}.statCard span{font-size:11px;color:#737e94}.statCard.good strong{color:#52eca0}.statCard.warn strong{color:#ffc45d}.statCard.bad strong{color:#ff687f}.dashWelcome{margin-top:16px}@media(max-width:760px){.dashGrid{grid-template-columns:1fr 1fr}}.sysStrip{display:flex;gap:9px;flex-wrap:wrap;margin:14px 0 2px}.sysPill{display:flex;align-items:center;gap:7px;padding:8px 11px;border:1px solid #1d293b;border-radius:999px;background:#070c14;color:#8794aa;font-size:10px;font-weight:900;letter-spacing:.6px}.sysPill i{width:6px;height:6px;border-radius:50%;background:#4ce698;box-shadow:0 0 12px #4ce698}.sysPill.red i{background:#ff5269;box-shadow:0 0 12px #ff5269}.panel,.serverCard,.logsCard,.keys{transition:transform .25s,border-color .25s,box-shadow .25s}.serverCard:hover,.logsCard:hover{border-color:#2c3a52;box-shadow:0 20px 60px #0006}.topbar:after{content:"";position:absolute;left:0;right:0;bottom:0;height:1px;background:linear-gradient(90deg,transparent,#745cff,#ff405b,transparent);opacity:.35}.topbar{position:sticky}.kbdShade{display:none!important}@keyframes fade{from{opacity:0}to{opacity:1}}.pageHero{position:relative;overflow:hidden;margin:16px 0;padding:16px 18px;border:1px solid #202a3b;border-radius:17px;background:linear-gradient(120deg,#080d17,#0c0a14);box-shadow:0 14px 40px #0004}.pageHero:after{content:"";position:absolute;width:180px;height:180px;right:-70px;top:-100px;border-radius:50%;background:#745cff18;box-shadow:0 0 80px #745cff25}.pageHero h2{margin:0 0 5px;font-size:18px}.pageHero p{margin:0;color:#758198;font-size:11px}.heroLive{display:inline-flex;align-items:center;gap:7px;margin-top:10px;padding:6px 9px;border:1px solid #223149;border-radius:999px;color:#91a0ba;font:800 9px monospace}.heroLive i{width:6px;height:6px;border-radius:50%;background:#55e99e;box-shadow:0 0 12px #55e99e;animation:pulse 1.4s infinite}.miniInsight{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin:12px 0}.insight{padding:12px;border:1px solid #1c2637;border-radius:13px;background:#070b13}.insight b{display:block;font-size:16px;margin-bottom:3px}.insight small{color:#6f7b91;font-size:9px;letter-spacing:.7px}.serverCard,.logsCard,.panel{position:relative;overflow:hidden}.serverCard:before,.logsCard:before{content:"";position:absolute;left:0;top:0;width:100%;height:1px;background:linear-gradient(90deg,transparent,#795dff88,transparent)}.keys-head h3:after{content:" // LIVE";font-size:8px;color:#56e89e;letter-spacing:1px;margin-left:7px}.clockChip{font:800 10px monospace;color:#8390a8;padding:7px 10px;border:1px solid #202b3e;border-radius:10px;background:#070c14}@media(max-width:760px){.miniInsight{grid-template-columns:1fr 1fr}.kbKey{height:54px;font-size:14px}.virtualKeyboard:before{font-size:9px}}
.featureDeck{display:grid;grid-template-columns:repeat(5,1fr);gap:9px;margin:13px 0 18px}
.fx{min-height:92px;padding:13px;border:1px solid #1d293c;border-radius:14px;background:linear-gradient(145deg,#090e18,#050810);position:relative;overflow:hidden}
.fx:after{content:"";position:absolute;width:70px;height:70px;border-radius:50%;right:-30px;top:-30px;background:#7357ff12;box-shadow:0 0 35px #7357ff18}
.fx .ico{font-size:17px}.fx b{display:block;margin:8px 0 4px;font-size:11px}.fx span{display:block;color:#727f96;font-size:9px;line-height:1.45}
.fx strong{display:block;font:900 17px monospace;margin-top:7px;color:#e7ebf5}
.fx button{margin-top:8px;padding:6px 8px;font-size:9px;background:#0b1220;color:#aeb9ce;border:1px solid #27334a;cursor:pointer}
.loginExtras{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}
.loginExtra{padding:10px;border:1px solid #202a3b;border-radius:12px;background:#070b13}
.loginExtra b{font-size:10px;display:block;margin-bottom:4px}.loginExtra span{font-size:8px;color:#758198;line-height:1.4;display:block}
.loginMeter{height:3px;background:#151d2a;border-radius:8px;overflow:hidden;margin-top:7px}.loginMeter i{display:block;height:100%;width:78%;background:linear-gradient(90deg,#745cff,#ff4761);box-shadow:0 0 10px #8b64ff}
.loginClock{font:900 11px monospace;color:#aeb9ce}.loginFootGrid{display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-top:10px}.loginFootGrid div{text-align:center;padding:8px 5px;border:1px solid #1c2637;border-radius:10px;background:#060a11}.loginFootGrid b{display:block;font-size:9px}.loginFootGrid small{font-size:7px;color:#6f7b91}
.heroTools{position:absolute;right:13px;bottom:13px;display:flex;gap:7px;z-index:3}.heroTools button{padding:7px 9px;border-radius:10px;background:#070b13cc;color:#d7deed;border:1px solid #2b3850;font-size:9px;cursor:pointer;backdrop-filter:blur(8px)}
.hero-border{position:relative}.hero-border:before{content:"KEY MANAGER // VISUAL ID";position:absolute;z-index:4;left:14px;top:14px;padding:7px 9px;border-radius:9px;background:#050810cc;border:1px solid #29354a;color:#d5dced;font:900 9px monospace;letter-spacing:1px}
.hero-border:after{content:"LIVE ASSET";position:absolute;z-index:4;right:14px;top:14px;padding:6px 8px;border-radius:999px;background:#092519cc;border:1px solid #1d6945;color:#52eca0;font:900 8px monospace;letter-spacing:1px}
.hero img{transition:transform .6s ease,filter .6s ease}.hero-border:hover .hero img{transform:scale(1.025);filter:contrast(1.05) saturate(1.08)}
@media(max-width:900px){.featureDeck{grid-template-columns:repeat(2,1fr)}}@media(max-width:520px){.featureDeck{grid-template-columns:1fr 1fr}.fx{min-height:84px;padding:11px}.loginExtras{grid-template-columns:1fr}}

.hero-border{isolation:isolate}
.ceoOverlay{position:absolute;z-index:3;inset:0;pointer-events:none}
.ceoPerson{position:absolute;bottom:0;height:92%;pointer-events:auto;cursor:pointer;filter:drop-shadow(0 0 0 transparent);transition:.25s}
.ceoPerson svg{width:100%;height:100%;overflow:visible}.ceoPerson path{fill:transparent;stroke:#ff334f;stroke-width:1.5;stroke-dasharray:7 7;opacity:.42;vector-effect:non-scaling-stroke;transition:.25s}
.ceoPerson:hover path{stroke:#ff1538;stroke-width:3;stroke-dasharray:0;opacity:1;filter:drop-shadow(0 0 7px #ff1d42) drop-shadow(0 0 16px #ff1d4266)}
.ceoPerson:hover{z-index:8}.ceoTag{position:absolute;left:50%;top:48%;transform:translate(-50%,-8px);white-space:nowrap;padding:5px 8px;border:1px solid #ff4158;background:#08070bcc;border-radius:999px;color:#ff7182;font:900 8px monospace;letter-spacing:1px;opacity:0;transition:.22s;box-shadow:0 0 18px #ff28452f}.ceoPerson:hover .ceoTag{opacity:1;transform:translate(-50%,0)}
.ceoPerson:nth-child(2) path{stroke:#ff5d42}.ceoPerson:nth-child(3) path{stroke:#ff3b78}.ceoPerson:nth-child(4) path{stroke:#ff253c}.ceoPerson:nth-child(5) path{stroke:#ff704d}.ceoPerson:nth-child(6) path{stroke:#ff315f}
.ceoLegend{position:absolute;z-index:5;left:14px;bottom:14px;padding:8px 10px;border-radius:10px;background:#050810d9;border:1px solid #4a2029;color:#ff7787;font:900 8px monospace;letter-spacing:1px;box-shadow:0 0 20px #ff29451d}

/* Midnight copy control */
.copyBtn,.copy-key,.copyKey,[onclick*="copyKey"]{
  position:relative!important;overflow:hidden!important;
  min-width:38px!important;height:34px!important;padding:0 10px!important;
  border:1px solid #56347d!important;border-radius:10px!important;
  background:linear-gradient(145deg,#101321,#080b13)!important;
  color:#bca8ff!important;box-shadow:inset 0 1px 0 #ffffff0d,0 0 0 1px #6c42b51c,0 7px 20px #0008!important;
  transition:.2s ease!important
}
.copyBtn:hover,.copy-key:hover,.copyKey:hover,[onclick*="copyKey"]:hover{
  border-color:#9a59ff!important;color:#fff!important;
  box-shadow:0 0 14px #8a3dff55,inset 0 0 15px #7c3cff18!important;
  transform:translateY(-1px)
}
.copyBtn:active,.copy-key:active,.copyKey:active,[onclick*="copyKey"]:active{transform:scale(.93)}
.copyBtn:after,.copy-key:after,.copyKey:after,[onclick*="copyKey"]:after{
  content:"";position:absolute;inset:-80% -35%;
  background:linear-gradient(105deg,transparent 42%,#b991ff66 50%,transparent 58%);
  transform:translateX(-80%);animation:copySweep 4s ease-in-out infinite
}
@keyframes copySweep{0%,72%{transform:translateX(-85%)}88%,100%{transform:translateX(85%)}}

/* Moving light follows each executive contour */
.ceoPerson path{
  stroke:#641b2a!important;stroke-width:1.25!important;stroke-dasharray:none!important;
  opacity:.55!important;filter:drop-shadow(0 0 2px #ff1738)!important
}
.ceoPerson .runner{
  fill:none!important;stroke:#ff1738!important;stroke-width:3.2!important;
  stroke-linecap:round!important;stroke-dasharray:12 88!important;
  opacity:1!important;filter:drop-shadow(0 0 3px #ff1738) drop-shadow(0 0 8px #ff1738) drop-shadow(0 0 15px #ff173888)!important;
  animation:bodyRunner 2.25s linear infinite!important
}
.ceoPerson:nth-child(2) .runner{animation-delay:-.35s!important}
.ceoPerson:nth-child(3) .runner{animation-delay:-.7s!important}
.ceoPerson:nth-child(4) .runner{animation-delay:-1.05s!important}
.ceoPerson:nth-child(5) .runner{animation-delay:-1.4s!important}
.ceoPerson:nth-child(6) .runner{animation-delay:-1.75s!important}
@keyframes bodyRunner{to{stroke-dashoffset:-100}}
.ceoPerson:hover .runner{stroke:#ff5b70!important;stroke-width:4!important;filter:drop-shadow(0 0 5px #ff2948) drop-shadow(0 0 12px #ff2948) drop-shadow(0 0 24px #ff2948)!important}

/* Photo-calibrated executive contour */
.ceoPerson path:not(.runner){stroke:#a91f35!important;stroke-width:.8!important;opacity:.30!important}
.ceoPerson .runner{
  stroke-width:2.15!important;
  stroke-dasharray:7 93!important;
  filter:drop-shadow(0 0 2px #ff1738) drop-shadow(0 0 6px #ff1738)!important;
}
.ceoPerson:hover .runner{stroke-width:2.8!important}
.ceoPerson svg{transform:none!important;transform-origin:center bottom}

/* FINAL body scanner: one short red light only */
.loginBodyTrace .traceBase{stroke:transparent!important;opacity:0!important}
.loginBodyTrace .traceRunner{
 stroke:#ff1838!important;stroke-width:2.25!important;stroke-linecap:round!important;
 stroke-dasharray:2.8 97.2!important;opacity:1!important;
 filter:drop-shadow(0 0 2px #ff1838) drop-shadow(0 0 5px #ff1838)!important;
 animation:loginBodyRun 3s linear infinite!important
}
.ceoPerson path:not(.runner){stroke:transparent!important;opacity:0!important;filter:none!important}
.ceoPerson .runner{
 stroke:#ff1838!important;stroke-width:2.2!important;stroke-linecap:round!important;
 stroke-dasharray:2.8 97.2!important;opacity:1!important;
 filter:drop-shadow(0 0 2px #ff1838) drop-shadow(0 0 5px #ff1838)!important;
 animation:bodyRunner 3s linear infinite!important
}
.ceoPerson:nth-child(n) .runner{animation-delay:0s!important}
.ceoPerson:hover .runner{stroke-width:2.2!important}

/* CEO tap focus mode */
.hero-border.ceoFocus .ceoPerson{opacity:.30!important;pointer-events:auto!important;filter:blur(1.7px) grayscale(.25)!important}
.hero-border.ceoFocus .ceoPerson.ceoSelected{
 opacity:1!important;pointer-events:auto!important;z-index:12!important;
 filter:none!important
}
.hero-border.ceoFocus .ceoPerson.ceoSelected .ceoTag{
 top:48%!important;opacity:1!important;transform:translate(-50%,0)!important;
 color:#fff!important;background:#21070ddd!important;
 box-shadow:0 0 20px #ff183866!important
}
.ceoFocusShade{position:absolute;z-index:2;inset:0;pointer-events:none;display:none}
.hero-border.ceoFocus .ceoFocusShade{display:block}
.ceoFocusShade span{position:absolute;top:0;bottom:0;background:#03050b55;backdrop-filter:blur(3.2px);transition:.32s ease}
.ceoFocusShade .focusLeft{left:0}
.ceoFocusShade .focusRight{right:0}
.hero-border.ceoFocus .hero img{filter:saturate(.82) contrast(1.05)}
.ceoLegend{cursor:pointer;pointer-events:auto}
.hero-border.ceoFocus .ceoLegend{z-index:15;color:#fff;border-color:#ff4059}
</style></head><body>
<div class="drawerShade" id="shade" onclick="menu(false)"></div><aside class="drawer" id="drawer"><div class="profile"><div class="avatar2">C</div><h3>Cheto_Admin</h3></div><nav class="nav">
<a href="#" id="navDashboard" onclick="page('dashboard');return false"><span>◇</span><b data-en="Dashboard" data-ar="لوحة المعلومات">Dashboard</b></a>
<a href="#" id="navKeys" class="active" onclick="page('keys');return false"><span>⌘</span><b data-en="Keys Manager" data-ar="إدارة المفاتيح">Keys Manager</b></a>
<a href="#" id="navServer" onclick="page('server');return false"><span>◈</span><b data-en="Server Manager" data-ar="إدارة السيرفر">Server Manager</b></a>
<a href="#" id="navLogs" onclick="page('logs');return false"><span>≡</span><b data-en="Activity Logs" data-ar="سجل النشاط">Activity Logs</b></a></nav></aside>
<div class="wrap"><div class="top"><div><div class="eyebrow">MIDNIGHT CONTROL</div><div class="title" data-en="Key Manager" data-ar="إدارة المفاتيح">Key Manager</div></div>
<div class="topright"><div><a class="logout" href="/logout" data-en="Logout" data-ar="تسجيل الخروج">Logout</a><div class="lang"><button onclick="setLang('en')">EN</button><button onclick="setLang('ar')">عربي</button></div></div><button class="menuBtn" onclick="menu(true)">☰</button></div></div>

<section class="dashboardPage" id="dashboardPage"><div class="pageHero"><h2>Infrastructure Overview</h2><p>One control surface for access, devices, database and verification.</p><span class="heroLive"><i></i>LIVE CONTROL PLANE</span></div><div class="featureDeck">
<div class="fx"><span class="ico">◉</span><b>Key Health</b><strong>{{stats["active"]}}/{{stats["total"]}}</strong><span>Active credential ratio.</span></div>
<div class="fx"><span class="ico">⌁</span><b>Device Load</b><strong>{{stats["devices"]}}</strong><span>Total bound devices.</span></div>
<div class="fx"><span class="ico">◇</span><b>Expired Queue</b><strong>{{stats["expired"]}}</strong><span>Credentials needing review.</span></div>
<div class="fx"><span class="ico">↯</span><b>Verify State</b><strong>{{"ON" if server["enabled"] else "OFF"}}</strong><span>Global verification gate.</span></div>
<div class="fx"><span class="ico">☄</span><b>Broadcast</b><strong>{{"LIVE" if server["update_active"] else "CLEAR"}}</strong><span>Client update channel.</span></div>
<div class="fx"><span class="ico">⌚</span><b>Live Clock</b><strong id="dashClock">--:--</strong><span>Local operator time.</span></div>
<div class="fx"><span class="ico">⌘</span><b>Quick Keys</b><button onclick="page('keys')">OPEN KEYS</button><span>Jump to credentials.</span></div>
<div class="fx"><span class="ico">▣</span><b>Quick Audit</b><button onclick="page('logs')">OPEN LOGS</button><span>Review recent actions.</span></div>
<div class="fx"><span class="ico">◎</span><b>Server Control</b><button onclick="page('server')">OPEN SERVER</button><span>Manage client state.</span></div>
<div class="fx"><span class="ico">✓</span><b>Database</b><strong>READY</strong><span>Persistent storage connected.</span></div>
</div><div class="dashGrid">
<div class="statCard"><small>TOTAL KEYS</small><strong>{{stats["total"]}}</strong><span>All issued access keys</span></div>
<div class="statCard good"><small>ACTIVE</small><strong>{{stats["active"]}}</strong><span>Currently usable</span></div>
<div class="statCard warn"><small>STOPPED</small><strong>{{stats["stopped"]}}</strong><span>Paused access</span></div>
<div class="statCard bad"><small>EXPIRED</small><strong>{{stats["expired"]}}</strong><span>Expired access</span></div>
<div class="statCard"><small>DEVICES</small><strong>{{stats["devices"]}}</strong><span>Registered devices</span></div>
<div class="statCard"><small>SERVER</small><strong>{{"ONLINE" if server["enabled"] else "OFFLINE"}}</strong><span>Verification status</span></div>
</div><div class="serverCard dashWelcome"><h2>Control Center</h2><div class="hint">Live overview of keys, devices and verification server.</div><span class="updateBadge {{'live' if server['update_active'] else 'clear'}}"><i class="miniDot"></i>{{"UPDATE LIVE" if server["update_active"] else "SYSTEM NORMAL"}}</span></div></section><section class="keysPage show" id="keysPage"><div class="pageHero"><h2>Access Intelligence</h2><p>Generate, search, filter and control every issued credential from one place.</p><span class="heroLive"><i></i>KEY INDEX READY</span></div><div class="miniInsight"><div class="insight"><b>{{stats["active"]}}</b><small>ACTIVE NOW</small></div><div class="insight"><b>{{stats["expired"]}}</b><small>EXPIRED</small></div><div class="insight"><b>{{stats["devices"]}}</b><small>BOUND DEVICES</small></div></div>
<div class="hero-border"><div class="hero"><img src="/meer.jpg" alt="meer"><div class="ceoFocusShade"><span class="focusLeft"></span><span class="focusRight"></span></div><div class="ceoOverlay" aria-label="Executive team"><div class="ceoPerson" style="left:4.4%;width:15.0%;bottom:0;height:88.5%"><span class="ceoTag">CEO // 01</span><svg viewBox="0 0 100 300" preserveAspectRatio="none"><path d="M50 8 C34 9 28 27 31 45 C32 54 37 61 39 67 C27 73 21 88 18 108 L11 295 L89 295 L82 108 C79 88 73 73 61 67 C63 61 68 54 69 45 C72 27 66 9 50 8Z"/><path class="runner" d="M50 8 C34 9 28 27 31 45 C32 54 37 61 39 67 C27 73 21 88 18 108 L11 295 L89 295 L82 108 C79 88 73 73 61 67 C63 61 68 54 69 45 C72 27 66 9 50 8Z"/></svg></div>
<div class="ceoPerson" style="left:20.0%;width:15.0%;bottom:0;height:90%"><span class="ceoTag">CEO // 02</span><svg viewBox="0 0 100 300" preserveAspectRatio="none"><path d="M50 9 C34 10 29 28 31 45 C32 55 37 62 39 68 C27 74 21 89 18 109 L11 295 L89 295 L82 109 C79 89 73 74 61 68 C63 62 68 55 69 45 C71 28 66 10 50 9Z"/><path class="runner" d="M50 9 C34 10 29 28 31 45 C32 55 37 62 39 68 C27 74 21 89 18 109 L11 295 L89 295 L82 109 C79 89 73 74 61 68 C63 62 68 55 69 45 C71 28 66 10 50 9Z"/></svg></div>
<div class="ceoPerson" style="left:36.1%;width:13.0%;bottom:0;height:89.5%"><span class="ceoTag">CEO // 03</span><svg viewBox="0 0 100 300" preserveAspectRatio="none"><path d="M50 9 C35 10 30 28 32 45 C33 55 38 62 40 68 C29 75 23 90 20 110 L14 295 L86 295 L80 110 C77 90 71 75 60 68 C62 62 67 55 68 45 C70 28 65 10 50 9Z"/><path class="runner" d="M50 9 C35 10 30 28 32 45 C33 55 38 62 40 68 C29 75 23 90 20 110 L14 295 L86 295 L80 110 C77 90 71 75 60 68 C62 62 67 55 68 45 C70 28 65 10 50 9Z"/></svg></div>
<div class="ceoPerson" style="left:51.0%;width:13.0%;bottom:0;height:87.5%"><span class="ceoTag">CEO // 04</span><svg viewBox="0 0 100 300" preserveAspectRatio="none"><path d="M50 9 C35 10 30 28 32 45 C33 55 38 62 40 68 C29 75 23 90 20 110 L14 295 L86 295 L80 110 C77 90 71 75 60 68 C62 62 67 55 68 45 C70 28 65 10 50 9Z"/><path class="runner" d="M50 9 C35 10 30 28 32 45 C33 55 38 62 40 68 C29 75 23 90 20 110 L14 295 L86 295 L80 110 C77 90 71 75 60 68 C62 62 67 55 68 45 C70 28 65 10 50 9Z"/></svg></div>
<div class="ceoPerson" style="left:65.4%;width:13.5%;bottom:0;height:87.5%"><span class="ceoTag">CEO // 05</span><svg viewBox="0 0 100 300" preserveAspectRatio="none"><path d="M50 9 C35 10 30 28 32 45 C33 55 38 62 40 68 C29 75 23 90 20 110 L14 295 L86 295 L80 110 C77 90 71 75 60 68 C62 62 67 55 68 45 C70 28 65 10 50 9Z"/><path class="runner" d="M50 9 C35 10 30 28 32 45 C33 55 38 62 40 68 C29 75 23 90 20 110 L14 295 L86 295 L80 110 C77 90 71 75 60 68 C62 62 67 55 68 45 C70 28 65 10 50 9Z"/></svg></div>
<div class="ceoPerson" style="left:80.5%;width:14.0%;bottom:0;height:87%"><span class="ceoTag">CEO // 06</span><svg viewBox="0 0 100 300" preserveAspectRatio="none"><path d="M50 9 C34 10 29 28 31 45 C32 55 37 62 39 68 C27 74 21 89 18 109 L11 295 L89 295 L82 109 C79 89 73 74 61 68 C63 62 68 55 69 45 C71 28 66 10 50 9Z"/><path class="runner" d="M50 9 C34 10 29 28 31 45 C32 55 37 62 39 68 C27 74 21 89 18 109 L11 295 L89 295 L82 109 C79 89 73 74 61 68 C63 62 68 55 69 45 C71 28 66 10 50 9Z"/></svg></div></div><div class="ceoLegend">EXECUTIVE TEAM // HOVER A MEMBER</div></div><div class="heroTools"><button onclick="this.closest('.hero-border').querySelector('img').requestFullscreen?.()">⛶ FULL VIEW</button><button onclick="location.href='/meer.jpg'">↗ OPEN IMAGE</button></div></div><div class="featureDeck">
<div class="fx"><span class="ico">⌕</span><b>Instant Finder</b><button onclick="focusSmartSearch()">SEARCH NOW</button><span>Find partial key text instantly.</span></div>
<div class="fx"><span class="ico">⧉</span><b>Bulk Copy</b><button onclick="copyVisibleKeys()">COPY VISIBLE</button><span>Copy filtered results.</span></div>
<div class="fx"><span class="ico">◌</span><b>Active Filter</b><button onclick="document.querySelectorAll('.filterChip')[1].click()">SHOW ACTIVE</button><span>Only usable credentials.</span></div>
<div class="fx"><span class="ico">⊘</span><b>Stopped Filter</b><button onclick="document.querySelectorAll('.filterChip')[2].click()">SHOW STOPPED</button><span>Review suspended keys.</span></div>
<div class="fx"><span class="ico">⌛</span><b>Expired Filter</b><button onclick="document.querySelectorAll('.filterChip')[3].click()">SHOW EXPIRED</button><span>Find expired access.</span></div>
<div class="fx"><span class="ico">＋</span><b>Generator</b><button onclick="jumpTo('keyCreateGrid')">GENERATE</button><span>Create random credentials.</span></div>
<div class="fx"><span class="ico">✎</span><b>Custom Key</b><button onclick="jumpTo('keyCreateGrid')">CREATE CUSTOM</button><span>Issue memorable access.</span></div>
<div class="fx"><span class="ico">◫</span><b>Visual Identity</b><strong>LIVE</strong><span>Panel image asset verified.</span></div>
<div class="fx"><span class="ico">#</span><b>Total Index</b><strong>{{stats["total"]}}</strong><span>All credentials indexed.</span></div>
<div class="fx"><span class="ico">⚡</span><b>Fast Actions</b><strong>READY</strong><span>Start, stop and delete inline.</span></div>
</div><div class="grid" id="keyCreateGrid">
<div class="motion-border"><div class="card"><h3 data-en="Generate Key" data-ar="إنشاء مفتاح">Generate Key</h3><div class="hint" data-en="Random 25-character Cheto key with days, hours and device limit." data-ar="إنشاء مفتاح Cheto عشوائي مع تحديد الأيام والساعات وعدد الأجهزة.">Random 25-character Cheto key with days, hours and device limit.</div><form action="/generate" method="POST"><div class="fields"><input type="number" name="days" value="30" min="0" placeholder="Days"><input type="number" name="hours" value="0" min="0" placeholder="Hours"><input type="number" name="max_devices" value="1" min="1" max="100" placeholder="Devices"></div><button class="primary" data-en="Generate Key" data-ar="إنشاء المفتاح">Generate Key</button></form></div></div>
<div class="motion-border"><div class="card"><h3 data-en="Add Custom Key" data-ar="إضافة مفتاح مخصص">Add Custom Key</h3><div class="hint" data-en="Custom key with days, hours and up to 100 devices." data-ar="مفتاح مخصص مع الأيام والساعات وحتى 100 جهاز.">Custom key with days, hours and up to 100 devices.</div><form action="/add" method="POST"><div class="custom fields"><input name="key" placeholder="Custom key" required><input type="number" name="days" value="30" min="0" placeholder="Days"><input type="number" name="hours" value="0" min="0" placeholder="Hours"><input type="number" name="max_devices" value="1" min="1" max="100" placeholder="Devices"></div><button class="primary" data-en="Add Key" data-ar="إضافة المفتاح">Add Key</button></form></div></div></div>
<div class="keys"><div class="keys-head"><h3 data-en="Access Keys" data-ar="مفاتيح الوصول">Access Keys</h3></div><div class="keyTools"><div class="searchRow"><div class="searchBox"><input id="keySearch" type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="Search keys instantly..." oninput="filterKeys()"><button class="clearSearch" type="button" onclick="clearKeySearch()">×</button></div><button class="toolBtn" type="button" onclick="focusSmartSearch()">⌕ FOCUS SEARCH</button><button class="toolBtn" type="button" onclick="copyVisibleKeys()">⧉ COPY RESULTS</button></div><div class="searchMeta"><span><b id="matchCount">{{stats["total"]}}</b> matching key(s) • searches anywhere inside the key</span><div class="quickFilters"><button class="filterChip active" onclick="setKeyFilter('ALL',this)">ALL</button><button class="filterChip" onclick="setKeyFilter('ACTIVE',this)">ACTIVE</button><button class="filterChip" onclick="setKeyFilter('STOPPED',this)">STOPPED</button><button class="filterChip" onclick="setKeyFilter('EXPIRED',this)">EXPIRED</button></div></div></div><table><thead><tr><th data-en="NAME / KEY" data-ar="الاسم / المفتاح">NAME / KEY</th><th data-en="TIME LEFT" data-ar="الوقت المتبقي">TIME LEFT</th><th data-en="DEVICES" data-ar="الأجهزة">DEVICES</th><th data-en="STATUS" data-ar="الحالة">STATUS</th><th data-en="ACTION" data-ar="الإجراء">ACTION</th></tr></thead><tbody>
{% for k in keys %}<tr class="keyRow" data-key="{{k['key']|e}}" data-state="{{k['state']}}"><td><div class="keycell"><span class="keyicon {{'on' if k['state']=='ACTIVE' else 'off'}}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 1.8 21.2 12 12 22.2 2.8 12 12 1.8Zm0 4.1L7.1 12l4.9 6.1 4.9-6.1L12 5.9Z"/><path d="M12 8.6 14.8 12 12 15.4 9.2 12 12 8.6Z" opacity=".72"/></svg></span><span class="keyText">{{k["key"]}}</span><button class="copyKey" type="button" onclick="copyOneKey(this)">⧉</button></div></td><td class="exp" data-seconds="{{k['seconds']}}" data-running="{{1 if k['state']=='ACTIVE' else 0}}">{{k["remaining"]}}</td><td class="devices">{{k["used_devices"]}} / {{k["max_devices"]}}</td><td><span class="status {{'on' if k['state']=='ACTIVE' else 'off'}}"><i class="dot"></i>{{k["state"]}}</span></td><td>
{% if k["state"] == "ACTIVE" %}<form class="action stop" action="/stop/{{k['key']}}" method="POST"><button>STOP</button></form>{% elif k["state"] == "STOPPED" %}<form class="action start" action="/start/{{k['key']}}" method="POST"><button>START</button></form>{% endif %}<span class="action edit"><button type="button" onclick="openEdit(this)" data-key="{{k['key']|e}}" data-seconds="{{k['seconds']}}" data-max="{{k['max_devices']}}">EDIT</button></span><form class="action reset" action="/reset/{{k['key']}}" method="POST"><button type="submit">RESET</button></form><form class="action delete" action="/delete/{{k['key']}}" method="POST"><button data-en="Delete" data-ar="حذف">Delete</button></form></td></tr>{% endfor %}</tbody></table><div class="noResults" id="noKeyResults" style="display:none">No keys match this search or filter.</div></div><div class="editModal" id="editModal" onclick="if(event.target===this)closeEdit()"><div class="editCard"><div class="editTop"><div><div class="eyebrow">PREMIUM CREDENTIAL EDITOR</div><h3>Edit key</h3></div><button class="editClose" type="button" onclick="closeEdit()">×</button></div><form id="editKeyForm" class="editKeyForm" method="POST"><div class="editFields"><label>KEY NAME<input id="editKeyName" name="new_key" maxlength="80" required></label><label>DAYS<input id="editDays" name="days" type="number" min="0" max="3650" value="0"></label><label>HOURS<input id="editHours" name="hours" type="number" min="0" max="23" value="1"></label><label>MAX DEVICES<input id="editMax" name="max_devices" type="number" min="1" max="100" value="1"></label></div><p class="editNote">Midnight editor • Duration is stored as the key’s original time. A new or reset key does not count down until its first successful use.</p><button class="primary" type="submit">SAVE CHANGES</button></form></div></div>
</section>

<section class="server" id="serverPage"><div class="featureDeck">
<div class="fx"><span class="ico">●</span><b>Gate Status</b><strong>{{"ONLINE" if server["enabled"] else "LOCKED"}}</strong><span>Current verify availability.</span></div>
<div class="fx"><span class="ico">↟</span><b>Update Channel</b><strong>{{"ACTIVE" if server["update_active"] else "IDLE"}}</strong><span>Current broadcast state.</span></div>
<div class="fx"><span class="ico">☷</span><b>Message Preview</b><span>{{server["update_message"] or "No active update message."}}</span></div>
<div class="fx"><span class="ico">⚑</span><b>Incident Mode</b><strong>{{"ON" if not server["enabled"] else "OFF"}}</strong><span>Shows suspension UI to clients.</span></div>
<div class="fx"><span class="ico">⌁</span><b>Client Recovery</b><strong>AUTO</strong><span>Clients can recover when service returns.</span></div>
<div class="fx"><span class="ico">◎</span><b>Status Endpoint</b><strong>READY</strong><span>Public state endpoint available.</span></div>
<div class="fx"><span class="ico">↺</span><b>State Refresh</b><button onclick="location.reload()">REFRESH</button><span>Reload current server state.</span></div>
<div class="fx"><span class="ico">◈</span><b>Control Safety</b><strong>FORM</strong><span>Changes require explicit action.</span></div>
<div class="fx"><span class="ico">☍</span><b>Update Visibility</b><strong>GLOBAL</strong><span>Broadcast reaches all site pages.</span></div>
<div class="fx"><span class="ico">✓</span><b>Persistence</b><strong>DB</strong><span>Server state survives web restarts.</span></div>
</div><div class="serverGrid">
<div class="serverCard"><div class="updateTop"><div><h2 data-en="Send Updates Online" data-ar="إرسال التحديثات أونلاين">Send Updates Online</h2><div class="hint" data-en="Publish an update message to connected clients." data-ar="إرسال رسالة تحديث للعملاء المتصلين.">Publish an update message to connected clients.</div></div>
<span class="updateBadge {{'live' if server['update_active'] else 'clear'}}"><i class="miniDot"></i>{{"UPDATE LIVE" if server["update_active"] else "NO ACTIVE UPDATE"}}</span></div>
<form action="/server/update" method="POST"><input name="title" value="{{server['title']}}" required {% if server["update_active"] %}disabled{% endif %}><textarea name="message" required {% if server["update_active"] %}disabled{% endif %}>{{server["message"]}}</textarea><button class="primary" {% if server["update_active"] %}disabled style="opacity:.42;cursor:not-allowed"{% endif %} data-en="SEND UPDATE" data-ar="إرسال التحديث">SEND UPDATE</button></form>
{% if server["update_active"] %}<form action="/server/update/cancel" method="POST"><button class="cancelUpdate" data-en="CANCEL CURRENT UPDATE" data-ar="إلغاء التحديث الحالي">CANCEL CURRENT UPDATE</button></form>{% endif %}</div>
<div class="beam"></div>
<div class="serverCard"><div class="serverStatus"><div><h2 data-en="Hack Server Control" data-ar="التحكم بسيرفر الهاك">Hack Server Control</h2><div class="hint" data-en="Enable or completely stop key verification from the server." data-ar="تشغيل أو إيقاف التحقق من المفاتيح بالكامل من السيرفر.">Enable or completely stop key verification from the server.</div><b>{{"ONLINE" if server["enabled"] else "OFFLINE"}}</b></div><div class="lamp {{'' if server['enabled'] else 'off'}}"></div></div>
<form action="/server/toggle" method="POST"><button class="primary toggleServer">{{"STOP SERVER" if server["enabled"] else "START SERVER"}}</button></form></div></div></section>
<section class="logsPage" id="logsPage"><div class="pageHero"><h2>Activity Intelligence</h2><p>Operational history for keys, server controls and administrative actions.</p><span class="heroLive"><i></i>AUDIT STREAM</span></div><div class="featureDeck">
<div class="fx"><span class="ico">☷</span><b>Audit Stream</b><strong>{{logs|length}}</strong><span>Loaded recent records.</span></div>
<div class="fx"><span class="ico">⌛</span><b>24H Rotation</b><strong>AUTO</strong><span>Old audit cycle clears automatically.</span></div>
<div class="fx"><span class="ico">◷</span><b>Next Cycle</b><span>{{log_reset_at}}</span></div>
<div class="fx"><span class="ico">↻</span><b>Refresh Feed</b><button onclick="location.reload()">REFRESH</button><span>Fetch newest actions.</span></div>
<div class="fx"><span class="ico">⌕</span><b>Browser Find</b><button onclick="window.find('key')">FIND KEY EVENTS</button><span>Jump through matching log text.</span></div>
<div class="fx"><span class="ico">▤</span><b>Operational Trail</b><strong>ON</strong><span>Administrative actions recorded.</span></div>
<div class="fx"><span class="ico">◇</span><b>Storage</b><strong>POSTGRES</strong><span>Audit records use persistent DB.</span></div>
<div class="fx"><span class="ico">↯</span><b>Fast Scan</b><strong>RECENT</strong><span>Newest activity shown first.</span></div>
<div class="fx"><span class="ico">⊙</span><b>Context</b><strong>ACTION</strong><span>Each record keeps operation details.</span></div>
<div class="fx"><span class="ico">✓</span><b>Audit Health</b><strong>READY</strong><span>Logging subsystem available.</span></div>
</div><div class="logWrap"><div class="logHead"><h2 style="margin:0" data-en="Activity Logs" data-ar="سجل النشاط">Activity Logs</h2><div class="hint" data-en="Recent actions performed from this control panel." data-ar="آخر العمليات التي تمت من لوحة التحكم.">Recent actions performed from this control panel.</div></div>
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

function selectCeo(el){
 const hero=el.closest(".hero-border");
 const people=[...hero.querySelectorAll(".ceoPerson")];
 const same=el.classList.contains("ceoSelected") && hero.classList.contains("ceoFocus");
 people.forEach(p=>p.classList.remove("ceoSelected"));
 if(same){
   hero.classList.remove("ceoFocus");
   hero.querySelector(".ceoLegend").textContent="EXECUTIVE TEAM // TAP A MEMBER";
   return;
 }
 el.classList.add("ceoSelected");
 hero.classList.add("ceoFocus");
 const left=parseFloat(el.style.left)||0, width=parseFloat(el.style.width)||15;
 const shade=hero.querySelector(".ceoFocusShade");
 shade.querySelector(".focusLeft").style.width=Math.max(0,left)+"%";
 shade.querySelector(".focusRight").style.width=Math.max(0,100-left-width)+"%";
 hero.querySelector(".ceoLegend").textContent=el.querySelector(".ceoTag").textContent+" // SELECTED";
}
document.querySelectorAll(".ceoPerson").forEach(el=>{
 el.addEventListener("click",e=>{e.preventDefault();e.stopPropagation();selectCeo(el)});
});
function menu(x){document.getElementById("drawer").classList.toggle("show",x);document.getElementById("shade").classList.toggle("show",x)}
function page(p){let d=p==="dashboard",k=p==="keys",sv=p==="server",lg=p==="logs";document.getElementById("dashboardPage").classList.toggle("show",d);document.getElementById("keysPage").classList.toggle("hide",!k);document.getElementById("serverPage").classList.toggle("show",sv);document.getElementById("logsPage").classList.toggle("show",lg);document.getElementById("navDashboard").classList.toggle("active",d);document.getElementById("navKeys").classList.toggle("active",k);document.getElementById("navServer").classList.toggle("active",sv);document.getElementById("navLogs").classList.toggle("active",lg);localStorage.setItem("km_page",p);menu(false)}
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

let currentKeyFilter="ALL";
function filterKeys(){const q=(document.getElementById("keySearch").value||"").trim().toUpperCase();let n=0;document.querySelectorAll(".keyRow").forEach(row=>{const key=(row.dataset.key||"").toUpperCase(),state=row.dataset.state||"";const show=(!q||key.includes(q))&&(currentKeyFilter==="ALL"||state===currentKeyFilter);row.style.display=show?"":"none";row.classList.toggle("searchHit",show&&!!q);const t=row.querySelector(".keyText");if(t){const raw=row.dataset.key||"";t.textContent=raw;if(q&&key.includes(q)){const i=key.indexOf(q);t.innerHTML=raw.slice(0,i)+'<mark class="keyMatch">'+raw.slice(i,i+q.length)+'</mark>'+raw.slice(i+q.length)}}if(show)n++});document.getElementById("matchCount").textContent=n;let empty=document.getElementById("noKeyResults");if(empty)empty.style.display=(n===0&&(q||currentKeyFilter!=="ALL"))?"block":"none"}
function clearKeySearch(){let i=document.getElementById("keySearch");i.value="";i.focus();filterKeys()}
function setKeyFilter(f,b){currentKeyFilter=f;document.querySelectorAll(".filterChip").forEach(x=>x.classList.remove("active"));b.classList.add("active");filterKeys()}
async function copyOneKey(btn){let k=btn.closest(".keyRow").dataset.key;try{await navigator.clipboard.writeText(k);toast("⧉","Key copied")}catch(e){}}
async function copyVisibleKeys(){let a=[...document.querySelectorAll(".keyRow")].filter(r=>r.style.display!=="none").map(r=>r.dataset.key);if(!a.length)return toast("!","No matching keys");try{await navigator.clipboard.writeText(a.join("\\n"));toast("⧉",a.length+" key(s) copied")}catch(e){}}
document.addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){e.preventDefault();page("keys");document.getElementById("keySearch").focus()}});
filterKeys();

// Instant key actions: delegated submit handler survives every live panel refresh.
// This prevents the browser from doing a normal page navigation after the first action.
document.addEventListener('submit',async e=>{
 const form=e.target;
 if(!(form.matches('form[action="/generate"]')||form.matches('form[action="/add"]')||form.matches('form.action.stop')||form.matches('form.action.start')||form.matches('form.action.delete')||form.matches('form.editKeyForm'))) return;
 e.preventDefault();
 if(form.dataset.busy==='1') return;
 form.dataset.busy='1';
 const btn=form.querySelector('button');
 const old=btn?btn.innerHTML:'';
 if(btn){btn.disabled=true;btn.style.opacity='.65';}
 try{
   const res=await fetch(form.action,{method:'POST',body:new FormData(form),credentials:'same-origin',headers:{'X-Requested-With':'fetch'}});
   if(!res.ok) throw new Error('request failed');
   const html=await res.text();
   const doc=new DOMParser().parseFromString(html,'text/html');
   const fresh=doc.getElementById('keysPage');
   const current=document.getElementById('keysPage');
   if(fresh&&current){current.innerHTML=fresh.innerHTML;}
   page('keys');
   currentKeyFilter='ALL';
   const allChip=document.querySelector('#keysPage .filterChip');
   if(allChip) allChip.classList.add('active');
   filterKeys();
   const msg=form.matches('.delete')?'Key deleted instantly':form.matches('.stop')?'Key stopped instantly':form.matches('.start')?'Key started instantly':form.matches('.editKeyForm')?'Key updated successfully':form.action.endsWith('/add')?'Custom key added instantly':'New key generated instantly';
   toast('✓',msg);
 }catch(err){
   toast('!','Could not update key');
   if(btn){btn.disabled=false;btn.style.opacity='';btn.innerHTML=old;}
 }finally{form.dataset.busy='0';}
});

function openEdit(btn){const modal=document.getElementById('editModal'),form=document.getElementById('editKeyForm');if(!modal||!form)return;const key=btn.dataset.key||'';let sec=Math.max(0,parseInt(btn.dataset.seconds||'0',10));document.getElementById('editKeyName').value=key;document.getElementById('editDays').value=Math.floor(sec/86400);document.getElementById('editHours').value=Math.max(0,Math.ceil((sec%86400)/3600));document.getElementById('editMax').value=btn.dataset.max||1;form.action='/edit/'+encodeURIComponent(key);modal.classList.add('show')}function closeEdit(){let m=document.getElementById('editModal');if(m)m.classList.remove('show')}
function jumpTo(id){let e=document.getElementById(id);if(e)e.scrollIntoView({behavior:"smooth",block:"start"})}
setInterval(()=>{let e=document.getElementById("dashClock");if(e)e.textContent=new Date().toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})},1000);

function safePage(p){
 const ids={dashboard:"dashboardPage",keys:"keysPage",server:"serverPage",logs:"logsPage"};
 Object.entries(ids).forEach(([name,id])=>{const el=document.getElementById(id);if(!el)return;el.style.display=name===p?"block":"none"});
 ["Dashboard","Keys","Server","Logs"].forEach(n=>{let a=document.getElementById("nav"+n);if(a)a.classList.toggle("active",n.toLowerCase()===p)});
 localStorage.setItem("km_page",p);menu(false);
}
page=safePage;
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
                session.permanent=True
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
    icons={"KEY_CREATED":"✦","KEY_ADDED":"＋","KEY_STOPPED":"Ⅱ","KEY_STARTED":"▶","KEY_DELETED":"×","KEY_EDITED":"✎","KEY_RESET":"↺","UPDATE_SENT":"↑","UPDATE_CANCELLED":"↶","SERVER_STOPPED":"■","SERVER_STARTED":"●"}
    logs=[]
    for lr in logrows:
        z=dict(lr);z["icon"]=icons.get(z["action"],"•")
        try:z["created_short"]=datetime.fromisoformat(z["created"]).strftime("%Y-%m-%d %H:%M:%S")
        except:z["created_short"]=z["created"]
        z["action"]=z["action"].replace("_"," ").title()
        logs.append(z)
    stats=_stats(con)
    con.close()
    notice=session.pop("notice",None);notice_icon=session.pop("notice_icon","✓")
    force_keys=session.pop("open_keys_after_login",False)
    return render_template_string(PANEL_HTML,keys=items,server=server,stats=stats,logs=logs,notice=notice,notice_icon=notice_icon,log_reset_at=log_reset_at,force_keys=force_keys)

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
    con.execute("INSERT INTO keys(key,expiry,active,created,max_devices,paused_seconds,stopped,duration_seconds,activated_at) VALUES(?,?,?,?,?,NULL,0,?,?)",
                (key,(now+duration).isoformat(),1,now.isoformat(),limit,int(duration.total_seconds()),None))
    add_log(con,"KEY_CREATED",f"Generated {key} • {days}D {hours}H • {limit} device(s)")
    con.commit();con.close();session["notice"]="New key generated successfully";session["notice_icon"]="✦";return redirect("/")

@app.route("/add",methods=["POST"])
def add_key():
    if not logged_in(): return redirect("/")
    key=request.form.get("key","").strip().upper()
    if not key:return redirect("/")
    duration,_,_=duration_from_form();limit=max_devices_from_form();now=datetime.utcnow()
    con=db()
    con.execute("DELETE FROM key_devices WHERE key=?",(key,))
    con.execute("DELETE FROM keys WHERE key=?",(key,))
    con.execute("INSERT INTO keys(key,expiry,active,created,max_devices,paused_seconds,stopped,duration_seconds,activated_at) VALUES(?,?,?,?,?,NULL,0,?,?)",
                (key,(now+duration).isoformat(),1,now.isoformat(),limit,int(duration.total_seconds()),None))
    add_log(con,"KEY_ADDED",f"Added custom key {key} • limit {limit} device(s)")
    con.commit();con.close();session["notice"]="Custom key added successfully";session["notice_icon"]="＋";return redirect("/")

@app.route("/edit/<key>",methods=["POST"])
def edit_key(key):
    if not logged_in(): return redirect("/")
    old_key=key.strip().upper();new_key=request.form.get("new_key","").strip().upper() or old_key
    duration,days,hours=duration_from_form();limit=max_devices_from_form();con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(old_key,)).fetchone()
    if not r:
        con.close();session["notice"]="Key not found";session["notice_icon"]="!";return redirect("/")
    if new_key!=old_key and con.execute("SELECT 1 FROM keys WHERE key=?",(new_key,)).fetchone():
        con.close();session["notice"]="That key name already exists";session["notice_icon"]="!";return redirect("/")
    new_seconds=max(1,int(duration.total_seconds()));expiry=(datetime.utcnow()+timedelta(seconds=new_seconds)).isoformat();stopped=bool(r["stopped"]) or not bool(r["active"])
    unused=r["activated_at"] is None
    if stopped: con.execute("UPDATE keys SET key=?,expiry=?,max_devices=?,paused_seconds=?,duration_seconds=? WHERE key=?",(new_key,expiry,limit,new_seconds,new_seconds,old_key))
    elif unused: con.execute("UPDATE keys SET key=?,expiry=?,max_devices=?,paused_seconds=NULL,duration_seconds=?,activated_at=NULL WHERE key=?",(new_key,expiry,limit,new_seconds,old_key))
    else: con.execute("UPDATE keys SET key=?,expiry=?,max_devices=?,paused_seconds=NULL,duration_seconds=? WHERE key=?",(new_key,expiry,limit,new_seconds,old_key))
    if new_key!=old_key: con.execute("UPDATE key_devices SET key=? WHERE key=?",(new_key,old_key))
    add_log(con,"KEY_EDITED",f"Edited {old_key} -> {new_key} • {days}D {hours}H • {limit} device(s)")
    con.commit();con.close();session["notice"]="Key updated successfully";session["notice_icon"]="✦";return redirect("/")

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
        sec=max(0,int(r["paused_seconds"] or r["duration_seconds"] or 0))
        if r["activated_at"] is None:
            con.execute("UPDATE keys SET active=1,stopped=0,paused_seconds=NULL WHERE key=?",(key,))
        else:
            con.execute("UPDATE keys SET active=1,stopped=0,paused_seconds=NULL,expiry=? WHERE key=?",
                        ((datetime.utcnow()+timedelta(seconds=sec)).isoformat(),key))
        add_log(con,"KEY_STARTED",f"Started key {key} with {pretty_time(sec)} remaining")
        con.commit()
    con.close();session["notice"]="Key started and timer resumed";session["notice_icon"]="▶";return redirect("/")

@app.route("/reset/<key>",methods=["POST"])
def reset_key(key):
    if not logged_in(): return redirect("/")
    con=db();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if r:
        sec=max(1,int(r["duration_seconds"] or 3600))
        # Restore original duration and arm it for first-use activation. Device bindings stay intact.
        con.execute("UPDATE keys SET active=1,stopped=0,paused_seconds=NULL,activated_at=NULL,expiry=? WHERE key=?",
                    ((datetime.utcnow()+timedelta(seconds=sec)).isoformat(),key))
        add_log(con,"KEY_RESET",f"Reset key {key} to original duration {pretty_time(sec)}")
        con.commit()
    con.close();session["notice"]="Key duration reset • countdown waits for first use";session["notice_icon"]="↺";return redirect("/")

@app.route("/delete/<key>",methods=["POST"])
def delete(key):
    if not logged_in(): return redirect("/")
    con=db();con.execute("DELETE FROM key_devices WHERE key=?",(key,));con.execute("DELETE FROM keys WHERE key=?",(key,));add_log(con,"KEY_DELETED",f"Deleted key {key}");con.commit();con.close()
    session["notice"]="Key deleted";session["notice_icon"]="×";return redirect("/")

@app.route("/keylist.json",methods=["GET"])
def keylist_json():
    """Public read-only snapshot for Lua clients that cannot make HTTPS requests themselves."""
    con=db()
    rows=con.execute("SELECT * FROM keys").fetchall()
    out={}
    for r in rows:
        devices=con.execute("SELECT device_id FROM key_devices WHERE key=? ORDER BY first_seen",(r["key"],)).fetchall()
        out[str(r["key"]).upper()]={
            "expiry":r["expiry"],
            "active":bool(r["active"]),
            "stopped":bool(r["stopped"]),
            "max_devices":int(r["max_devices"] or 1),
            "devices":[str(x["device_id"]) for x in devices],
        }
    con.close()
    resp=jsonify(out)
    resp.headers["Cache-Control"]="no-store, no-cache, must-revalidate, max-age=0"
    return resp


@app.route("/verify",methods=["POST"])
def verify():
    if not _rate_ok(): return jsonify(valid=False,reason="rate_limited"),429
    data=request.get_json(silent=True) or {}
    key=str(data.get("key","")).strip().upper()
    device_id=str(data.get("device_id","")).strip()
    if not key:return jsonify(valid=False,reason="invalid_key")
    con=db();server=con.execute("SELECT * FROM server_state WHERE id=1").fetchone()
    if server and not server["enabled"]:
        con.close();return jsonify(valid=False,reason="server_offline")
    r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
    if not r or not r["active"] or r["stopped"]:
        con.close();return jsonify(valid=False,reason="inactive")
    if r["activated_at"] is not None and seconds_left(r)<=0:
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
    # Activate only after every validity/device check has succeeded.
    if r["activated_at"] is None:
        sec=max(1,int(r["duration_seconds"] or 3600)); now=datetime.utcnow()
        con.execute("UPDATE keys SET activated_at=?,expiry=? WHERE key=?",(now.isoformat(),(now+timedelta(seconds=sec)).isoformat(),key))
        con.commit();r=con.execute("SELECT * FROM keys WHERE key=?",(key,)).fetchone()
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

@app.route("/health")
def health():
    try:
        con=db();con.execute("SELECT 1").fetchone();con.close()
        return jsonify(ok=True,database=True),200
    except Exception:
        return jsonify(ok=False,database=False),503

@app.route("/logout")
def logout():
    session.clear();return redirect("/")

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"]="nosniff"
    resp.headers["X-Frame-Options"]="DENY"
    resp.headers["Referrer-Policy"]="no-referrer"
    resp.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    return resp

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",10000)))
