"""NIGHTSHIFT live console — a real, interactive payment-security app.

    python -m nightshift dashboard

One screen, two halves:
  * a working shop ("Acme Pay") running on a real Razorpay-style webhook integration,
    with a live merchant order board;
  * an attack console that red-teams it in real time, one attack at a time, with a
    cinematic reveal (each attack "fires", then lands or bounces).

Buy something → a legit order appears. Launch the attack → fraudulent orders flood the
board and the money-stolen counter climbs. Flip the shop to its hardened integration and
every attack bounces. Then download a security report. Everything runs on 127.0.0.1 —
nothing is published. You can also point the scanner at ANY external URL (your own app,
or Razorpay's sample app) instead of the bundled shop.
"""
from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import constants as C
from .advisories import to_markdown
from .config import DEFAULT
from .refserver import build_server
from .scanner import ATTACKS, _register, _send, _state, _webhook, scan

_BY_NAME = {f.__name__.replace("_atk_", ""): f for f in ATTACKS}

ATTACK_META = [
    ("replay", "Webhook replay", "HIGH"),
    ("race", "Concurrency race double-spend", "CRITICAL"),
    ("unsigned", "Signature not verified", "CRITICAL"),
    ("forged", "Forged event accepted", "CRITICAL"),
    ("tamper", "Tampered amount booked", "HIGH"),
    ("over_refund", "Refund exceeds capture", "HIGH"),
    ("stale", "Stale-timestamp event", "MEDIUM"),
    ("idor", "Unknown-order (IDOR)", "CRITICAL"),
]

_TARGETS: dict[str, tuple] = {}
_BUY_N = 0


def _spawn(name: str, hardened: bool, secret: str) -> None:
    old = _TARGETS.get(name)
    if old:
        try:
            old[0].shutdown()
        except Exception:
            pass
    httpd = build_server(0, hardened=hardened, secret=secret)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    _TARGETS[name] = (httpd, f"http://127.0.0.1:{httpd.server_address[1]}")


def _buy(url: str, secret: str) -> str:
    global _BUY_N
    _BUY_N += 1
    oid = f"buy_{_BUY_N}"
    _register(url, oid, 50000)
    _send(url, _webhook(C.CAPTURE, oid, "pay_" + oid, 50000, event_id="evt_" + oid), secret)
    return oid


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NIGHTSHIFT — live payment security</title>
<style>
:root{
  --bg:#07070b; --panel:#100e18; --panel2:#16131f; --line:#241f31;
  --ink:#ece7f7; --dim:#8b8399; --red:#ff4d5e; --green:#42d67f;
  --amber:#f7c250; --blue:#49a8ff; --purple:#8a6cff; color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  overflow-x:hidden}
.bg{position:fixed;inset:0;z-index:-1;
  background:
    radial-gradient(60vw 50vh at 80% -10%, rgba(138,108,255,.14), transparent 60%),
    radial-gradient(50vw 40vh at 0% 110%, rgba(255,77,94,.12), transparent 60%),
    linear-gradient(transparent 39px,rgba(255,255,255,.025) 40px),
    linear-gradient(90deg,transparent 39px,rgba(255,255,255,.025) 40px);
  background-size:auto,auto,40px 40px,40px 40px;
  animation:drift 24s linear infinite}
@keyframes drift{to{background-position:0 0,0 0,0 400px,400px 0}}
.wrap{max-width:1120px;margin:0 auto;padding:30px 22px 90px}
.hero{opacity:0;animation:fadeUp .6s .05s forwards}
.logo{font:800 30px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.14em;
  background:linear-gradient(90deg,#fff,#b9a9ff 60%,#7f6bff);-webkit-background-clip:text;background-clip:text;color:transparent;
  text-shadow:0 0 30px rgba(138,108,255,.25)}
.tag{color:var(--dim);margin-top:6px;font-size:13px;font-family:ui-monospace,Menlo,monospace}
.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:20px 0 16px;opacity:0;animation:fadeUp .6s .12s forwards}
.seg{display:flex;border:1px solid var(--line);border-radius:11px;overflow:hidden;background:#0d0b14}
.seg button{background:transparent;color:#cfc7dd;border:0;padding:10px 16px;font:600 13px/1 inherit;cursor:pointer;transition:.18s}
.seg button.on{background:linear-gradient(180deg,#efe9fb,#d9cffb);color:#161022;box-shadow:0 2px 12px rgba(138,108,255,.35)}
.seg button:not(.on):hover{background:#171425}
.lbl{color:var(--dim);font-size:12px;font-family:ui-monospace,monospace}
input.url{flex:1;min-width:210px;background:#0c0a12;border:1px solid var(--line);border-radius:11px;
  color:var(--ink);padding:10px 13px;font:13px/1 ui-monospace,Menlo,monospace;outline:none;transition:.18s}
input.url:focus{border-color:var(--purple);box-shadow:0 0 0 3px rgba(138,108,255,.18)}
.grid{display:grid;grid-template-columns:1fr 1.05fr;gap:18px}
@media(max-width:860px){.grid{grid-template-columns:1fr}}
.card{position:relative;background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--line);border-radius:18px;padding:20px;opacity:0;
  box-shadow:0 20px 60px -30px rgba(0,0,0,.9);animation:fadeUp .6s .2s forwards}
.card.console{animation-delay:.3s}
.card h2{font:700 15px/1.2 ui-monospace,Menlo,monospace;margin:0 0 2px;display:flex;align-items:center;gap:8px}
.card .h{color:var(--dim);font-size:12px;margin:2px 0 15px}
.prod{display:flex;justify-content:space-between;align-items:center;background:#17141f;
  border:1px solid #272134;border-radius:13px;padding:15px 17px;margin-bottom:14px}
.prod b{font-size:16px}
.btn{border:0;border-radius:11px;padding:11px 17px;font:700 14px/1 inherit;cursor:pointer;transition:transform .1s,box-shadow .2s,opacity .2s}
.btn:active{transform:translateY(1px) scale(.99)}
.buy{background:linear-gradient(180deg,#5bb8ff,#2f95ff);color:#04121e;box-shadow:0 6px 20px -8px rgba(73,168,255,.7)}
.btn:disabled{opacity:.45;cursor:default;box-shadow:none}
.board{max-height:340px;overflow:auto;margin-top:4px;padding-right:4px}
.board::-webkit-scrollbar{width:8px}.board::-webkit-scrollbar-thumb{background:#2a2438;border-radius:8px}
.o{display:flex;justify-content:space-between;gap:8px;padding:9px 13px;border-radius:10px;margin:7px 0;font-size:13px;
  border:1px solid var(--line);animation:orderIn .4s both;font-family:ui-monospace,Menlo,monospace}
.o.legit{background:linear-gradient(90deg,rgba(66,214,127,.12),rgba(66,214,127,.03));border-color:#1e3f2b}
.o.fraud{background:linear-gradient(90deg,rgba(255,77,94,.14),rgba(255,77,94,.03));border-color:#4a1e28}
.o .tag2{font-weight:800}.o.legit .tag2{color:var(--green)}.o.fraud .tag2{color:var(--red)}
.empty{color:#5f596b;font-size:13px;font-family:ui-monospace,monospace;padding:6px 2px}
.kpis{display:flex;gap:10px;margin:6px 0 14px}
.kpi{flex:1;background:#141120;border:1px solid #262034;border-radius:13px;padding:12px 13px;position:relative;overflow:hidden}
.kpi .n{font:800 24px/1 ui-monospace,Menlo,monospace;font-variant-numeric:tabular-nums;transition:color .3s}
.kpi .l{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.1em;margin-top:6px}
.kpi.pop .n{animation:pop .34s}
.red{color:var(--red)!important}.green{color:var(--green)!important}
.launch{width:100%;position:relative;overflow:hidden;background:linear-gradient(180deg,#ff5d6c,#ec2f43);color:#fff;
  font-size:15px;letter-spacing:.04em;box-shadow:0 8px 26px -10px rgba(255,77,94,.8);padding:13px}
.launch.scanning{background:linear-gradient(90deg,#2a2238,#3a2f4e,#2a2238);background-size:200% 100%;
  animation:shimmer 1.1s linear infinite;color:#d9cffb;cursor:default}
.rows{margin-top:12px;position:relative}
.row{position:relative;display:flex;align-items:flex-start;gap:11px;background:#120f1b;border:1px solid var(--line);
  border-left:3px solid #2c2640;border-radius:11px;padding:11px 13px;margin:8px 0;opacity:.32;
  transform:translateY(8px);transition:opacity .3s,border-color .3s,background .3s}
.row.reveal{opacity:1;transform:none;animation:rowIn .4s both}
.row.firing{border-left-color:var(--amber);background:#181228;animation:firePulse 1s ease-in-out infinite}
.row.hit{border-left-color:var(--red);background:linear-gradient(90deg,rgba(255,77,94,.13),transparent);animation:shake .4s}
.row.safe{border-left-color:var(--green);background:linear-gradient(90deg,rgba(66,214,127,.11),transparent)}
.st{width:46px;flex:none;font:800 12px/1.3 ui-monospace,monospace;padding-top:1px}
.st .spin{width:13px;height:13px;border:2px solid rgba(247,194,80,.28);border-top-color:var(--amber);border-radius:50%;display:inline-block;animation:spin .6s linear infinite}
.nm{flex:1;font-size:13.5px;font-weight:600}
.nm small{display:block;color:var(--dim);font-size:11.5px;font-weight:400;margin-top:2px;min-height:14px;font-family:ui-monospace,menlo,monospace}
.chip{font:800 9px/1 ui-monospace,monospace;padding:4px 8px;border-radius:999px;flex:none;letter-spacing:.05em;align-self:center}
.chip.CRITICAL{background:#3a1421;color:#ff8090}.chip.HIGH{background:#3a2712;color:#ffb659}.chip.MEDIUM{background:#2c2a12;color:#e9dc5a}
.prog{position:absolute;left:0;bottom:0;height:2px;width:100%;background:transparent;border-radius:0 0 11px 11px;overflow:hidden}
.prog i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--amber),#ff8a3d)}
.foot{margin-top:18px;padding:15px 18px;background:linear-gradient(180deg,var(--panel),var(--panel2));
  border:1px solid var(--line);border-radius:14px;min-height:26px;font-size:14px;opacity:0;animation:fadeUp .6s .4s forwards}
.gradewrap{display:inline-flex;align-items:baseline;gap:8px}
.grade{font:900 26px/1 ui-monospace,monospace}
.grade.show{animation:gradeIn .6s cubic-bezier(.2,1.4,.4,1)}
a.dl{color:var(--blue);font-weight:700;text-decoration:none;border-bottom:1px dashed rgba(73,168,255,.5)}
a.dl:hover{border-bottom-style:solid}
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes rowIn{from{opacity:0;transform:translateY(12px) scale(.985)}to{opacity:1;transform:none}}
@keyframes firePulse{0%,100%{box-shadow:-2px 0 0 0 rgba(247,194,80,0)}50%{box-shadow:-5px 0 18px -3px rgba(247,194,80,.55)}}
@keyframes shake{10%,90%{transform:translateX(-1px)}30%,70%{transform:translateX(2px)}50%{transform:translateX(-3px)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pop{0%{transform:scale(1)}42%{transform:scale(1.2)}100%{transform:scale(1)}}
@keyframes shimmer{to{background-position:-200% 0}}
@keyframes orderIn{from{opacity:0;transform:translateX(22px)}to{opacity:1;transform:none}}
@keyframes gradeIn{0%{opacity:0;transform:scale(.4) rotate(-8deg)}70%{transform:scale(1.22)}100%{opacity:1;transform:none}}
</style></head><body><div class="bg"></div><div class="wrap">
<header class="hero"><div class="logo">NIGHTSHIFT</div>
<div class="tag">live payment-security scanner · a real shop, robbed in real time</div></header>
<div class="bar">
  <div class="seg" id="seg">
    <button data-t="naive" class="on">Vulnerable integration</button>
    <button data-t="hardened">Hardened integration</button>
  </div>
  <span class="lbl">or scan any URL:</span>
  <input class="url" id="url" placeholder="http://localhost:5000  (blank = bundled shop)">
</div>
<div class="grid">
  <section class="card shop">
    <h2>🛒 Acme Pay — checkout</h2><p class="h" id="shoph">running on the selected integration</p>
    <div class="prod"><span><b>Premium Plan</b><br><small style="color:var(--dim)">1 seat · monthly</small></span>
      <span><b>₹500</b> &nbsp;<button class="btn buy" id="buy">Buy now</button></span></div>
    <p class="h" style="margin:16px 0 4px;letter-spacing:.08em">MERCHANT ORDER BOARD</p>
    <div class="board" id="board"><div class="empty">no orders yet — buy something, then launch the attack.</div></div>
  </section>
  <section class="card console">
    <h2>☠ Attack console</h2><p class="h">8 real attacks fired over HTTP at the shop's webhook endpoint</p>
    <div class="kpis">
      <div class="kpi" id="k-stolen"><div class="n red">Rs 0</div><div class="l">stolen</div></div>
      <div class="kpi" id="k-landed"><div class="n">0/8</div><div class="l">landed</div></div>
      <div class="kpi" id="k-grade"><div class="n grade">—</div><div class="l">grade</div></div>
    </div>
    <button class="btn launch" id="go">▶ LAUNCH ATTACK</button>
    <div class="rows" id="rows"></div>
  </section>
</div>
<div class="foot" id="foot">Tip: click <b>Buy now</b> a couple of times (green = real orders), then <b>LAUNCH ATTACK</b> and watch the shop get robbed line by line.</div>
</div>
<script>
let META=[],target="naive",busy=false,legit=0;
const rupee=p=>'Rs '+(p/100).toLocaleString('en-IN');
const $=id=>document.getElementById(id);
const q=()=>{const u=$('url').value.trim();return u?('&url='+encodeURIComponent(u)):'';};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

document.querySelectorAll('#seg button').forEach(b=>b.onclick=async()=>{if(busy)return;
  target=b.dataset.t;document.querySelectorAll('#seg button').forEach(x=>x.classList.toggle('on',x===b));
  await newSession();});

async function boot(){META=await (await fetch('/api/attacks')).json();drawRows(false);await newSession();}

function drawRows(reveal){
  $('rows').innerHTML=META.map((a,i)=>`<div class="row${reveal?' reveal':''}" id="r${i}" style="animation-delay:${i*45}ms">
    <div class="st">—</div>
    <div class="nm">${a.title}<small class="det"></small></div>
    <span class="chip ${a.severity}">${a.severity}</span>
    <div class="prog"><i></i></div></div>`).join('');
  setKpi('k-stolen','Rs 0','n red');setKpi('k-landed','0/8','n');setKpi('k-grade','—','n grade');
}
function setKpi(id,txt,cls){const el=$(id).querySelector('.n');el.textContent=txt;el.className=cls;el.dataset.v=0;}
function popKpi(id){const k=$(id);k.classList.remove('pop');void k.offsetWidth;k.classList.add('pop');}

async function newSession(){legit=0;await fetch('/api/reset?target='+target+q());
  drawRows(true);board();$('foot').innerHTML='Fresh shop ready. Buy something, then launch the attack.';}

async function board(){
  const d=await (await fetch('/api/orders?target='+target+q())).json();
  const c={};(d.fulfillments||[]).forEach(o=>c[o]=(c[o]||0)+1);
  const keys=Object.keys(c);
  if(!keys.length){$('board').innerHTML='<div class="empty">no orders yet.</div>';return;}
  $('board').innerHTML=keys.map((o,i)=>{const isLegit=o.startsWith('buy_');const n=c[o];
    return `<div class="o ${isLegit?'legit':'fraud'}" style="animation-delay:${i*35}ms"><span>${isLegit?'✓ ':'⚠ '}${o}${n>1?' ×'+n:''}</span>
      <span class="tag2">${isLegit?'PAID ₹500':'FRAUD · no payment'}</span></div>`;}).join('');
}

$('buy').onclick=async()=>{if(busy)return;legit++;await fetch('/api/buy?target='+target+q());await board();
  $('foot').innerHTML='Real order placed and paid. Now <b>LAUNCH ATTACK</b>.';};

async function tick(el,to){let cur=+(el.dataset.v||0);const s=Math.max(1,Math.round((to-cur)/18));
  while(cur<to){cur=Math.min(to,cur+s);el.textContent=rupee(cur);await sleep(16);}el.dataset.v=to;}

async function fire(i){
  const row=$('r'+i);const st=row.querySelector('.st');const det=row.querySelector('.det');const fill=row.querySelector('.prog i');
  row.classList.remove('hit','safe');row.classList.add('reveal','firing');
  st.innerHTML='<span class="spin"></span>';det.textContent='firing…';
  fill.style.transition='none';fill.style.width='0';void fill.offsetWidth;
  fill.style.transition='width .82s cubic-bezier(.4,.1,.3,1)';fill.style.width='100%';
  const [r]=await Promise.all([
    fetch('/api/run?attack='+META[i].name+'&target='+target+q()).then(x=>x.json()),
    sleep(880) ]);
  row.classList.remove('firing');det.textContent=r.detail;
  if(r.succeeded){row.classList.add('hit');st.innerHTML='<span class="red">HIT</span>';}
  else{row.classList.add('safe');st.innerHTML='<span class="green">safe</span>';}
  return r;
}

$('go').onclick=async()=>{if(busy)return;busy=true;
  const go=$('go');go.disabled=true;$('buy').disabled=true;
  go.classList.add('scanning');go.textContent='◈ SCANNING WEBHOOK ENDPOINT…';
  drawRows(false);
  // fresh run: reset, replay the legit purchases so they stay on the board, then attack
  await fetch('/api/reset?target='+target+q());
  for(let i=0;i<legit;i++){await fetch('/api/buy?target='+target+q());}await board();
  await sleep(500);
  let stolen=0,hits=0;
  for(let i=0;i<META.length;i++){
    const r=await fire(i);
    if(r.succeeded){stolen+=r.money;hits++;
      const el=$('k-stolen').querySelector('.n');await tick(el,stolen);popKpi('k-stolen');}
    setKpi('k-landed',hits+'/'+META.length,'n'+(hits?' red':''));popKpi('k-landed');
    await board();await sleep(260);
  }
  const g=hits===0?'A+':hits===1?'B':hits<=2?'C':hits<=4?'D':'F';
  const ge=$('k-grade').querySelector('.n');ge.textContent=g;ge.className='n grade show '+(hits?'red':'green');
  popKpi('k-grade');
  go.classList.remove('scanning');go.textContent='▶ LAUNCH ATTACK';
  if(hits===0){$('foot').innerHTML='<span class="gradewrap"><b class="green">GRADE A+</b></span> — every attack bounced. The shop kept all its money. This is the hardened integration.';}
  else{$('foot').innerHTML='<b class="red">Grade '+g+' — '+hits+' attacks landed, '+rupee(stolen)+' stolen.</b> &nbsp; <a class="dl" href="/api/report?target='+target+q()+'" download="nightshift-advisories.md">⬇ Download security report ('+hits+' CVEs)</a> &nbsp;·&nbsp; now flip to <b>Hardened integration</b> and launch again.';}
  busy=false;go.disabled=false;$('buy').disabled=false;};

boot();
</script></body></html>"""


def _url_for(q: dict) -> str | None:
    u = q.get("url", [""])[0].strip()
    return u or None


def _target_url(q: dict) -> str:
    ext = _url_for(q)
    if ext:
        return ext
    name = q.get("target", ["naive"])[0]
    if name not in _TARGETS:
        _spawn(name, hardened=(name == "hardened"), secret=DEFAULT.secret)
    return _TARGETS[name][1]


def _make_handler(secret: str):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, code, body, ctype="application/json", extra=None):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path == "/":
                    return self._send(200, PAGE, "text/html; charset=utf-8")
                if u.path == "/api/attacks":
                    return self._send(200, json.dumps(
                        [{"name": n, "title": t, "severity": s} for n, t, s in ATTACK_META]))
                if u.path == "/api/reset":
                    name = q.get("target", ["naive"])[0]
                    if not _url_for(q):
                        _spawn(name, hardened=(name == "hardened"), secret=secret)
                    return self._send(200, json.dumps({"ok": True}))
                if u.path == "/api/buy":
                    return self._send(200, json.dumps({"order": _buy(_target_url(q), secret)}))
                if u.path == "/api/orders":
                    return self._send(200, json.dumps({"fulfillments": _state(_target_url(q)).get("fulfillments", [])}))
                if u.path == "/api/run":
                    name = q.get("attack", [""])[0]
                    if name not in _BY_NAME:
                        return self._send(400, json.dumps({"error": "unknown attack"}))
                    f = _BY_NAME[name](_target_url(q), secret)
                    return self._send(200, json.dumps({
                        "attack": f.attack, "title": f.title, "severity": f.severity,
                        "succeeded": f.succeeded, "detail": f.detail, "money": f.money_at_risk}))
                if u.path == "/api/report":
                    ext = _url_for(q)
                    if ext:
                        rep = scan(ext, secret)
                    else:  # a clean throwaway target so the report isn't polluted by the console run
                        tmp = build_server(0, hardened=(q.get("target", ["naive"])[0] == "hardened"), secret=secret)
                        threading.Thread(target=tmp.serve_forever, daemon=True).start()
                        rep = scan(f"http://127.0.0.1:{tmp.server_address[1]}", secret)
                        tmp.shutdown()
                    return self._send(200, to_markdown(rep), "text/markdown; charset=utf-8",
                                      {"Content-Disposition": "attachment; filename=nightshift-advisories.md"})
                self._send(404, json.dumps({"error": "not found"}))
            except Exception as e:
                self._send(200, json.dumps({"succeeded": False, "detail": f"probe error: {e}",
                                            "attack": "?", "title": "?", "severity": "MEDIUM", "money": 0}))

    return H


def serve(port: int = 8888, secret: str = DEFAULT.secret, open_browser: bool = True) -> None:
    _spawn("naive", hardened=False, secret=secret)
    _spawn("hardened", hardened=True, secret=secret)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _make_handler(secret))
    url = f"http://127.0.0.1:{port}"
    print(f"NIGHTSHIFT live console -> {url}   (Ctrl-C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nightshift-dashboard")
    p.add_argument("--port", type=int, default=8888)
    p.add_argument("--secret", default=DEFAULT.secret)
    p.add_argument("--no-open", action="store_true")
    a = p.parse_args(argv)
    serve(a.port, a.secret, open_browser=not a.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
