"""Attack cinema — a self-contained animated replay of the heist.

A money counter climbs as each attack lands and steals, the attacks stack up red,
then "PATCH DEPLOYED" snaps the counter to zero. One HTML file, no dependencies,
deploys to Vercel as a static page. It's the 20-second clip that opens the video.
"""
from __future__ import annotations

import html
import json

from .runner import DEFAULT_SECRET, run_all


def render(secret: str = DEFAULT_SECRET) -> str:
    attacks = [
        {"name": r.title, "paise": r.money_at_risk}
        for r in run_all("naive", secret) if r.money_at_risk > 0
    ]
    total = sum(a["paise"] for a in attacks)
    data = json.dumps(attacks)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NIGHTSHIFT — attack cinema</title>
<style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0a0a0c;color:#e9e4d8;font:16px/1.5 ui-monospace,Menlo,monospace;
 min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px}}
h1{{letter-spacing:-.5px;margin:0 0 4px}}
.sub{{color:#8f887d;margin:0 0 28px}}
.counter{{font-size:64px;font-weight:800;color:#ff5b5b;transition:color .4s;font-variant-numeric:tabular-nums}}
.counter.safe{{color:#7ee081}}
.rail{{width:min(560px,92vw);margin:28px 0}}
.atk{{display:flex;justify-content:space-between;gap:12px;padding:11px 16px;margin:8px 0;border-radius:10px;
 background:#141317;border:1px solid #24202a;opacity:.25;transform:translateX(-6px);transition:.35s}}
.atk.on{{opacity:1;transform:none;border-color:#5a2530;background:#1c1418}}
.atk .amt{{color:#ff6b6b;font-weight:700}}
.verdict{{font-size:22px;font-weight:700;height:30px;margin-top:8px}}
.btn{{margin-top:22px;background:#efe9dd;color:#111;border:0;border-radius:8px;padding:11px 20px;font:inherit;font-weight:700;cursor:pointer}}
</style></head><body>
<h1>NIGHTSHIFT</h1>
<p class="sub">a payment integration, under attack — live</p>
<div class="counter" id="counter">Rs 0</div>
<div class="verdict" id="verdict"></div>
<div class="rail" id="rail"></div>
<button class="btn" id="run">▶ replay the attack</button>
<script>
const ATTACKS = {data};
const TOTAL = {total};
const counter = document.getElementById('counter');
const verdict = document.getElementById('verdict');
const rail = document.getElementById('rail');
const rupee = p => 'Rs ' + (p/100).toLocaleString('en-IN');
function build(){{
  rail.innerHTML = '';
  ATTACKS.forEach((a,i)=>{{
    const d=document.createElement('div'); d.className='atk'; d.id='a'+i;
    d.innerHTML = `<span>✗ ${{a.name}}</span><span class="amt">+${{rupee(a.paise)}}</span>`;
    rail.appendChild(d);
  }});
}}
function sleep(ms){{return new Promise(r=>setTimeout(r,ms));}}
async function run(){{
  counter.className='counter'; verdict.textContent=''; counter.textContent='Rs 0';
  build(); let stolen=0;
  for(let i=0;i<ATTACKS.length;i++){{
    await sleep(650);
    document.getElementById('a'+i).classList.add('on');
    stolen+=ATTACKS[i].paise; counter.textContent=rupee(stolen);
  }}
  verdict.style.color='#ff6b6b'; verdict.textContent='grade F — '+rupee(TOTAL)+' stolen';
  await sleep(1100);
  verdict.style.color='#7ee081'; verdict.textContent='PATCH DEPLOYED';
  counter.className='counter safe';
  let cur=stolen; const step=Math.max(1,Math.floor(stolen/24));
  while(cur>0){{ cur=Math.max(0,cur-step); counter.textContent=rupee(cur); await sleep(28); }}
  document.querySelectorAll('.atk').forEach(e=>{{e.classList.remove('on');e.style.borderColor='#1c3a24';}});
  verdict.textContent='grade A+ — Rs 0 at risk';
}}
document.getElementById('run').onclick=run;
run();
</script></body></html>"""


def write(path: str = "attack_cinema.html", secret: str = DEFAULT_SECRET) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render(secret))
    return path
