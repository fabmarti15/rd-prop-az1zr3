#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cifra un HTML (AES-256-GCM + PBKDF2-SHA256 250k iter) y lo envuelve en un gate
que descifra en el navegador con WebCrypto. El repo solo guarda el cifrado.
Uso: python3 _build_gate.py "CLAVE" inner.html salida.html "Titulo" "Subtitulo"
"""
import os, sys, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 250000
BASE = "https://fabmarti15.github.io/rd-prop-az1zr3/coach/"

GATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="googlebot" content="noindex, nofollow">
<title>__TITLE__</title>
<!-- Preview para WhatsApp / redes (Open Graph) -->
<meta property="og:type" content="website">
<meta property="og:site_name" content="Coach de Retención · RedArbor">
<meta property="og:url" content="https://fabmarti15.github.io/rd-prop-az1zr3/coach/">
<meta property="og:title" content="Coach de Retención — Demo B2B">
<meta property="og:description" content="Un agente de IA acompaña a cada nuevo ingreso por WhatsApp, detecta las señales de fuga y evita la renuncia. Confidencial · RedArbor 🔒">
<meta property="og:image" content="https://fabmarti15.github.io/rd-prop-az1zr3/coach/og.jpg">
<meta property="og:image:secure_url" content="https://fabmarti15.github.io/rd-prop-az1zr3/coach/og.jpg">
<meta property="og:image:type" content="image/jpeg">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Coach de Retención — ¿Por qué se va tu gente?">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Coach de Retención — Demo B2B">
<meta name="twitter:description" content="Un agente de IA acompaña a cada nuevo ingreso por WhatsApp y evita la renuncia.">
<meta name="twitter:image" content="https://fabmarti15.github.io/rd-prop-az1zr3/coach/og.jpg">
<style>
  :root{--teal:#0d9488;--tealD:#0a766c;--teal2:#14b8a6;--ink:#0e1b26;--muted:#7fa8a3;--line:#1d3a44;}
  *{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    background:radial-gradient(1200px 700px at 50% -8%,#103642 0%,#081820 60%,#06141a 100%);
    color:#dfeceb;min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px;}
  .gate{width:100%;max-width:420px;background:#0c2128;border:1px solid var(--line);border-bottom:6px solid #123;
    border-radius:22px;padding:34px 28px 28px;text-align:center;box-shadow:0 30px 80px rgba(0,0,0,.6);}
  .lock{font-size:44px;line-height:1;margin-bottom:6px}
  .brand{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:12px}
  .brand .mk{width:30px;height:30px;border-radius:9px;background:linear-gradient(160deg,var(--teal2),var(--teal));display:flex;align-items:center;justify-content:center;font-size:17px}
  .brand b{font-size:16px;font-weight:800;letter-spacing:-.4px;color:#fff}
  .gate h1{font-size:19px;margin:6px 0 4px;letter-spacing:-.3px;color:#fff}
  .gate p{font-size:13px;color:var(--muted);margin:0 0 22px;line-height:1.5}
  .row{display:flex;gap:8px}
  input[type=password]{flex:1;font-size:16px;padding:14px;border-radius:13px;border:2px solid var(--line);
    background:#06141a;color:#fff;outline:none}
  input[type=password]:focus{border-color:var(--teal2)}
  button{font-size:15px;font-weight:800;color:#fff;background:var(--teal);border:none;border-bottom:4px solid var(--tealD);
    border-radius:13px;padding:13px 18px;cursor:pointer;white-space:nowrap}
  button:active{transform:translateY(2px);border-bottom-width:2px}
  button:disabled{opacity:.6;cursor:wait}
  .err{color:#ff8a7a;font-size:13px;margin-top:14px;min-height:18px;font-weight:600}
  .foot{margin-top:20px;font-size:11px;color:var(--muted)}
  .badge{display:inline-block;margin-bottom:10px;font-size:10.5px;font-weight:800;color:var(--teal2);
    background:rgba(20,184,166,.12);border:1px solid #1d4a44;padding:4px 10px;border-radius:999px;letter-spacing:.4px}
</style>
</head>
<body>
  <form class="gate" id="g" onsubmit="return false;">
    <div class="lock">&#128274;</div>
    <div class="brand"><span class="mk">&#128735;</span><b>Coach de Retención</b></div>
    <div class="badge">CONFIDENCIAL &middot; REDARBOR</div>
    <h1>__TITLE__</h1>
    <p>__SUB__<br>Documento confidencial. Ingresa la clave para abrir.</p>
    <div class="row">
      <input type="password" id="pwd" placeholder="Clave" autocomplete="off" autofocus>
      <button id="btn" type="submit">Abrir</button>
    </div>
    <div class="err" id="err"></div>
    <div class="foot">RedArbor &middot; Demo B2B</div>
  </form>
<script>
const P = __PAYLOAD_JSON__;
function b64(s){const bin=atob(s);const u=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)u[i]=bin.charCodeAt(i);return u;}
const btn=document.getElementById('btn'),pwd=document.getElementById('pwd'),err=document.getElementById('err'),g=document.getElementById('g');
async function unlock(){
  const pass=pwd.value; if(!pass){pwd.focus();return;}
  btn.disabled=true; err.textContent='Descifrando…';
  try{
    const enc=new TextEncoder();
    const km=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(P.salt),iterations:P.iter,hash:'SHA-256'},km,{name:'AES-GCM',length:256},false,['decrypt']);
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(P.iv)},key,b64(P.ct));
    const html=new TextDecoder().decode(pt);
    document.open(); document.write(html); document.close();
  }catch(e){ err.textContent='Clave incorrecta.'; btn.disabled=false; pwd.select(); }
}
g.addEventListener('submit',unlock);
if(!(window.crypto&&crypto.subtle)){err.textContent='Abre este enlace en https:// (no funciona como archivo local).';}
</script>
</body>
</html>
"""

def main():
    password, inner_path, out_path, title, sub = sys.argv[1:6]
    with open(inner_path, "r", encoding="utf-8") as f:
        inner = f.read()
    salt, iv = os.urandom(16), os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, inner.encode("utf-8"), None)
    payload = {"salt": base64.b64encode(salt).decode(), "iv": base64.b64encode(iv).decode(),
               "ct": base64.b64encode(ct).decode(), "iter": ITER}
    out = (GATE.replace("__PAYLOAD_JSON__", json.dumps(payload))
              .replace("__TITLE__", title).replace("__SUB__", sub))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"  {out_path}: {os.path.getsize(out_path)/1024:.0f} KB  (inner {len(inner)/1024:.0f} KB)")

if __name__ == "__main__":
    main()
