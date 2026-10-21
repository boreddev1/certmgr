"""HTTP-Server des Cert-Managers.

Zwei Listener, zwei Aufgaben:

  :8103 (oeffentlich, nur ueber den Cloudflare-Tunnel erreichbar)
      /onboard/<token>   Abholseite: Passwort eingeben, einmalig
                         herunterladen. Sonst nichts.

  :8104 (nur Loopback, ueber nginx :8443 im LAN erreichbar)
      /                  Admin-Oberflaeche
      /api/...           JSON-API fuer die Oberflaeche und den MCP-Server

Die Trennung ist Absicht: Der Onboarding-Port ist im Internet sichtbar
und darf ausschliesslich den Einmal-Download anbieten. Der Admin-Port
ist nie direkt im Internet - er haengt hinter nginx, das wiederum nur im
LAN erreichbar ist.
"""
import json
import mimetypes
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import ca
from .manager import CertManager, NotSignedError

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")

SESSION_TTL = 8 * 3600
SESSION_COOKIE = "certmgr_session"


class AdminAuth:
    """Passwort-Login mit signierten Session-Cookies.

    scrypt-Hash des Admin-Passworts liegt in der Secret-Datei. Sessions
    sind HMAC-signiert - kein Server-seitiger Session-Store noetig, und
    ein Neustart des Dienstes raeumt die Sessions automatisch ab (der
    Session-Secret ist im Arbeitsspeicher).

    Wichtig: ein Logout muss die Session auch serverseitig ungueltig
    machen. Ein HMAC-signiertes Cookie bleibt sonst gueltig, bis es
    ablaeuft - jemand, der den Cookie abgefangen hat, koennte ihn
    weiterverwenden. Deshalb gibt es eine Sperrliste der abgemeldeten
    Sessions.
    """

    def __init__(self, password, secret=None):
        self.password_hash = ca.hash_password(password)
        self.secret = secret or secrets.token_bytes(32)
        self._revoked = set()
        # RLock statt Lock: _prune_revoked() wird auch aus revoke_session()
        # heraus gerufen, das den Lock selbst haelt. Ein normales Lock
        # wuerde dort deadlocken (es ist nicht reentrant).
        self._lock = threading.RLock()

    def check_password(self, password):
        return ca.verify_password(password, self.password_hash)

    def make_session(self):
        exp = int(time.time()) + SESSION_TTL
        payload = f"{exp}"
        sig = _sign(self.secret, payload)
        return f"{payload}.{sig}"

    def check_session(self, token):
        if not token or "." not in token:
            return False
        payload, sig = token.rsplit(".", 1)
        if not secrets.compare_digest(_sign(self.secret, payload), sig):
            return False
        try:
            expired = int(payload) <= time.time()
        except ValueError:
            return False
        if expired:
            return False
        with self._lock:
            if token in self._revoked:
                return False
        # Gelegentlich auffraeumen, damit die Sperrliste nicht waechst.
        # WICHTIG: nicht innerhalb des Lock aufrufen - _prune_revoked
        # nimmt ihn selbst und ein threading.Lock ist nicht reentrant.
        self._prune_revoked()
        return True

    def revoke_session(self, token):
        """Session serverseitig sperren (Logout)."""
        if not token:
            return
        with self._lock:
            self._revoked.add(token)
            self._prune_revoked()

    def _prune_revoked(self):
        """Abgelaufene Eintraege aus der Sperrliste entfernen.

        Wird bei jedem Logout und bei jeder Pruefung aufgerufen, damit
        die Liste nicht unbegrenzt waechst, auch wenn sich niemand
        abmeldet. Eine abgelaufene Session ist ohnehin wertlos - die
        Pruefung in check_session lehnt sie schon ab.
        """
        now = int(time.time())
        with self._lock:
            for old in list(self._revoked):
                try:
                    if int(old.split(".")[0]) < now:
                        self._revoked.discard(old)
                except (ValueError, IndexError):
                    self._revoked.discard(old)


def _sign(secret, payload):
    import hashlib
    import hmac

    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()[:32]


class Handler(BaseHTTPRequestHandler):
    server_version = "certmgr"
    sys_version = ""
    manager = None
    auth = None
    mode = "admin"

    # ----------------------------------------------------------- Hilfsmittel

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(
            code,
            json.dumps(obj, default=str),
            "application/json; charset=utf-8",
            extra,
        )

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length or length > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except Exception:
            return {}

    def _client_ip(self):
        """Die IP des Clients fuer das Rate-Limit.

        Der Header CF-Connecting-IP wird von cloudflared gesetzt. Er
        darf aber NICHT blind vertraut werden: jeder Client kann den
        Header selbst mitsenden. Sonst laesst sich das Rate-Limit
        umgehen, indem man bei jedem Versuch eine andere IP vorgibt.

        Vertraut wird der Header deshalb nur, wenn die Anfrage
        nachweislich ueber den Tunnel kam. cloudflared stellt genau
        zwei Dinge bere, die ein direkter Client nicht faelschen kann:

          - die Verbindung kommt von 127.0.0.1 (der Tunnel laeuft auf
            demselben Host)
          - der Header CF-Ray ist gesetzt (wird von der Edge erzeugt
            und ist keine vom Client steuerbare Groesse)

        Andernfalls zaehlt die Socket-Adresse. Die ist nicht
        spoofbar - und wer direkt auf 127.0.0.1 zugreift, ist ohnehin
        schon auf dem Host.
        """
        peer = self.client_address[0]
        cf_ip = self.headers.get("CF-Connecting-IP")

        if cf_ip and self._from_tunnel():
            return cf_ip.strip()

        return peer

    def _from_tunnel(self):
        """Kam die Anfrage ueber den Cloudflare-Tunnel?

        Zwei Bedingungen muessen zutreffen: die Verbindung kommt vom
        Loopback (cloudflared laeuft hier) und der CF-Ray-Header ist
        gesetzt (Edge-Kennung).
        """
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return False
        return bool(self.headers.get("CF-Ray"))

    def _static(self, name):
        path = os.path.join(STATIC, name)
        if not os.path.isfile(path):
            self._send(404, "nicht gefunden")
            return
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as fh:
            self._send(200, fh.read(), ctype)

    def _authorized(self):
        """Admin-Zugriff: Session-Cookie ODER API-Token-Header."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            if secrets.compare_digest(token, self.manager.api_token or ""):
                return True
        token = self._session_token()
        return bool(token) and self.auth.check_session(token)

    def _session_token(self):
        """Session-Cookie aus dem Request lesen."""
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE:
                return value
        return ""

    def log_message(self, fmt, *args):
        if self.mode == "public":
            # Nur ungewoehnliche Vorkommnisse loggen, sonst wird das
            # Log bei jedem Abruf der Onboarding-Seite unlesbar.
            pass
        else:
            super().log_message(fmt, *args)

    # ------------------------------------------------------------ GET-Routen

    def do_GET(self):
        if self.mode == "public":
            return self._public_get()
        return self._admin_get()

    def do_HEAD(self):
        self.do_GET()

    def _public_get(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            return self._json(200, {"ok": True})

        # Alles ausser /onboard/ ist gesperrt. Die Cloudflare-WAF-Regel
        # macht das zusaetzlich, aber hier ist die zweite Schicht.
        if not path.startswith("/onboard/"):
            return self._send(404, self._page("Nicht gefunden", "<p>404</p>"))

        token = path[len("/onboard/"):].strip("/")
        if not token:
            return self._send(404, self._page("Nicht gefunden", "<p>404</p>"))

        row = self.manager.store.get_by_token_hash(ca.hash_token(token))
        if not row:
            return self._send(
                404, self._page("Ungültiger Link", "<p>Dieser Link ist unbekannt.</p>")
            )
        if row.get("downloaded_at"):
            return self._send(
                410,
                self._page(
                    "Link bereits benutzt",
                    "<p>Dieser Link wurde bereits verwendet. Der private "
                    "Schlüssel liegt beim Empfänger. Bitte ein neues "
                    "Zertifikat anfordern.</p>",
                ),
            )
        if row.get("token_expires", 0) < time.time():
            return self._send(
                410,
                self._page(
                    "Link abgelaufen",
                    "<p>Dieser Link ist abgelaufen (24 h). "
                    "Bitte ein neues Zertifikat anfordern.</p>",
                ),
            )
        return self._send(200, self._onboard_page(row))

    def _admin_get(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)

        if path == "/healthz":
            return self._json(200, {"ok": True, "mode": "admin"})

        if path == "/api/certs":
            if not self._authorized():
                return self._json(401, {"error": "nicht angemeldet"})
            return self._json(200, {"certs": self.manager.store.list_certs()})

        if path == "/api/audit":
            if not self._authorized():
                return self._json(401, {"error": "nicht angemeldet"})
            return self._json(
                200, {"audit": self.manager.store.recent_audit(limit=200)}
            )

        if path == "/api/status":
            if not self._authorized():
                return self._json(401, {"error": "nicht angemeldet"})
            return self._json(
                200,
                {
                    "cf_api": self.manager.cf.has_token,
                    "cf_mode": self.manager.mode_name,
                    "base_url": self.manager.base_url,
                    "certs": len(self.manager.store.list_certs()),
                },
            )

        if path in ("/", "/index.html"):
            if not self._authorized():
                return self._send(200, self._login_page())
            return self._send(200, self._admin_page())

        return self._send(404, self._page("Nicht gefunden", "<p>404</p>"))

    # ----------------------------------------------------------- POST-Routen

    def do_POST(self):
        if self.mode == "public":
            return self._public_post()
        return self._admin_post()

    def _public_post(self):
        parsed = urlparse(self.path)
        path = parsed.path
        remote = self._client_ip()

        if not path.startswith("/onboard/"):
            return self._send(404, "nicht gefunden")

        token = path[len("/onboard/"):].strip("/")
        data = self._read_json()
        password = str(data.get("password", ""))

        if not self.manager.check_client(remote, bucket="onboard"):
            self.manager.store.audit(
                "rate-limited", detail=f"{remote}", remote=remote
            )
            return self._send(
                429,
                self._page(
                    "Zu viele Versuche",
                    "<p>Bitte in 15 Minuten erneut versuchen.</p>",
                ),
            )

        try:
            bundle, device = self.manager.deliver(token, password, remote=remote)
        except PermissionError:
            return self._send(
                401,
                self._page(
                    "Falsches Passwort",
                    "<p>Das Passwort stimmt nicht.</p>",
                ),
            )
        except NotSignedError as e:
            # Temporaerer Zustand: der Link ist noch gueltig, es fehlt
            # nur die Signatur.
            return self._send(
                409,
                self._page("Noch nicht signiert", f"<p>{e}</p>"),
            )
        except ValueError as e:
            # "Link nicht mehr gueltig" - verbraucht, abgelaufen, unbekannt.
            return self._send(410, self._page("Link nicht mehr gültig", f"<p>{e}</p>"))
        except Exception as e:  # noqa: BLE001
            # Technischer Fehler (z.B. Schluessel-Dekryption). Das ist
            # kein Benutzerfehler - deshalb 500 und kein 410.
            self.manager.log(f"[certmgr] Fehler bei der Auslieferung: {e}")
            return self._send(
                500,
                self._page(
                    "Interner Fehler",
                    "<p>Die Auslieferung ist fehlgeschlagen. Bitte den "
                    "Admin-Bereich prüfen.</p>",
                ),
            )

        filename = f"certmgr-{device}.zip"
        self._send(
            200,
            bundle,
            "application/zip",
            {"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def _admin_post(self):
        parsed = urlparse(self.path)
        path = parsed.path
        remote = self._client_ip()
        data = self._read_json()

        if path == "/api/login":
            # Eigene Bremse fuer den Admin-Login. scrypt allein bremst
            # nicht - ein Versuch kostet nur ~50 ms, das wuerde im LAN
            # rund 1700 Versuche pro Minute erlauben. Der Admin-Port ist
            # zwar nur ueber nginx im LAN erreichbar, aber ein
            # LAN-Angreifer soll das Passwort nicht raten koennen.
            if not self.manager.check_client(remote, bucket="login", limit=8):
                self.manager.store.audit(
                    "login-rate-limited", remote=remote
                )
                return self._json(
                    429,
                    {"error": "Zu viele Fehlversuche. Bitte in 15 Minuten "
                              "erneut versuchen."},
                )
            pw = str(data.get("password", ""))
            if not self.auth.check_password(pw):
                self.manager.store.audit("login-failed", remote=remote)
                return self._json(401, {"error": "falsches Passwort"})
            # Erfolgreicher Login: die Bremse zuruecksetzen, sonst
            # sperrt ein Nutzer sich selbst aus.
            self.manager.clear_rate_limit(remote, bucket="login")
            self.manager.store.audit("login", remote=remote)
            cookie = (
                f"{SESSION_COOKIE}={self.auth.make_session()}; Path=/; "
                "HttpOnly; SameSite=Strict; Max-Age=%d" % SESSION_TTL
            )
            return self._json(200, {"ok": True}, {"Set-Cookie": cookie})

        if path == "/api/logout":
            # Die Session serverseitig sperren - ein nur geloeschtes
            # Cookie waere ein abgefangenes Cookie weiterhin wert.
            token = self._session_token()
            if token:
                self.auth.revoke_session(token)
            cookie = f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            return self._json(200, {"ok": True}, {"Set-Cookie": cookie})

        if not self._authorized():
            return self._json(401, {"error": "nicht angemeldet"})

        if path == "/api/create":
            try:
                result = self.manager.create(
                    device=data.get("device", ""),
                    note=data.get("note", ""),
                    validity_days=int(data.get("validity_days", 365) or 365),
                    remote=remote,
                )
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                return self._json(500, {"error": str(e)})
            return self._json(200, result)

        if path == "/api/revoke":
            try:
                row = self.manager.revoke(
                    data.get("id", ""), remote=remote, reason=data.get("reason", "")
                )
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            return self._json(200, {"cert": row})

        if path == "/api/reactivate":
            try:
                row = self.manager.reactivate(data.get("id", ""), remote=remote)
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            return self._json(200, {"cert": row})

        if path == "/api/attach":
            try:
                row = self.manager.attach_certificate(
                    data.get("id", ""), data.get("certificate", ""), remote=remote
                )
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            return self._json(200, {"cert": row})

        if path == "/api/sync":
            n = self.manager.sync_status()
            return self._json(200, {"changed": n})

        return self._json(404, {"error": "nicht gefunden"})

    # ------------------------------------------------------------- Seiten

    def _page(self, title, body):
        return f"""<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
 body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
      background:#0f1115;color:#e6e9ef;font:15px/1.6 system-ui,-apple-system,sans-serif}}
 .card{{background:#171a21;border:1px solid #2a2f3a;border-radius:12px;padding:28px 32px;
       max-width:440px;width:calc(100% - 40px)}}
 h1{{font-size:20px;margin:0 0 14px}}
 p{{color:#98a1b3;margin:0 0 14px}}
 input{{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #2a2f3a;
       background:#0f1115;color:#e6e9ef;font-size:15px;box-sizing:border-box}}
 button{{width:100%;margin-top:12px;padding:11px;border:0;border-radius:8px;background:#7aa2f7;
        color:#0f1115;font-size:15px;font-weight:600;cursor:pointer}}
 .err{{color:#e78a8a;font-size:14px;min-height:20px;margin-top:10px}}
 code{{font-family:ui-monospace,monospace;font-size:13px;background:#1e222b;padding:2px 6px;border-radius:4px}}
</style></head><body><div class="card"><h1>{title}</h1>{body}</div></body></html>"""

    def _onboard_page(self, row):
        device = row["device"]
        return self._page(
            "Zertifikat abholen",
            f"""<p>Gerät <code>{device}</code></p>
<p>Gib das Passwort ein, das du bekommen hast. Der Download ist einmalig
möglich - danach ist der Link tot.</p>
<input id="pw" type="password" placeholder="Onboarding-Passwort" autofocus>
<button id="go">Zertifikat herunterladen</button>
<div class="err" id="err"></div>
<script>
const btn=document.getElementById('go'),pw=document.getElementById('pw'),err=document.getElementById('err');
btn.onclick=async()=>{{
  err.textContent='';btn.disabled=true;btn.textContent='lade...';
  try{{
    const r=await fetch(location.pathname,{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{password:pw.value}})}});
    if(r.ok){{
      const b=await r.blob();
      const a=document.createElement('a');
      a.href=URL.createObjectURL(b);
      a.download='certmgr-{device}.zip';
      a.click();
      btn.textContent='geladen ✓';
      setTimeout(()=>{{document.body.innerHTML='<div class="card"><h1>Fertig</h1><p>Das Zertifikat wurde heruntergeladen. Installiere es jetzt aus dem ZIP (siehe INSTALL.txt). Dieser Link ist ab jetzt tot.</p></div>';}},2500);
      return;
    }}
    const t=await r.text();
    err.textContent = r.status===429 ? 'Zu viele Versuche - bitte 15 Minuten warten.'
      : r.status===401 ? 'Falsches Passwort.'
      : 'Dieser Link ist nicht mehr gültig.';
  }}catch(e){{err.textContent='Fehler: '+e;}}
  btn.disabled=false;btn.textContent='Zertifikat herunterladen';
}};
pw.addEventListener('keydown',e=>{{if(e.key==='Enter')btn.click();}});
</script>""",
        )

    def _login_page(self):
        return self._page(
            "Cert-Manager",
            """<p>Admin-Bereich. Passwort eingeben.</p>
<input id="pw" type="password" placeholder="Admin-Passwort" autofocus>
<button id="go">Anmelden</button>
<div class="err" id="err"></div>
<script>
document.getElementById('go').onclick=async()=>{
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({password:document.getElementById('pw').value})});
  if(r.ok){location.href='/';}else{document.getElementById('err').textContent='Falsches Passwort.';}
};
</script>""",
        )

    def _admin_page(self):
        with open(os.path.join(STATIC, "admin.html"), encoding="utf-8") as fh:
            return fh.read()


def serve(manager, auth, host="127.0.0.1", public_port=8103, admin_port=8104):
    """Startet beide Listener. Blockiert.

    Der Admin-Port laeuft zusaetzlich in einem Thread, damit der
    oeffentliche Port nicht blockiert, wenn jemand die Admin-Seite
    laedt.
    """
    public_handler = type("PublicHandler", (Handler,), {
        "manager": manager, "auth": auth, "mode": "public",
    })
    admin_handler = type("AdminHandler", (Handler,), {
        "manager": manager, "auth": auth, "mode": "admin",
    })

    public_srv = ThreadingHTTPServer((host, public_port), public_handler)
    admin_srv = ThreadingHTTPServer((host, admin_port), admin_handler)
    for srv in (public_srv, admin_srv):
        srv.daemon_threads = True

    t = threading.Thread(target=admin_srv.serve_forever, daemon=True)
    t.start()
    print(f"[certmgr] Onboarding (public) auf http://{host}:{public_port}")
    print(f"[certmgr] Admin        auf http://{host}:{admin_port}")
    try:
        public_srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        public_srv.shutdown()
        admin_srv.shutdown()
