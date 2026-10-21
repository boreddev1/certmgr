#!/usr/bin/env python3
"""HTTP-Test des Cert-Managers: beide Ports, Login, API, Onboarding."""
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certmgr import ca  # noqa: E402
from certmgr.app import AdminAuth, serve  # noqa: E402
from certmgr.cfapi import CloudflareClient  # noqa: E402
from certmgr.manager import CertManager  # noqa: E402
from certmgr.store import Store  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_e2e import MockCF  # noqa: E402

FAILURES = []
PUBLIC_PORT = 18103
ADMIN_PORT = 18104
BASE = f"http://127.0.0.1:{PUBLIC_PORT}"
ADMIN = f"http://127.0.0.1:{ADMIN_PORT}"


def check(name, cond, detail=""):
    if cond:
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        print(f"  \033[31mFAIL\033[0m {name} {detail}")
        FAILURES.append(name)


def req(url, payload=None, method=None, headers=None, raw=False):
    data = json.dumps(payload).encode() if payload is not None else None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    r = urllib.request.Request(
        url, data=data, method=method or ("POST" if data else "GET"), headers=h
    )
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            body = resp.read()
            if raw:
                return resp.status, body, dict(resp.headers)
            try:
                return resp.status, json.loads(body.decode()), dict(resp.headers)
            except Exception:
                return resp.status, body.decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        if raw:
            return e.code, body, dict(e.headers)
        try:
            return e.code, json.loads(body.decode()), dict(e.headers)
        except Exception:
            return e.code, body.decode(errors="replace"), dict(e.headers)
    except Exception as e:
        return 0, str(e), {}


def main():
    tmp = tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "registry.sqlite"))
    cf = MockCF()
    mgr = CertManager(
        store=store, cf=cf, master_key=b"X" * 32,
        base_url="https://access.boreddev1.cc", api_token="secret-token",
    )
    auth = AdminAuth("admin-passwort")

    t = threading.Thread(
        target=serve,
        args=(mgr, auth),
        kwargs={"public_port": PUBLIC_PORT, "admin_port": ADMIN_PORT},
        daemon=True,
    )
    t.start()
    time.sleep(1.2)

    print("\n[1] Healthchecks")
    s, _, _ = req(f"{BASE}/healthz")
    check("Public-Port antwortet", s == 200, s)
    s, _, _ = req(f"{ADMIN}/healthz")
    check("Admin-Port antwortet", s == 200, s)

    print("\n[2] Onboarding-Port ist abgesperrt")
    for path in ("/", "/admin", "/api/certs", "/static/admin.html"):
        s, _, _ = req(BASE + path)
        check(f"{path} -> 404", s == 404, s)

    print("\n[3] Admin-Port ohne Login")
    s, body, _ = req(f"{ADMIN}/api/certs")
    check("API lehnt ohne Login ab", s == 401, s)

    print("\n[4] Login")
    s, body, hdr = req(f"{ADMIN}/api/login", {"password": "falsch"})
    check("Falsches Passwort -> 401", s == 401, s)
    s, body, hdr = req(f"{ADMIN}/api/login", {"password": "admin-passwort"})
    check("Richtiges Passwort -> 200", s == 200, s)
    cookie = hdr.get("Set-Cookie", "")
    check("Session-Cookie gesetzt", "certmgr_session=" in cookie, cookie)
    check("Cookie ist HttpOnly", "HttpOnly" in cookie)
    check("Cookie ist SameSite=Strict", "SameSite=Strict" in cookie)
    sess = cookie.split("certmgr_session=")[1].split(";")[0]

    print("\n[5] Erstellung via API")
    s, body, _ = req(
        f"{ADMIN}/api/create",
        {"device": "laptop-sven", "validity_days": 365, "note": "Test"},
        headers={"Cookie": f"certmgr_session={sess}"},
    )
    check("Erstellen -> 200", s == 200, s)
    check("Passwort geliefert", "password" in body)
    check("Link geliefert", body.get("link", "").startswith("https://"))
    password = body["password"]
    token = body["link"].split("/onboard/")[1]
    cert_id = body["id"]

    print("\n[6] Bearer-Token funktioniert auch")
    s, body, _ = req(f"{ADMIN}/api/certs", headers={"Authorization": "Bearer secret-token"})
    check("Bearer-Token akzeptiert", s == 200, s)
    s, body, _ = req(f"{ADMIN}/api/certs", headers={"Authorization": "Bearer falsch"})
    check("Falscher Bearer-Token abgelehnt", s == 401, s)

    print("\n[7] Onboarding-Seite")
    s, body, hdr = req(f"{BASE}/onboard/{token}")
    check("Seite liefert 200", s == 200, s)
    check("Seite nennt das Geraet", "laptop-sven" in body)
    check("Passwort-Feld vorhanden", 'type="password"' in body)

    print("\n[8] Onboarding-Download")
    s, body, hdr = req(f"{BASE}/onboard/{token}", {"password": "falsch"})
    check("Falsches Passwort -> 401", s == 401, s)
    s, bundle, hdr = req(
        f"{BASE}/onboard/{token}", {"password": password}, raw=True
    )
    check("Download -> 200", s == 200, s)
    check("Content-Type application/zip", "application/zip" in hdr.get("Content-Type", ""))
    check("Content-Disposition gesetzt", "attachment" in hdr.get("Content-Disposition", ""))
    if isinstance(bundle, bytes):
        with zipfile.ZipFile(BytesIO(bundle)) as zf:
            check("ZIP enthaelt client.p12", "client.p12" in zf.namelist())

    print("\n[9] Einmaligkeit")
    s, body, _ = req(f"{BASE}/onboard/{token}", {"password": password})
    check("Zweiter Versuch -> 410", s == 410, s)
    s, body, _ = req(f"{BASE}/onboard/{token}")
    check("Bereits benutzter Link -> 410", s == 410, s)

    print("\n[10] Unbekannter Token")
    s, body, _ = req(f"{BASE}/onboard/gibtsnicht")
    check("Unbekannter Token -> 404", s == 404, s)

    print("\n[11] Widerruf via API")
    s, body, _ = req(
        f"{ADMIN}/api/revoke",
        {"id": cert_id, "reason": "Test"},
        headers={"Cookie": f"certmgr_session={sess}"},
    )
    check("Widerrufen -> 200", s == 200, s)

    print("\n[12] Audit-Log")
    s, body, _ = req(f"{ADMIN}/api/audit", headers={"Authorization": "Bearer secret-token"})
    check("Audit abrufbar", s == 200, s)
    actions = [a["action"] for a in body.get("audit", [])]
    check("Audit enthaelt create", "create" in actions)
    check("Audit enthaelt revoke", "revoke" in actions)

    print("\n[13] Status-Endpoint")
    s, body, _ = req(f"{ADMIN}/api/status", headers={"Authorization": "Bearer secret-token"})
    check("Status abrufbar", s == 200, s)
    check("Modus gemeldet", body.get("cf_mode") in ("api", "manual"), body.get("cf_mode"))

    print("\n[14] Logout")
    s, _, hdr = req(f"{ADMIN}/api/logout", {}, headers={"Cookie": f"certmgr_session={sess}"})
    check("Logout -> 200", s == 200, s)
    s, _, _ = req(f"{ADMIN}/api/certs", headers={"Cookie": f"certmgr_session={sess}"})
    check("Alte Session nach Logout ungueltig", s == 401, s)

    print("\n[15] Admin-Seite")
    s, body, _ = req(f"{ADMIN}/", headers={"Authorization": "Bearer secret-token"})
    check("Admin-Seite liefert HTML", s == 200 and "Cert-Manager" in body, s)

    print()
    if FAILURES:
        print(f"\033[1;31m{len(FAILURES)} Test(s) fehlgeschlagen:\033[0m")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\033[1;32mAlle HTTP-Tests bestanden.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
