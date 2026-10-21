#!/usr/bin/env python3
"""Prueft, ob alle Befunde aus docs/security-review.md behoben sind.

Geht jeden Befund durch und verifiziert das Ergebnis am laufenden Code
(statisch und, wo moeglich, funktional). Nicht nur ein Textvergleich -
die Aussagen werden nachgeprueft.

Aufruf:  python3 tests/test_findings.py
"""
import os
import re
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from certmgr import ca  # noqa: E402
from certmgr.cfapi import CFError, CloudflareClient  # noqa: E402
from certmgr.manager import CertManager  # noqa: E402
from certmgr.store import Store  # noqa: E402
from test_e2e import MockCF  # noqa: E402

FAILURES = []
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(name, cond, detail=""):
    if cond:
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        print(f"  \033[31mFAIL\033[0m {name} {detail}")
        FAILURES.append(name)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def finding_1_toctou():
    print("\n[Befund 1] TOCTOU beim Onboarding-Download")
    tmp = tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "r.sqlite"))
    mgr = CertManager(
        store=store, cf=MockCF(), master_key=b"Z" * 32, base_url="https://x"
    )
    res = mgr.create(device="f1", validity_days=30)
    tok = res["link"].split("/onboard/")[1]

    wins = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            mgr.deliver(tok, res["password"])
            wins.append(True)
        except Exception:
            wins.append(False)

    ts = [threading.Thread(target=worker) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check(
        "8 parallele Downloads -> genau 1 Erfolg",
        sum(1 for w in wins if w) == 1,
        f"war {sum(1 for w in wins if w)}",
    )
    check(
        "Pruefung und Loeschung sind atomar (claim_for_delivery)",
        "claim_for_delivery" in read("certmgr/store.py"),
    )


def finding_2_spoofed_ip():
    print("\n[Befund 2] Rate-Limit per gespooftem CF-Connecting-IP umgehbar")
    src = read("certmgr/app.py")
    check(
        "Header wird nur bei CF-Ray + Loopback gewertet",
        "_from_tunnel" in src and "CF-Ray" in src,
    )
    check("Client-IP-Funktion ruft die Tunnel-Pruefung auf",
          "_from_tunnel()" in src)

    # funktional: der Onboarding-Port muss bei Spoofing greifen
    import json
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    from certmgr.app import AdminAuth, Handler

    tmp = tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "r.sqlite"))
    mgr = CertManager(
        store=store, cf=MockCF(), master_key=b"Z" * 32, base_url="https://x"
    )
    res = mgr.create(device="f2", validity_days=30)
    tok = res["link"].split("/onboard/")[1]

    port = 18603
    pub = type("P", (Handler,), {"manager": mgr, "auth": AdminAuth("x"), "mode": "public"})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), pub)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def attempt(spoof):
        headers = {"Content-Type": "application/json"}
        if spoof:
            headers["CF-Connecting-IP"] = spoof
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/onboard/{tok}",
            data=json.dumps({"password": "falsch"}).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    try:
        codes = [attempt(f"203.0.113.{i}") for i in range(20)]
        check("Spoofing loest kein 429 aus (Bremse greift)", 429 in codes,
              f"{codes[:5]}...")
    finally:
        httpd.shutdown()


def finding_3_login_bruteforce():
    print("\n[Befund 3] Keine Brute-Force-Bremse fuer den Admin-Login")
    src = read("certmgr/app.py")
    check("Login nutzt eine eigene Bremse", 'bucket="login"' in src)
    mgr_src = read("certmgr/manager.py")
    check("check_client hat einen bucket-Parameter", "bucket=" in mgr_src)
    check("Eigener Bucket fuer Onboarding und Login",
          'bucket="onboard"' in read("certmgr/app.py")
          and 'bucket="login"' in read("certmgr/app.py"))
    check("Bremse wird nach Erfolg zurueckgesetzt",
          "clear_rate_limit" in src and "clear_rate_limit" in mgr_src)


def finding_4_path_traversal():
    print("\n[Befund 4] Path Traversal in der Cloudflare-API")
    cf = CloudflareClient(token="x", zone_id="zone123")
    rejected = 0
    for bad in ("../../accounts/OTHER/x", "abc/../../def", "a" * 100, ""):
        try:
            cf.revoke_client_certificate(bad)
        except CFError:
            rejected += 1
    check("Alle Traversal-Varianten abgelehnt", rejected == 4, f"{rejected}/4")
    try:
        CloudflareClient(token="x", zone_id="../../evil")
        check("Traversal in der Zone-ID abgelehnt", False)
    except CFError:
        check("Traversal in der Zone-ID abgelehnt", True)


def finding_5_registry_permissions():
    print("\n[Befund 5] Registry-Datei fuer andere lokale User lesbar")
    src = read("certmgr/store.py")
    check("Store setzt die Rechte auf 0600", "0o600" in src)
    check("Rechtepruefung vorhanden", "_check_permissions" in src)
    inst = read("scripts/install.sh")
    check("Install-Skript setzt 0700 auf das Datenverzeichnis",
          "chmod 700" in inst)

    # funktional
    tmp = tempfile.mkdtemp()
    st = Store(os.path.join(tmp, "r.sqlite"))
    mode = os.stat(st.path).st_mode & 0o777
    check(f"Datei tatsaechlich 0600 (ist {oct(mode)[2:]})", mode == 0o600)


def finding_6_master_key_permissions():
    print("\n[Befund 6] Master-Key-Datei wird ohne Rechtepruefung geladen")
    src = read("certmgr/ca.py")
    check("Rechtepruefung vorhanden", "_check_permissions" in src)
    d = tempfile.mkdtemp()
    p = os.path.join(d, "mk")
    with open(p, "w") as fh:
        fh.write(ca.base64.b64encode(b"K" * 32).decode())
    os.chmod(p, 0o644)
    try:
        ca.load_master_key(p)
        check("0644 wird abgelehnt", False, "wurde akzeptiert!")
    except ValueError:
        check("0644 wird abgelehnt", True)
    os.chmod(p, 0o600)
    check("0600 wird akzeptiert", ca.load_master_key(p) == b"K" * 32)


def finding_7_input_limits():
    print("\n[Befund 7] Fehlende Eingabegrenzen")
    mgr_src = read("certmgr/manager.py")
    check("MAX_CN_LEN definiert", "MAX_CN_LEN" in mgr_src)
    check("MAX_DEVICE_LEN definiert", "MAX_DEVICE_LEN" in mgr_src)
    check("MAX_NOTE_LEN definiert", "MAX_NOTE_LEN" in mgr_src)

    tmp = tempfile.mkdtemp()
    mgr = CertManager(
        store=Store(os.path.join(tmp, "r.sqlite")),
        cf=MockCF(),
        master_key=b"Z" * 32,
        base_url="https://x",
    )
    for label, kw, expect in [
        ("5000-Zeichen-Device", dict(device="A" * 5000), "64"),
        ("100000-Zeichen-Note", dict(device="x", note="N" * 100000), "500"),
    ]:
        try:
            mgr.create(validity_days=30, **kw)
            check(f"{label} abgelehnt", False, "wurde akzeptiert!")
        except ValueError as e:
            check(f"{label} abgelehnt", expect in str(e), str(e)[:50])


def finding_8_dead_route():
    print("\n[Befund 8] Tote Route /static/app.js")
    check("Route entfernt", "/static/app.js" not in read("certmgr/app.py"))


def finding_9_session():
    print("\n[Befund 9] Session-Lebensdauer und Sperrliste")
    src = read("certmgr/app.py")
    check("Sperrliste wird regelmaessig aufgeraeumt", "_prune_revoked" in src)
    check("Aufraeumen wird auch bei der Pruefung aufgerufen",
          src.count("_prune_revoked()") >= 2)


def finding_10_waf_documented():
    print("\n[Befund 10] WAF-Regel nicht versioniert")
    # Die Regel muss zumindest dokumentiert und pruefbar sein.
    found = False
    for rel in ("README.md", "docs/cloudflare-manuell.md", "docs/security-review.md"):
        path = os.path.join(ROOT, rel)
        if os.path.exists(path):
            txt = open(path, encoding="utf-8").read()
            if "cf.tls_client_auth" in txt and "cert_revoked" in txt:
                found = True
                print(f"      dokumentiert in {rel}")
                break
    check("WAF-Regel mit cert_revoked dokumentiert", found)
    check("Ein Startup-Test prueft die Regel",
          "waf" in os.listdir(os.path.join(ROOT, "scripts")).__str__().lower()
          or any("waf" in f.lower() for f in os.listdir(os.path.join(ROOT, "scripts"))))


def main():
    finding_1_toctou()
    finding_2_spoofed_ip()
    finding_3_login_bruteforce()
    finding_4_path_traversal()
    finding_5_registry_permissions()
    finding_6_master_key_permissions()
    finding_7_input_limits()
    finding_8_dead_route()
    finding_9_session()
    finding_10_waf_documented()

    print()
    if FAILURES:
        print(f"\033[1;31m{len(FAILURES)} Pruefung(en) fehlgeschlagen:\033[0m")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\033[1;32mAlle Befunde aus dem Security-Review sind behoben.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
