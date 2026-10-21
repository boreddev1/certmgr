#!/usr/bin/env python3
"""Regressionstests fuer die Security-Fixes.

Deckt die Befunde ab, die im Security-Review gefunden wurden:

  1. TOCTOU: parallele Abholversuche duerfen nicht alle den privaten
     Schluessel bekommen.
  2. Rate-Limit: ein gespoofter CF-Connecting-IP-Header darf die
     Bremse nicht umgehen.
  3. Path-Traversal in der Cloudflare-API: eine ID mit ".." darf
     nicht in einen API-Pfad gelangen.
  4. Master-Key-Datei mit zu weiten Rechten muss abgelehnt werden.
"""
import os
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


def check(name, cond, detail=""):
    if cond:
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        print(f"  \033[31mFAIL\033[0m {name} {detail}")
        FAILURES.append(name)


def make_manager(tmp=None):
    tmp = tmp or tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "r.sqlite"))
    mgr = CertManager(
        store=store, cf=MockCF(), master_key=b"Z" * 32, base_url="https://x"
    )
    return mgr, store


def test_race():
    print("\n[1] TOCTOU: parallele Abholversuche")
    mgr, store = make_manager()
    res = mgr.create(device="race", validity_days=30)
    tok = res["link"].split("/onboard/")[1]

    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            bundle, _ = mgr.deliver(tok, res["password"])
            results.append(True)
        except Exception:
            results.append(False)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok = sum(1 for r in results if r)
    check("Genau ein Download erfolgreich", ok == 1, f"war {ok} von 8")
    check("7 Downloads abgelehnt", ok < 8, f"war {ok}")
    row = store.get_cert(res["id"])
    check("Key serverseitig geloescht", row["key_blob"] is None)
    check("key_deleted gesetzt", row["key_deleted"] == 1)


def test_rate_limit_spoofing():
    print("\n[2] Rate-Limit gegen gespoofte Client-IP")
    # Der Test laeuft gegen die echte HTTP-Schicht: dort entscheidet
    # _client_ip(), ob der CF-Connecting-IP-Header ueberhaupt
    # verwendet wird. Gegen check_client() direkt waere der Test
    # sinnlos - dort kommt ja nur die bereits berechnete IP an.
    import json
    import threading
    import urllib.error
    import urllib.request

    from certmgr.app import AdminAuth, serve

    mgr, _ = make_manager()
    res = mgr.create(device="rl", validity_days=30)
    tok = res["link"].split("/onboard/")[1]

    port = 18503
    stop = threading.Event()

    class Server:
        pass

    from certmgr.app import Handler

    pub = type(
        "PublicHandler",
        (Handler,),
        {"manager": mgr, "auth": AdminAuth("x"), "mode": "public"},
    )
    from http.server import ThreadingHTTPServer

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
        # Spoofing: jede Anfrage mit einer anderen IP. Ohne Fix wuerde
        # das Limit nie greifen.
        codes = [attempt(f"203.0.113.{i}") for i in range(20)]
        limited = 429 in codes
        check(
            "Rate-Limit greift trotz wechselnder Spoof-IP",
            limited,
            f"kein 429 in {codes}",
        )
        check(
            "Nicht alle 20 Versuche durchgelassen",
            codes.count(401) <= 13,
            f"{codes.count(401)} x 401",
        )
    finally:
        httpd.shutdown()



def test_client_ip_header():
    print("\n[3] CF-Connecting-IP wird nur vom Tunnel akzeptiert")
    # Der Header wird nur gewertet, wenn CF-Ray gesetzt ist (Tunnel).
    mgr, _ = make_manager()
    # check_client nutzt die uebergebene IP. Hier geht es um die
    # Entscheidung in app.py - dort wird der Header nur bei
    # CF-Ray + Loopback-Peer gewertet.
    from certmgr.app import Handler

    class H(Handler):
        pass

    h = H.__new__(H)
    h.headers = {"CF-Connecting-IP": "1.2.3.4"}
    h.client_address = ("10.0.0.5", 1234)
    check(
        "Header ohne CF-Ray wird ignoriert",
        h._client_ip() == "10.0.0.5",
        h._client_ip(),
    )

    h2 = H.__new__(H)
    h2.headers = {"CF-Connecting-IP": "1.2.3.4", "CF-Ray": "abc-SJC"}
    h2.client_address = ("127.0.0.1", 1234)
    check(
        "Header vom Tunnel wird uebernommen",
        h2._client_ip() == "1.2.3.4",
        h2._client_ip(),
    )

    h3 = H.__new__(H)
    h3.headers = {"CF-Connecting-IP": "1.2.3.4", "CF-Ray": "abc-SJC"}
    h3.client_address = ("10.0.0.5", 1234)
    check(
        "Header von einem Nicht-Tunnel wird ignoriert",
        h3._client_ip() == "10.0.0.5",
        h3._client_ip(),
    )


def test_path_traversal():
    print("\n[4] Path-Traversal in der Cloudflare-API")
    cf = CloudflareClient(token="x", zone_id="zone123")
    for bad in (
        "../../accounts/OTHER/something",
        "..%2f..%2faccounts",
        "abc/../../def",
        "a" * 100,
        "",
    ):
        try:
            cf.revoke_client_certificate(bad)
            check(f"'{bad[:30]}' abgelehnt", False, "wurde akzeptiert!")
        except CFError:
            check(f"'{bad[:30]}' abgelehnt", True)
        except Exception as e:
            check(f"'{bad[:30]}' abgelehnt", False, f"falsche Exception {e!r}")

    try:
        CloudflareClient(token="x", zone_id="../../evil")
        check("Traversal in der Zone-ID abgelehnt", False)
    except CFError:
        check("Traversal in der Zone-ID abgelehnt", True)


def test_master_key_permissions():
    print("\n[5] Master-Key-Datei mit zu weiten Rechten")
    d = tempfile.mkdtemp()
    p = os.path.join(d, "mk")
    with open(p, "w") as fh:
        fh.write(ca.base64.b64encode(b"K" * 32).decode())
    os.chmod(p, 0o644)
    try:
        ca.load_master_key(p)
        check("Zu offene Datei wird abgelehnt", False, "wurde akzeptiert!")
    except ValueError as e:
        check("Zu offene Datei wird abgelehnt", True)

    os.chmod(p, 0o600)
    key = ca.load_master_key(p)
    check("Korrekte Rechte werden akzeptiert", key == b"K" * 32)


def test_claim_atomicity():
    print("\n[6] claim_for_delivery ist atomar")
    mgr, store = make_manager()
    res = mgr.create(device="claim", validity_days=30)
    th = ca.hash_token(res["link"].split("/onboard/")[1])
    wins = []
    barrier = threading.Barrier(6)

    def worker():
        barrier.wait()
        wins.append(store.claim_for_delivery(res["id"], th))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("Genau ein Gewinner", sum(1 for w in wins if w) == 1, str(wins))


def main():
    test_race()
    test_rate_limit_spoofing()
    test_client_ip_header()
    test_path_traversal()
    test_master_key_permissions()
    test_claim_atomicity()

    print()
    if FAILURES:
        print(f"\033[1;31m{len(FAILURES)} Test(s) fehlgeschlagen:\033[0m")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\033[1;32mAlle Security-Regressionstests bestanden.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
