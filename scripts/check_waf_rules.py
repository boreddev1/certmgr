#!/usr/bin/env python3
"""Prueft, ob die Cloudflare-WAF-Regeln wirklich greifen.

Die Regel, die den Onboarding-Port auf /onboard/ beschraenkt, liegt im
Cloudflare-Dashboard - nicht in diesem Repository. Faellt sie dort weg
(Edit im Dashboard, neuer Tunnel, zweiter Tunnel ohne die Regel), ist
der komplette Admin-Port des Cert-Managers ueber das Internet
erreichbar. Das faellt nur auf, wenn es jemand prueft.

Dieses Skript macht genau das: es schickt eine Anfrage an einen Pfad
ausserhalb von /onboard/ und erwartet, dass die Edge blockt.

Aufruf:
  python3 scripts/check_waf_rules.py            # nur pruefen
  python3 scripts/check_waf_rules.py --portal   # auch den Onboarding-Portal-Pfad

Rueckgabewert 0 = alles in Ordnung, 1 = Regel fehlt oder wirkt nicht.
"""
import argparse
import sys
import urllib.error
import urllib.request

PORTAL_HOST = "access.boreddev1.cc"
MTLS_HOST = "ki.boreddev1.cc"

# Pfade, die die Edge NICHT durchlassen duerfte. Sie liegen absichtlich
# ausserhalb von /onboard/.
#
# Erwartet wird 403 (WAF blockt) ODER 404 (der certmgr selbst lehnt
# alles ausser /onboard/ ab). Beides ist in Ordnung - 404 ist sogar
# besser, weil die Absicherung dann nicht allein von der WAF-Regel
# abhaengt. 200 waere das Problem: dann waere der Admin-Port
# durchgelassen.
FORBIDDEN_PATHS = [
    "/api/certs",
    "/api/status",
    "/api/audit",
    "/api/create",
    "/",
]

# Werte, die auf ein Durchkommen hindeuten.
BAD_CODES = (200, 201, 204, 301, 302)

# Pfade, die funktionieren MUESSEN.
EXPECTED_OK = [
    "/onboard/nicht-existierender-token",
]


def probe(url, timeout=15):
    """-> (status_code, oder None bei Netzwerkfehler)"""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def client_cert_requested(host, timeout=20):
    """Fragt die Edge im TLS-Handshake nach einem Client-Zertifikat.

    Am zuverlaessigsten ist der Handshake selbst: fordert der Server
    ein Zertifikat an, schickt er eine CertificateRequest-Nachricht.
    Das erkennt man an "Acceptable client certificate CA names" in der
    Ausgabe von openssl s_client.

    Wichtig: das prueft die mTLS-Hostname-Zuordnung, nicht die
    WAF-Regel. Eine fehlende WAF-Regel faellt hier nicht auf - dafuer
    ist der HTTP-Test zustaendig.
    """
    import subprocess

    try:
        out = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{host}:443",
                "-servername", host,
                "-tls1_2",
            ],
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
        ).stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if "Acceptable client certificate CA names" in out:
        return True
    # Manche TLS-Stacken zeigen statt der CA-Namen den Hinweis
    # "No client certificate CA names sent".
    if "No client certificate CA names sent" in out:
        return False
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--portal", action="store_true",
                    help="auch den Onboarding-Portal-Pfad pruefen")
    args = ap.parse_args()

    problems = []

    print("== Onboarding-Portal: nur /onboard/ darf erreichbar sein ==")
    for path in FORBIDDEN_PATHS:
        url = f"https://{PORTAL_HOST}{path}"
        code = probe(url)
        ok = code not in BAD_CODES and code is not None
        print(f"  {path:32} -> HTTP {code}  {'ok' if ok else 'DURCHGELASSEN!'}")
        if not ok:
            problems.append(
                f"{url} lieferte HTTP {code} - der Pfad ist erreichbar. "
                f"Die WAF-Regel und/oder die certmgr-Absicherung fehlen."
            )

    if args.portal:
        print("\n== Onboarding-Portal: /onboard/ muss erreichbar sein ==")
        for path in EXPECTED_OK:
            url = f"https://{PORTAL_HOST}{path}"
            code = probe(url)
            # 404 heisst: das Portal lebt, der Token ist nur unbekannt.
            ok = code == 404
            print(f"  {path:32} -> HTTP {code}  {'ok' if ok else 'PROBLEM'}")
            if not ok:
                problems.append(f"{url} lieferte HTTP {code} statt 404")

    print("\n== mTLS-Gate: ki.boreddev1.cc ohne Zertifikat ==")
    code = probe(f"https://{MTLS_HOST}/")
    ok = code == 403
    print(f"  ohne Client-Zertifikat -> HTTP {code}  {'ok' if ok else 'NICHT BLOCKIERT!'}")
    if not ok:
        problems.append(
            f"https://{MTLS_HOST}/ lieferte HTTP {code} statt 403 - die "
            f"mTLS-WAF-Regel fehlt oder greift nicht"
        )

    print("\n== mTLS-Gate: fordert die Edge ueberhaupt ein Zertifikat an? ==")
    asked = client_cert_requested(MTLS_HOST)
    print(
        f"  CertificateRequest im TLS-Handshake: "
        f"{'ja' if asked else 'NEIN'}"
    )
    if not asked:
        problems.append(
            f"Die Edge fragt bei {MTLS_HOST} kein Client-Zertifikat ab. "
            f"Die mTLS-Hostname-Zuordnung fehlt - das Gate ist nicht aktiv."
        )

    print()
    if problems:
        print("\033[1;31mProblem gefunden:\033[0m")
        for p in problems:
            print(f"  - {p}")
        print()
        print("Die Regeln im Cloudflare-Dashboard pruefen:")
        print("  Security -> WAF -> Custom Rules")
        print("  1. mTLS erzwingen (host + cert_verified + cert_revoked)")
        print("  2. Portal auf /onboard/ beschraenken")
        print("  Alternativ neu aufsetzen: scripts/cloudflare-setup.sh")
        return 1

    print("\033[1;32mAlle Cloudflare-Regeln greifen.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
