#!/usr/bin/env python3
"""End-to-End-Test des Cert-Managers gegen eine Mock-Cloudflare-API.

Testet den kompletten Lebenszyklus, ohne echte Zertifikate zu erzeugen:
  create -> deliver (einmalig) -> zweiter Versuch -> revoke -> sync
"""
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certmgr import ca  # noqa: E402
from certmgr.app import AdminAuth  # noqa: E402
from certmgr.cfapi import CloudflareClient  # noqa: E402
from certmgr.manager import CertManager, NotSignedError  # noqa: E402
from certmgr.store import Store  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"  \033[32mPASS\033[0m {name}")
    else:
        print(f"  \033[31mFAIL\033[0m {name} {detail}")
        FAILURES.append(name)


class MockCF(CloudflareClient):
    """Cloudflare-API als Attrappe. Signiert mit einer lokalen Test-CA."""

    def __init__(self):
        super().__init__(token="mock", zone_id="mockzone")
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timedelta, timezone

        self._key = ca.generate_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mock CA")])
        self._ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        self.certs = {}
        self.revoked = set()
        self._n = 0

    def create_client_certificate(self, csr_pem, validity_days=365):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from datetime import datetime, timedelta, timezone

        csr = x509.load_pem_x509_csr(csr_pem.encode())
        self._n += 1
        cid = f"mock-{self._n:04d}"
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._ca.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        self.certs[cid] = {
            "id": cid,
            "certificate": pem,
            "serial_number": format(cert.serial_number, "x"),
            "fingerprint_sha256": ca.key_fingerprint(self._key),
            "issued_on": "2026-01-01T00:00:00Z",
            "expires_on": "2027-01-01T00:00:00Z",
            "status": "active",
        }
        return cid, pem, dict(self.certs[cid])

    def revoke_client_certificate(self, cert_id):
        self.revoked.add(cert_id)
        self.certs[cert_id]["status"] = "revoked"
        return self.certs[cert_id]

    def list_client_certificates(self):
        return list(self.certs.values())


def main():
    tmp = tempfile.mkdtemp()
    store = Store(os.path.join(tmp, "registry.sqlite"))
    cf = MockCF()
    master = b"M" * 32
    mgr = CertManager(
        store=store, cf=cf, master_key=master,
        base_url="https://access.boreddev1.cc", api_token="apitest",
    )

    print("\n[1] Erstellung")
    res = mgr.create(device="laptop-sven", note="Test", validity_days=365)
    check("Zertifikat erstellt", res["id"].startswith("mock-"))
    check("Passwort zurueckgegeben", len(res["password"]) >= 8, res["password"])
    check("Link erzeugt", res["link"].startswith("https://access.boreddev1.cc/onboard/"))
    check("Link enthaelt Token", len(res["link"].split("/onboard/")[1]) > 20)
    check("Status active", res["status"] == "active", res["status"])

    print("\n[2] Registry")
    row = store.get_cert(res["id"])
    check("Eintrag in DB", row is not None)
    check("Key verschluesselt gespeichert", row["key_blob"] is not None and row["key_blob"][:4] == b"CMK1")
    check("Token nur als Hash", row["token_hash"] != res["link"].split("/onboard/")[1])
    check("Kein Klartext-Key in der DB", b"PRIVATE KEY" not in (row["key_blob"] or b""))

    print("\n[3] Onboarding")
    token = res["link"].split("/onboard/")[1]
    try:
        mgr.deliver(token, "falsches-passwort")
        check("Falsches Passwort abgelehnt", False)
    except PermissionError:
        check("Falsches Passwort abgelehnt", True)
    except Exception as e:
        check("Falsches Passwort abgelehnt", False, repr(e))

    bundle, device = mgr.deliver(token, res["password"])
    check("Bundle geliefert", device == "laptop-sven")
    check("Bundle ist ein ZIP", bundle[:2] == b"PK")
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(bundle)) as zf:
        names = zf.namelist()
        check("client.crt im ZIP", "client.crt" in names)
        check("client.key im ZIP", "client.key" in names)
        check("client.p12 im ZIP", "client.p12" in names)
        check("INSTALL.txt im ZIP", "INSTALL.txt" in names)
        p12 = zf.read("client.p12")
        check("P12 mit Passwort geschuetzt", p12[:2] != b"-----")
    check(
        "P12 laesst sich mit Passwort oeffnen",
        _p12_ok(p12, res["password"]),
    )

    print("\n[4] Einmaligkeit")
    try:
        mgr.deliver(token, res["password"])
        check("Zweite Abholung abgelehnt", False)
    except ValueError as e:
        check("Zweite Abholung abgelehnt", "bereits" in str(e).lower(), str(e))
    row = store.get_cert(res["id"])
    check("Key serverseitig geloescht", row["key_blob"] is None)
    check("key_deleted gesetzt", row["key_deleted"] == 1)
    check("downloaded_at gesetzt", row["downloaded_at"] > 0)

    print("\n[5] Widerruf")
    row = mgr.revoke(res["id"], reason="Test")
    # Cloudflare widerruft asynchron: direkt nach dem API-Call steht das
    # Zertifikat auf pending_revocation, erst der Status-Sync bringt es
    # auf revoked.
    check("Status pending_revocation", row["status"] == "pending_revocation", row["status"])
    check("Bei Cloudflare widerrufen", res["id"] in cf.revoked)
    mgr.sync_status()
    row = store.get_cert(res["id"])
    check("Sync setzt Status revoked", row["status"] == "revoked", row["status"])

    print("\n[6] Abgelaufener Link")
    res2 = mgr.create(device="tablet", validity_days=30)
    token2 = res2["link"].split("/onboard/")[1]
    store.update_cert(res2["id"], token_expires=time.time() - 10)
    try:
        mgr.deliver(token2, res2["password"])
        check("Abgelaufener Link abgelehnt", False)
    except ValueError as e:
        check("Abgelaufener Link abgelehnt", "abgelaufen" in str(e).lower(), str(e))

    print("\n[7] Unbekannter Token")
    try:
        mgr.deliver("unbekannter-token", "egal")
        check("Unbekannter Token abgelehnt", False)
    except ValueError:
        check("Unbekannter Token abgelehnt", True)

    print("\n[8] Rate-Limit")
    for i in range(20):
        mgr.check_client("203.0.113.99")
    check("Rate-Limit greift", mgr.check_client("203.0.113.99") is False)
    check("Andere IP nicht betroffen", mgr.check_client("198.51.100.5") is True)

    print("\n[9] Sync")
    n = mgr.sync_status()
    check("Sync laeuft ohne Fehler", isinstance(n, int))

    print("\n[10] Audit")
    actions = [a["action"] for a in store.recent_audit(50)]
    for expected in ("create", "deliver", "deliver-failed", "revoke"):
        check(f"Audit enthaelt '{expected}'", expected in actions)

    print("\n[11] Manuelle Modus")
    store2 = Store(os.path.join(tmp, "r2.sqlite"))
    mgr2 = CertManager(
        store=store2, cf=CloudflareClient(token=None, zone_id=None),
        master_key=master, base_url="https://access.boreddev1.cc",
    )
    r3 = mgr2.create(device="ohne-token")
    check("Modus manual", r3["status"] == "manual", r3["status"])
    check("CSR wird mitgeliefert", "BEGIN CERTIFICATE REQUEST" in r3["csr"])
    check("ID hat manual-Praefix", r3["id"].startswith("manual-"))
    try:
        mgr2.deliver(r3["link"].split("/onboard/")[1], r3["password"])
        check("Abholung ohne signiertes Cert gesperrt", False)
    except NotSignedError as e:
        check("Abholung ohne signiertes Cert gesperrt", "signiert" in str(e).lower(), str(e))
    except ValueError as e:
        check("Abholung ohne signiertes Cert gesperrt", False, f"falsche Exception: {e}")

    print("\n[11b] Signiertes Zertifikat passt zum Schluessel")
    # CSR des Eintrags holen und mit einem passenden Key signieren.
    import subprocess
    import tempfile as tf
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from datetime import datetime, timedelta, timezone

    r4 = mgr2.create(device="signiert-wrong-key", validity_days=30)
    with tf.NamedTemporaryFile("w", suffix=".csr", delete=False) as f:
        f.write(r4["csr"])
        csr_path = f.name
    # Anderer Key -> passt nicht zum gespeicherten Schluessel.
    subprocess.run(
        "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 "
        f"-out {csr_path}.key 2>/dev/null && openssl x509 -req -in {csr_path} "
        f"-signkey {csr_path}.key -days 30 -out {csr_path}.pem 2>/dev/null",
        shell=True,
    )
    wrong_pem = open(f"{csr_path}.pem").read()
    try:
        mgr2.attach_certificate(r4["id"], wrong_pem)
        check("Fremdes Zertifikat abgelehnt", False, "wurde akzeptiert!")
    except ValueError as e:
        check("Fremdes Zertifikat abgelehnt", "passt nicht" in str(e).lower(), str(e))

    # Richtiger Key: den aus der Registry holen.
    row = mgr2.store.get_cert(r4["id"])
    key_pem = ca.decrypt_key(master, row["key_blob"])
    with open(f"{csr_path}.key", "w") as f:
        f.write(key_pem)
    subprocess.run(
        f"openssl x509 -req -in {csr_path} -signkey {csr_path}.key -days 30 "
        f"-out {csr_path}.ok.pem 2>/dev/null",
        shell=True,
    )
    ok_pem = open(f"{csr_path}.ok.pem").read()
    attached = mgr2.attach_certificate(r4["id"], ok_pem)
    check("Passendes Zertifikat akzeptiert", attached["status"] == "active", attached["status"])
    bundle, dev = mgr2.deliver(r4["link"].split("/onboard/")[1], r4["password"])
    check("Bundle mit passendem Zertifikat lieferbar", bundle[:2] == b"PK", dev)

    print("\n[12] Leeres Device abgelehnt")
    try:
        mgr.create(device="")
        check("Leeres Device abgelehnt", False)
    except ValueError:
        check("Leeres Device abgelehnt", True)

    print("\n[12b] Eingabegrenzen")
    try:
        mgr.create(device="A" * 5000, validity_days=30)
        check("Ueberlanges Device abgelehnt", False)
    except ValueError as e:
        check("Ueberlanges Device abgelehnt", "64" in str(e), str(e)[:60])
    try:
        mgr.create(device="x", note="N" * 100000, validity_days=30)
        check("Ueberlange Note abgelehnt", False)
    except ValueError as e:
        check("Ueberlange Note abgelehnt", "500" in str(e), str(e)[:60])
    r_ok = mgr.create(device="B" * 64, validity_days=30)
    check("64-Zeichen-Device akzeptiert", len(r_ok["common_name"]) == 64)

    print("\n[13] Ungueltige Gueltigkeit abgelehnt")
    try:
        mgr.create(device="x", validity_days=9999)
        check("Ungueltige Gueltigkeit abgelehnt", False)
    except ValueError:
        check("Ungueltige Gueltigkeit abgelehnt", True)

    print()
    if FAILURES:
        print(f"\033[1;31m{len(FAILURES)} Test(s) fehlgeschlagen:\033[0m")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\033[1;32mAlle Tests bestanden.\033[0m")
    return 0


def _p12_ok(p12_bytes, password):
    from cryptography.hazmat.primitives.serialization import pkcs12
    try:
        pkcs12.load_key_and_certificates(p12_bytes, password.encode())
        return True
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
