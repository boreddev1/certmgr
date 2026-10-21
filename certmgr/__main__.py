"""Cert-Manager: lokale Verwaltung von Client-Zertifikaten.

Kurzfassung der Aufgaben:

  * Private Schluessel entstehen IM Dienst und verlassen ihn nie
    unverschluesselt. Nur der CSR geht zu Cloudflare.
  * Ausstellung, Widerruf und Status liegen in einer SQLite-Datei.
  * Ein Onboarding-Portal haelt das Zertifikat fuer den Empfaenger
    bereit, bis es genau einmal abgeholt wurde.
  * Eine Admin-Oberflaeche (nur LAN) erlaubt Erstellen und Widerrufen.
  * Ein MCP-Server erlaubt demselben Agenten (Hermes) dieselben
    Aktionen.

Konfiguration kommt aus der Umgebung, damit der Container gleich
bleibt:

  CERTMGR_DATA           Datenverzeichnis (SQLite)          default /data
  CERTMGR_MASTER_KEY     Pfad zur Master-Key-Datei           required
  CERTMGR_ADMIN_PASS     Pfad zur Admin-Passwort-Datei       required
  CERTMGR_API_TOKEN      Pfad zur API-Token-Datei            optional
  CERTMGR_CF_TOKEN       Pfad zum Cloudflare-API-Token       optional
  CERTMGR_ZONE_ID        Cloudflare-Zone-ID                  optional
  CERTMGR_BASE_URL       oeffentliche Basis-URL              required
  CERTMGR_PUBLIC_PORT    Port fuer Onboarding                default 8103
  CERTMGR_ADMIN_PORT     Port fuer Admin                     default 8104
"""
import os
import sys
import threading
import time

from .app import AdminAuth, serve
from .cfapi import CloudflareClient
from .manager import CertManager
from .store import Store

SYNC_INTERVAL = 300  # 5 Minuten


def _read_secret(path, default="", allow_empty=False):
    """Secret-Datei lesen. Fehlt sie, ist das ein Fehler - nicht ein leerer Wert.

    Ein leeres Master-Passwort waere stiller Datenverlust, das darf
    nicht passieren.

    Fuer optionale Secrets gibt es allow_empty=True: dort ist eine leere
    Datei ein gueltiger Zustand (z.B. der Cloudflare-Token, solange er
    noch nicht existiert).
    """
    if not path:
        return default
    if not os.path.exists(path):
        raise SystemExit(f"[certmgr] Secret-Datei fehlt: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        value = fh.read().strip()
    if not value:
        if allow_empty:
            return default
        raise SystemExit(f"[certmgr] Secret-Datei ist leer: {path}")
    return value


def _sync_loop(manager):
    """Periodischer Status-Sync mit Cloudflare im Hintergrund."""
    while True:
        try:
            manager.sync_status()
        except Exception as e:  # noqa: BLE001
            print(f"[certmgr] Sync-Fehler: {e}")
        time.sleep(SYNC_INTERVAL)


def main():
    data_dir = os.environ.get("CERTMGR_DATA", "/data")
    db_path = os.path.join(data_dir, "registry.sqlite")

    master_key_path = os.environ.get("CERTMGR_MASTER_KEY", "")
    if not master_key_path:
        raise SystemExit("[certmgr] CERTMGR_MASTER_KEY fehlt")

    from . import ca

    # Der Master-Key wird genau einmal gelesen und nur als Bytes
    # gehalten. load_master_key prueft dabei auch die Dateirechte -
    # eine zu offene Datei waere ein Fundus fuer jeden lokalen User.
    try:
        master = ca.load_master_key(master_key_path)
    except ValueError as e:
        raise SystemExit(f"[certmgr] Master-Key unbrauchbar: {e}")
    except OSError as e:
        raise SystemExit(f"[certmgr] Master-Key nicht lesbar: {e}")

    admin_pass = _read_secret(os.environ.get("CERTMGR_ADMIN_PASS", ""))
    if not admin_pass:
        raise SystemExit("[certmgr] CERTMGR_ADMIN_PASS fehlt")

    api_token = _read_secret(
        os.environ.get("CERTMGR_API_TOKEN", ""), default="", allow_empty=True
    )
    cf_token = _read_secret(
        os.environ.get("CERTMGR_CF_TOKEN", ""), default="", allow_empty=True
    )
    zone_id = os.environ.get("CERTMGR_ZONE_ID", "").strip()
    base_url = os.environ.get("CERTMGR_BASE_URL", "").strip()
    if not base_url:
        raise SystemExit("[certmgr] CERTMGR_BASE_URL fehlt")

    cf = CloudflareClient(token=cf_token or None, zone_id=zone_id or None)
    if cf.has_token:
        if not zone_id:
            print(
                "[certmgr] Cloudflare-Token gesetzt, aber keine Zone-ID - "
                "der manuelle Modus wird verwendet."
            )
            cf.token = None
        else:
            ok, msg = cf.check_token()
            print(f"[certmgr] Cloudflare-API: {msg}")
            if not ok:
                cf.token = None
    else:
        print("[certmgr] Kein Cloudflare-Token - manueller Modus.")

    store = Store(db_path)
    manager = CertManager(
        store=store,
        cf=cf,
        master_key=master,
        base_url=base_url,
        api_token=api_token,
    )
    auth = AdminAuth(admin_pass)

    print(f"[certmgr] Datenverzeichnis: {data_dir}")
    print(f"[certmgr] Basis-URL: {base_url}")

    threading.Thread(target=_sync_loop, args=(manager,), daemon=True).start()

    serve(
        manager,
        auth,
        host="127.0.0.1",
        public_port=int(os.environ.get("CERTMGR_PUBLIC_PORT", "8103")),
        admin_port=int(os.environ.get("CERTMGR_ADMIN_PORT", "8104")),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
