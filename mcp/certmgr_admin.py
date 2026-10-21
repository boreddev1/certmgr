#!/usr/bin/env python3
"""MCP-Server: Client-Zertifikate verwalten.

Laeuft als stdio-Server unter Hermes. Greift auf die JSON-API des
Cert-Managers zu (127.0.0.1:8104).

Sicherheitsmodell - bewusst zweistufig, wie beim LiteLLM-MCP-Server:

  Standardmaessig sind NUR lesende Werkzeuge registriert.
  Aendernde Werkzeuge (erstellen, widerrufen, reaktivieren) erscheinen
  erst, wenn CERTMGR_MCP_ALLOW_WRITE=1 gesetzt ist. Das Vergeben von
  Zertifikaten und das Sperren gehoeren zu den Aktionen, die ein Agent
  nicht versehentlich ausfuehren sollte.

  Der API-Token wird aus einer Datei gelesen, nicht aus der
  Kommandozeile - so landet er nicht in der Prozessliste.
"""
import json
import os
import pathlib
import urllib.error
import urllib.request

from mcp.server.fastmcp import FastMCP

BASE_URL = os.environ.get("CERTMGR_BASE_URL", "http://127.0.0.1:8104").rstrip("/")
TOKENFILE = os.environ.get(
    "CERTMGR_API_TOKEN_FILE",
    str(pathlib.Path.home() / "ai-stack/secrets/certmgr-api-token"),
)
ALLOW_WRITE = os.environ.get("CERTMGR_MCP_ALLOW_WRITE", "0") == "1"
ALLOW_REVOKE = os.environ.get("CERTMGR_MCP_ALLOW_REVOKE", "0") == "1"

mcp = FastMCP("certmgr")


def _token():
    if not os.path.exists(TOKENFILE):
        raise RuntimeError(
            f"API-Token-Datei fehlt: {TOKENFILE}. Der MCP-Server kann sich "
            "nicht am Cert-Manager anmelden."
        )
    with open(TOKENFILE, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def _call(path, payload=None, method=None):
    url = BASE_URL + path
    data = json.dumps(payload).encode() if payload is not None else None
    try:
        token = _token()
    except RuntimeError as e:
        # Sauberer Fehler statt Absturz: der Agent sieht eine Meldung,
        # keine Traceback-Wand.
        return {"error": str(e)}
    req = urllib.request.Request(
        url,
        data=data,
        method=method or ("POST" if data else "GET"),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return json.loads(raw)
        except Exception:
            return {"error": f"HTTP {e.code}: {raw[:200]}"}
    except urllib.error.URLError as e:
        return {"error": f"Cert-Manager nicht erreichbar: {e.reason}"}


@mcp.tool()
def list_client_certs() -> dict:
    """Alle ausgegebenen Client-Zertifikate auflisten.

    Liefert Geraet, CN, Status, Ablaufdatum und Fingerprint.
    """
    res = _call("/api/certs")
    if "error" in res:
        return res
    return {"certs": res.get("certs", [])}


@mcp.tool()
def certmgr_status() -> dict:
    """Status des Cert-Managers: Modus, Anzahl Zertifikate, Basis-URL."""
    return _call("/api/status")


if ALLOW_WRITE:

    @mcp.tool()
    def create_client_cert(
        device: str, validity_days: int = 365, note: str = ""
    ) -> dict:
        """Ein neues Client-Zertifikat ausstellen.

        Gibt das Onboarding-Passwort und den Einmal-Link zurueck. Beides
        wird dem Empfaenger einmalig uebermittelt - danach ist der Link
        tot und der private Schluessel existiert nur noch beim
        Empfaenger.

        Args:
            device: Geraetename, z.B. "laptop-sven".
            validity_days: Gueltigkeit in Tagen (1-825).
            note: Freitext, z.B. "Wohnzimmer-Rechner".
        """
        return _call(
            "/api/create",
            {"device": device, "validity_days": validity_days, "note": note},
        )

if ALLOW_REVOKE:

    @mcp.tool()
    def revoke_client_cert(cert_id: str, reason: str = "") -> dict:
        """Ein Client-Zertifikat widerrufen.

        Der Zugriff mit diesem Zertifikat endet. Nicht umkehrbar durch
        eine einfache Reaktivierung, wenn Cloudflare den Widerruf bereits
        verarbeitet hat.

        Args:
            cert_id: Die Zertifikats-ID (UUID aus create/list).
            reason: Freitext fuer das Audit-Log.
        """
        return _call("/api/revoke", {"id": cert_id, "reason": reason})

    @mcp.tool()
    def reactivate_client_cert(cert_id: str) -> dict:
        """Ein widerrufenes Zertifikat reaktivieren.

        Args:
            cert_id: Die Zertifikats-ID.
        """
        return _call("/api/reactivate", {"id": cert_id})


if __name__ == "__main__":
    mcp.run()
