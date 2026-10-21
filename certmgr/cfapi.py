"""Cloudflare-API-Client fuer Client-Zertifikate.

Der Dienst arbeitet in zwei Modi:

  api     - Token mit "SSL and Certificates Write". Ausstellung und
            Widerruf laufen vollautomatisch ueber die Cloudflare-API.

  manual  - Kein Token (oder Token ohne passende Rechte). Der Dienst
            erzeugt dann nur den CSR und legt einen Eintrag mit Status
            "manual" an. Das signierte Zertifikat wird danach per
            Web-UI/Paste oder per API nachgetragen. Der Widerruf geht
            dann nur ueber die Cloudflare-API - der lokale Status bleibt
            "revoked_pending_cf" und wird beim naechsten Sync korrigiert.

Der Modus wird zur Laufzeit erkannt und im Log ausgewiesen. Wichtig:
Ein 403 von Cloudflare ist kein Grund, den Dienst anzuhalten - der
manuelle Weg funktioniert ohne jeden Token.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

CF_API = "https://api.cloudflare.com/client/v4"

# Erlaubte Zeichen fuer eine Zertifikats-ID. Cloudflare nutzt UUIDs
# (36 Zeichen). Alles andere wird abgelehnt - sonst koennte ein
# Angreifer mit ".." im Pfad einen ganz anderen API-Endpunkt treffen
# (Path-Traversal in der URL).
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _check_id(value, what="ID"):
    """Prueft eine ID, bevor sie in einen URL-Pfad kommt."""
    v = str(value or "")
    if not _ID_RE.match(v):
        raise CFError(
            f"Ungueltige {what}: nur Buchstaben, Ziffern, '-' und '_' "
            f"erlaubt (max. 64 Zeichen)"
        )
    return v


def _check_zone(zone_id):
    return _check_id(zone_id, "Zone-ID")


class CFError(Exception):
    """Fehler aus der Cloudflare-API."""

    def __init__(self, message, status=None, code=None):
        super().__init__(message)
        self.status = status
        self.code = code


class CloudflareClient:
    def __init__(self, token=None, zone_id=None, timeout=30):
        self.token = token
        self.zone_id = _check_zone(zone_id) if zone_id else None
        self.timeout = timeout

    @property
    def has_token(self):
        return bool(self.token)

    def _request(self, method, path, body=None):
        if not self.token:
            raise CFError("Kein Cloudflare-Token gesetzt")
        url = CF_API + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                errs = json.loads(raw).get("errors", [])
                msg = errs[0].get("message") if errs else raw[:200]
                code = errs[0].get("code") if errs else None
            except Exception:
                msg, code = raw[:200], None
            raise CFError(msg or f"HTTP {e.code}", status=e.code, code=code) from e
        except Exception as e:
            raise CFError(f"Netzwerkfehler: {e}") from e
        if not payload.get("success"):
            errs = payload.get("errors", [])
            raise CFError(
                errs[0].get("message") if errs else "Unbekannter Fehler",
                code=errs[0].get("code") if errs else None,
            )
        return payload.get("result")

    # ------------------------------------------------------------ Zertifikate

    def create_client_certificate(self, csr_pem, validity_days=365):
        """CSR -> signiertes Client-Zertifikat.

        Gibt zurueck: (id, certificate_pem, meta-dict).
        """
        result = self._request(
            "POST",
            f"/zones/{self.zone_id}/client_certificates",
            {"csr": csr_pem, "validity_days": int(validity_days)},
        )
        return (
            result["id"],
            result["certificate"],
            {
                "serial_number": result.get("serial_number", ""),
                "fingerprint": result.get("fingerprint_sha256", ""),
                "issued_on": result.get("issued_on", ""),
                "expires_on": result.get("expires_on", ""),
                "status": result.get("status", "active"),
                "common_name": result.get("common_name", ""),
            },
        )

    def list_client_certificates(self):
        return self._request("GET", f"/zones/{self.zone_id}/client_certificates")

    def get_client_certificate(self, cert_id):
        cert_id = _check_id(cert_id, "Zertifikats-ID")
        return self._request("GET", f"/zones/{self.zone_id}/client_certificates/{cert_id}")

    def revoke_client_certificate(self, cert_id):
        """Widerruf. Cloudflare verarbeitet das asynchron."""
        cert_id = _check_id(cert_id, "Zertifikats-ID")
        return self._request(
            "DELETE", f"/zones/{self.zone_id}/client_certificates/{cert_id}"
        )

    def reactivate_client_certificate(self, cert_id):
        cert_id = _check_id(cert_id, "Zertifikats-ID")
        return self._request(
            "PATCH", f"/zones/{self.zone_id}/client_certificates/{cert_id}", {}
        )

    # ------------------------------------------------- mTLS-Hostname-Zuordnung

    def set_mtls_hostnames(self, hostnames, mtls_certificate_id=None):
        """Hostname-Association fuer mTLS.

        Ohne mtls_certificate_id wird die Cloudflare Managed CA verwendet
        (die ist im Free-Plan enthalten). Mit ID waere es eine eigene CA -
        das ist Enterprise-only und deshalb hier nicht der Default.
        """
        body = {"hostnames": list(hostnames)}
        if mtls_certificate_id:
            body["mtls_certificate_id"] = mtls_certificate_id
        return self._request(
            "PUT", f"/zones/{self.zone_id}/certificate_authorities/hostname_associations", body
        )

    def get_mtls_hostnames(self):
        return self._request(
            "GET", f"/zones/{self.zone_id}/certificate_authorities/hostname_associations"
        )

    # ------------------------------------------------------------- Diagnose

    def check_token(self):
        """Prueft, ob der Token überhaupt Zertifikate verwalten darf.

        Wird beim Start aufgerufen, damit klar ist, in welchem Modus der
        Dienst laeuft. Wirft CFError mit konkretem Hinweis bei 403.
        """
        try:
            self.list_client_certificates()
            return True, "Token hat SSL-and-Certificates-Rechte"
        except CFError as e:
            if e.status == 403:
                return False, (
                    "Token hat kein 'SSL and Certificates Write'. "
                    "Ausstellung laeuft im manuellen Modus."
                )
            if e.status == 404:
                return False, f"Zone nicht gefunden: {e}"
            return False, f"Token-Pruefung fehlgeschlagen: {e}"
