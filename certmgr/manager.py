"""Fachlogik des Cert-Managers.

Hier passiert der eigentliche Lebenszyklus eines Client-Zertifikats:

    create()  erzeugt Schluessel + CSR, laesst Cloudflare signieren (oder
              markiert den Fall als "manual"), legt das Onboarding-Passwort
              und den Einmal-Token an.

    deliver() gibt das Bundle EINMAL aus: cert.crt, key, p12, Hinweise.
              Danach wird der private Schluessel serverseitig geloescht.

    revoke()  widerruft bei Cloudflare und markiert lokal.

Die Web-Oberflaeche und der MCP-Server benutzen ausschliesslich diese
Funktionen - nicht direkt die Cloudflare-API. So gibt es genau eine
Stelle, an der die Logik sitzt.
"""
import ipaddress
import os
import threading
import time

from . import ca
from .cfapi import CFError

STATUS_ACTIVE = "active"
STATUS_PENDING_REVOCATION = "pending_revocation"
STATUS_REVOKED = "revoked"
STATUS_MANUAL = "manual"          # CSR erzeugt, Zertifikat fehlt noch
STATUS_MANUAL_REVOKED = "manual_revoked"  # lokal widerrufen, CF noch nicht

# Zertifikate duerfen maximal so lange gueltig sein.
MAX_VALIDITY_DAYS = 825  # Browser-/OS-Grenze,-public-CA-Maximum


class NotSignedError(Exception):
    """Das Zertifikat existiert, ist aber noch nicht von Cloudflare signiert.

    Eigenes Exception-Typ, weil der HTTP-Status sich unterscheidet:
    ein noch nicht signiertes Zertifikat ist ein temporaerer Zustand
    (409), ein verbrauchter Link ist endgueltig weg (410).
    """


class CertManager:
    def __init__(self, store, cf, master_key, base_url, logger=print,
                 api_token=""):
        self.store = store
        self.cf = cf
        self.master_key = master_key
        self.base_url = base_url.rstrip("/")
        self.log = logger
        # Token fuer die JSON-API (MCP-Server). Leer = nur Session-Cookie.
        self.api_token = api_token
        self.mode_name = "api" if cf.has_token else "manual"
        # Rate-Limit-Zaehler fuer das Onboarding-Portal: IP -> Zeitstempel
        # der fehlgeschlagenen Versuche. Nur im Arbeitsspeicher - nach
        # einem Neustart faengt die Bremse neu an.
        self._rate = {}
        self._rate_lock = threading.Lock()

    # ------------------------------------------------------------ Ausstellung

    def create(self, device, note="", validity_days=365, common_name=None,
               password=None, remote=""):
        """Neues Client-Zertifikat ausstellen.

        Rueckgabe: dict mit id, password, link, status und - falls es
        schon signiert ist - dem Zertifikat.
        """
        device = (device or "").strip()
        if not device:
            raise ValueError("device fehlt")
        if not 1 <= int(validity_days) <= MAX_VALIDITY_DAYS:
            raise ValueError(
                f"validity_days muss zwischen 1 und {MAX_VALIDITY_DAYS} liegen"
            )

        cn = (common_name or device).strip()
        key = ca.generate_key()
        key_pem = ca.key_to_pem(key)
        csr_pem = ca.build_csr(key, cn)

        # Der Schluessel wird verschluesselt gespeichert, BEVOR er das
        # Haus verlaesst. Erst danach geht der CSR raus.
        key_blob = ca.encrypt_key(self.master_key, key_pem)

        plain_password = password or ca.generate_password()
        token = ca.generate_token()
        now = time.time()

        cert_id = None
        certificate = ""
        meta = {}
        status = STATUS_MANUAL

        if self.cf.has_token:
            try:
                cert_id, certificate, meta = self.cf.create_client_certificate(
                    csr_pem, validity_days
                )
                status = meta.get("status", STATUS_ACTIVE)
                self.mode_name = "api"
            except CFError as e:
                # 403 = Token hat keine Rechte -> manueller Modus.
                # Sonst ist es ein echter Fehler -> weiterwerfen.
                if e.status in (403, 401):
                    self.log(
                        f"[certmgr] Cloudflare-API nicht nutzbar ({e}); "
                        "Zertifikat wird im manuellen Modus angelegt."
                    )
                    cert_id = None
                else:
                    raise
        else:
            self.log("[certmgr] Kein Cloudflare-Token - manueller Modus.")

        if cert_id is None:
            # Ohne CF-ID brauchen wir eine eigene, mit der die spaetere
            # Zuordnung des signierten Zertifikats klappt.
            cert_id = "manual-" + ca.token_fingerprint(token)

        self.store.insert_cert(
            id=cert_id,
            device=device,
            note=note,
            common_name=cn,
            certificate=certificate,
            serial_number=meta.get("serial_number", ""),
            fingerprint=meta.get("fingerprint", ca.key_fingerprint(key)),
            issued_on=meta.get("issued_on", ""),
            expires_on=meta.get("expires_on", ""),
            status=status,
            cf_status=meta.get("status", ""),
            key_blob=key_blob,
            key_deleted=0,
            token_hash=ca.hash_token(token),
            token_expires=now + 24 * 3600,
            password_hash=ca.hash_password(plain_password),
            created_at=now,
            updated_at=now,
        )
        self.store.audit(
            "create",
            device=device,
            detail=f"status={status} cn={cn}",
            remote=remote,
        )

        return {
            "id": cert_id,
            "device": device,
            "common_name": cn,
            "status": status,
            "password": plain_password,
            "link": f"{self.base_url}/onboard/{token}",
            "expires_on": meta.get("expires_on", ""),
            "fingerprint": meta.get("fingerprint", ""),
            "csr": csr_pem if not certificate else "",
            "note": note,
        }

    def attach_certificate(self, cert_id, certificate_pem, remote=""):
        """Signiertes Zertifikat nachtragen (manueller Modus).

        Das Zertifikat muss zum gespeicherten privaten Schluessel
        passen - sonst waere das ausgelieferte P12 unbrauchbar und der
        Empfenger haette ein Zertifikat, das zu keinem Schluessel
        gehoert. Die Pruefung passiert hier, beim Eintragen, nicht
        spaeter beim Download.
        """
        row = self.store.get_cert(cert_id)
        if not row:
            raise ValueError(f"Unbekanntes Zertifikat: {cert_id}")
        if not certificate_pem or "BEGIN CERTIFICATE" not in certificate_pem:
            raise ValueError("Kein gueltiges PEM-Zertifikat uebergeben")

        # Seriennummer, Ablauf und Schluesselzuordnung pruefen.
        serial = ""
        expires = ""
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization

            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            serial = format(cert.serial_number, "x")
            expires = cert.not_valid_after_utc.isoformat()

            # Der oeffentliche Schluessel des Zertifikats muss zum
            # gespeicherten privaten Schluessel gehoeren.
            if not row.get("key_blob"):
                raise ValueError(
                    "Zu diesem Zertifikat ist kein privater Schluessel "
                    "gespeichert - es kann nicht zugeordnet werden."
                )
            key_pem = ca.decrypt_key(self.master_key, row["key_blob"])
            key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            cert_pub = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            key_pub = key.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if cert_pub != key_pub:
                raise ValueError(
                    "Das Zertifikat passt nicht zum gespeicherten privaten "
                    "Schluessel. Wurde der CSR zwischenzeitlich neu "
                    "erzeugt? Dann bitte ein neues Zertifikat ausstellen."
                )
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Zertifikat konnte nicht geprueft werden: {e}")

        self.store.update_cert(
            cert_id,
            certificate=certificate_pem,
            status=STATUS_ACTIVE,
            cf_status=STATUS_ACTIVE,
            serial_number=serial or row.get("serial_number", ""),
            expires_on=expires or row.get("expires_on", ""),
        )
        self.store.audit("attach", device=row["device"], detail=cert_id, remote=remote)
        return self.store.get_cert(cert_id)

    # --------------------------------------------------------------- Abholung

    def deliver(self, token, password, remote=""):
        """Einmalige Auslieferung des Bundles.

        Gibt (bundle_bytes, device) zurueck oder wirft ValueError mit
        verstaendlicher Meldung. Bei Erfolg wird der private Schluessel
        serverseitig geloescht - ab dann gibt es kein zweites Mal.

        Wichtig: die Pruefung "bereits benutzt" und das Loeschen des
        Schluessels passieren in EINEM atomaren Schritt (claim_for_delivery).
        Sonst koennten zwei parallele Abholversuche beide den privaten
        Schluessel bekommen - der Server wuerde das Schluesselmaterial
        zweimal herausgeben.
        """
        token_hash = ca.hash_token(token)
        row = self.store.get_by_token_hash(token_hash)
        if not row:
            raise ValueError("Ungueltiger Link")
        if row.get("downloaded_at"):
            raise ValueError("Dieser Link wurde bereits benutzt")
        if row.get("token_expires", 0) < time.time():
            raise ValueError("Dieser Link ist abgelaufen")
        if not ca.verify_password(password, row.get("password_hash") or ""):
            self.store.audit(
                "deliver-failed", device=row["device"], detail="falsches Passwort",
                remote=remote,
            )
            raise PermissionError("Falsches Passwort")
        if row.get("status") == STATUS_MANUAL:
            raise NotSignedError(
                "Das Zertifikat wurde noch nicht signiert. Bitte den "
                "signierten Zertifikat-PEM im Admin-Bereich eintragen."
            )
        if not row.get("key_blob"):
            raise ValueError("Der private Schluessel ist nicht mehr vorhanden")

        # Atomar beanspruchen. Nur der Gewinner kommt hier durch - und
        # verliert den Key im selben Moment, in dem er ihn abholt.
        if not self.store.claim_for_delivery(row["id"], token_hash):
            self.store.audit(
                "deliver-race", device=row["device"], detail=row["id"], remote=remote
            )
            raise ValueError("Dieser Link wurde bereits benutzt")

        # Der Key ist jetzt aus der DB entfernt. Er existiert nur noch
        # in diesem Speicherbereich - und wird gleich an den Client
        # ausgeliefert.
        key_pem = ca.decrypt_key(self.master_key, row["key_blob"])
        bundle = ca.build_bundle_zip(key_pem, row["certificate"], password)

        self.store.audit(
            "deliver", device=row["device"], detail=row["id"], remote=remote
        )
        return bundle, row["device"]

    # -------------------------------------------------------------- Widerruf

    def revoke(self, cert_id, remote="", reason=""):
        row = self.store.get_cert(cert_id)
        if not row:
            raise ValueError(f"Unbekanntes Zertifikat: {cert_id}")
        if row.get("status") in (STATUS_REVOKED, STATUS_MANUAL_REVOKED):
            return row

        cf_ok = False
        cf_error = ""
        if self.cf.has_token and not str(cert_id).startswith("manual-"):
            try:
                self.cf.revoke_client_certificate(cert_id)
                cf_ok = True
            except CFError as e:
                cf_error = str(e)
                self.log(f"[certmgr] Cloudflare-Widerruf fehlgeschlagen: {e}")

        new_status = (
            STATUS_PENDING_REVOCATION if cf_ok else STATUS_MANUAL_REVOKED
        )
        self.store.update_cert(
            cert_id, status=new_status, cf_status=new_status, key_deleted=1
        )
        self.store.delete_key_blob(cert_id)
        self.store.audit(
            "revoke",
            device=row["device"],
            detail=f"{cert_id} status={new_status} {reason}".strip(),
            remote=remote,
        )
        return self.store.get_cert(cert_id)

    def reactivate(self, cert_id, remote=""):
        row = self.store.get_cert(cert_id)
        if not row:
            raise ValueError(f"Unbekanntes Zertifikat: {cert_id}")
        if self.cf.has_token and not str(cert_id).startswith("manual-"):
            try:
                self.cf.reactivate_client_certificate(cert_id)
            except CFError as e:
                self.log(f"[certmgr] Reaktivierung fehlgeschlagen: {e}")
        self.store.update_cert(
            cert_id, status=STATUS_ACTIVE, cf_status=STATUS_ACTIVE
        )
        self.store.audit("reactivate", device=row["device"], detail=cert_id, remote=remote)
        return self.store.get_cert(cert_id)

    # ------------------------------------------------------------------ Sync

    def sync_status(self):
        """Haelt den lokalen Status mit Cloudflare in Sync.

        Cloudflare widerruft asynchron (pending_revocation -> revoked).
        Der Admin-UI zeigt den lokalen Stand; dieser Sync laeuft
        periodisch im Hintergrund.
        """
        if not self.cf.has_token:
            return 0
        try:
            remote_certs = self.cf.list_client_certificates()
        except CFError as e:
            self.log(f"[certmgr] Status-Sync fehlgeschlagen: {e}")
            return 0
        if not isinstance(remote_certs, list):
            return 0
        changed = 0
        for rc in remote_certs:
            rid = rc.get("id")
            rstatus = rc.get("status", "")
            row = self.store.get_cert(rid)
            if not row:
                continue
            if rstatus and row.get("status") != rstatus:
                self.store.update_cert(rid, status=rstatus, cf_status=rstatus)
                changed += 1
                self.store.audit("sync", device=row["device"], detail=f"{rid} {rstatus}")
        if changed:
            self.log(f"[certmgr] Status-Sync: {changed} Zertifikat(e) aktualisiert")
        return changed

    # -------------------------------------------------------- Zugriffslogik

    def check_client(self, remote_ip):
        """Prueft die Quell-IP gegen die Rate-Limit-Liste.

        Onboarding-Port ist oeffentlich erreichbar. Ohne Bremse koennte
        jemand das Passwort raten. Der Free-Plan erlaubt keine
        Rate-Limit-Regel mit Host-Filter, also passiert das hier.
        """
        try:
            ip = ipaddress.ip_address(remote_ip)
        except ValueError:
            return True
        key = str(ip)
        now = time.time()
        window = 15 * 60
        limit = 12
        with self._rate_lock:
            hits = [t for t in self._rate.get(key, []) if now - t < window]
            if len(hits) >= limit:
                self._rate[key] = hits
                return False
            hits.append(now)
            self._rate[key] = hits
            # Speicher nicht unbegrenzt wachsen lassen.
            if len(self._rate) > 4096:
                for k in list(self._rate):
                    if not [t for t in self._rate[k] if now - t < window]:
                        del self._rate[k]
        return True
