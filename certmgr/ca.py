"""Krypto-Teil des Cert-Managers.

Drei Aufgaben:

1. Schluessel + CSR erzeugen. Der private Schluessel entsteht HIER, im
   Dienst. Er wird nie an Cloudflare geschickt - nur der CSR. Das ist der
   Grund, warum der ganze Dienst ueberhaupt lokal laeuft: niemand sonst
   sieht den Schluessel.

2. Private Schluessel at rest verschluesseln. AES-256-GCM, Schluessel aus
   der Master-Key-Datei per scrypt abgeleitet. Das ist Schutz gegen
   "jemand liest die Festplatte" - kein Schutz gegen einen Angreifer mit
   Root-Zugriff auf den laufenden Dienst.

3. Passwoerter hashen. scrypt mit eigenem Salt, Format wie beim
   Hermes-Dashboard: scrypt$n$r$p$salt_b64$hash_b64.
"""
import base64
import hashlib
import hmac
import os
import secrets
import zipfile
from io import BytesIO

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

# Gute Werte fuer scrypt. $2b$ statt $2a$, 16 MiB Speicher.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32


# --------------------------------------------------------------- Schluessel


def generate_key():
    """Neuer ECDSA-Key (P-256).

    ECDSA statt RSA: kleinere Keys, schneller. Alle modernen Browser und
    Betriebssysteme koennen ECDSA-P256-Client-Zertifikate.
    """
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def build_csr(key, common_name, organization="Homelab", ou="certmgr"):
    """CSR mit dem Subject, den Cloudflare spaeter als CN uebernimmt."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        ]
    )
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


def key_fingerprint(key):
    """Kurzer, gut lesbarer Fingerprint des oeffentlichen Schluessels."""
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:16]


# ------------------------------------------------------- Verschluesselung


def _check_permissions(path):
    """Prueft, dass die Secret-Datei nicht zu offen ist.

    Der Master-Key schuetzt alle privaten Schluessel. Ist die Datei
    fuer andere lokale User lesbar, koennte jeder von ihnen die
    Schluessel aller Zertifikate entschluesseln. Deshalb: Gruppe und
    Others duerfen nichts lesen.
    """
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        raise ValueError(
            f"Master-Key-Datei hat zu weite Rechte ({oct(mode)[2:]}). "
            f"Erwartet: 600. Korrigiere mit: chmod 600 {path}"
        )


def load_master_key(path):
    """Master-Key aus Datei. 32 Byte, hex oder base64.

    Wird beim Start einmal gelesen und im Speicher gehalten. Die Datei
    bekommt 0600.

    Die Erkennung ist bewusst strikt: es muss genau 32 Byte herauskommen.
    Sonst koennte eine base64-Zeichenkette, die zufaellig auch gueltiges
    Hex ist, als 22-Byte-Hex-Schluessel durchgehen - und dann waere
    die Ableitung eine andere als beim Erzeugen.
    """
    raw = open(path, "rb").read().strip()
    if not raw:
        raise ValueError(f"Master-Key-Datei ist leer: {path}")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(f"Master-Key-Datei enthaelt kein ASCII: {path}")

    candidates = []
    # Hex zuerst, aber nur wenn die Laenge zu genau 32 Byte passt.
    if len(text) == 64:
        try:
            candidates.append(("hex", bytes.fromhex(text)))
        except ValueError:
            pass
    # Base64: 32 Byte ergeben 44 Zeichen mit Padding.
    try:
        candidates.append(("base64", base64.b64decode(text, validate=True)))
    except Exception:
        pass

    for kind, key in candidates:
        if len(key) == KEY_LEN:
            # Rechte zuerst pruefen, dann korrigieren. Sonst wuerde
            # das chmod die Warnung wieder verstecken - und der
            # Dienst laeuft auf einem read-only-Mount, auf dem das
            # chmod ohnehin fehlschlaegt.
            _check_permissions(path)
            # Der Mount ist read-only - chmod schlaegt dann fehl. Die
            # Rechte setzt das Installationsskript auf dem Host.
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return key

    raise ValueError(
        f"Master-Key muss genau {KEY_LEN} Byte ergeben (hex oder base64), "
        f"bekam: {[f'{k}:{len(v)}' for k, v in candidates] or 'kein gueltiges Format'}"
    )


def _derive(master_key, salt):
    """scrypt-Ableitung: Master-Key + Salt -> 32 Byte AES-Schluessel."""
    return hashlib.scrypt(
        master_key, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_LEN
    )


def encrypt_key(master_key, pem):
    """Privater Schluessel -> AES-GCM-Blob.

    Format: magic(4) | version(1) | salt(16) | nonce(12) | ciphertext
    """
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    aes_key = _derive(master_key, salt)
    blob = AESGCM(aes_key).encrypt(nonce, pem.encode(), None)
    return b"CMK1" + b"\x01" + salt + nonce + blob


def decrypt_key(master_key, blob):
    """AES-GCM-Blob -> privater Schluessel (PEM-String)."""
    if not blob:
        raise ValueError("Kein Schluessel gespeichert")
    if blob[:4] != b"CMK1":
        raise ValueError("Unbekanntes Schluesselformat")
    version = blob[4]
    if version != 1:
        raise ValueError(f"Nicht unterstuetzte Schluesselversion {version}")
    salt = blob[5:21]
    nonce = blob[21:33]
    ct = blob[33:]
    aes_key = _derive(master_key, salt)
    return AESGCM(aes_key).decrypt(nonce, ct, None).decode()


# ------------------------------------------------------------ Passwoerter


def hash_password(password, salt=None):
    """scrypt-Hash im Hermes-Format: scrypt$n$r$p$salt$hash."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def verify_password(password, stored):
    """Konstante Zeit. Falsch bei jedem Fehler - inkl. kaputtem Hash."""
    try:
        _, n, r, p, salt_b64, hash_b64 = stored.split("$")
        dk = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
        )
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except Exception:
        return False


def generate_password(n_words=4):
    """Einmal-Passwort, das man sich am Telefon diktieren kann.

    Unambigues Alphabet (kein O/0, kein l/1) in Vierergruppen.
    """
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    groups = []
    for _ in range(n_words):
        groups.append("".join(secrets.choice(alphabet) for _ in range(4)))
    return "-".join(groups)


def generate_token(nbytes=32):
    """Onboarding-Token: URL-sicher und lang genug."""
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode().rstrip("=")


def hash_token(token):
    """Token wird nur als Hash gespeichert. Ein DB-Dump reicht dann nicht."""
    return hashlib.sha256(token.encode()).hexdigest()


def token_fingerprint(token):
    """Kurze Anzeige fuer das Audit-Log, ohne den Token preiszugeben."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


# ------------------------------------------------------------------ Bundle


def build_p12(key_pem, cert_pem, password):
    """PKCS#12-Bundle fuer Windows/macOS/iOS-Import.

    Das P12 enthaelt den privaten Schluessel UND das Zertifikat. Das
    Passwort dafuer ist das Onboarding-Passwort - der Empfaenger hat es
    bereits, es muss also nicht noch einmal kommuniziert werden.
    """
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    # Der Name wird als Bytes uebergeben: cryptography 46 verlangt das,
    # 50 akzeptiert auch Strings. Bytes funktionieren in beiden.
    name = cert.subject.rfc4514_string().encode()
    return pkcs12.serialize_key_and_certificates(
        name=name,
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )


INSTALL_HINT = """Installation des Client-Zertifikats
=====================================

WICHTIG: Es geht um das CLIENT-Zertifikat (das beweist deine Identitaet),
nicht um ein Server-Zertifikat. Der Browser zeigt einen Zertifikats-Prompt.

Dateien im Archiv
-----------------
  client.p12   Cert + privater Schluessel, mit Passwort geschuetzt.
                Das ist die Datei, die du brauchst.
  client.crt   Das Zertifikat allein (PEM). Nur zur Info/Pruefung.
  client.key   Der private Schluessel allein (PEM, unverschluesselt).
                Nur fuer Kommandozeilen-Werkzeuge.

Firefox (Linux/macOS/Windows)
-----------------------------
  1. Zertifikatsverwaltung oeffnen: Einstellungen -> Privacy & Security ->
     Certificates -> View Certificates -> Authorities -> Importieren.
     Alternativ: about:config -> security.enterprise_roots.enabled (nur
     fuer System-CAs, nicht noetig fuer Client-Zertifikate).
  2. "client.p12" importieren, Passwort = dein Onboarding-Passwort.
     Haken bei "This certificate will identify you as a website" NICHT
     setzen - das ist fuer Server-Zertifikate.
  3. Beim naechsten Aufruf von ki.boreddev1.cc fragt Firefox nach dem
     Zertifikat und bietet das importierte an.

Chrome / Edge (Windows, macOS)
------------------------------
  Windows: Doppelklick auf client.p12 -> "Alle Zertifikate speichern" ->
  certmgr. Der Assistent fragt nach dem Passwort (dein Onboarding-Passwort).
  Danach ist das Zertifikat im Windows-Speicher und Chrome nutzt es
  automatisch.
  macOS: Doppelklick auf client.p12 -> Keychain oeffnet sich, Passwort
  eingeben -> zur Schluesselkette hinzufuegen. In Chrome ->
  chrome://settings/security -> Zertifikate verwalten.

Chrome / Edge (Linux)
---------------------
  Chrome nutzt auf Linux die NSS-Datenbank, nicht den System-Keyring:
    openssl pkcs12 -in client.p12 -nodes -out client.pem
    certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n certmgr -i client.pem
  Alternativ mit dem PKCS#12-Import in Firefox und dann in Chrome
  ueber die Systemintegration.

Kommandozeile testen
--------------------
  curl --cert client.p12:DEIN_PASSWORT https://ki.boreddev1.cc/
  Erwartet: die Open-WebUI-Seite. Ohne --cert: HTTP 403.
"""


def build_bundle_zip(key_pem, cert_pem, password):
    """ZIP mit Zertifikat, Schluessel, P12 und Installationshilfe."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("client.crt", cert_pem)
        zf.writestr("client.key", key_pem)
        zf.writestr(
            "client.p12", build_p12(key_pem, cert_pem, password)
        )
        zf.writestr("INSTALL.txt", INSTALL_HINT)
    return buf.getvalue()
