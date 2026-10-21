# Status: was ist erledigt, was fehlt

## Erledigt und verifiziert

| Punkt | Nachweis |
|---|---|
| certmgr laeuft in podman, healthy, systemd-enabled | `podman ps`, `systemctl --user is-enabled` |
| Admin-Oberflaeche nur im LAN | Port 8104 bindet auf `127.0.0.1`, nginx-Route `:8443/certmgr/` |
| Onboarding-Portal nur ueber den Tunnel | Port 8103 bindet auf `127.0.0.1`, CNAME `access.boreddev1.cc` |
| Origin fuer `ki.boreddev1.cc` nur auf Loopback | Port 8445 bindet auf `127.0.0.1` |
| LiteLLM-API unveraendert | `api.boreddev1.cc/v1/models` liefert 401 (Virtual Key noetig) |
| Portal-Pfade ausser `/onboard/` gesperrt | `https://access.boreddev1.cc/api/certs` → 404 |
| Onboarding-Portal erreichbar | `https://access.boreddev1.cc/onboard/<token>` → 200 |
| Security-Review durchgefuehrt, 10 Befunde behoben | `docs/security-review.md`, `tests/test_findings.py` (28 Pruefungen) |
| 143 Tests gruen | test_e2e 46, test_http 37, test_security 18, test_findings 28, test_mcp 14 |
| Registry und Secrets korrekt geschuetzt | `registry.sqlite` 0600, Verzeichnis 0700, Master-Key 0600 |
| Code im GitHub | https://github.com/boreddev1/certmgr |

## OFFEN - das mTLS-Gate ist NICHT aktiv

```
$ curl -sI https://ki.boreddev1.cc/
HTTP/2 200        <- kein 403, kein Cert-Prompt
```

Die Cloudflare-Edge fordert bei `ki.boreddev1.cc` **kein** Client-Zertifikat
an. Es fehlt die mTLS-Hostname-Zuordnung.

Das ist kein Fehler im certmgr - es ist der Teil, der in Cloudflare
konfiguriert werden muss (Free-Plan-Grenze: BYOCA ist Enterprise, die
Cloudflare Managed CA ist der Free-taugliche Weg).

### Warum das nicht per API ging

Der Token in `~/.cloudflared/cert.pem` hat nur DNS-Rechte. Beide
noetigen Endpunkte antworten mit 403:

- `PUT /zones/{z}/certificate_authorities/hostname_associations` → 403
  (benoetigt `SSL and Certificates Write`)
- `POST /zones/{z}/rulesets/.../rules` → 403 (benoetigt `Zone WAF Edit`)

## Was zu tun ist

### Schritt 1 - API-Token anlegen (2 Minuten)

Dashboard → **My Profile** → **API Tokens** → **Create Token** →
**Custom token**:

| Permission | Scope |
|---|---|
| `SSL and Certificates Write` | Zone `boreddev1.cc` |
| `Zone WAF Edit` | Zone `boreddev1.cc` |
| `Zone DNS Edit` | Zone `boreddev1.cc` |

Dann:

```bash
echo -n 'der_neue_token' > ~/ai-stack/secrets/certmgr-cf-token
systemctl --user restart certmgr.service
```

Ab dann laeuft der Dienst im **api-Modus** und stellt Zertifikate selbst
aus (statt den CSR zum Nachtragen zu erzeugen).

### Schritt 2 - Cloudflare-Regeln setzen

```bash
cd ~/devs/certmgr
CF_TOKEN=der_neue_token ./scripts/cloudflare-setup.sh
```

Das setzt:

1. mTLS-Hostname-Zuordnung fuer `ki.boreddev1.cc` (Cloudflare Managed CA)
2. WAF-Regel: mTLS erzwingen
   ```
   http.host in {"ki.boreddev1.cc"} and (not cf.tls_client_auth.cert_verified
                                         or cf.tls_client_auth.cert_revoked) → block
   ```
3. WAF-Regel: Portal auf `/onboard/` beschraenken
4. DNS-Eintrag fuer `access.boreddev1.cc` (existiert schon, wird
   uebersprungen)

**Ohne Token** geht es auch ueber das Dashboard:
`docs/cloudflare-manuell.md` beschreibt die fuenf Klicks.

### Schritt 3 - pruefen

```bash
cd ~/devs/certmgr
python3 scripts/check_waf_rules.py
```

Erwartet:

```
== Onboarding-Portal: nur /onboard/ darf erreichbar sein ==
  /api/certs   -> HTTP 404  ok
  ...
== mTLS-Gate: ki.boreddev1.cc ohne Zertifikat ==
  ohne Client-Zertifikat -> HTTP 403  ok
== mTLS-Gate: fordert die Edge ueberhaupt ein Zertifikat an? ==
  CertificateRequest im TLS-Handshake: ja
```

Der letzte Punkt ist der eigentliche Nachweis: erst wenn dort `ja`
steht, ist das Gate aktiv.

### Schritt 4 - erstes Zertifikat ausstellen

```bash
TOKEN=$(cat ~/ai-stack/secrets/certmgr-api-token)
curl -s -X POST http://127.0.0.1:8104/api/create \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"device":"laptop-test","validity_days":365}'
```

Antwort enthaelt `password` und `link`. In der Admin-Oberflaeche
(`https://192.168.178.63:8443/certmgr/`) steht dasselbe.

### Schritt 5 - Zertifikat installieren und testen

```bash
# Herunterladen (mit dem Passwort aus Schritt 4)
curl -X POST "https://access.boreddev1.cc/onboard/<token>" \
  -H "Content-Type: application/json" -d '{"password":"<passwort>"}' \
  -o certmgr-test.zip

unzip certmgr-test.zip
# client.crt, client.key, client.p12, INSTALL.txt

# Test ohne Zertifikat: 403
curl -sI https://ki.boreddev1.cc/ | head -1

# Test mit Zertifikat: 200
curl -sI --cert client.p12:"<passwort>" https://ki.boreddev1.cc/ | head -1
```

Fuer den Browser: `client.p12` importieren, Anleitung steht in
`INSTALL.txt` im Archiv.

## Zusammenfassung

Der Dienst ist fertig, getestet und in GitHub. Es fehlt die
Cloudflare-seitige Aktivierung des mTLS-Gates - dafuer braucht es einen
Token mit zwei Zusaetzlichen Berechtigungen (Schritt 1) und einen
Aufruf des Setup-Skripts (Schritt 2).

**Sobald Schritt 1 und 2 erledigt sind, funktioniert der Rest ohne
Zutun.**
