# Cert-Manager

Lokale Verwaltung der Client-Zertifikate für das **mTLS-Gate** der GUI-Services.

Wenn `ki.boreddev1.cc` aufgerufen wird, fragt die Cloudflare-Edge ein
Client-Zertifikat ab. Nur Geräte mit einem gültigen Zertifikat kommen
durch. Dieses Tool erzeugt diese Zertifikate, verteilt sie sicher an ihre
Empfänger und widerruft sie wieder.

```
                    Internet
                       │
  ┌────────────────────▼─────────────────────────────────────┐
  │ Cloudflare Edge (Free Plan)                             │
  │  ki.boreddev1.cc      → mTLS aktiv, Client-Cert-Prompt   │
  │  access.boreddev1.cc  → nur /onboard/ (kein mTLS)        │
  │  api.boreddev1.cc     → unangetastet (LiteLLM /v1)       │
  └───────────┬──────────────────────────┬──────────────────┘
              │ Tunnel                    │ Tunnel
  ┌───────────▼──────────────┐   ┌───────▼──────────────────┐
  │ nginx :8445              │   │ certmgr :8103 (public)    │
  │ → Open WebUI :8099       │   │ Onboarding: Passwort →    │
  └──────────────────────────┘   │ einmaliger Download       │
                                 └───────────┬──────────────┘
  ┌──────────────────────────┐               │
  │ nginx :8443 (LAN)        │◄──────────────┘
  │ /certmgr/                │   ┌───────────▼──────────────┐
  └──────────────────────────┘   │ certmgr :8104 (admin)     │
                                 │ Admin-GUI + API + SQLite  │
                                 └───────────▲──────────────┘
                                             │ Hermes/MCP (stdio)
```

---

## Was das Tool macht und was nicht

| | |
|---|---|
| **Private Schlüssel** | entstehen **im Dienst** und verlassen ihn nie unverschlüsselt. Zu Cloudflare geht nur der CSR. |
| **CA-Wurzel** | Cloudflare Managed CA (Free-Plan-Constraint, s.u.) |
| **Verwaltung** | SQLite, lokal |
| **Widerruf** | über die Cloudflare-API, asynchron |
| **Onboarding** | Einmal-Link + Passwort pro Gerät, danach ist der Schlüssel weg |
| **Admin-UI** | nur im LAN (`https://<host>:8443/certmgr/`) |
| **Agent-Zugriff** | MCP-Server für Hermes |

### Warum die CA-Wurzel von Cloudflare kommt

Eine eigene CA an der Cloudflare-Edge hochzuladen ("BYOCA") ist
**Enterprise-only**. Dasselbe gilt für Access-mTLS und Workers-mTLS. Im
Free-Plan bleibt nur die Cloudflare Managed CA — die ist kostenlos und
deckt 100 aktive Client-Zertifikate pro Zone.

Was trotzdem komplett bei dir liegt: Schlüsselerzeugung, Verwaltung,
Widerruf, Audit-Log, Onboarding-Portal, Admin-Oberfläche.

> **Auswirkung:** Die Clients müssen **keine** CA installieren. Ein
> Client-Zertifikat prüft der Server, nicht der Client. Nur das
> Server-Zertifikat muss der Browser kennen — und das kommt von
> Cloudflare.
>
> **Bekannte Einschränkung:** Chrome auf Android braucht die vollständige
> Kette im Client-Zertifikat. Die Cloudflare-ROOT-CA ist nicht einzeln
> exportierbar, deshalb ist Android der Problemfall. Desktop, Firefox,
> macOS, Windows und iOS funktionieren.

---

## Installation

```bash
git clone https://github.com/boreddev1/certmgr.git ~/devs/certmgr
cd ~/devs/certmgr
./scripts/install.sh
```

Das Skript ist idempotent. Erzeugte Secrets werden **nicht** überschrieben
— sonst wäre der Master-Key weg und alle gespeicherten Schlüssel unlesbar.

Danach liegt:

| Pfad | Inhalt |
|---|---|
| `~/ai-stack/certmgr/` | der Dienst (Code + Daten) |
| `~/ai-stack/certmgr.yml` | podman-compose-Datei |
| `~/ai-stack/secrets/certmgr-master-key` | verschlüsselt die Private Keys at rest |
| `~/ai-stack/secrets/certmgr-admin-pass` | Login für die Admin-Oberfläche |
| `~/ai-stack/secrets/certmgr-api-token` | Token für den MCP-Server |
| `~/ai-stack/secrets/certmgr-cf-token` | Cloudflare-Token (optional, siehe unten) |
| `~/.config/systemd/user/certmgr.service` | systemd-Unit |

### Cloudflare-Token

Für vollautomatische Ausstellung braucht der Dienst einen API-Token mit:

- `SSL and Certificates Write` — Zertifikate ausstellen und widerrufen
- `Zone WAF Edit` — die mTLS-WAF-Regel
- `Zone DNS Edit` — DNS-Eintrag für das Portal

```bash
echo -n 'ghp_...' > ~/ai-stack/secrets/certmgr-cf-token
systemctl --user restart certmgr.service
```

**Ohne** diesen Token läuft der Dienst im *manuellen Modus*: er erzeugt
den CSR und legt den Eintrag an, das signierte Zertifikat wird dann per
Web-Oberfläche nachgetragen. Alles andere funktioniert gleich.

### Cloudflare-Seite einrichten

```bash
CF_TOKEN=ghp_... ./scripts/cloudflare-setup.sh
```

Das setzt:

1. **mTLS-Hostname-Zuordnung** für `ki.boreddev1.cc` (ohne
   `mtls_certificate_id` = Cloudflare Managed CA)
2. **WAF-Custom-Rule**:
   ```
   http.host in {"ki.boreddev1.cc"} and (not cf.tls_client_auth.cert_verified
                                         or cf.tls_client_auth.cert_revoked)  → block
   ```
   ⚠️ `cert_verified` ist laut Cloudflare-Doku **auch bei widerrufenen
   Zertifikaten `true`**. Deshalb gehört `cert_revoked` zwingend in den
   Ausdruck — sonst bleibt ein gesperrtes Gerät nutzbar.
3. **WAF-Custom-Rule** für das Portal:
   ```
   http.host eq "access.boreddev1.cc" and not starts_with(http.request.uri.path, "/onboard/")
   → block
   ```
   Ohne diese Regel wäre die komplette Admin-API über das Internet
   erreichbar.
4. **DNS-Eintrag** `access.boreddev1.cc` → Tunnel

Der Free-Plan erlaubt 5 Custom Rules — hier werden 2 verbraucht. Das
Rate-Limit läuft **in der App**, nicht an der Edge: die Free-Plan-Regel
kennt im Ausdruck nur `Path`, kein `http.host`, und es gibt nur eine
Stück.

---

## Benutzung

### Admin-Oberfläche (LAN)

`https://192.168.178.63:8443/certmgr/` — Passwort aus
`~/ai-stack/secrets/certmgr-admin-pass`.

- Neues Zertifikat erstellen → Passwort + Einmal-Link erscheinen
- Zertifikate ansehen, widerrufen, reaktivieren
- Aktivitätsprotokoll (wer hat wann was gemacht)

### Der Ablauf

```
Ewen            Hermes/MCP              certmgr            Cloudflare         Client
 │                    │                     │                   │               │
 │─ neues Gerät ─────►│                     │                   │               │
 │                    │─ create_client_cert ─►│                   │               │
 │                    │                     │─ Key+CSR (lokal)  │               │
 │                    │                     │─ POST client_certificates ──────► │
 │                    │                     │◄─ signiertes Cert ─│               │
 │                    │◄─ {password, link} ─│                   │               │
 │◄─ password + https://access.boreddev1.cc/onboard/<token>     │               │
 │                                                                       │
 │                         gibt Person → Passwort + Link  ─────────────────►│
 │                                                                       │
 │                    Onboarding-Seite: Passwort eingeben ──────────────────►│
 │                    Download: client.p12 + client.crt + client.key + INSTALL.txt
 │                    → Key wird serverseitig gelöscht, Token verbrannt     │
 │                                                                       │
 │                    Browser öffnet https://ki.boreddev1.cc ──────────────►│
 │                    Edge fragt Client-Cert an → WAF prüft → Tunnel → WebUI│
```

**Nach dem Download existiert der private Schlüssel nur noch beim
Empfänger.** Ein zweiter Download ist unmöglich — der Token ist
verbrannt, der Key gelöscht. Das ist Absicht: der Server kann ein
verlorenes Zertifikat nicht wiederherstellen, nur neu ausstellen.

### MCP (Hermes)

In `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  certmgr:
    command: /home/ewen/ai-stack/hermes/venv/bin/python
    args:
      - /home/ewen/ai-stack/mcp/certmgr_admin.py
    env:
      CERTMGR_BASE_URL: http://127.0.0.1:8104
      CERTMGR_API_TOKEN_FILE: /home/ewen/ai-stack/secrets/certmgr-api-token
      CERTMGR_MCP_ALLOW_WRITE: '1'
      CERTMGR_MCP_ALLOW_REVOKE: '1'
    enabled: true
```

Werkzeuge:

| Werkzeug | Standard | Beschreibung |
|---|---|---|
| `list_client_certs()` | immer | Alle Zertifikate auflisten |
| `certmgr_status()` | immer | Modus, Anzahl, Basis-URL |
| `create_client_cert(device, validity_days, note)` | nur mit `ALLOW_WRITE` | Ausstellen, gibt Passwort + Link zurück |
| `revoke_client_cert(cert_id, reason)` | nur mit `ALLOW_REVOKE` | Widerrufen |
| `reactivate_client_cert(cert_id)` | nur mit `ALLOW_REVOKE` | Reaktivieren |

Das Sicherheitsmodell ist zweistufig wie beim LiteLLM-MCP-Server: ein
Agent kann nicht versehentlich ein Zertifikat vergeben, weil das
Werkzeug gar nicht existiert, solange der Schalter fehlt.

---

## Erweiterung auf weitere GUI-Services

Aktuell ist nur Open WebUI (`ki.boreddev1.cc`) mTLS-geschützt. Jeder
weitere Service braucht:

1. einen CNAME auf den Tunnel
2. eine Tunnel-Regel in `~/.cloudflared/config.yml`
3. eine mTLS-Hostname-Zuordnung
4. eine WAF-Regel (den Hostnamen in `MTLS_HOSTS` aufnehmen)
5. einen nginx-Server-Block auf einem eigenen Port

Die Zertifikatslogik ändert sich nicht — ein Zertifikat gilt für alle
mTLS-Hostnamen der Zone (Cloudflare validiert account-level).

> **Wichtig:** Die Ports 8443 und 8444 bleiben LAN-only. Kein CNAME
> darauf. Sonst erreicht jemand Open WebUI oder Hermes direkt im LAN
> und umgeht das mTLS-Gate.

---

## Sicherheit

| Thema | Maßnahme |
|---|---|
| Private Keys at rest | AES-256-GCM, Schlüssel aus `certmgr-master-key` per scrypt abgeleitet |
| Master-Key | 32 Byte, Datei 0600, `chmod` beim Start |
| Onboarding-Token | 32 Byte, nur als SHA-256-Hash gespeichert, 24 h gültig, einmalig |
| Passwörter | scrypt (N=16384, r=8, p=1) mit eigenem Salt, konstante Zeit |
| Admin-Login | scrypt-Hash, Session-Cookie HMAC-signiert, HttpOnly, SameSite=Strict |
| Logout | sperrt die Session **serverseitig** — ein abgefangenes Cookie ist danach wertlos |
| Rate-Limit | 12 Fehlversuche pro IP in 15 min (in der App) |
| Header-Injection | `Client-Cert` wird von der Edge gesetzt, der Certmgr prüft selbst |
| Audit-Log | jede Aktion mit Zeitpunkt, Gerät, Quelle |
| Schlüssel nach Download | gelöscht — keine Wiederherstellung möglich |

---

## API

Die JSON-API hört auf `127.0.0.1:8104` (nur Loopback, nie direkt im
Internet).

| Methode | Pfad | Zweck |
|---|---|---|
| POST | `/api/login` | `{password}` → Session-Cookie |
| POST | `/api/logout` | Session serverseitig sperren |
| GET | `/api/certs` | Liste (Bearer-Token oder Session) |
| GET | `/api/audit` | Aktivitätsprotokoll |
| GET | `/api/status` | Modus, Anzahl, Basis-URL |
| POST | `/api/create` | `{device, validity_days, note}` → Passwort + Link |
| POST | `/api/revoke` | `{id, reason}` |
| POST | `/api/reactivate` | `{id}` |
| POST | `/api/attach` | `{id, certificate}` — signiertes PEM nachtragen |
| POST | `/api/sync` | Status mit Cloudflare abgleichen |

Der öffentliche Onboarding-Port `:8103` beantwortet **nur**
`/onboard/<token>` und liefert für alles andere 404.

---

## Tests

```bash
python3 tests/test_e2e.py    # Lebenszyklus gegen eine Mock-API
python3 tests/test_http.py   # beide Ports, Login, API, Onboarding
~/ai-stack/hermes/venv/bin/python tests/test_mcp.py   # MCP-Werkzeuge
```

Der MCP-Test braucht das Hermes-venv, weil dort das `mcp`-Paket liegt.

---

## Aufbau

```
certmgr/
├── __init__.py
├── __main__.py     # Konfiguration, Start, Sync-Loop
├── app.py          # HTTP-Server, beide Ports, Admin-Oberfläche
├── ca.py           # Krypto: Keys, CSR, AES-GCM, scrypt, P12, ZIP
├── cfapi.py        # Cloudflare-API-Client (api- und manual-Modus)
├── manager.py      # Fachlogik: create / deliver / revoke / sync
└── store.py        # SQLite-Registry
mcp/certmgr_admin.py   # MCP-Server für Hermes
deploy/
├── Dockerfile
├── certmgr.yml     # podman-compose
├── certmgr.service # systemd-Unit
└── .dockerignore
scripts/
├── install.sh            # Installation
└── cloudflare-setup.sh   # mTLS + WAF + DNS
tests/
```

### Modus api vs. manual

| | api | manual |
|---|---|---|
| Ausstellung | automatisch über die Cloudflare-API | CSR wird erzeugt, Zertifikat per Hand eingetragen |
| Widerruf | automatisch | lokal markiert, bei späterem Token korrigiert |
| Braucht | CF-Token mit `SSL and Certificates Write` | nichts |

Der Dienst erkennt den Modus beim Start selbst und loggt ihn.

---

## Bekannte Grenzen

- **Widerruf ist asynchron.** Cloudflare verarbeitet ihn über
  `pending_revocation` → `revoked`. Latenz: Sekunden bis Minuten. Für ein
  verlorenes Gerät ist das in Ordnung, für eine Notfall-Sperrung nicht.
- **Chrome auf Android** braucht die vollständige Kette im
  Client-Zertifikat — die CF-ROOT-CA ist nicht einzeln exportierbar.
- **100 aktive Client-Zertifikate** pro Zone (Free-Plan-Kontingent).
  Widerrufe geben Slots frei.
- **`cert_verified` bleibt bei widerrufenen Zertifikaten `true`** — die
  WAF-Regel muss zusätzlich `cert_revoked` prüfen.
- **Der Dienst ist single-tenant.** Er kennt genau eine Zone und eine
  Basis-URL.

---

## Lizenz

MIT
