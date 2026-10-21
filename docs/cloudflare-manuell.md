# Cloudflare manuell einrichten

Das Skript `scripts/cloudflare-setup.sh` macht alles automatisch, wenn ein
API-Token mit den passenden Rechten vorliegt. Ohne diesen Token sind die
Schritte hier manuell im Dashboard zu erledigen — es sind fünf Klicks.

## 1. API-Token anlegen

Dashboard → **My Profile** → **API Tokens** → **Create Token**.

Berechtigungen:

| Permission | Scope | Wofür |
|---|---|---|
| SSL and Certificates Write | Zone `boreddev1.cc` | Client-Zertifikate ausstellen und widerrufen |
| Zone WAF Edit | Zone `boreddev1.cc` | die beiden mTLS-Regeln |
| Zone DNS Edit | Zone `boreddev1.cc` | CNAME für das Portal |

Dann:

```bash
echo -n 'der_token' > ~/ai-stack/secrets/certmgr-cf-token
systemctl --user restart certmgr.service
```

## 2. mTLS für `ki.boreddev1.cc` aktivieren

Dashboard → **SSL/TLS** → **Client Certificates** → bei **Hosts** auf
**Edit** klicken → `ki` eintragen (die Domain wird automatisch
angehängt) → **Save**.

Ab jetzt fragt die Edge bei `ki.boreddev1.cc` ein Client-Zertifikat ab.

## 3. WAF-Regel: mTLS erzwingen

Dashboard → **Security** → **WAF** → **Custom Rules** → **Create rule**.

*Ausdruck:*
```
(http.host in {"ki.boreddev1.cc"} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
```
*Aktion:* Block

> ⚠️ **`cert_revoked` nicht weglassen.** Laut Cloudflare-Doku ist
> `cert_verified` auch bei widerrufenen Zertifikaten `true`. Ohne den
> zweiten Term bleibt ein gesperrtes Gerät voll nutzbar.

Es gibt im Dashboard eine Vorlage **"Create an mTLS Rule"** — die trägt
den Ausdruck schon richtig ein, aber ohne `cert_revoked`. Der Ausdruck
muss von Hand ergänzt werden.

## 4. WAF-Regel: Portal beschränken

*Ausdruck:*
```
(http.host eq "access.boreddev1.cc" and not starts_with(http.request.uri.path, "/onboard/"))
```
*Aktion:* Block

Ohne diese Regel wäre die komplette Admin-API des Cert-Managers über
`https://access.boreddev1.cc/api/...` erreichbar. Zwar nur mit
Passwort, aber das ist eine zweite Angriffsflaeche, die es nicht geben
muss.

## 5. DNS-Eintrag

Dashboard → **DNS** → **Records** → **Add record**:

| Feld | Wert |
|---|---|
| Type | CNAME |
| Name | `access` |
| Target | `9490c112-d223-4717-927d-0e63614e5399.cfargotunnel.com` |
| Proxy status | Proxied (orange) |
| TTL | Auto |

Für `ki.boreddev1.cc` existiert der CNAME bereits.

## 6. Testen

```bash
# Portal: 404 heisst "unbekannter Token", das Portal lebt
curl -sI https://access.boreddev1.cc/onboard/xyz | head -1

# Admin-API darf nicht durchkommen
curl -sI https://access.boreddev1.cc/api/certs | head -1   # 403

# ki ohne Zertifikat: 403 (WAF blockt)
curl -sI https://ki.boreddev1.cc/ | head -1

# ki mit Zertifikat: 200
curl -sI --cert client.p12:passwort https://ki.boreddev1.cc/ | head -1
```

Wenn `ki.boreddev1.cc` **ohne** Zertifikat `200` liefert, greift die
WAF-Regel nicht. Dann prüfen:

- Ist die mTLS-Hostname-Zuordnung aktiv? (Schritt 2)
- Stimmt der Ausdruck? (`http.host in {"ki.boreddev1.cc"}` — der
  tatsächliche Hostname, nicht der CNAME-Ziel)
- Wurde die Regel veröffentlicht?

## Fehlersuche

| Symptom | Ursache |
|---|---|
| Browser fragt **nicht** nach einem Zertifikat | mTLS-Zuordnung fehlt oder ist am falschen Hostnamen |
| Browser fragt, WAF blockt trotzdem | `cert_revoked` fehlt im Ausdruck, oder Cert ist abgelaufen |
| `403` auf `/api/certs` | Regel aus Schritt 4 greift (gut) oder WAF blockt alles |
| `500` im Onboarding-Portal | Container-Logs prüfen: `podman logs --tail 30 certmgr` |
| Portal liefert `404` statt der Abholseite | Tunnel-Regel fehlt in `~/.cloudflared/config.yml` |
