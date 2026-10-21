#!/usr/bin/env bash
# Cloudflare-Seite einrichten:
#   1. mTLS-Hostname-Zuordnung  (Browser bekommt den Client-Cert-Prompt)
#   2. WAF-Custom-Rule         (nur mit gueltigem Cert durchlassen)
#   3. WAF-Custom-Rule         (Onboarding-Portal auf /onboard/ beschraenken)
#   4. DNS-Eintrag             (access.boreddev1.cc -> Tunnel)
#
# Braucht einen API-Token mit:
#   - SSL and Certificates Write   (mTLS-Hostname-Zuordnung)
#   - Zone WAF Edit                (Custom Rules)
#   - Zone DNS Edit                (DNS-Eintrag)
#
# Aufruf:
#   CF_TOKEN=ghp_... ./scripts/cloudflare-setup.sh
# oder der Token liegt in ~/ai-stack/secrets/certmgr-cf-token
set -euo pipefail

STACK="${STACK_DIR:-$HOME/ai-stack}"
CF_API="https://api.cloudflare.com/client/v4"
ZONE_ID="${ZONE_ID:-a5442d8946137e4d48e8020256b3786e}"
TUNNEL_ID="${TUNNEL_ID:-9490c112-d223-4717-927d-0e63614e5399}"

# Zu schuetzende Hostnames. Der erste ist der mTLS-geschuetzte
# GUI-Service, der zweite das Onboarding-Portal (bewusst OHNE mTLS).
MTLS_HOSTS="${MTLS_HOSTS:-ki.boreddev1.cc}"
PORTAL_HOST="${PORTAL_HOST:-access.boreddev1.cc}"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWarnung:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

TOKEN="${CF_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -s "$STACK/secrets/certmgr-cf-token" ]; then
  TOKEN="$(cat "$STACK/secrets/certmgr-cf-token")"
fi
[ -n "$TOKEN" ] || die "Kein Token. Setze CF_TOKEN=... oder lege $STACK/secrets/certmgr-cf-token an."

API() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" "$CF_API$path" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body"
  else
    curl -sS -X "$method" "$CF_API$path" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json"
  fi
}

# API mit Fehlerbehandlung: gibt den Fehlertext aus, exitet mit 1.
api_checked() {
  local method="$1" path="$2" body="${3:-}"
  local out
  out=$(API "$method" "$path" "$body")
  if printf '%s' "$out" | python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin).get('success') else 1)" 2>/dev/null; then
    printf '%s' "$out"
    return 0
  fi
  local msg
  msg=$(printf '%s' "$out" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    e=d.get('errors') or [{}]
    print(e[0].get('message','unbekannt'))
except Exception:
    print('unbekannt')
" 2>/dev/null || echo "unbekannt")
  printf 'FEHLER: %s\n' "$msg" >&2
  return 1
}

# -------------------------------------------------- 1. mTLS-Hostnamen
say "mTLS-Hostname-Zuordnung setzen"
for host in $MTLS_HOSTS; do
  # Ohne mtls_certificate_id wird die Cloudflare Managed CA verwendet.
  # Das ist die Variante, die im Free-Plan funktioniert.
  body=$(printf '{"hostnames":["%s"]}' "$host")
  if api_checked PUT "/zones/$ZONE_ID/certificate_authorities/hostname_associations" "$body" >/dev/null; then
    echo "  $host: mTLS aktiv"
  else
    warn "  $host: Zuordnung fehlgeschlagen"
    warn "    noetig: Token mit 'SSL and Certificates Write'"
  fi
done

# ------------------------------------------------------ 2. WAF-Regeln
say "WAF-Custom-Rules pruefen"

# Bestehende Regeln der Zone holen, um Doppel-Anlage zu vermeiden.
RULES=$(api_checked GET "/zones/$ZONE_ID/rulesets?phase=http_request_firewall_custom" || echo '{"result":[]}')
RULESET_ID=$(printf '%s' "$RULES" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
except Exception:
    print(''); raise SystemExit
for r in d.get('result',[]):
    if r.get('phase')=='http_request_firewall_custom':
        print(r.get('id')); break
else:
    print('')
" 2>/dev/null || true)

if [ -z "$RULESET_ID" ]; then
  say "  Custom-Ruleset existiert noch nicht - wird angelegt"
  CREATED=$(api_checked POST "/zones/$ZONE_ID/rulesets" \
    '{"name":"certmgr-mtls","kind":"zone","phase":"http_request_firewall_custom","rules":[]}' || echo "")
  RULESET_ID=$(printf '%s' "$CREATED" | python3 -c "import json,sys; print(json.load(sys.stdin).get('result',{}).get('id',''))" 2>/dev/null || echo "")
  if [ -z "$RULESET_ID" ]; then
    die "Konnte kein Ruleset anlegen - der Token braucht 'Zone WAF Edit'."
  fi
  echo "  Ruleset-ID: $RULESET_ID"
fi

add_rule() {
  local desc="$1" expr="$2"
  local existing
  existing=$(api_checked GET "/zones/$ZONE_ID/rulesets/$RULESET_ID" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(sum(1 for r in d.get('result',{}).get('rules',[]) if r.get('description')=='''$desc'''))
" 2>/dev/null || echo 0)
  if [ "$existing" != "0" ]; then
    echo "  '$desc' existiert bereits - uebersprungen"
    return 0
  fi
  local body
  body=$(python3 -c "
import json,sys
print(json.dumps({'description':'''$desc''','expression':'''$expr''','action':'block'}))
")
  if api_checked POST "/zones/$ZONE_ID/rulesets/$RULESET_ID/rules" "$body" >/dev/null; then
    echo "  '$desc' angelegt"
  else
    warn "  '$desc' fehlgeschlagen - der Token braucht 'Zone WAF Edit'"
  fi
}

# Regel 1: mTLS-Durchsetzung.
#
# cert_verified ist laut Cloudflare-Doku AUCH bei widerrufenen Zertifikaten
# true - deshalb muss cert_revoked zwingend mit geprueft werden. Ohne das
# waere ein gesperrtes Geraet weiterhin nutzbar.
add_rule "certmgr: mTLS erzwingen" \
  "(http.host in {\"$MTLS_HOSTS\"} and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))"

# Regel 2: Portal nur auf /onboard/.
#
# Ohne diese Regel waere die komplette Admin-API des Cert-Managers
# ueber das Internet erreichbar - zwar durch das Passwort geschuetzt,
# aber das ist eine zweite Angriffsflaeche, die es nicht braucht.
add_rule "certmgr: Portal auf /onboard/ beschraenken" \
  "(http.host eq \"$PORTAL_HOST\" and not starts_with(http.request.uri.path, \"/onboard/\"))"

# ------------------------------------------------------------- 3. DNS
say "DNS-Eintrag fuer $PORTAL_HOST"
EXISTING=$(api_checked GET "/zones/$ZONE_ID/dns_records?type=CNAME&name=$PORTAL_HOST" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(d.get('result',[{}])[0].get('id','') if d.get('result') else '')
" 2>/dev/null || echo '')

if [ -n "$EXISTING" ]; then
  echo "  existiert bereits (ID $EXISTING)"
else
  BODY=$(printf '{"type":"CNAME","name":"%s","content":"%s.cfargotunnel.com","proxied":true,"ttl":1}' \
    "$PORTAL_HOST" "$TUNNEL_ID")
  if api_checked POST "/zones/$ZONE_ID/dns_records" "$BODY" >/dev/null; then
    echo "  $PORTAL_HOST -> $TUNNEL_ID.cfargotunnel.com"
  else
    warn "  DNS-Eintrag fehlgeschlagen - der Token braucht 'Zone DNS Edit'"
  fi
fi

cat <<EOF

$(say "Naechste Schritte im Dashboard:")

  1. Tunnel-Route in ~/.cloudflared/config.yml ergaenzen:
       - hostname: $PORTAL_HOST
         service: http://127.0.0.1:8103
       - hostname: $MTLS_HOSTS
         service: http://127.0.0.1:8445
     Dann: systemctl --user restart cloudflared-ki.service

  2. Testen:
       curl -sI https://$PORTAL_HOST/onboard/xyz | head -1
       -> 404 (Onboarding-Seite existiert, Token ist falsch)
       -> Die Regel 'Portal auf /onboard/ beschraenken' greift.

EOF
