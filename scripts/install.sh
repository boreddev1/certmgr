#!/usr/bin/env bash
# certmgr installieren: Code nach ~/ai-stack kopieren, Secrets anlegen,
# Container starten, nginx-Route und systemd-Unit einrichten.
#
# Idempotent: laesst sich mehrfach laufen. Erzeugte Secrets werden
# NICHT ueberschrieben (sonst waere der Master-Key weg und alle
# gespeicherten Schluessel unlesbar).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK="${STACK_DIR:-$HOME/ai-stack}"
ZONE_ID="${ZONE_ID:-a5442d8946137e4d48e8020256b3786e}"
BASE_URL="${BASE_URL:-https://access.boreddev1.cc}"
ADMIN_HOST="${ADMIN_HOST:-192.168.178.63}"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWarnung:\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

command -v podman-compose >/dev/null || die "podman-compose fehlt"
[ -d "$STACK" ] || die "Stack-Verzeichnis $STACK fehlt"

# ---------------------------------------------------------------- Code
say "Code nach $STACK/certmgr kopieren"
mkdir -p "$STACK/certmgr"
rm -rf "$STACK/certmgr/certmgr"
cp -r "$REPO/certmgr" "$STACK/certmgr/certmgr"
cp "$REPO/deploy/Dockerfile" "$STACK/certmgr/Dockerfile"
cp "$REPO/deploy/certmgr.yml" "$STACK/certmgr.yml"
mkdir -p "$STACK/certmgr/data"

# -------------------------------------------------------------- Secrets
say "Secrets pruefen"
mkdir -p "$STACK/secrets"
chmod 700 "$STACK/secrets"

gen_secret() {
  local path="$1" len="$2"
  if [ -s "$path" ]; then
    say "  $(basename "$path") existiert bereits - unveraendert"
  else
    openssl rand -base64 "$len" | tr -d '\n' > "$path"
    chmod 600 "$path"
    say "  $(basename "$path") neu erzeugt"
  fi
}

gen_secret "$STACK/secrets/certmgr-master-key" 32
gen_secret "$STACK/secrets/certmgr-admin-pass" 18
gen_secret "$STACK/secrets/certmgr-api-token" 32

# Cloudflare-Token: optional. Ohne ihn laeuft der Dienst im manuellen
# Modus (CSR wird erzeugt, Zertifikat wird per Hand eingetragen).
CF_TOKEN_FILE="$STACK/secrets/certmgr-cf-token"
if [ -s "$CF_TOKEN_FILE" ]; then
  say "  certmgr-cf-token existiert bereits"
else
  printf '' > "$CF_TOKEN_FILE"
  chmod 600 "$CF_TOKEN_FILE"
  warn "certmgr-cf-token ist leer - der Dienst laeuft im manuellen Modus."
  warn "Token mit 'SSL and Certificates Write' dort eintragen, dann:"
  warn "  systemctl --user restart certmgr.service"
fi

# Zone-ID und Basis-URL in die Compose-Datei eintragen
say "Compose-Datei anpassen (Zone-ID, Basis-URL)"
sed -i "s|CERTMGR_ZONE_ID: .*|CERTMGR_ZONE_ID: \"$ZONE_ID\"|" "$STACK/certmgr.yml"
sed -i "s|CERTMGR_BASE_URL: .*|CERTMGR_BASE_URL: \"$BASE_URL\"|" "$STACK/certmgr.yml"

# ------------------------------------------------------------ systemd
say "systemd-Unit einrichten"
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/certmgr.service" <<EOF
[Unit]
Description=Cert-Manager (Client-Zertifikate fuer das mTLS-Gate)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$STACK
ExecStart=/home/ewen/.local/bin/podman-compose -f $STACK/certmgr.yml up -d --build
ExecStop=/home/ewen/.local/bin/podman-compose -f $STACK/certmgr.yml down
TimeoutStartSec=600

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable certmgr.service >/dev/null 2>&1 || true

# --------------------------------------------------------------- nginx
NGINX_CONF="$STACK/config/nginx/open-webui.conf"
if [ -f "$NGINX_CONF" ]; then
  if grep -q "location /certmgr/" "$NGINX_CONF"; then
    say "nginx-Route /certmgr/ existiert bereits"
  else
    say "nginx-Route /certmgr/ ergaenzen"
    cp "$NGINX_CONF" "$NGINX_CONF.bak-certmgr"
    python3 - "$NGINX_CONF" <<'PYEOF'
import re, sys
path = sys.argv[1]
src = open(path, encoding="utf-8").read()
block = '''
    # Cert-Manager: Admin-Oberflaeche fuer Client-Zertifikate.
    # Nur im LAN erreichbar - der Dienst selbst bindet auf Loopback.
    location /certmgr/ {
        proxy_pass http://127.0.0.1:8104/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
'''
# In den ersten Server-Block (Port 8443) einfuegen, vor der letzten }
# Klammer dieses Blocks.
m = re.search(r'(server \{[^}]*?listen 8443 ssl;.*?)(    location = /vault \{)', src, re.S)
if m:
    src = src[:m.end(2)] + block + src[m.end(2):]
    open(path, "w", encoding="utf-8").write(src)
    print("  Location /certmgr/ eingefuegt")
else:
    print("  WARN: Anker nicht gefunden - bitte von Hand eintragen")
PYEOF
  fi
fi

# --------------------------------------------------------------- Start
say "Container starten"
systemctl --user restart certmgr.service || die "Start fehlgeschlagen"

sleep 4
say "Healthcheck"
if curl -fsS --max-time 5 http://127.0.0.1:8104/healthz >/dev/null 2>&1; then
  echo "  Admin-Port antwortet"
else
  warn "Admin-Port antwortet noch nicht - Logs pruefen:"
  warn "  podman logs --tail 40 certmgr"
fi

cat <<EOF

$(say "Fertig. Naechste Schritte:")

  Admin-Oberflaeche : https://$ADMIN_HOST:8443/certmgr/
  Onboarding-Basis   : $BASE_URL/onboard/<token>

  Cloudflare-Token mit 'SSL and Certificates Write' eintragen:
    echo -n 'ghp_...' > $STACK/secrets/certmgr-cf-token
    systemctl --user restart certmgr.service

  MCP-Server in Hermes eintragen (siehe mcp/README.md).
EOF
