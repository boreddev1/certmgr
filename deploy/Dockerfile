# Cert-Manager. Nur cryptography als Abhaengigkeit - alles andere kommt
# aus der Standardbibliothek. Das haelt das Image klein und die
# Abhaengigkeiten ueberschaubar.
FROM docker.io/library/python:3.12-alpine

# cryptography bringt musllinux-Wheels mit, deshalb kein Compiler noetig.
# Nur die Laufzeit-Abhaengigkeiten von cryptography (libffi, openssl)
# werden gebraucht.
RUN apk add --no-cache libffi openssl \
 && pip install --no-cache-dir "cryptography>=42" \
 && rm -rf /root/.cache

# Kein USER-Setz: In rootless podman entspricht UID 0 im Container der
# Host-UID des aufrufenden Users (hier: ewen/1000). Nur so sind die
# 0600-Secret-Dateien ueber den Bind-Mount lesbar. Mit einem eigenen
# USER (UID 1000) wuerde podman auf eine subordinate UID abbilden, und
# der Dienst koennte die Secrets nicht mehr lesen.
#
# Das ist kein Root auf dem Host: rootless podman schuetzt den Host
# genauso, wie es das fuer alle anderen Container im Stack tut.
WORKDIR /app
COPY certmgr/ /app/certmgr/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

CMD ["python", "-m", "certmgr"]
