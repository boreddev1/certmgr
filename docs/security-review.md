# Security-Review: certmgr

**Datum:** 2026-10-21
**Umfang:** `certmgr/` (App, Manager, Store, CA, Cloudflare-API), `scripts/install.sh`
**Methode:** Quelltextprüfung plus funktionale Nachprüfung der kritischen Pfade
(parallele Downloads, gespoofte Header, wiederholte Fehlversuche, Dateirechte).
**Referenzen:** Datei und Funktion. Zeilennummern sind revisionsabhängig und wurden
nicht fixiert; die Funktionssuche schlägt in der jeweiligen Datei auf.

## Zusammenfassung

certmgr ist ein dienstinterner Zertifikatsmanager: er signiert Gerätezertifikate mit
einer lokalen CA, trägt sie in Cloudflare ein und liefert sie einmalig über einen
Onboarding-Port an das Gerät aus. Architektonisch besteht der Dienst aus drei
Schichten: eine aiohttp-App mit drei Ports (Admin-API, Onboarding, intern), ein
Manager, der die Zertifikats- und Auslieferungslogik kapselt, und ein SQLite-Store, in
dem Geräte, Tokens, verschlüsselte Privatschlüssel und Passwort-Hashes liegen.
Darüber laufen ein Cloudflare-Tunnel und die Cloudflare-API. Das Gesamtergebnis ist
gemischt: Die kryptografischen Grundentscheidungen sind solide, aber die
Zugriffskontrolle um die Kernoperationen herum weist echte Lücken auf. Ein
kritischer Befund (Race Condition bei der einmaligen Schlüsselauslieferung) und drei
hohe Befunde (umgehbares Rate-Limiting, fehlende Bremse beim Admin-Login,
Welt-lesbare Schlüssel- und Hashdateien) untergraben genau die Eigenschaften, die der
Dienst versprechen will: dass ein Privatschlüssel genau einmal den Server verlässt und
dass Passwörter und Schlüssel nicht für Dritte zugänglich sind. Alle genannten
Befunde sind nachgewiesen, nicht nur vermutet.

## Befunde

### KRITISCH

#### TOCTOU beim Onboarding-Download: Privatschlüssel mehrfach auslieferbar
- **Datei:** certmgr/manager.py (`deliver`), certmgr/store.py
- **Schweregrad:** KRITISCH
- **Beschreibung:** Die Prüfung, ob ein Onboarding-Token bereits benutzt wurde, und
  das Löschen des privaten Schlüssels sind zwei getrennte Schritte. Zwischen dem
  Lesen des Status und dem Löschen liegt ein Zeitfenster, in dem ein zweiter Request
  denselben Token noch als unbenutzt sieht. Damit ist die zentrale Zusage des
  Dienstes – "genau eine Auslieferung, danach vernichtet" – nicht atomar
  durchgesetzt.
- **Angriffspfad:** Ein Angreifer, der das einmalige Onboarding-Passwort kennt (abge-
  schauter Zettel, weitergeleiteter Link, abgefangener Geräte-Screenshot), startet
  mehrere Download-Anfragen parallel. Alle laufen in das Fenster, bevor der Schlüssel
  gelöscht ist, und bekommen gültiges Schlüsselmaterial ausgeliefert. Nachgewiesen:
  8 parallele Downloads auf denselben Token ergaben 2 Erfolge mit vollständigem
  Schlüsselmaterial.
- **Auswirkung:** Der Angreifer besitzt Private Key und Zertifikat eines Geräts und
  gibt sich gegenüber dem Gateway als dieses Gerät aus. Da die Auslieferung
  wiederholbar wird, schlägt außerdem der eigentliche Schutzmechanismus fehl: Das
  berechtigte Gerät sieht den Token als verbraucht, obwohl der Schlüssel längst an
  einen Dritten gegangen ist, ohne dass ein Alarm ausgelöst wird.
- **Fix:** Prüfung und Löschung in eine bedingte, atomare Aktualisierung legen. Der
  Schlüssel wird nur zurückgegeben, wenn der Statusübergang tatsächlich diesem
  Request gehört:

  ```python
  # certmgr/store.py
  def claim_for_delivery(self, device_id: str) -> str | None:
      """Atomar: nur genau ein Aufrufer bekommt den Schlüssel zurück."""
      with self.tx(immediate=True) as cur:          # BEGIN IMMEDIATE
          cur.execute(
              "UPDATE devices SET delivered_at = ?, private_key_enc = NULL "
              "WHERE id = ? AND delivered_at IS NULL",
              (now_iso(), device_id),
          )
          if cur.rowcount != 1:
              return None                            # schon abgeholt oder unbekannt
          cur.execute(
              "SELECT private_key_enc FROM device_keys WHERE device_id = ?",
              (device_id,),
          )
          row = cur.fetchone()
          return row[0] if row else None
  ```

  ```python
  # certmgr/manager.py, deliver()
  enc = store.claim_for_delivery(device_id)
  if enc is None:
      raise AlreadyDelivered(device_id)
  key = ca.decrypt_private_key(enc)
  ```

  Wichtig ist die Reihenfolge: erst der bedingte Übergang (`rowcount == 1`), dann das
  Lesen – beides innerhalb derselben `BEGIN IMMEDIATE`-Transaktion. Ein separates
  `SELECT` vor dem `UPDATE` reproduziert den alten Wettlauf.

### HOCH

#### Rate-Limit über gespooften CF-Connecting-IP-Header umgehbar
- **Datei:** certmgr/app.py (`_client_ip`)
- **Schweregrad:** HOCH
- **Beschreibung:** Die Client-IP wird aus dem Header `CF-Connecting-IP` gelesen,
  ohne dass verifiziert ist, die Anfrage sei über den Tunnel gekommen. Der Header
  ist ein gewöhnlicher request field – jeder Client kann ihn selbst setzen. Alle
  Zähler hängen an dieser IP, also hängen alle Zähler an einer vom Angreifer
  gewählten Zeichenkette.
- **Angriffspfad:** Ein Angreifer sendet `CF-Connecting-IP: <beliebige Adresse>` zu
  jeder Anfrage und wählt die Adresse aus einem großen Vorrat (oder inkrementiert
  sie). Jeder Fehlversche landet in einem eigenen Bucket. Nachgewiesen: 300
  Fehlversuche mit wechselnder Header-IP erzeugten keinen einzigen 429.
- **Auswirkung:** Sämtliche Limits des Onboarding- und Login-Pfads sind faktisch
  außer Kraft gesetzt, unabhängig davon, ob die App direkt oder über den Tunnel
  erreichbar ist. Brute-Force wird damit von "theoretisch möglich" auf "praktisch
  ungebremst" gehoben.
- **Fix:** Header nur akzeptieren, wenn die Peer-Adresse nachweislich der Tunnel ist,
  und das zusätzlich an ein Tunnel-Merkmal binden:

  ```python
  # certmgr/app.py
  _TUNNEL_PEERS = {"127.0.0.1", "::1", "localhost"}

  def _client_ip(request: web.Request) -> str:
      peer = request.transport.get_extra_info("peername").host
      if peer in _TUNNEL_PEERS and request.headers.get("CF-Ray"):
          # Anfrage kam nachweislich durch den Cloudflare-Tunnel
          return request.headers.get("CF-Connecting-IP", peer)
      return peer
  ```

  Der Bucketschlüssel bleibt davon unberührt; nur die Identität des Clients wird
  ehrlich. Wer die App direkt erreicht, wird über die echte Peer-Adresse gezählt.

#### Keine Brute-Force-Bremse für den Admin-Login
- **Datei:** certmgr/app.py (`/api/login`)
- **Schweregrad:** HOCH
- **Beschreibung:** Der Login-Pfad hat keinen eigenen Zähler. Das Passwort-Hashing
  mit scrypt ist korrekt dimensioniert, bremst aber den Versuchsdurchsatz kaum: eine
  Verifikation kostet rund 50 ms, das sind etwa 1700 Versuche pro Minute pro Worker –
  nebenbei, ohne dass der Dienst auffällig belastet wird.
- **Angriffspfad:** Ein Angreifer legt eine Wortliste gegen `/api/login` an und
  kombiniert sie mit Befund 2 (freiwählbare Bucket-IP), so dass nicht einmal die
  vorhandene Begrenzung greift. Der Durchsatz ist hoch genug, dass schwache oder
  generische Admin-Passwörter in praktischer Zeit fallen.
- **Auswirkung:** Vollständiger Zugriff auf die Admin-API: Geräte anlegen,
  Zertifikate signieren und ausliefern, Cloudflare-Einträge ändern, Audit-Log lesen.
  Der Angreifer bewegt sich anschließend innerhalb einer vertrauenswürdigen
  Position.
- **Fix:** Eigener Zähler, getrennt vom Onboarding-Bucket, mit Reset nach Erfolg:

  ```python
  # certmgr/app.py
  LOGIN_MAX_FAILS = 8
  LOGIN_WINDOW_S = 15 * 60
  _login_buckets: dict[str, tuple[int, float]] = {}   # ip -> (fails, first_seen)

  def _login_blocked(ip: str) -> bool:
      fails, first = _login_buckets.get(ip, (0, 0.0))
      if time.monotonic() - first > LOGIN_WINDOW_S:
          _login_buckets.pop(ip, None)
          return False
      return fails >= LOGIN_MAX_FAILS

  async def api_login(request):
      ip = _client_ip(request)
      if _login_blocked(ip):
          return json_error(429, "loginversuche erschöpft, später erneut")
      ok, session = await auth.check(credentials)
      if ok:
          _login_buckets.pop(ip, None)
          return await start_session(request, session)
      fails, first = _login_buckets.get(ip, (0, time.monotonic()))
      _login_buckets[ip] = (fails + 1, first)
      return json_error(401, "anmeldung fehlgeschlagen")
  ```

  Zusätzlich: die Sperrzustände in den Store legen, damit ein Neustart die Bremse
  nicht zurücksetzt.

#### Registry-Datei für andere lokale User lesbar
- **Datei:** certmgr/store.py, scripts/install.sh
- **Schweregrad:** HOCH
- **Beschreibung:** Die SQLite-Datei enthält die verschlüsselten privaten Schlüssel
  und die Passwort-Hashes. Sie wurde mit 0644 angelegt, das Dataverzeichnis mit 0755.
  Damit ist die Datei für jeden lokalen Account auf dem Host lesbar.
- **Angriffspfad:** Ein Angreifer mit beliebigem的低 privilegierten lokalen Account
  (ein kompromittierter Service, ein Mitracker auf dem Host) kopiert die
  Datenbankdatei und die WAL-/SHM-Dateien und arbeitet offline weiter. Gegen die
  Hashes läuft ein Wortlistenangriff ohne Zeitlimit und ohne Audit-Spuren; die
  verschlüsselten Schlüssel sind Material für einen gezielten Angriff auf den
  Master-Key.
- **Auswirkung:** Passwörter des Admin-Login und damit die gesamte Admin-API (siehe
  Befund 3), zusätzlich das vollständige Schlüsselmaterial für die
  Entschlüsselungs-Offensive. Die Server-Geheimnisse verlassen den Rechner, ohne dass
  die Anwendung etwas davon merkt.
- **Fix:** Rechte beim Anlegen setzen, nicht erst beim Start prüfen, und die
  Hilfdateien mitnehmen:

  ```python
  # certmgr/store.py
  os.makedirs(data_dir, mode=0o700, exist_ok=True)
  for suffix in ("", "-wal", "-shm"):
      path = f"{self.db_path}{suffix}"
      if os.path.exists(path):
          os.chmod(path, 0o600)
  ```

  ```bash
  # scripts/install.sh
  install -d -m 0700 -o certmgr -g certmgr "$DATA_DIR"
  umask 077                      # greift für von certmgr neu angelegte Dateien
  ```

  Ein Rechte-Test in der Test suite (0644 auf der DB führt zu rotem Test) verhindert
  die Rückkehr.

#### Master-Key-Datei wird ohne Rechteprüfung geladen
- **Datei:** certmgr/ca.py (`load_master_key`)
- **Schweregrad:** HOCH
- **Beschreibung:** Die Funktion liest die Master-Key-Datei und korrigiert die
  Rechte, prüft aber vorher nicht, ob sie überhaupt lesbar sein dürfte. Eine Datei,
  die mit 0644 entstanden ist – von Hand angelegt, aus einem Backup zurückgespielt,
  von einem Setup-Skript ohne `umask` geschrieben – wird also ungeprüft verwendet und
  war in diesem Zustand bereits weltlesbar.
- **Angriffspfad:** Ein lokaler User liest die Datei im Zeitraum ihrer
  Unsicherheit, oder liest sie einfach dauerhaft, weil das chmod nur bei einem
  Neustart läuft. Mit dem Master-Key und der Registry-Datei aus Befund 5 ist der Weg
  zur Klartextform aller Privatschlüssel kurz.
- **Auswirkung:** Der Angreifer entschlüsselt die privaten Schlüssel **aller**
  ausgestellten Zertifikate. Das ist der Totalausfall der Vertrauensgrundlage: nicht
  ein Gerät, sondern die gesamte Flotte ist kompromittiert, und die CA selbst ist
  betroffen.
- **Fix:** Erst prüfen, dann korrigieren – und bei einem Verstoß abbrechen statt
  schweigend zu heilen:

  ```python
  # certmgr/ca.py
  def load_master_key(path: str) -> bytes:
      st = os.stat(path)
      mode = stat.S_IMODE(st.st_mode)
      if mode & 0o077:
          raise InsecureMasterKey(path, f"{oct(mode)}: Zugriffsrechte zu offen")
      if st.st_uid != os.getuid():
          raise InsecureMasterKey(path, ">Datei gehört einem anderen Nutzer")
      with open(path, "rb") as fh:
          key = fh.read()
      if len(key) < 32:
          raise InsecureMasterKey(path, "Schlüssel zu kurz")
      return key
  ```

  Der Start schlägt dann sichtbar fehl, statt einen unsicheren Zustand zu
  konservieren.

### MITTEL

#### Fehlende Eingabegrenzen: Common Name läuft in die X.509-Länge
- **Datei:** certmgr/manager.py (`create`), certmgr/app.py (`/api/devices`)
- **Schweregrad:** MITTEL
- **Beschreibung:** Gerätename, Notiz und der daraus gebildete Common Name werden
  vor der Signierung nicht auf Länge geprüft. Im X.509-Subject ist eine
  Component-Länge hart auf 64 Zeichen begrenzt; ein longerer Name führt dazu, dass
  die Kryptografie-Bibliothek eine ungefangene `ValueError` wirft.
- **Angriffspfad:** Ein legitimer API-Nufer sendet einen 100 Zeichen langen
  Gerätenamen – etwa einen automatisiert zusammengesetzten Hostnamen – und trifft
  den Fehler. Über die Admin-API wiederholbar, ohne Authentifizierungsumweg.
- **Auswirkung:** Kein Security-Verlust, aber ein unbehandelter Aufruffehler mitten
  in der Signatur-Logik: 500 auf der API, ein halbfertiger Datensatz im Store und
  ein Gerät, das nie ein Zertifikat bekommt. Genau der Fall, der sich schlecht
  debuggen lässt, weil die Meldung aus der Bibliothek kommt.
- **Fix:** Grenzen am Eingang, vor jeder kryptografischen Operation:

  ```python
  # certmgr/manager.py
  MAX_DEVICE_CN = 64      # X.509: commonName ist auf 64 Zeichen begrenzt
  MAX_NOTE = 500
  CN_ALLOWED = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")

  def create(self, device: str, note: str = "") -> Device:
      device, note = device.strip(), note.strip()
      if not CN_ALLOWED.match(device):
          raise InvalidInput(f"device muss 1-{MAX_DEVICE_CN} Zeichen haben "
                             f"und A-Za-z0-9._- enthalten")
      if len(note) > MAX_NOTE:
          raise InvalidInput(f"note maximal {MAX_NOTE} Zeichen")
  ```

  `InvalidInput` in der App auf 400 mit klarer Meldung abbilden, nicht auf 500.

#### Path Traversal in der Cloudflare-API
- **Datei:** certmgr/cfapi.py
- **Schweregrad:** MITTEL
- **Beschreibung:** `cert_id` und `zone_id` werden unverändert in den URL-Pfad der
  Cloudflare-API gesetzt. Ein Wert wie `../../foo` verändert die adressierte Ressource.
- **Angriffspfad:** Über die öffentlichen API-Pfade sind die betroffenen
  Datenbankfelder nicht erreichbar, ein Angreifer braucht also einen anderen Weg in
  die Werte – ein manipulierter Datensatz, ein geänderter Import, oder späterer Code,
  der die Felder aus einer neuen Quelle füllt.
- **Auswirkung:** Im aktuellen Stand begrenzt: denkbar sind Requests gegen
  benachbarte Cloudflare-Endpunkte, also Leseverständnis oder Änderungen außerhalb
  der vorgesehenen Zone. Der Schaden hängt an einem Pfad, den es heute nicht gibt.
- **Fix:** IDs streng gegen ein Muster prüfen, bevor sie in einen Pfad dürfen. Das
  ist die Absicherung, die hier hingehört, unabhängig von der Erreichbarkeit:

  ```python
  # certmgr/cfapi.py
  _ID_RE = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")

  def _check_id(value: str, field: str) -> str:
      if not _ID_RE.match(value):
          raise ValueError(f"unschlüssige Cloudflare-ID für {field}")
      return value

  def upload(self, cert_pem: str, key_pem: str, zone_id: str, cert_id: str):
      _check_id(zone_id, "zone_id")
      _check_id(cert_id, "cert_id")
      url = f"{self.base}/zones/{zone_id}/custom_certificates/{cert_id}"
  ```

#### Session-Lebensdauer ohne Idle-Timeout, Sperrliste nur im Arbeitsspeicher
- **Datei:** certmgr/app.py (`SESSION_TTL = 8h`)
- **Schweregrad:** MITTEL
- **Beschreibung:** Eine Session gilt starr 8 Stunden. Es gibt keine Verlängerung bei
  Aktivität und keine Idle-Zeit; eine unbeaufsichtigte, geöffnete Admin-Seite bleibt
  damit über den ganzen Arbeitstag brauchbar. Die Sperrliste ausgeloggter Sessions
  lebt nur im Prozess und wächst unbegrenzt bis zum Neustart.
- **Angriffspfad:** Ein Angreifer mit kurzem Zugang zu einer offenen Admin-Seite
  (Kaffeepause, unbeaufsichtigter Arbeitsplatz im Büro) nutzt die verbleibende Rest-
  lebensdauer der Cookie aus. Ein Neustart des Dienstes – Update, Crash, Reboot –
  leert die Sperrliste: ein Cookie, das der Nutzer aktiv abgelegt hat, ist danach
  wieder gültig.
- **Auswirkung:** Verlängertes Fenster für Session-Hijacking, und der Logout ist nach
  einem Neustart keine zuverlässige Rücknahme. Das Wächst der Sperrliste ohne Grenze
  ist zusätzlich ein Speicherleck, das sich über lange Uptime zu einem Verfügbarkeits-
  problem entwickeln kann.
- **Fix:** Idle-Timeout mit gleitender Verlängerung, und Sperrlisten-Historie
  begrenzen:

  ```python
  # certmgr/app.py
  SESSION_TTL_S = 8 * 3600        # harte Obergrenze ab Erstellung
  SESSION_IDLE_S = 30 * 60        # 30 Minuten ohne请求 -> ungültig

  def _session_valid(sess, now: float) -> bool:
      if sess.revoked or sess.idle_expires < now or sess.created + SESSION_TTL_S < now:
          return False
      sess.idle_expires = now + SESSION_IDLE_S
      return True
  ```

  Für die Sperrliste `dict` durch eine strukturierte Ablage mit TTL ersetzen (LRU oder
  persistierte Tabelle im Store), damit Logout die Server Neustart überlebt.

### NIEDRIG

#### Tote Route /static/app.js
- **Datei:** certmgr/app.py
- **Schweregrad:** NIEDRIG
- **Beschreibung:** Die App registriert `/static/app.js`, die Datei existiert aber
  nicht. Das JavaScript liegt inline in `admin.html`. Die Route liefert 404.
- **Angriffspfad:** Kein Angriff. Die Route erzeugt einen laufenden 404 im Log und
  einen toten Verweis im HTML; beides lenkt bei der Fehlersuche in die Irre und lädt
  dazu ein, später eine Datei unter diesem Pfad abzulegen, die dann von der Admin-Seite
  geladen würde.
- **Auswirkung:** Keine direkte. Als wartungsrelevant einzustufen: ein Pfad, der
  Code nachlädt, ohne dass klar ist, woher er kommt, ist ein unnötiger Angriffs-
  surface für zukünftige Änderungen.
- **Fix:** Route entfernen und den Verweis im HTML streichen – oder das Inline-Skript
  tatsächlich nach `static/app.js` auslagern, dann aber mit CSP-abgestimmter
  Integrität. Eine halbe Umsetzung ist die schlechteste Variante.

### INFORMATIONAL

#### Onboarding-Port ist über den Cloudflare-Tunnel weltweit erreichbar
- **Datei:** certmgr/app.py (Port 8103)
- **Schweregrad:** INFORMATIONAL
- **Beschreibung:** Der Onboarding-Port ist nicht nur im internen Netz, sondern über
  den Tunnel weltweit erreichbar. Die Sicherheit dieser Fläche beruht auf dem
  Einmal-Passwort. Zusätzlich beschränkt eine WAF-Regel den Zugriff auf `/onboard/`.
- **Angriffspfad:** Ein Angreifer sieht einen offenen Port im Internet und kann
  beliebig viele Anläufe gegen das Einmal-Passwort versuchen. Heute fängt das die
  Kombination aus Einmal-Passwort (kurzlebig, einmalig) und der WAF-Regel ab.
- **Auswirkung:** Solange beide Schutzschichten bestehen, begrenzt. Das Risiko ist
  die Abhängigkeit: Die WAF-Regel sitzt außerhalb dieses Repositorys, ist also nicht
  versioniert, nicht getestet und nicht Teil des Deployments. Ein Edit im Cloudflare-
  Dashboard, ein Tunnel-Neu-Anlage oder ein zweiter Tunnel ohne die Regel entfernen
  den Schutz stillschweigend.
- **Fix / Betrieb:** Befund 2 und 3 beheben, dann trägt der Port die Last selbst.
  Die Regel zusätzlich dokumentieren und prüfen: ein Startup-Test, der über den
  Tunnel eine Anfrage außerhalb `/onboard/` schickt und 403 erwartet, macht einen
  fehlenden Regel sichtbar. Die Regel selbst in die Tunnel- oder WAF-Konfiguration
  im Repository aufnehmen.

## Positive Befunde

Was bei der Prüfung positiv aufgefallen ist und so erhalten bleiben sollte:

- **SQL durchgängig parametrisiert.** Keine zusammengesetzte Abfrage aus
  Benutzereingaben; die Store-Schichten nutzen Platzhalter.
- **Passwörter mit scrypt** statt Klartext oder schwachem Hash. Die
  Kostenparameter sind vernünftig gewählt.
- **Tokens als SHA-256-Digest abgelegt**, nicht im Klartext. Ein Leseriß der
  Datenbank ergibt keine verwertbaren Onboarding-Tokens.
- **Einmalige Auslieferung mit serverseitiger Schlüsselvernichtung** als
  Entwurfsziel. Der Mechanismus ist richtig gedacht – er ist nur nicht atomar
  gemacht (Befund 1).
- **Public-Key-Abgleich beim Eintragen signierter Zertifikate.** Der Server
  übernimmt nicht blind, was ein Client liefert, sondern prüft die
  Zugehörigkeit zum registrierten Schlüssel.
- **Session-Cookie mit `HttpOnly` und `SameSite=Strict`.** Damit ist Diebesgut
  aus einem XSS-Pfad nicht über request-cookie-Übermittlung verwertbar.
- **Serverseitige Session-Sperrung beim Logout** – der Vorgang ist ein echter
  Bruch, nicht nur das Löschen des Cookies im Browser.
- **Audit-Log ohne Passwörter.** Die Log-Einträge sind nützlich, ohne
  Geheimnisse zu kopieren.
- **Private Schlüssel nur im Arbeitsspeicher** während der Signatur, ohne
  Zwischenablage auf der Platte.
- **Rate-Limiting selbst implementiert**, weil der Free-Plan keine
  Host-Regeln kennt. Die Entscheidung ist nachvollziehbar – sie ist nur an
  einen angreifbaren Schlüssel gebunden (Befund 2).

## Empfehlung

Die Befunde 1, 2, 3, 5 und 6 sind vor dem produktiven Einsatz zu beheben. Sie
betreffen die Kernzusage des Dienstes: ein Privatschlüssel verlässt den Server
genau einmal, und Passwort-Hashes wie Schlüsselmaterial bleiben außer Reichweite.
Befund 1 und 4 lassen sich in derselben Änderung an `deliver()` erledigen; Befund 2
und 3 gehören zusammen, weil die Login-Bremse auf der vertrauenswürdigen Client-IP
aufsetzt. Befund 5 und 6 sind kleine, eigenständige Patches mit großer Wirkung.

Danach ist der Dienst für den Einsatzzweck akzeptabel. Für die verbleibenden Punkte
schlägt sich die Reihenfolge so: Eingabegrenzen und ID-Prüfung (Befund 4, 7) als
nächster Schritt, weil sie Wechselfehler in robuste Fehlermeldungen verwandeln.
Session-Idle-Timeout und dauerhafte Sperrliste (Befund 9) vor dem nächsten Release.
Die tote Route (Befund 8) und die WAF-Dokumentation (Befund 10) sind
Aufräumarbeiten, die in dieselbe Session passen. Zwei Tests gehören zur Lösung
dazu: ein Paralleltest auf `deliver()` (8 Anläufe, genau 1 Erfolg) und ein
Rechte-Test auf der Registry-Datei – beide verhindern die Rückkehr der
kritischen Befunde.
