# TrailerGuard

Prüft die Trailer, die [Trailarr](https://github.com/nandyalu/trailarr) herunterlädt, und ersetzt falsche automatisch.

Trailarr holt Trailer per YouTube-Suche und erwischt dabei regelmäßig das Falsche: Fan-Trailer, Reviews, Reaction-Videos oder den Trailer eines anderen Films mit ähnlichem Namen. TrailerGuard liest den YouTube-Titel aus jeder Trailer-Datei und prüft:

- **Titel:** Passt das Video zum Film bzw. zur Serie? Verglichen wird mit dem englischen, deutschen (TMDB) und Originaltitel sowie mit Alternativtiteln.
- **Jahr:** Passen genannte Jahreszahlen zum Erscheinungsjahr (Film) bzw. zur Laufzeit (Serie)?
- **Art des Videos:** keine Reviews, Fan-Made-, Reaction-, „Ending explained“-Videos usw. Die Liste der Begriffe ist einstellbar.
- **Länge:** standardmäßig zwischen 20 und 600 Sekunden.

Ist ein Trailer falsch, wird er gelöscht und per yt-dlp ein geprüfter Ersatz gesucht (deutsch bevorzugt), den Trailarr dann herunterlädt. Gibt es keinen passenden Ersatz, bleibt der Trailer weg und Trailarr überwacht den Titel nicht mehr. Sonst würde Trailarr wieder etwas Falsches laden.

Im **Probelauf** (Standard) wird nur protokolliert, nichts gelöscht.

## Weboberfläche

Unter `http://<server>:8097`:

- **Übersicht:** Status, Fortschritt, manuelle Prüfung bzw. Vollprüfung, Verbindungstest
- **Funde:** falsche Trailer mit Begründung und Ersatz
- **Abgelehnt:** abgelehnte Videos je Titel zurücksetzen, Trailarr-Überwachung wieder einschalten
- **Einstellungen:** Probelauf, Intervalle, Verbindungen und Prüfregeln
- **Konto:** Benutzername/Passwort ändern, Zwei-Faktor-Anmeldung (TOTP)
- **Log:** Live-Protokoll

### Anmeldung

- Beim ersten Aufruf wird ein Benutzer angelegt. Solange keiner existiert, kann ihn jeder anlegen, der die Seite zuerst öffnet. Daher gleich nach dem Start einrichten oder vorab `WEB_USER`/`WEB_PASSWORD` setzen.
- **2FA (optional):** mit jeder TOTP-App (Google Authenticator, Aegis, 2FAS, Bitwarden …) per QR-Code. Beim Einschalten gibt es 10 einmalige Wiederherstellungscodes.
- **Passwort vergessen:** Ein Reset-Code wird ins Container-Protokoll geschrieben (`docker logs trailer-guard`). Er ist 15 Minuten gültig. Bei aktiver 2FA ist zusätzlich ein App- oder Wiederherstellungscode nötig.
- **Alles verloren:** Container einmal mit `WEB_RESET_AUTH=1` starten. Benutzer und 2FA werden gelöscht. Die Variable danach wieder entfernen.
- Der Server spricht nur HTTP. Für Zugriff von außen einen Reverse Proxy mit HTTPS davorsetzen.

## Installation

Fertige Images (amd64 und arm64) baut GitHub bei jedem Push auf `main`: `ghcr.io/snaker-l/trailer-guard:latest`. Versions-Tags `v1.2.3` ergeben zusätzlich `:1.2.3`.

```sh
docker run -d --name trailer-guard --restart unless-stopped \
  -p 8097:8097 \
  -v /pfad/zu/state:/state \
  -v /pfad/zu/medien:/pfad/zu/medien \
  -e TRAILARR_URL=http://trailarr:7889 \
  -e TRAILARR_API_KEY=... \
  -e TMDB_API_KEY=... \
  ghcr.io/snaker-l/trailer-guard:latest
```

Selbst bauen: `docker build -t trailer-guard .` und dann `trailer-guard` als Image angeben.

Die Mediendateien müssen unter **demselben Pfad** eingebunden sein wie bei Trailarr, weil TrailerGuard die Pfade aus der Trailarr-API direkt verwendet. Das Volume `/state` enthält Prüfstatus, Einstellungen und Zugangsdaten und muss erhalten bleiben.

Den Trailarr-API-Key findest du in den Trailarr-Einstellungen. Ein TMDB-Key ist optional, verringert aber Fehlalarme deutlich (deutsche Titel, Ausstrahlungsjahre).

## Umgebungsvariablen

Alle Werte lassen sich auch in der Weboberfläche ändern. Was dort gespeichert wird, hat Vorrang.

| Variable | Bedeutung | Standard |
|---|---|---|
| `TRAILARR_URL` | Adresse von Trailarr | `http://trailarr:7889` |
| `TRAILARR_API_KEY` | API-Key (alternativ aus `TRAILARR_ENV`, Standard `/trailarr.env`) | – |
| `TMDB_API_KEY` | TMDB-API-Key (v3) oder Lesetoken (v4) | – |
| `DRY_RUN` | `1` = Probelauf, `0` = falsche Trailer wirklich ersetzen | `1` |
| `INTERVAL` | Sekunden zwischen den Prüfungen neuer Downloads | `300` |
| `FULL_EVERY` | Sekunden zwischen Vollprüfungen aller Trailer | `86400` |
| `WEB_PORT` | Port der Weboberfläche | `8097` |
| `WEB_USER`, `WEB_PASSWORD` | ersten Benutzer beim Start anlegen | – |
| `WEB_RESET_AUTH` | `1` = Anmeldedaten beim Start löschen | – |
| `STATE`, `CONFIG`, `AUTH` | Dateipfade | `/state/state.json`, `/state/config.json`, `/state/auth.json` |
