"""trailer-guard: prueft Trailarr-Trailer und ersetzt falsche automatisch.

Pruefung je Trailer-Datei (YouTube-Titel steht als Tag in der MP4, Trailarr bettet ihn ein):
  * Titel des Videos muss zum Film/zur Serie passen (englischer Titel, deutscher TMDB-Titel, Originaltitel)
  * genannte Jahreszahlen muessen zur Laufzeit passen (Film: Jahr +-1, Serie: Erstausstrahlung-1 .. letzte Ausstrahlung+1)
  * keine Fan-/Review-/Reaction-Videos u. a.
Falscher Trailer -> Datei loeschen, geprueften Ersatz suchen (yt-dlp, deutsch bevorzugt) und ueber die Trailarr-API laden.
Kein passender Ersatz -> Trailer bleibt weg und Trailarr ueberwacht den Titel nicht mehr (sonst laedt es wieder Falsches).

Weboberflaeche (Standard Port 8097, WEB_PORT) mit Anmeldung (Benutzer/Passwort, optional 2FA per TOTP-App).
Einstellungen aus der Oberflaeche liegen in CONFIG (Standard /state/config.json) und haben Vorrang vor der Umgebung.

Umgebung (Startwerte): TRAILARR_URL, TRAILARR_API_KEY, TMDB_API_KEY, DRY_RUN (1 = nur protokollieren),
          INTERVAL (s, Standard 300), FULL_EVERY (s, Standard 86400), STATE (Pfad, Standard /state/state.json),
          CONFIG, AUTH (Standard /state/auth.json), WEB_PORT, WEB_USER + WEB_PASSWORD (erster Benutzer),
          WEB_RESET_AUTH=1 (Anmeldedaten loeschen, z. B. bei vergessenem Passwort oder verlorener 2FA-App)
"""
import base64
import collections
import datetime
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import struct
import subprocess
import threading
import time
import unicodedata
import urllib.parse
import urllib.request

try:
    import segno  # QR-Code fuer die 2FA-Einrichtung (optional)
except ImportError:  # pragma: no cover
    segno = None

STATE = os.environ.get("STATE", "/state/state.json")
CONFIG = os.environ.get("CONFIG", os.path.join(os.path.dirname(STATE), "config.json"))
AUTH_FILE = os.environ.get("AUTH", os.path.join(os.path.dirname(STATE), "auth.json"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8097"))


def _env_trailarr_key():
    if os.environ.get("TRAILARR_API_KEY"):
        return os.environ["TRAILARR_API_KEY"]
    try:
        m = re.search(r"API_KEY=[\"']?([^\"'\n]+)", open(os.environ.get("TRAILARR_ENV", "/trailarr.env")).read())
        return m.group(1) if m else ""
    except OSError:
        return ""


DEFAULT_BAD = [r"reaction", r"react", r"review", r"kritik", r"explained", r"erkl[äa]rt", r"ending", r"recap", r"parody",
               r"parodie", r"fan[\s-]?made", r"fan trailer", r"fanmade", r"gameplay", r"full movie", r"ganzer film",
               r"ganze folge", r"full episode", r"unboxing", r"interview", r"top ?\d+", r"breakdown", r"concept trailer",
               r"ai trailer", r"ki[- ]trailer", r"tribute", r"remake", r"live[- ]action", r"lyrics", r"karaoke", r"abridged",
               r"shorts?"]

DEFAULTS = {
    "trailarr_url": os.environ.get("TRAILARR_URL", "http://trailarr:7889").rstrip("/"),
    "trailarr_api_key": _env_trailarr_key(),
    "tmdb_api_key": os.environ.get("TMDB_API_KEY", ""),
    "dry_run": os.environ.get("DRY_RUN", "1") == "1",
    "interval": int(os.environ.get("INTERVAL", "300")),
    "full_every": int(os.environ.get("FULL_EVERY", "86400")),
    "bad_words": DEFAULT_BAD,
    "min_len": 20,
    "max_len": 600,
    "year_tol": 1,
    "max_rejects": 4,
    "prefer_german": True,
}
INT_FIELDS = {"interval": (30, 7 * 86400), "full_every": (300, 30 * 86400), "min_len": (0, 3600), "max_len": (10, 7200),
              "year_tol": (0, 10), "max_rejects": (1, 50)}
SECRET_FIELDS = ("trailarr_api_key", "tmdb_api_key")

STOP = {"the", "and", "der", "die", "das", "und", "des", "den", "dem", "ein", "eine", "of", "a", "an", "in", "im", "to", "von",
        "mit", "for", "on", "le", "la", "les", "de", "du"}
GERMAN = re.compile(r"(?i)\b(deutsch|german|ger)\b")

# --- laufende Konfiguration (wird von apply_config gesetzt) ---
CFG = {}
TR = TR_KEY = TMDB_KEY = ""
DRY = True
INTERVAL = FULL_EVERY = 0
BAD = None

LOCK = threading.RLock()          # schuetzt ST, CFG und AUTH
LOGBUF = collections.deque(maxlen=1500)
LOGSEQ = [0]
STATUS = {"running": False, "full": False, "started": 0, "finished": 0, "progress": 0, "total": 0, "error": "",
          "last_count": 0}
CTRL = {"full": False, "stop": False}
WAKE = threading.Event()
ST = {}


def log(*a):
    line = " ".join([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "DRY" if DRY else "LIVE"] + [str(x) for x in a])
    print(line, flush=True)
    with LOCK:
        LOGSEQ[0] += 1
        LOGBUF.append((LOGSEQ[0], line))


def _write_private(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def load_config():
    c = dict(DEFAULTS)
    try:
        with open(CONFIG, encoding="utf-8") as f:
            saved = json.load(f)
        c.update({k: v for k, v in saved.items() if k in DEFAULTS})
    except (FileNotFoundError, ValueError):
        pass
    return c


def apply_config(c):
    global CFG, TR, TR_KEY, TMDB_KEY, DRY, INTERVAL, FULL_EVERY, BAD
    with LOCK:
        CFG = c
        TR = c["trailarr_url"].rstrip("/") + "/api/v1"
        TR_KEY = c["trailarr_api_key"]
        TMDB_KEY = c["tmdb_api_key"]
        DRY = bool(c["dry_run"])
        INTERVAL = int(c["interval"])
        FULL_EVERY = int(c["full_every"])
        words = [w for w in c["bad_words"] if w.strip()]
        BAD = re.compile(r"(?i)\b(" + "|".join(f"(?:{w})" for w in words) + r")\b") if words else None
        _tmdb.clear()


def clean_config(data, cur):
    """Prueft Eingaben aus der Oberflaeche; ValueError mit verstaendlicher Meldung bei Fehlern."""
    c = dict(cur)
    labels = {"interval": "Intervall", "full_every": "Vollpruefung", "min_len": "Mindestlaenge", "max_len": "Hoechstlaenge",
              "year_tol": "Jahrestoleranz", "max_rejects": "Max. Ersatzversuche"}
    for k, (lo, hi) in INT_FIELDS.items():
        if k in data:
            try:
                v = int(data[k])
            except (TypeError, ValueError):
                raise ValueError(f"{labels[k]}: keine ganze Zahl") from None
            if not lo <= v <= hi:
                raise ValueError(f"{labels[k]}: erlaubt sind {lo} bis {hi}")
            c[k] = v
    if c["min_len"] >= c["max_len"]:
        raise ValueError("Mindestlaenge muss kleiner als die Hoechstlaenge sein")
    for k in ("dry_run", "prefer_german"):
        if k in data:
            c[k] = bool(data[k])
    if "trailarr_url" in data:
        u = str(data["trailarr_url"]).strip().rstrip("/")
        if not re.match(r"^https?://[^\s/]+", u):
            raise ValueError("Trailarr-URL muss mit http:// oder https:// beginnen")
        c["trailarr_url"] = u
    for k in SECRET_FIELDS:
        v = data.get(k)
        if isinstance(v, str) and v.strip():
            c[k] = v.strip()
        if data.get(k + "_clear"):
            c[k] = ""
    if "bad_words" in data:
        words = data["bad_words"]
        if isinstance(words, str):
            words = words.splitlines()
        words = [str(w).strip() for w in words if str(w).strip()]
        for w in words:
            try:
                re.compile(w)
            except re.error as ex:
                raise ValueError(f"Ungueltiger Begriff '{w}': {ex}") from None
        c["bad_words"] = words
    return c


# ---------------------------------------------------------------- Pruefung

ROMAN = {"ii": "2", "iii": "3", "iv": "4", "v": "5", "vi": "6", "vii": "7", "viii": "8"}


def norm(s):
    s = unicodedata.normalize("NFKD", s or "").encode("ascii", "ignore").decode().lower()
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    return " ".join(ROMAN.get(w, w) for w in s.split())


def squash(s):
    return norm(s).replace(" ", "")


def tmdb_get(path, **params):
    """TMDB v3: klassischer API-Key als Parameter oder v4-Lesetoken (Bearer)."""
    h = {}
    if len(TMDB_KEY) > 40:
        h["Authorization"] = "Bearer " + TMDB_KEY
    else:
        params["api_key"] = TMDB_KEY
    return http("GET", f"https://api.themoviedb.org/3/{path}?" + urllib.parse.urlencode(params), h, timeout=30)


def http(method, url, headers=None, timeout=120):
    r = urllib.request.Request(url, headers=headers or {}, method=method, data=b"" if method != "GET" else None)
    raw = urllib.request.urlopen(r, timeout=timeout).read()
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode(errors="replace")


def tr(method, path):
    return http(method, TR + path, {"X-API-KEY": TR_KEY})


_tmdb = {}


def tmdb_info(media):
    """Deutscher Titel, Originaltitel, Alternativtitel und Ausstrahlungszeitraum von TMDB."""
    tid = media.get("tmdb_id")
    kind = "movie" if media["is_movie"] else "tv"
    if not tid or not TMDB_KEY:
        return {}
    k = f"{kind}/{tid}"
    if k in _tmdb:
        return _tmdb[k]
    info = {"titles": set(), "alt": set(), "first": None, "last": None}
    try:
        de = tmdb_get(f"{kind}/{tid}", language="de-DE")
        for f in ("title", "name", "original_title", "original_name"):
            if de.get(f):
                info["titles"].add(de[f])
        if kind == "movie":
            y = (de.get("release_date") or "")[:4]
            info["first"] = info["last"] = int(y) if y.isdigit() else None
        else:
            a, b = (de.get("first_air_date") or "")[:4], (de.get("last_air_date") or "")[:4]
            info["first"] = int(a) if a.isdigit() else None
            info["last"] = int(b) if b.isdigit() else None
        alt = tmdb_get(f"{kind}/{tid}/alternative_titles")
        for t in (alt.get("titles") or alt.get("results") or []):
            if t.get("iso_3166_1") in ("DE", "AT", "CH", "US", "GB"):
                info["alt"].add(t.get("title", ""))
    except Exception as ex:  # noqa: BLE001
        log("TMDB-Fehler", k, ex)
    _tmdb[k] = info
    return info


def names(media, alt=False):
    info = tmdb_info(media)
    out = set(info.get("alt", set())) if alt else ({media["title"], media.get("clean_title") or ""} | info.get("titles", set()))
    res = set()
    for n in out:
        n = re.sub(r"\((19|20)\d\d\)", "", n or "").strip()          # "Bluey (2018)" -> "Bluey"
        n = re.sub(r"(?i)^the adventures of (the )?", "", n).strip()   # "The Adventures of the Galaxy Rangers" -> "Galaxy Rangers"
        if len(squash(n)) >= 2:
            res.add(n)
    return list(res)


def video_years(vtitle):
    return [int(y) for y in re.findall(r"\b(19[3-9]\d|20[0-4]\d)\b", vtitle)]


def title_matches(vtitle, media):
    vs, vn = squash(vtitle), set(norm(vtitle).split())
    # Haupttitel vor ":" bzw. " - " (mind. 3 Woerter) genuegt, wenn das Video das passende Jahr nennt
    y = media.get("year") or 0
    if any(abs(v - y) <= CFG["year_tol"] for v in video_years(vtitle)):
        for n in names(media):
            head = re.split(r":| - ", n)[0]
            hw = [w for w in norm(head).split() if w not in STOP]
            if len(hw) >= 3 and all(w in vn for w in hw):
                return True
    # Alternativtitel (TMDB) nur, wenn ALLE ihre (mind. 2) Woerter vorkommen - sie sind oft sehr allgemein ("The Curse")
    for n in names(media, alt=True):
        aw = [w for w in norm(n).split() if w not in STOP and not re.fullmatch(r"(19|20)\d\d", w)]
        if len(aw) >= 2 and all(w in vn for w in aw):
            return True
    for n in names(media):
        sq = squash(n)
        if len(sq) >= 4 and sq in vs:
            return True
        allw = [w for w in norm(n).split() if not re.fullmatch(r"(19|20)\d\d", w)]
        words = [w for w in allw if w not in STOP and (len(w) > 2 or w.isdigit())]
        if not words and allw:                      # sehr kurze Titel wie "Es": ganzes Wort muss vorkommen
            words = allw
        need = 1.0 if len(words) <= 4 else 0.75     # kurze Titel: alle Woerter, lange: drei Viertel
        if words and sum(1 for w in words if w in vn) / len(words) >= need:
            return True
    return False


def year_ok(vtitle, media):
    years = video_years(vtitle)
    if not years:
        return True
    tol = CFG["year_tol"]
    info = tmdb_info(media)
    lo = (info.get("first") or media.get("year") or 0) - tol
    hi = (info.get("last") or media.get("year") or 9999) + tol
    if media["is_movie"]:
        hi = (media.get("year") or hi) + tol
        lo = (media.get("year") or lo) - tol
    return any(lo <= y <= hi for y in years)


def verdict(vtitle, media, duration=None):
    why = []
    if not vtitle:
        why.append("kein Videotitel")
    else:
        if not title_matches(vtitle, media):
            why.append("Titel passt nicht")
        if not year_ok(vtitle, media):
            why.append("Jahr passt nicht")
        m = BAD.search(vtitle) if BAD else None
        if m:
            why.append("verdaechtig: " + m.group(1))
        film = re.search(r"(?i)\b(kinofilm|kino|movie|der film|film)\b", vtitle)
        if not media["is_movie"] and film and not re.search(r"(?i)\b(film|movie|kino)\b", " ".join(names(media))):
            why.append("Kinofilm statt Serie")
    if duration and (duration < CFG["min_len"] or duration > CFG["max_len"]):
        why.append(f"Laenge {int(duration)} s")
    return why


def video_title(path):
    try:
        r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration:format_tags=title", "-of", "json", path],
                           capture_output=True, text=True, timeout=60)
        f = json.loads(r.stdout or "{}").get("format", {})
        return (f.get("tags") or {}).get("title", ""), float(f.get("duration") or 0)
    except Exception:  # noqa: BLE001
        return "", 0


def search_candidates(media):
    info = tmdb_info(media)
    de = [t for t in info.get("titles", []) if t] or [media["title"]]   # nur Haupt-/deutscher/Originaltitel
    first_de = sorted(de, key=lambda t: (not GERMAN.search(t or ""), len(t)))[0]
    y = media.get("year") or ""
    qs = [f"{first_de} trailer deutsch", f"{first_de} {y} trailer german", f"{media['title']} trailer deutsch"]
    if not media["is_movie"]:
        qs += [f"{first_de} intro deutsch", f"{media['title']} intro german"]
    seen, out = set(), []
    for q in qs:
        try:
            r = subprocess.run(["yt-dlp", "--flat-playlist", "--print", "%(id)s\t%(duration)s\t%(title)s", f"ytsearch8:{q}"],
                               capture_output=True, text=True, timeout=120)
        except Exception:  # noqa: BLE001
            continue
        for line in r.stdout.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3 or parts[0] in seen:
                continue
            seen.add(parts[0])
            try:
                dur = float(parts[1])
            except ValueError:
                dur = 0
            out.append((parts[0], dur, parts[2]))
    return out


def pick_replacement(media, rejected):
    cands = [c for c in search_candidates(media) if c[0] not in rejected and not verdict(c[2], media, c[1] or None)]
    if not cands:
        return None
    # deutsch vor englisch (abschaltbar), "trailer" vor "intro"
    ger = CFG["prefer_german"]
    cands.sort(key=lambda c: (ger and not GERMAN.search(c[2]), "trailer" not in c[2].lower()))
    return cands[0]


def load_state():
    try:
        with open(STATE, encoding="utf-8") as f:
            st = json.load(f)
    except (FileNotFoundError, ValueError):
        st = {}
    for k, v in (("checked", {}), ("rejected", {}), ("last_full", 0), ("events", []), ("names", {}), ("unmonitored", {})):
        st.setdefault(k, v)
    return st


def save_state(st):
    with LOCK:
        os.makedirs(os.path.dirname(STATE) or ".", exist_ok=True)
        tmp = STATE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, indent=1, ensure_ascii=False)
        os.replace(tmp, STATE)


def add_event(st, ev):
    ev["time"] = time.time()
    with LOCK:
        evs = [e for e in st["events"] if not (e.get("key") == ev["key"] and e.get("action") == ev["action"])]
        evs.append(ev)
        st["events"] = evs[-300:]


def handle(media, dl, st, full=False):
    path = dl.get("path") or ""
    if not path or not os.path.exists(path) or "/Trailers/" not in path:
        return
    key = f"{dl.get('id')}:{dl.get('youtube_id')}"
    seen = st["checked"].get(key)
    if seen == "ok" or (seen == "dry" and DRY and not full):   # Probelauf-Funde nur bei Vollpruefung erneut
        return
    vtitle, dur = video_title(path)
    why = verdict(vtitle, media, dur)
    if not why:
        st["checked"][key] = "ok"
        return
    mid = str(media["id"])
    st["names"][mid] = f"{media['title']} ({media.get('year')})"
    log(f"FALSCH: {media['title']} ({media.get('year')}) <- '{vtitle}' [{dl.get('youtube_id')}] : {', '.join(why)}")
    rej = st["rejected"].setdefault(mid, [])
    if dl.get("youtube_id") and dl["youtube_id"] not in rej:
        rej.append(dl["youtube_id"])
    rep = pick_replacement(media, set(rej))
    ev = {"key": key, "media_id": mid, "title": media["title"], "year": media.get("year"), "video": vtitle,
          "yt_id": dl.get("youtube_id"), "why": why, "replacement": {"id": rep[0], "title": rep[2]} if rep else None}
    if DRY:
        log(f"   wuerde loeschen: {path}")
        log(f"   Ersatz: {rep[2]!r} [{rep[0]}]" if rep else "   kein passender Ersatz -> Trailer bleibt weg, Trailarr-Ueberwachung aus")
        st["checked"][key] = "dry"
        add_event(st, dict(ev, action="dry"))
        return
    try:
        os.remove(path)
        log(f"   geloescht: {path}")
    except OSError as ex:
        log(f"   Loeschen fehlgeschlagen: {ex}")
        add_event(st, dict(ev, action="error", error=str(ex)))
        return
    if rep and len(rej) <= CFG["max_rejects"]:
        prof = 1 if media["is_movie"] else 2
        tr("POST", f"/media/{media['id']}/update?yt_id={rep[0]}")
        tr("POST", f"/media/{media['id']}/download?profile_id={prof}&yt_id={rep[0]}")
        log(f"   Ersatz geladen: {rep[2]!r} [{rep[0]}]")
        add_event(st, dict(ev, action="replaced"))
    else:
        tr("POST", f"/media/{media['id']}/monitor?monitor=false")
        st["unmonitored"][mid] = True
        log("   kein passender Ersatz - Trailer bleibt weg, Trailarr ueberwacht den Titel nicht mehr")
        add_event(st, dict(ev, action="removed", replacement=None))
    tr("POST", f"/media/{media['id']}/rescan_files")
    st["checked"][key] = "removed"


def run(full):
    if not TR_KEY:
        raise RuntimeError("kein Trailarr-API-Key eingestellt")
    st = ST
    if full:
        items = [m for m in tr("GET", "/media/all") if m.get("downloaded_at")]
        log(f"Vollpruefung: {len(items)} Titel mit Trailer")
    else:
        items = tr("GET", "/media/downloaded")
    STATUS["total"] = len(items)
    n = 0
    for i, m in enumerate(items):
        if CTRL["stop"]:
            log("Durchlauf abgebrochen")
            break
        STATUS["progress"] = i + 1
        try:
            media = m if "downloads" in m else tr("GET", f"/media/{m['id']}")
            for dl in media.get("downloads") or tr("GET", f"/media/{m['id']}/downloads"):
                handle(media, dl, st, full)
                n += 1
        except Exception as ex:  # noqa: BLE001
            log("Fehler bei", m.get("title"), ex)
        if i % 25 == 24:
            save_state(st)
    if full and not CTRL["stop"]:
        st["last_full"] = time.time()
    save_state(st)
    return n


def worker():
    while True:
        full = CTRL["full"] or time.time() - ST.get("last_full", 0) > FULL_EVERY
        CTRL["full"] = CTRL["stop"] = False
        STATUS.update(running=True, full=full, started=time.time(), progress=0, total=0, error="")
        try:
            STATUS["last_count"] = run(full)
        except Exception as ex:  # noqa: BLE001
            STATUS["error"] = str(ex)
            log("Durchlauf-Fehler:", ex)
        STATUS.update(running=False, finished=time.time())
        while not WAKE.is_set() and time.time() < STATUS["finished"] + INTERVAL:
            WAKE.wait(2)
        WAKE.clear()


# ---------------------------------------------------------------- Anmeldung

AUTH = {}
SESSIONS = {}
SESSION_TTL = 12 * 3600
FAILS = collections.defaultdict(list)
MAX_FAILS, FAIL_WINDOW = 5, 600


def hash_pw(pw, salt=None, it=240000):
    salt = salt or os.urandom(16)
    return f"pbkdf2_sha256${it}${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, it).hex()}"


def check_pw(pw, stored):
    try:
        _, it, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex()
        return hmac.compare_digest(calc, h)
    except (ValueError, AttributeError):
        return False


def hotp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    d = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def totp_step(secret, code, last=0):
    """Gibt den Zeitschritt des gueltigen Codes zurueck (+-30 s Toleranz, kein erneutes Verwenden) oder None."""
    code = re.sub(r"\s", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code):
        return None
    now = int(time.time() // 30)
    for s in (now - 1, now, now + 1):
        if s > last and hmac.compare_digest(hotp(secret, s), code):
            return s
    return None


def _code_hash(code):
    return hashlib.sha256(re.sub(r"[\s-]", "", str(code or "")).lower().encode()).hexdigest()


def new_recovery_codes():
    """Zehn einmalige Wiederherstellungscodes (falls die 2FA-App verloren geht); gespeichert werden nur Hashes."""
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(10)]
    AUTH["recovery"] = [_code_hash(c) for c in codes]
    return codes


def second_factor(code):
    """TOTP-Code oder Wiederherstellungscode pruefen (unter LOCK aufrufen). Gibt 'totp', 'recovery' oder None zurueck."""
    s = totp_step(AUTH.get("totp_secret", ""), code, AUTH.get("totp_last", 0)) if AUTH.get("totp_secret") else None
    if s is not None:
        AUTH["totp_last"] = s
        return "totp"
    h = _code_hash(code)
    if len(re.sub(r"[\s-]", "", str(code or ""))) == 12 and h in AUTH.get("recovery", []):
        AUTH["recovery"].remove(h)
        log(f"Wiederherstellungscode verwendet, noch {len(AUTH['recovery'])} uebrig")
        return "recovery"
    return None


RESET = {}          # laufender Passwort-Reset: {"hash", "exp", "created", "tries"}
RESET_TTL = 900


def load_auth():
    if os.environ.get("WEB_RESET_AUTH") == "1" and os.path.exists(AUTH_FILE):
        os.remove(AUTH_FILE)
        log("WEB_RESET_AUTH=1: Anmeldedaten geloescht - bitte neu einrichten und die Variable wieder entfernen")
    try:
        with open(AUTH_FILE, encoding="utf-8") as f:
            a = json.load(f)
    except (FileNotFoundError, ValueError):
        a = {}
    if not a.get("user") and os.environ.get("WEB_USER") and os.environ.get("WEB_PASSWORD"):
        a = {"user": os.environ["WEB_USER"], "pw": hash_pw(os.environ["WEB_PASSWORD"])}
        _write_private(AUTH_FILE, a)
        log(f"Benutzer '{a['user']}' aus WEB_USER/WEB_PASSWORD angelegt")
    a.setdefault("totp_on", False)
    a.setdefault("totp_secret", "")
    a.setdefault("totp_last", 0)
    return a


def save_auth():
    with LOCK:
        _write_private(AUTH_FILE, {k: v for k, v in AUTH.items() if k != "pending"})


def new_session(user):
    tok = secrets.token_urlsafe(32)
    SESSIONS[tok] = {"user": user, "exp": time.time() + SESSION_TTL}
    return tok


def too_many_fails(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS[ip] if now - t < FAIL_WINDOW]
    return len(FAILS[ip]) >= MAX_FAILS


def valid_user(u):
    return bool(re.fullmatch(r"[\w.@-]{3,40}", u or ""))


# ---------------------------------------------------------------- Weboberflaeche

def public_config():
    with LOCK:
        c = {k: v for k, v in CFG.items() if k not in SECRET_FIELDS}
        for k in SECRET_FIELDS:
            c[k + "_set"] = bool(CFG.get(k))
    return c


def status_info():
    with LOCK:
        counts = collections.Counter(ST["checked"].values())
        warn = []
        if not TR_KEY:
            warn.append("Kein Trailarr-API-Key eingestellt - es wird nichts geprueft.")
        if not TMDB_KEY:
            warn.append("Kein TMDB-API-Key - deutsche Titel und Ausstrahlungsjahre fehlen, mehr Fehlalarme moeglich.")
        if DRY:
            warn.append("Probelauf aktiv: falsche Trailer werden nur protokolliert, nicht geloescht.")
        return dict(STATUS, dry_run=DRY, interval=INTERVAL, full_every=FULL_EVERY, last_full=ST.get("last_full", 0),
                    next_run=0 if STATUS["running"] else STATUS["finished"] + INTERVAL,
                    next_full=ST.get("last_full", 0) + FULL_EVERY, now=time.time(),
                    checked={"ok": counts.get("ok", 0), "dry": counts.get("dry", 0), "removed": counts.get("removed", 0)},
                    rejected=len(ST["rejected"]), warnings=warn)


def test_connections():
    res = {}
    try:
        items = tr("GET", "/media/downloaded")
        res["trailarr"] = {"ok": True, "msg": f"verbunden, {len(items)} Titel mit Trailer"}
    except Exception as ex:  # noqa: BLE001
        res["trailarr"] = {"ok": False, "msg": str(ex)}
    if not TMDB_KEY:
        res["tmdb"] = {"ok": False, "msg": "kein Key eingestellt"}
    else:
        try:
            tmdb_get("configuration")
            res["tmdb"] = {"ok": True, "msg": "verbunden"}
        except Exception as ex:  # noqa: BLE001
            res["tmdb"] = {"ok": False, "msg": str(ex)}
    try:
        v = subprocess.run(["yt-dlp", "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
        res["ytdlp"] = {"ok": bool(v), "msg": "Version " + v if v else "nicht gefunden"}
    except Exception as ex:  # noqa: BLE001
        res["ytdlp"] = {"ok": False, "msg": str(ex)}
    return res


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


class Handler(BaseHTTPRequestHandler):
    server_version = "trailer-guard"
    sys_version = ""

    def log_message(self, *a):
        pass

    # --- Hilfen
    def send(self, code, body, ctype, extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def json(self, obj, code=200, extra=None):
        self.send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", extra)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ApiError("Anfrage zu gross", 413)
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError("ungueltiges JSON") from None
        if not isinstance(d, dict):
            raise ApiError("ungueltige Anfrage")
        return d

    def ip(self):
        return self.client_address[0]

    def session(self):
        m = re.search(r"(?:^|;\s*)tg_session=([\w-]+)", self.headers.get("Cookie") or "")
        if not m:
            return None
        with LOCK:
            s = SESSIONS.get(m.group(1))
            if not s or s["exp"] < time.time() or s["user"] != AUTH.get("user"):
                SESSIONS.pop(m.group(1), None)
                return None
            s["exp"] = time.time() + SESSION_TTL
            return m.group(1)

    @staticmethod
    def cookie(tok, age=SESSION_TTL):
        return {"Set-Cookie": f"tg_session={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}"}

    # --- Verteilung
    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        path = urllib.parse.urlsplit(self.path).path
        try:
            if method == "GET" and path in ("/", "/index.html"):
                return self.send(200, PAGE, "text/html; charset=utf-8")
            if not path.startswith("/api/"):
                return self.send(404, "nicht gefunden", "text/plain; charset=utf-8")
            if method == "POST" and self.headers.get("X-TG") != "1":   # Schutz gegen fremde Formulare (CSRF)
                raise ApiError("fehlender Header", 403)
            fn = PUBLIC.get((method, path))
            if fn:
                return fn(self)
            tok = self.session()
            if not tok:
                raise ApiError("nicht angemeldet", 401)
            fn = PROTECTED.get((method, path))
            if not fn:
                raise ApiError("unbekannter Pfad", 404)
            self.tok = tok
            return fn(self)
        except ApiError as ex:
            self.json({"error": str(ex)}, ex.code)
        except Exception as ex:  # noqa: BLE001
            log("Web-Fehler:", path, ex)
            self.json({"error": "interner Fehler: " + str(ex)}, 500)

    # --- oeffentlich
    def api_me(self):
        tok = self.session()
        with LOCK:
            self.json({"setup": not AUTH.get("user"), "logged_in": bool(tok), "user": AUTH.get("user") if tok else None,
                       "totp_on": bool(AUTH.get("totp_on")) if tok else None})

    def api_setup(self):
        d = self.body()
        with LOCK:
            if AUTH.get("user"):
                raise ApiError("bereits eingerichtet", 409)
            u, pw = str(d.get("user", "")).strip(), str(d.get("password", ""))
            if not valid_user(u):
                raise ApiError("Benutzername: 3-40 Zeichen, nur Buchstaben, Ziffern und . _ - @")
            if len(pw) < 8:
                raise ApiError("Passwort muss mindestens 8 Zeichen haben")
            AUTH.clear()
            AUTH.update({"user": u, "pw": hash_pw(pw), "totp_on": False, "totp_secret": "", "totp_last": 0})
            save_auth()
            tok = new_session(u)
        log(f"Weboberflaeche: Benutzer '{u}' eingerichtet")
        self.json({"ok": True}, extra=self.cookie(tok))

    def api_login(self):
        d = self.body()
        ip = self.ip()
        with LOCK:
            if too_many_fails(ip):
                raise ApiError("Zu viele Fehlversuche - bitte 10 Minuten warten", 429)
            if not AUTH.get("user"):
                raise ApiError("noch kein Benutzer eingerichtet", 409)
            user_ok = hmac.compare_digest(str(d.get("user", "")).strip().encode(), AUTH["user"].encode())
            pw_ok = check_pw(str(d.get("password", "")), AUTH["pw"])     # immer pruefen (gleiche Antwortzeit)
            if not (user_ok and pw_ok):
                FAILS[ip].append(time.time())
                log(f"Anmeldung fehlgeschlagen von {ip}")
                raise ApiError("Benutzername oder Passwort falsch", 403)
            if AUTH.get("totp_on"):
                if not d.get("code"):
                    return self.json({"need_code": True})
                if not second_factor(d["code"]):
                    FAILS[ip].append(time.time())
                    log(f"Anmeldung: falscher 2FA-Code von {ip}")
                    raise ApiError("Bestaetigungscode falsch oder abgelaufen", 403)
                save_auth()
            FAILS.pop(ip, None)
            tok = new_session(AUTH["user"])
        log(f"Anmeldung: {AUTH['user']} von {ip}")
        self.json({"ok": True}, extra=self.cookie(tok))

    def api_pwreset_request(self):
        with LOCK:
            if not AUTH.get("user"):
                raise ApiError("noch kein Benutzer eingerichtet", 409)
            now = time.time()
            if RESET and now - RESET["created"] < 60:
                raise ApiError("Es wurde gerade ein Code erzeugt - bitte im Protokoll nachsehen oder 1 Minute warten", 429)
            code = "-".join(secrets.token_hex(2).upper() for _ in range(3))
            RESET.clear()
            RESET.update(hash=_code_hash(code), exp=now + RESET_TTL, created=now, tries=0)
        log("=" * 60)
        log(f"PASSWORT-RESET angefordert von {self.ip()} - Code (15 Min. gueltig): {code}")
        log("=" * 60)
        self.json({"ok": True})

    def api_pwreset_confirm(self):
        d = self.body()
        ip = self.ip()
        with LOCK:
            if too_many_fails(ip):
                raise ApiError("Zu viele Fehlversuche - bitte 10 Minuten warten", 429)
            if not RESET or RESET["exp"] < time.time():
                RESET.clear()
                raise ApiError("Kein gueltiger Reset-Code - bitte neu anfordern", 403)
            if not hmac.compare_digest(_code_hash(d.get("reset_code")), RESET["hash"]):
                RESET["tries"] += 1
                FAILS[ip].append(time.time())
                if RESET["tries"] >= 5:
                    RESET.clear()
                    raise ApiError("Zu oft falsch - bitte neuen Code anfordern", 403)
                raise ApiError("Reset-Code falsch", 403)
            pw = str(d.get("password", ""))
            if len(pw) < 8:
                raise ApiError("Passwort muss mindestens 8 Zeichen haben")
            if AUTH.get("totp_on") and not second_factor(d.get("code")):
                FAILS[ip].append(time.time())
                raise ApiError("2FA aktiv: bitte gueltigen Code aus der App oder einen Wiederherstellungscode angeben", 403)
            AUTH["pw"] = hash_pw(pw)
            save_auth()
            RESET.clear()
            SESSIONS.clear()
            FAILS.pop(ip, None)
        log(f"Passwort per Reset-Code neu gesetzt (von {ip})")
        self.json({"ok": True, "user": AUTH["user"]})

    def api_logout(self):
        tok = self.session()
        if tok:
            SESSIONS.pop(tok, None)
        self.json({"ok": True}, extra=self.cookie("x", 0))

    # --- angemeldet
    def api_status(self):
        self.json(status_info())

    def api_config_get(self):
        self.json(public_config())

    def api_config_set(self):
        d = self.body()
        with LOCK:
            try:
                c = clean_config(d, CFG)
            except ValueError as ex:
                raise ApiError(str(ex)) from None
            _write_private(CONFIG, c)
            apply_config(c)
        log("Einstellungen gespeichert")
        self.json(public_config())

    def api_events(self):
        with LOCK:
            self.json(list(reversed(ST["events"])))

    def api_log(self):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        since = int((q.get("since") or ["0"])[0] or 0)
        with LOCK:
            self.json({"seq": LOGSEQ[0], "lines": [line for s, line in LOGBUF if s > since]})

    def api_rejected(self):
        with LOCK:
            self.json([{"id": k, "title": ST["names"].get(k, f"Medium {k}"), "videos": v, "unmonitored": bool(ST["unmonitored"].get(k))}
                       for k, v in ST["rejected"].items()])

    def api_run(self):
        CTRL["full"] = bool(self.body().get("full"))
        if STATUS["running"]:
            return self.json({"ok": True, "msg": "laeuft bereits - wird danach erneut gestartet"})
        WAKE.set()
        self.json({"ok": True, "msg": "gestartet"})

    def api_stop(self):
        CTRL["stop"] = True
        self.json({"ok": True})

    def api_reset(self):
        d = self.body()
        what = d.get("what")
        msg = ""
        with LOCK:
            if what == "checked":
                ST["checked"].clear()
                msg = "Pruefstatus zurueckgesetzt - beim naechsten Durchlauf wird alles neu geprueft"
            elif what == "events":
                ST["events"] = []
                msg = "Fundliste geleert"
            elif what == "rejected":
                mid = str(d.get("id", ""))
                if mid not in ST["rejected"]:
                    raise ApiError("unbekannter Eintrag", 404)
                ST["rejected"].pop(mid)
                if ST["unmonitored"].pop(mid, None) and d.get("monitor"):
                    try:
                        tr("POST", f"/media/{mid}/monitor?monitor=true")
                        msg = "zurueckgesetzt, Trailarr ueberwacht den Titel wieder"
                    except Exception as ex:  # noqa: BLE001
                        msg = f"zurueckgesetzt, aber Trailarr-Ueberwachung fehlgeschlagen: {ex}"
                msg = msg or "zurueckgesetzt"
            else:
                raise ApiError("unbekannte Aktion")
            save_state(ST)
        log(msg)
        self.json({"ok": True, "msg": msg})

    def api_test(self):
        self.json(test_connections())

    def api_account(self):
        d = self.body()
        with LOCK:
            if not check_pw(str(d.get("current", "")), AUTH["pw"]):
                raise ApiError("aktuelles Passwort falsch", 403)
            u = str(d.get("user") or AUTH["user"]).strip()
            if not valid_user(u):
                raise ApiError("Benutzername: 3-40 Zeichen, nur Buchstaben, Ziffern und . _ - @")
            pw = str(d.get("password") or "")
            if pw and len(pw) < 8:
                raise ApiError("neues Passwort muss mindestens 8 Zeichen haben")
            AUTH["user"] = u
            if pw:
                AUTH["pw"] = hash_pw(pw)
            save_auth()
            for t in [t for t in SESSIONS if t != self.tok]:   # andere Sitzungen abmelden
                SESSIONS.pop(t, None)
            SESSIONS[self.tok]["user"] = u
        log("Zugangsdaten geaendert")
        self.json({"ok": True, "user": u})

    def api_totp_start(self):
        with LOCK:
            sec = base64.b32encode(os.urandom(20)).decode().rstrip("=")
            AUTH["pending"] = sec
            uri = (f"otpauth://totp/TrailerGuard:{urllib.parse.quote(AUTH['user'])}?secret={sec}"
                   "&issuer=TrailerGuard&algorithm=SHA1&digits=6&period=30")
        qr = None
        if segno:
            try:
                qr = segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000", light="#fff")
            except Exception:  # noqa: BLE001
                qr = None
        self.json({"secret": sec, "uri": uri, "qr": qr})

    def api_totp_enable(self):
        d = self.body()
        with LOCK:
            sec = AUTH.get("pending")
            if not sec:
                raise ApiError("Einrichtung zuerst starten")
            s = totp_step(sec, d.get("code"))
            if s is None:
                raise ApiError("Code stimmt nicht - Uhrzeit am Handy pruefen und erneut versuchen")
            AUTH.update(totp_on=True, totp_secret=sec, totp_last=s)
            AUTH.pop("pending", None)
            codes = new_recovery_codes()
            save_auth()
        log("2FA eingeschaltet")
        self.json({"ok": True, "recovery": codes})

    def api_totp_recovery(self):
        d = self.body()
        with LOCK:
            if not AUTH.get("totp_on"):
                raise ApiError("2FA ist nicht aktiv")
            if not check_pw(str(d.get("password", "")), AUTH["pw"]):
                raise ApiError("Passwort falsch", 403)
            codes = new_recovery_codes()
            save_auth()
        log("Neue Wiederherstellungscodes erzeugt")
        self.json({"ok": True, "recovery": codes})

    def api_totp_disable(self):
        d = self.body()
        with LOCK:
            if not check_pw(str(d.get("password", "")), AUTH["pw"]):
                raise ApiError("Passwort falsch", 403)
            if AUTH.get("totp_on") and not second_factor(d.get("code")):
                raise ApiError("Bestaetigungscode falsch", 403)
            AUTH.update(totp_on=False, totp_secret="", totp_last=0, recovery=[])
            save_auth()
        log("2FA ausgeschaltet")
        self.json({"ok": True})


PUBLIC = {("GET", "/api/me"): Handler.api_me, ("POST", "/api/setup"): Handler.api_setup,
          ("POST", "/api/login"): Handler.api_login, ("POST", "/api/logout"): Handler.api_logout,
          ("POST", "/api/pwreset/request"): Handler.api_pwreset_request,
          ("POST", "/api/pwreset/confirm"): Handler.api_pwreset_confirm}
PROTECTED = {("GET", "/api/status"): Handler.api_status, ("GET", "/api/config"): Handler.api_config_get,
             ("POST", "/api/config"): Handler.api_config_set, ("GET", "/api/events"): Handler.api_events,
             ("GET", "/api/log"): Handler.api_log, ("GET", "/api/rejected"): Handler.api_rejected,
             ("POST", "/api/run"): Handler.api_run, ("POST", "/api/stop"): Handler.api_stop,
             ("POST", "/api/reset"): Handler.api_reset, ("GET", "/api/test"): Handler.api_test,
             ("POST", "/api/account"): Handler.api_account, ("POST", "/api/totp/start"): Handler.api_totp_start,
             ("POST", "/api/totp/enable"): Handler.api_totp_enable, ("POST", "/api/totp/disable"): Handler.api_totp_disable,
             ("POST", "/api/totp/recovery"): Handler.api_totp_recovery}


PAGE = r"""<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrailerGuard</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--fg:#1d2330;--mute:#6b7280;--line:#e3e6ea;--acc:#2563eb;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--chip:#eef1f5}
@media(prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--mute:#9aa3b2;--line:#2b323e;--acc:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--chip:#252c38}}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;align-items:center;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);flex-wrap:wrap}
header h1{font-size:18px;margin:0;margin-right:auto}
.badge{padding:3px 9px;border-radius:99px;font-size:12px;font-weight:600;background:var(--chip)}
.badge.dry{color:var(--warn)}.badge.live{color:var(--ok)}
nav{display:flex;gap:4px;padding:0 20px;background:var(--card);border-bottom:1px solid var(--line);overflow-x:auto}
nav button{border:0;background:none;color:var(--mute);padding:10px 12px;border-bottom:2px solid transparent;cursor:pointer;font:inherit}
nav button.on{color:var(--fg);border-color:var(--acc)}
main{max-width:1100px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:16px}
.card h2{font-size:16px;margin:0 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}
.stat{background:var(--chip);border-radius:8px;padding:12px}.stat b{display:block;font-size:20px;margin-top:2px}.stat span{color:var(--mute);font-size:13px}
button.btn{font:inherit;border:1px solid var(--line);background:var(--card);color:var(--fg);padding:7px 14px;border-radius:7px;cursor:pointer}
button.btn:hover{border-color:var(--acc)}button.pri{background:var(--acc);border-color:var(--acc);color:#fff}
button.danger{color:var(--bad)}button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
label{display:block;font-size:13px;color:var(--mute);margin:12px 0 4px}
input,textarea{width:100%;font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--fg)}
textarea{min-height:180px;font-family:ui-monospace,Consolas,monospace;font-size:13px}
input[type=checkbox]{width:auto;margin-right:8px}
.chk{display:flex;align-items:center;color:var(--fg);font-size:15px}
.hint{color:var(--mute);font-size:13px;margin-top:4px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}@media(max-width:640px){.two{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:500;font-size:13px}
.tag{display:inline-block;padding:1px 7px;border-radius:99px;font-size:12px;background:var(--chip);margin:1px 2px 1px 0}
.tag.bad{color:var(--bad)}.tag.ok{color:var(--ok)}.tag.warn{color:var(--warn)}
.warn{border-left:3px solid var(--warn);padding:6px 10px;background:var(--chip);border-radius:4px;margin:6px 0}
pre{background:#0d1117;color:#c9d1d9;padding:12px;border-radius:8px;height:60vh;overflow:auto;font-size:12.5px;white-space:pre-wrap;margin:0}
a{color:var(--acc)}.mute{color:var(--mute)}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--fg);color:var(--bg);padding:10px 16px;border-radius:8px;display:none;max-width:90vw;z-index:9}
#toast.err{background:var(--bad);color:#fff}
.login{max-width:380px;margin:10vh auto}.login h1{font-size:22px;margin:0 0 4px}
.prog{height:6px;background:var(--chip);border-radius:3px;overflow:hidden;margin-top:8px}.prog i{display:block;height:100%;background:var(--acc)}
.hidden{display:none!important}.qr{background:#fff;padding:6px;border-radius:8px;display:inline-block}
code{background:var(--chip);padding:2px 6px;border-radius:4px;word-break:break-all}
</style></head><body>

<div id="loginView" class="hidden"><div class="login card">
  <h1>TrailerGuard</h1><p class="mute" id="loginSub">Anmelden</p>
  <form id="loginForm" autocomplete="on">
    <div id="lfCreds"><label>Benutzername</label><input id="lUser" autocomplete="username" required>
    <label>Passwort</label><input id="lPw" type="password" autocomplete="current-password" required>
    <div id="lfSetup" class="hidden"><label>Passwort wiederholen</label><input id="lPw2" type="password" autocomplete="new-password"></div></div>
    <div id="lfCode" class="hidden"><label>Bestätigungscode aus der Authenticator-App</label>
    <input id="lCode" autocomplete="one-time-code" maxlength="20" placeholder="123456">
    <div class="hint">App nicht zur Hand? Einen Wiederherstellungscode (xxxx-xxxx-xxxx) eingeben.</div></div>
    <div class="row" style="margin-top:16px"><button class="btn pri" id="lBtn">Anmelden</button>
    <a href="#" id="forgot" onclick="showReset();return false">Passwort vergessen?</a></div>
    <p class="hint" id="lHint"></p>
  </form>
  <form id="resetForm" class="hidden" autocomplete="off">
    <p>Ein einmaliger Reset-Code wird ins <b>Container-Protokoll</b> geschrieben (z. B. <code>docker logs trailer-guard</code>). Er ist 15 Minuten gültig.</p>
    <button type="button" class="btn" onclick="resetRequest()">Reset-Code erzeugen</button>
    <label>Reset-Code aus dem Protokoll</label><input id="rCode" placeholder="ABCD-1234-EF56" required>
    <label>Neues Passwort</label><input id="rPw" type="password" autocomplete="new-password" required>
    <label>Neues Passwort wiederholen</label><input id="rPw2" type="password" autocomplete="new-password" required>
    <label>2FA-Code oder Wiederherstellungscode (nur wenn 2FA aktiv)</label><input id="rTotp" maxlength="20">
    <div class="row" style="margin-top:16px"><button class="btn pri">Passwort setzen</button>
    <a href="#" onclick="showLogin();return false">Zurück zur Anmeldung</a></div>
  </form></div></div>

<div id="appView" class="hidden">
<header><h1>TrailerGuard</h1><span id="mode" class="badge"></span><span class="mute" id="who"></span>
<button class="btn" onclick="logout()">Abmelden</button></header>
<nav id="tabs"></nav>
<main>
<section data-tab="Übersicht">
  <div id="warns"></div>
  <div class="card"><h2>Status</h2><div class="grid" id="stats"></div><div class="prog hidden" id="prog"><i></i></div>
  <div class="row" style="margin-top:16px">
    <button class="btn pri" onclick="runNow(false)">Jetzt prüfen</button>
    <button class="btn" onclick="runNow(true)">Vollprüfung starten</button>
    <button class="btn danger" id="stopBtn" onclick="stopRun()">Abbrechen</button>
    <button class="btn" onclick="testConn()">Verbindungen testen</button></div>
  <div id="testRes" style="margin-top:12px"></div></div>
  <div class="card"><h2>Letzte Funde</h2><div id="recent"></div></div>
</section>
<section data-tab="Funde">
  <div class="card"><div class="row" style="justify-content:space-between"><h2>Falsche Trailer</h2>
  <button class="btn danger" onclick="reset('events','Fundliste leeren?')">Liste leeren</button></div><div id="events"></div></div>
</section>
<section data-tab="Abgelehnt">
  <div class="card"><h2>Abgelehnte Videos je Titel</h2>
  <p class="hint">Diese YouTube-Videos werden für den Titel nicht mehr als Ersatz genommen. Zurücksetzen erlaubt sie wieder und schaltet auf Wunsch die Trailarr-Überwachung wieder ein.</p>
  <div id="rejected"></div></div>
  <div class="card"><h2>Prüfstatus</h2><p class="hint">Bereits als korrekt geprüfte Trailer werden übersprungen. Nach geänderten Regeln kann man alles neu prüfen lassen.</p>
  <button class="btn danger" onclick="reset('checked','Alle Trailer beim nächsten Durchlauf neu prüfen?')">Prüfstatus zurücksetzen</button></div>
</section>
<section data-tab="Einstellungen">
<form id="cfgForm">
  <div class="card"><h2>Betrieb</h2>
    <label class="chk"><input type="checkbox" id="c_dry_run">Probelauf (nur protokollieren, nichts löschen)</label>
    <div class="hint">Erst ausschalten, wenn die Funde in der Liste stimmen.</div>
    <div class="two">
      <div><label>Prüfintervall (Sekunden)</label><input id="c_interval" type="number" min="30"><div class="hint">neue Downloads prüfen, z. B. 300 = 5 Min.</div></div>
      <div><label>Vollprüfung alle (Sekunden)</label><input id="c_full_every" type="number" min="300"><div class="hint">alle Trailer, z. B. 86400 = täglich</div></div>
    </div></div>
  <div class="card"><h2>Verbindungen</h2>
    <label>Trailarr-URL</label><input id="c_trailarr_url" placeholder="http://trailarr:7889">
    <div class="two">
      <div><label>Trailarr-API-Key</label><input id="c_trailarr_api_key" type="password" autocomplete="off"><div class="hint" id="h_trailarr_api_key"></div></div>
      <div><label>TMDB-API-Key oder Lesetoken</label><input id="c_tmdb_api_key" type="password" autocomplete="off"><div class="hint" id="h_tmdb_api_key"></div></div>
    </div></div>
  <div class="card"><h2>Prüfregeln</h2>
    <div class="two">
      <div><label>Mindestlänge (Sekunden)</label><input id="c_min_len" type="number" min="0"></div>
      <div><label>Höchstlänge (Sekunden)</label><input id="c_max_len" type="number" min="10"></div>
      <div><label>Jahrestoleranz (± Jahre)</label><input id="c_year_tol" type="number" min="0" max="10"></div>
      <div><label>Max. Ersatzversuche je Titel</label><input id="c_max_rejects" type="number" min="1"><div class="hint">danach bleibt der Trailer weg</div></div>
    </div>
    <label class="chk" style="margin-top:14px"><input type="checkbox" id="c_prefer_german">Deutsche Trailer bevorzugen</label>
    <label>Verdächtige Begriffe im Videotitel (einer pro Zeile, reguläre Ausdrücke erlaubt)</label>
    <textarea id="c_bad_words" spellcheck="false"></textarea>
    <div class="row" style="margin-top:6px"><button type="button" class="btn" onclick="defaultsBad()">Standardliste wiederherstellen</button></div>
  </div>
  <div class="row"><button class="btn pri">Speichern</button></div>
</form>
</section>
<section data-tab="Konto">
  <div class="card"><h2>Zugangsdaten</h2><form id="accForm" autocomplete="off">
    <div class="two"><div><label>Benutzername</label><input id="aUser" autocomplete="username"></div>
    <div><label>Neues Passwort (leer = unverändert)</label><input id="aPw" type="password" autocomplete="new-password"></div>
    <div><label>Neues Passwort wiederholen</label><input id="aPw2" type="password" autocomplete="new-password"></div>
    <div><label>Aktuelles Passwort (zur Bestätigung)</label><input id="aCur" type="password" autocomplete="current-password" required></div></div>
    <div class="row" style="margin-top:14px"><button class="btn pri">Ändern</button></div>
    <p class="hint">Andere angemeldete Geräte werden dabei abgemeldet.</p></form></div>
  <div class="card"><h2>Zwei-Faktor-Anmeldung (2FA)</h2>
    <div id="tfaOff"><p>Zusätzlich zum Passwort wird bei der Anmeldung ein 6-stelliger Code aus einer Authenticator-App abgefragt (z. B. Google Authenticator, Aegis, 2FAS, Bitwarden).</p>
      <button class="btn pri" onclick="tfaStart()">2FA einrichten</button>
      <div id="tfaSetup" class="hidden" style="margin-top:16px">
        <p>1. QR-Code mit der App scannen oder den Schlüssel manuell eingeben:</p>
        <div id="tfaQr"></div><p>Schlüssel: <code id="tfaSecret"></code></p>
        <p>2. Angezeigten Code eingeben:</p>
        <div class="row"><input id="tfaCode" inputmode="numeric" maxlength="7" placeholder="123456" style="max-width:160px">
        <button class="btn pri" onclick="tfaEnable()">Aktivieren</button></div></div></div>
    <div id="tfaOn" class="hidden"><p><span class="tag ok">aktiv</span> Die Anmeldung ist durch 2FA geschützt.</p>
      <div class="two"><div><label>Passwort</label><input id="tdPw" type="password" autocomplete="current-password"></div>
      <div><label>Aktueller Code oder Wiederherstellungscode</label><input id="tdCode" maxlength="20"></div></div>
      <div class="row" style="margin-top:14px"><button class="btn danger" onclick="tfaDisable()">2FA ausschalten</button>
      <button class="btn" onclick="tfaRecovery()">Neue Wiederherstellungscodes (nur Passwort nötig)</button></div></div>
    <div id="recBox" class="hidden" style="margin-top:16px"><div class="warn"><b>Wiederherstellungscodes – jetzt sicher aufbewahren!</b> Jeder Code funktioniert einmal anstelle des App-Codes. Sie werden nur dieses eine Mal angezeigt.</div>
      <pre id="recCodes" style="height:auto;font-size:15px"></pre>
      <div class="row" style="margin-top:8px"><button class="btn" onclick="navigator.clipboard.writeText($('#recCodes').textContent).then(()=>toast('Kopiert'))">Kopieren</button></div></div>
    <p class="hint">Handy und Wiederherstellungscodes verloren? Container einmal mit <code>WEB_RESET_AUTH=1</code> starten – dann werden Benutzer und 2FA gelöscht und neu eingerichtet.</p>
  </div>
</section>
<section data-tab="Log">
  <div class="card"><div class="row" style="justify-content:space-between;margin-bottom:10px"><h2 style="margin:0">Protokoll</h2>
  <label class="chk" style="margin:0"><input type="checkbox" id="follow" checked>automatisch mitscrollen</label></div><pre id="log"></pre></div>
</section>
</main></div>
<div id="toast"></div>

<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let me={},tab='Übersicht',logSeq=0,timer=null,mode='login';
const DEFAULT_BAD=%BAD%;
function toast(m,err){const t=$('#toast');t.textContent=m;t.className=err?'err':'';t.style.display='block';clearTimeout(t._h);t._h=setTimeout(()=>t.style.display='none',err?6000:3000)}
async function api(p,body){
  const o=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-TG':'1'},body:JSON.stringify(body)};
  const r=await fetch(p,o);const j=await r.json().catch(()=>({}));
  if(r.status===401&&!p.startsWith('/api/login')){showLogin();throw new Error('nicht angemeldet')}
  if(!r.ok)throw new Error(j.error||r.statusText);return j}
const wrap=f=>async(...a)=>{try{await f(...a)}catch(e){if(e.message!=='nicht angemeldet')toast(e.message,true)}};
function ago(t){if(!t)return'–';const s=Math.round(Date.now()/1000-t);if(s<60)return'gerade eben';if(s<3600)return'vor '+Math.round(s/60)+' Min.';if(s<86400)return'vor '+Math.round(s/3600)+' Std.';return new Date(t*1000).toLocaleString('de-AT')}
function inn(t){const s=Math.round(t-Date.now()/1000);if(s<=0)return'gleich';if(s<60)return'in '+s+' s';if(s<3600)return'in '+Math.round(s/60)+' Min.';return'in '+Math.round(s/3600)+' Std.'}
function dt(t){return new Date(t*1000).toLocaleString('de-AT',{dateStyle:'short',timeStyle:'short'})}
const yt=id=>id?`<a href="https://www.youtube.com/watch?v=${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>`:'';

// ---- Anmeldung
async function boot(){me=await api('/api/me');if(me.logged_in)showApp();else showLogin()}
function showReset(){$('#loginForm').classList.add('hidden');$('#resetForm').classList.remove('hidden');$('#loginSub').textContent='Passwort zurücksetzen';
  ['rCode','rPw','rPw2','rTotp'].forEach(i=>$('#'+i).value='')}
const resetRequest=wrap(async()=>{await api('/api/pwreset/request',{});toast('Reset-Code wurde ins Container-Protokoll geschrieben');$('#rCode').focus()});
$('#resetForm').onsubmit=wrap(async e=>{e.preventDefault();if($('#rPw').value!==$('#rPw2').value)throw new Error('Passwörter stimmen nicht überein');
  const r=await api('/api/pwreset/confirm',{reset_code:$('#rCode').value,password:$('#rPw').value,code:$('#rTotp').value});
  showLogin();$('#lUser').value=r.user;$('#lPw').focus();toast('Passwort geändert – bitte neu anmelden')});
function showLogin(){clearInterval(timer);$('#appView').classList.add('hidden');$('#loginView').classList.remove('hidden');
  $('#loginForm').classList.remove('hidden');$('#resetForm').classList.add('hidden');$('#forgot').classList.toggle('hidden',!!me.setup);
  mode=me.setup?'setup':'login';$('#lfSetup').classList.toggle('hidden',!me.setup);$('#lfCode').classList.add('hidden');$('#lfCreds').classList.remove('hidden');
  $('#loginSub').textContent=me.setup?'Ersteinrichtung: Benutzer für die Weboberfläche anlegen':'Anmelden';
  $('#lBtn').textContent=me.setup?'Benutzer anlegen':'Anmelden';$('#lPw').autocomplete=me.setup?'new-password':'current-password';
  $('#lHint').textContent=me.setup?'Passwort mit mindestens 8 Zeichen. 2FA lässt sich danach unter „Konto“ einschalten.':'';$('#lUser').focus()}
$('#loginForm').onsubmit=wrap(async e=>{e.preventDefault();
  const u=$('#lUser').value.trim(),p=$('#lPw').value;
  if(mode==='setup'){if(p!==$('#lPw2').value)throw new Error('Passwörter stimmen nicht überein');await api('/api/setup',{user:u,password:p})}
  else{const r=await api('/api/login',{user:u,password:p,code:mode==='code'?$('#lCode').value:undefined});
    if(r.need_code){mode='code';$('#lfCreds').classList.add('hidden');$('#lfCode').classList.remove('hidden');$('#lBtn').textContent='Bestätigen';$('#loginSub').textContent='Zwei-Faktor-Anmeldung';$('#lCode').value='';$('#lCode').focus();return}}
  $('#lPw').value=$('#lPw2').value=$('#lCode').value='';me=await api('/api/me');showApp()});
const logout=wrap(async()=>{await api('/api/logout',{});me=await api('/api/me');showLogin()});

// ---- App
function showApp(){$('#loginView').classList.add('hidden');$('#appView').classList.remove('hidden');$('#who').textContent=me.user;
  const tabs=[...document.querySelectorAll('section[data-tab]')].map(s=>s.dataset.tab);
  $('#tabs').innerHTML=tabs.map(t=>`<button data-t="${t}">${t}</button>`).join('');
  $('#tabs').onclick=e=>{if(e.target.dataset.t)go(e.target.dataset.t)};go(location.hash?decodeURIComponent(location.hash.slice(1)):tab)}
function go(t){if(!document.querySelector(`section[data-tab="${t}"]`))t='Übersicht';tab=t;history.replaceState(null,'','#'+encodeURIComponent(t));
  document.querySelectorAll('section[data-tab]').forEach(s=>s.classList.toggle('hidden',s.dataset.tab!==t));
  document.querySelectorAll('#tabs button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));
  clearInterval(timer);refresh(true);timer=setInterval(refresh,3000)}
const refresh=wrap(async first=>{
  const s=await api('/api/status');const m=$('#mode');m.textContent=s.dry_run?'PROBELAUF':'AKTIV';m.className='badge '+(s.dry_run?'dry':'live');
  if(tab==='Übersicht'){renderStatus(s);if(first||s.running)renderRecent(await api('/api/events'))}
  else if(tab==='Funde'&&first)$('#events').innerHTML=evTable(await api('/api/events'));
  else if(tab==='Abgelehnt'&&first)renderRejected(await api('/api/rejected'));
  else if(tab==='Einstellungen'&&first)fillCfg(await api('/api/config'));
  else if(tab==='Konto'&&first)renderAccount();
  else if(tab==='Log')loadLog(first)});
function renderStatus(s){
  $('#warns').innerHTML=s.warnings.map(w=>`<div class="warn">${esc(w)}</div>`).join('')+(s.error?`<div class="warn" style="border-color:var(--bad)">Letzter Fehler: ${esc(s.error)}</div>`:'');
  const st=s.running?`läuft${s.full?' (Vollprüfung)':''}`:'wartet';
  $('#stats').innerHTML=[['Status',st],['Letzter Durchlauf',s.running?'jetzt':ago(s.finished)],['Nächster Durchlauf',s.running?'–':inn(s.next_run)],
    ['Letzte Vollprüfung',ago(s.last_full)],['Nächste Vollprüfung',inn(s.next_full)],['Korrekt',s.checked.ok],['Probelauf-Funde',s.checked.dry],['Ersetzt/entfernt',s.checked.removed]]
    .map(([a,b])=>`<div class="stat"><span>${a}</span><b>${esc(b)}</b></div>`).join('');
  $('#prog').classList.toggle('hidden',!s.running||!s.total);$('#prog i').style.width=(s.total?100*s.progress/s.total:0)+'%';
  $('#stopBtn').disabled=!s.running}
const ACT={dry:['warn','würde ersetzt'],replaced:['ok','ersetzt'],removed:['bad','entfernt'],error:['bad','Fehler']};
function evTable(ev){if(!ev.length)return'<p class="mute">Noch keine falschen Trailer gefunden.</p>';
  return`<table><tr><th>Zeit</th><th>Titel</th><th>Gefundenes Video</th><th>Gründe</th><th>Ergebnis</th></tr>`+ev.map(e=>{const a=ACT[e.action]||['',e.action];
  const rep=e.replacement?`<br><span class="mute">Ersatz:</span> ${esc(e.replacement.title)} (${yt(e.replacement.id)})`:(e.action==='dry'?'<br><span class="mute">kein Ersatz – würde entfernt</span>':'');
  return`<tr><td class="mute">${dt(e.time)}</td><td>${esc(e.title)} <span class="mute">${esc(e.year||'')}</span></td><td>${esc(e.video||'–')}<br>${yt(e.yt_id)}</td>
  <td>${(e.why||[]).map(w=>`<span class="tag bad">${esc(w)}</span>`).join('')}</td><td><span class="tag ${a[0]}">${a[1]}</span>${rep}${e.error?'<br>'+esc(e.error):''}</td></tr>`}).join('')+'</table>'}
function renderRecent(ev){$('#recent').innerHTML=evTable(ev.slice(0,5))+(ev.length>5?`<p><a href="#" onclick="go('Funde');return false">Alle ${ev.length} anzeigen</a></p>`:'')}
function renderRejected(r){$('#rejected').innerHTML=!r.length?'<p class="mute">Keine abgelehnten Videos.</p>':
  `<table><tr><th>Titel</th><th>Abgelehnte Videos</th><th></th></tr>`+r.map(x=>`<tr><td>${esc(x.title)}${x.unmonitored?'<br><span class="tag warn">Trailarr-Überwachung aus</span>':''}</td>
  <td>${x.videos.map(yt).join(', ')}</td><td><button class="btn" onclick="unreject('${esc(x.id)}',${x.unmonitored})">Zurücksetzen</button></td></tr>`).join('')+'</table>'}
const unreject=wrap(async(id,unmon)=>{const monitor=unmon&&confirm('Trailarr-Überwachung für diesen Titel wieder einschalten?');
  const r=await api('/api/reset',{what:'rejected',id,monitor});toast(r.msg);renderRejected(await api('/api/rejected'))});
const reset=wrap(async(what,q)=>{if(!confirm(q))return;const r=await api('/api/reset',{what});toast(r.msg);refresh(true)});
const runNow=wrap(async full=>{const r=await api('/api/run',{full});toast(full?'Vollprüfung '+r.msg:'Prüfung '+r.msg);setTimeout(refresh,800)});
const stopRun=wrap(async()=>{await api('/api/stop',{});toast('wird nach dem aktuellen Titel abgebrochen')});
const testConn=wrap(async()=>{$('#testRes').innerHTML='<span class="mute">teste …</span>';const r=await api('/api/test');
  const n={trailarr:'Trailarr',tmdb:'TMDB',ytdlp:'yt-dlp'};$('#testRes').innerHTML=Object.entries(r).map(([k,v])=>`<div><span class="tag ${v.ok?'ok':'bad'}">${v.ok?'OK':'Fehler'}</span> <b>${n[k]}</b>: ${esc(v.msg)}</div>`).join('')});

// ---- Einstellungen
const NUM=['interval','full_every','min_len','max_len','year_tol','max_rejects'];
function fillCfg(c){$('#c_dry_run').checked=c.dry_run;$('#c_prefer_german').checked=c.prefer_german;$('#c_trailarr_url').value=c.trailarr_url;
  NUM.forEach(k=>$('#c_'+k).value=c[k]);$('#c_bad_words').value=c.bad_words.join('\n');
  ['trailarr_api_key','tmdb_api_key'].forEach(k=>{$('#c_'+k).value='';$('#c_'+k).placeholder=c[k+'_set']?'•••••••• (gespeichert)':'nicht gesetzt';
  $('#h_'+k).textContent=c[k+'_set']?'leer lassen = unverändert':''})}
function defaultsBad(){$('#c_bad_words').value=DEFAULT_BAD.join('\n')}
$('#cfgForm').onsubmit=wrap(async e=>{e.preventDefault();const d={dry_run:$('#c_dry_run').checked,prefer_german:$('#c_prefer_german').checked,
  trailarr_url:$('#c_trailarr_url').value,bad_words:$('#c_bad_words').value,trailarr_api_key:$('#c_trailarr_api_key').value,tmdb_api_key:$('#c_tmdb_api_key').value};
  NUM.forEach(k=>d[k]=$('#c_'+k).value);
  const before=await api('/api/config');if(before.dry_run&&!d.dry_run&&!confirm('Probelauf ausschalten? Falsche Trailer werden dann wirklich gelöscht und ersetzt.'))return;
  fillCfg(await api('/api/config',d));toast('Gespeichert')});

// ---- Konto
function renderAccount(){$('#aUser').value=me.user;['aPw','aPw2','aCur','tdPw','tdCode','tfaCode'].forEach(i=>$('#'+i).value='');
  $('#tfaOn').classList.toggle('hidden',!me.totp_on);$('#tfaOff').classList.toggle('hidden',me.totp_on);$('#tfaSetup').classList.add('hidden');$('#recBox').classList.add('hidden')}
$('#accForm').onsubmit=wrap(async e=>{e.preventDefault();if($('#aPw').value!==$('#aPw2').value)throw new Error('Neue Passwörter stimmen nicht überein');
  const r=await api('/api/account',{user:$('#aUser').value.trim(),password:$('#aPw').value,current:$('#aCur').value});me.user=r.user;$('#who').textContent=r.user;renderAccount();toast('Zugangsdaten geändert')});
const tfaStart=wrap(async()=>{const r=await api('/api/totp/start',{});$('#tfaSetup').classList.remove('hidden');$('#tfaSecret').textContent=r.secret.replace(/(.{4})/g,'$1 ').trim();
  $('#tfaQr').innerHTML=r.qr?`<div class="qr"><img src="${r.qr}" alt="QR-Code"></div>`:`<p class="mute">QR-Code nicht verfügbar – Schlüssel manuell eingeben oder <a href="${esc(r.uri)}">Link öffnen</a>.</p>`;$('#tfaCode').focus()});
function showRec(c){$('#recCodes').textContent=c.join('\n');$('#recBox').classList.remove('hidden')}
const tfaEnable=wrap(async()=>{const r=await api('/api/totp/enable',{code:$('#tfaCode').value});me.totp_on=true;renderAccount();showRec(r.recovery);toast('2FA ist jetzt aktiv')});
const tfaRecovery=wrap(async()=>{if(!confirm('Neue Codes erzeugen? Die bisherigen werden ungültig.'))return;const r=await api('/api/totp/recovery',{password:$('#tdPw').value});$('#tdPw').value='';showRec(r.recovery)});
const tfaDisable=wrap(async()=>{if(!confirm('2FA wirklich ausschalten?'))return;await api('/api/totp/disable',{password:$('#tdPw').value,code:$('#tdCode').value});me.totp_on=false;renderAccount();toast('2FA ausgeschaltet')});

// ---- Log
async function loadLog(first){if(first){logSeq=0;$('#log').textContent=''}const r=await api('/api/log?since='+logSeq);
  if(r.seq<logSeq){logSeq=0;return}logSeq=r.seq;if(r.lines.length){const p=$('#log');p.textContent+=r.lines.join('\n')+'\n';if($('#follow').checked)p.scrollTop=p.scrollHeight}}
boot().catch(e=>toast(e.message,true));
</script></body></html>
""".replace("%BAD%", json.dumps(DEFAULT_BAD, ensure_ascii=False).replace("</", "<\\/"))


def serve():
    srv = ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler)
    srv.daemon_threads = True
    log(f"Weboberflaeche auf Port {WEB_PORT}" + ("" if AUTH.get("user") else " - noch kein Benutzer, bitte im Browser einrichten"))
    srv.serve_forever()


if __name__ == "__main__":
    apply_config(load_config())
    ST.update(load_state())
    AUTH.update(load_auth())
    log(f"trailer-guard gestartet, Intervall {INTERVAL} s, Vollpruefung alle {FULL_EVERY} s")
    threading.Thread(target=serve, daemon=True, name="web").start()
    worker()
