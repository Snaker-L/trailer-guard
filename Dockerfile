# trailer-guard: prueft Trailarr-Trailer gegen Titel/Jahr und ersetzt falsche (Quelle: /config/trailer-guard in Home Assistant)
# Weboberflaeche auf Port 8097 (WEB_PORT), Einstellungen/Anmeldedaten unter /state
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir yt-dlp segno
WORKDIR /app
COPY guard.py /app/guard.py
ENV PYTHONUNBUFFERED=1 TZ=Europe/Vienna WEB_PORT=8097
EXPOSE 8097
ENTRYPOINT ["tini", "--", "python3", "/app/guard.py"]
