# netio.patchman güncelleyici: panelden istenen sürüm yükseltmesini yapar.
# docker-compose.yml içindeki "updater" profiliyle çalışır (COMPOSE_PROFILES=updater).
# Betik depodan (/repo) okunur; böylece git pull ile kendisi de güncellenir.
FROM docker:29.10.0-cli
RUN apk add --no-cache git su-exec
COPY updater.sh /usr/local/bin/netio-patchman-updater
CMD ["sh", "-c", "if [ -f /repo/deploy/updater/updater.sh ]; then exec sh /repo/deploy/updater/updater.sh; else exec sh /usr/local/bin/netio-patchman-updater; fi"]
