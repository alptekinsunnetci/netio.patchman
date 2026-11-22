#!/bin/sh
# netio.patchman güncelleyici.
#
# Paylaşılan veri birimindeki /data/update-request.json dosyasını bekler (sunucu yazar). Dosya
# gelince sırasıyla: git pull --ff-only, veritabanı yedeği, yeni imajın
# derlenmesi, sunucunun yeniden başlatılması ve sağlık denetimi yapılır.
# Durum /data/update/status.json, ayrıntılı çıktı /data/update/update.log
# dosyasına yazılır; panel bunları gösterir. İstek dosyasının içeriği
# kullanılmaz: güncelleyici yalnızca bu sabit adımları çalıştırır.

set -u

REPO=/repo
DIR=/data/update
COMPOSE="docker compose --project-directory $REPO -f $REPO/docker-compose.yml"

mkdir -p "$DIR"
chmod 0755 "$DIR"

# Depo dosyaları, sahibinin kimliğiyle güncellenir (root'a geçmesin).
OWNER=$(stat -c %u:%g "$REPO")
git_() { su-exec "$OWNER" git -c safe.directory="$REPO" -C "$REPO" "$@"; }

version() {
	v=$(tr -d ' \r\n' < "$REPO/VERSION" 2>/dev/null)
	case "$v" in
		*[!0-9A-Za-z.+~_-]*|'') echo "unknown" ;;
		*) echo "$v" ;;
	esac
}

# write_status <durum> <adım> <başlangıç> <bitiş> <önceki sürüm> <yeni sürüm>
write_status() {
	printf '{"state":"%s","step":"%s","started_at":%s,"finished_at":%s,"from":"%s","to":"%s"}\n' \
		"$1" "$2" "$3" "$4" "$5" "$6" > "$DIR/status.json.tmp"
	chmod 0644 "$DIR/status.json.tmp"
	mv "$DIR/status.json.tmp" "$DIR/status.json"
}

log() { printf '\n[netio.patchman] %s\n' "$*" >> "$DIR/update.log"; }

run_update() {
	start=$(date +%s)
	from=$(version)
	: > "$DIR/update.log"
	chmod 0644 "$DIR/update.log"
	step=""
	fail() {
		log "HATA: adım başarısız: $step"
		write_status failed "$step" "$start" "$(date +%s)" "$from" "$(version)"
	}

	step=pull
	write_status running "$step" "$start" 0 "$from" ""
	log "git pull"
	if ! git_ fetch --tags --prune origin >> "$DIR/update.log" 2>&1 || ! git_ pull --ff-only >> "$DIR/update.log" 2>&1; then
		fail; return
	fi
	to=$(version)

	step=backup
	write_status running "$step" "$start" 0 "$from" "$to"
	backup="/data/before-update-$from-$(date -u +%Y%m%d%H%M%S).db"
	log "yedek: $backup"
	if ! $COMPOSE exec -T server netio-patchman-server backup -out "$backup" >> "$DIR/update.log" 2>&1; then
		fail; return
	fi

	step=build
	write_status running "$step" "$start" 0 "$from" "$to"
	log "docker compose build server"
	if ! $COMPOSE build server >> "$DIR/update.log" 2>&1; then
		fail; return
	fi

	step=restart
	write_status running "$step" "$start" 0 "$from" "$to"
	log "docker compose up -d server"
	if ! $COMPOSE up -d server >> "$DIR/update.log" 2>&1; then
		fail; return
	fi

	step=health
	write_status running "$step" "$start" 0 "$from" "$to"
	log "sağlık denetimi"
	i=0
	# İlk açılışta veritabanı aktarımı (0.8.0, SQLite -> PostgreSQL) sürebilir: en fazla 10 dakika.
	while [ $i -lt 120 ]; do
		id=$($COMPOSE ps -q server 2>/dev/null)
		health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id" 2>/dev/null)
		if [ "$health" = "healthy" ]; then
			log "sunucu çalışıyor: $to"
			write_status succeeded done "$start" "$(date +%s)" "$from" "$to"
			return
		fi
		i=$((i + 1))
		sleep 5
	done
	log "sunucu 10 dakika içinde sağlıklı duruma geçmedi: $health"
	fail
}

while true; do
	printf '{"version":"%s","seen_at":%s}\n' "$(version)" "$(date +%s)" > "$DIR/updater.json.tmp"
	chmod 0644 "$DIR/updater.json.tmp"
	mv "$DIR/updater.json.tmp" "$DIR/updater.json"
	if [ -f /data/update-request.json ]; then
		rm -f /data/update-request.json
		run_update
	fi
	sleep 5
done
