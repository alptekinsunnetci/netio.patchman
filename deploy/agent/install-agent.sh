#!/bin/sh
# netio.patchman ajan kurulum betiği
#
# Sunucudan indirerek kurulum:
#   curl -fsSL https://patchman.your-domain/downloads/install-agent.sh | \
#     sudo sh -s -- --server-url https://patchman.your-domain --token <kayıt-anahtarı>
#
# Çevrimdışı kurulum: ajan ikili dosyasını ve netio-patchman-agent.service
# dosyasını bu betikle aynı dizine koyun ve --binary seçeneğini kullanın.

set -eu

AGENT_BINARY="netio-patchman-agent"
SERVICE_NAME="netio-patchman-agent.service"
INSTALL_PATH="/usr/local/bin/${AGENT_BINARY}"
CONFIG_DIR="/etc/netio-patchman"
CONFIG_FILE="${CONFIG_DIR}/agent.env"
STATE_DIR="/var/lib/netio-patchman"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"

SERVER_URL=""
TOKEN=""
BINARY_SRC=""
CA_FILE=""
REMOTE_UPDATES="true"
AUTO_UPDATE="true"
TMP_DIR=""

bilgi() { printf '[netio.patchman] %s\n' "$*"; }
hata()  { printf '[netio.patchman] HATA: %s\n' "$*" >&2; exit 1; }
temizle() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
trap temizle EXIT

kullanim() {
	cat <<EOF
netio.patchman ajan kurulumu

Kullanım:
  sudo sh install-agent.sh --server-url <adres> --token <kayıt-anahtarı> [seçenekler]

Seçenekler:
  --server-url <adres>       Merkezi netio.patchman sunucusunun adresi (zorunlu)
  --token <anahtar>          Ajan kayıt anahtarı (yeni kurulumda zorunlu)
  --binary <dosya>           Ajanı sunucudan indirmek yerine bu dosyadan kur
  --ca-file <dosya>          Sunucu sertifikasını doğrulamak için ek CA dosyası
  --disable-remote-updates   Panelden başlatılan paket güncelleme işlerini bu sunucuda kapat
  --disable-auto-update      Ajanın kendini otomatik güncellemesini bu sunucuda kapat
  -h, --help                 Bu yardım metnini gösterir
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--server-url) [ $# -ge 2 ] || hata "--server-url için değer belirtilmedi."; SERVER_URL="${2%/}"; shift 2 ;;
		--token)      [ $# -ge 2 ] || hata "--token için değer belirtilmedi."; TOKEN="$2"; shift 2 ;;
		--binary)     [ $# -ge 2 ] || hata "--binary için değer belirtilmedi."; BINARY_SRC="$2"; shift 2 ;;
		--ca-file)    [ $# -ge 2 ] || hata "--ca-file için değer belirtilmedi."; CA_FILE="$2"; shift 2 ;;
		--disable-remote-updates) REMOTE_UPDATES="false"; shift ;;
		--disable-auto-update) AUTO_UPDATE="false"; shift ;;
		-h|--help)    kullanim; exit 0 ;;
		*)            kullanim >&2; hata "Bilinmeyen seçenek: $1" ;;
	esac
done

[ "$(uname -s)" = "Linux" ] || hata "Ajan yalnızca Linux sistemlerde desteklenir."
[ "$(id -u)" -eq 0 ]        || hata "Bu betik root yetkisiyle çalıştırılmalıdır (sudo kullanın)."
command -v systemctl >/dev/null 2>&1 || hata "systemd bulunamadı. Ajan, systemd kullanan dağıtımları destekler."
[ -n "$SERVER_URL" ]        || hata "Merkezi sunucu adresi (--server-url) zorunludur."
case "$SERVER_URL" in
	https://*) ;;
	http://*) bilgi "UYARI: Sunucu adresi şifrelenmemiş HTTP kullanıyor. Üretim ortamında HTTPS kullanın." ;;
	*) hata "Sunucu adresi http:// veya https:// ile başlamalıdır: $SERVER_URL" ;;
esac
if [ -z "$TOKEN" ] && [ ! -f "${STATE_DIR}/credentials.json" ]; then
	hata "Ajan kayıt anahtarı (--token) zorunludur. Anahtarı yönetim panelindeki Ajan Yönetimi sayfasından oluşturabilirsiniz."
fi
if [ -n "$CA_FILE" ] && [ ! -f "$CA_FILE" ]; then
	hata "CA dosyası bulunamadı: $CA_FILE"
fi

case "$(uname -m)" in
	x86_64|amd64)  ARCH="amd64" ;;
	aarch64|arm64) ARCH="arm64" ;;
	*) hata "Desteklenmeyen işlemci mimarisi: $(uname -m)" ;;
esac

indir() {
	# indir <adres> <hedef>
	if command -v curl >/dev/null 2>&1; then
		if [ -n "$CA_FILE" ]; then
			curl -fsSL --proto '=https,http' --cacert "$CA_FILE" -o "$2" "$1"
		else
			curl -fsSL --proto '=https,http' -o "$2" "$1"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [ -n "$CA_FILE" ]; then
			wget -q --ca-certificate="$CA_FILE" -O "$2" "$1"
		else
			wget -q -O "$2" "$1"
		fi
	else
		hata "Dosya indirmek için curl veya wget gereklidir."
	fi
}

TMP_DIR=$(mktemp -d)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo "")

if [ -z "$BINARY_SRC" ]; then
	DIST_NAME="${AGENT_BINARY}-linux-${ARCH}"
	bilgi "Ajan indiriliyor: ${SERVER_URL}/downloads/agent/${DIST_NAME}"
	indir "${SERVER_URL}/downloads/agent/${DIST_NAME}" "${TMP_DIR}/${AGENT_BINARY}" || hata "Ajan ikili dosyası indirilemedi."
	if indir "${SERVER_URL}/downloads/agent/${DIST_NAME}.sha256" "${TMP_DIR}/agent.sha256" 2>/dev/null; then
		if command -v sha256sum >/dev/null 2>&1; then
			BEKLENEN=$(cut -d' ' -f1 < "${TMP_DIR}/agent.sha256")
			HESAPLANAN=$(sha256sum "${TMP_DIR}/${AGENT_BINARY}" | cut -d' ' -f1)
			[ "$BEKLENEN" = "$HESAPLANAN" ] || hata "İndirilen dosyanın SHA-256 özeti eşleşmiyor."
			bilgi "SHA-256 doğrulaması başarılı."
		fi
	fi
	BINARY_SRC="${TMP_DIR}/${AGENT_BINARY}"
fi
[ -f "$BINARY_SRC" ] || hata "Ajan ikili dosyası bulunamadı: $BINARY_SRC"

UNIT_SRC=""
for aday in "${SCRIPT_DIR}/${SERVICE_NAME}" "$(dirname -- "$BINARY_SRC")/${SERVICE_NAME}"; do
	if [ -n "$aday" ] && [ -f "$aday" ]; then UNIT_SRC="$aday"; break; fi
done
if [ -z "$UNIT_SRC" ]; then
	indir "${SERVER_URL}/downloads/${SERVICE_NAME}" "${TMP_DIR}/${SERVICE_NAME}" || hata "systemd birim dosyası indirilemedi."
	UNIT_SRC="${TMP_DIR}/${SERVICE_NAME}"
fi

bilgi "Ajan ikili dosyası kuruluyor: ${INSTALL_PATH}"
install -m 0755 "$BINARY_SRC" "$INSTALL_PATH"
"$INSTALL_PATH" -version >/dev/null 2>&1 || hata "Kurulan ajan çalıştırılamadı. Mimariyi ve dosyayı kontrol edin."

install -d -m 0750 "$CONFIG_DIR"
install -d -m 0700 "$STATE_DIR"
if [ -f "$CONFIG_FILE" ]; then
	cp -p "$CONFIG_FILE" "${CONFIG_FILE}.$(date -u +%Y%m%dT%H%M%SZ).bak"
	bilgi "Mevcut yapılandırma yedeklendi."
fi
if [ -n "$CA_FILE" ]; then
	install -m 0644 "$CA_FILE" "${CONFIG_DIR}/ca.pem"
fi

bilgi "Yapılandırma yazılıyor: ${CONFIG_FILE}"
umask 077
{
	echo "# netio.patchman ajan yapılandırması"
	echo "PATCHMAN_SERVER_URL=${SERVER_URL}"
	if [ -n "$TOKEN" ]; then echo "PATCHMAN_ENROLLMENT_TOKEN=${TOKEN}"; fi
	if [ -n "$CA_FILE" ]; then echo "PATCHMAN_CA_FILE=${CONFIG_DIR}/ca.pem"; fi
	echo "PATCHMAN_REMOTE_UPDATES=${REMOTE_UPDATES}"
	echo "PATCHMAN_AUTO_UPDATE=${AUTO_UPDATE}"
} > "$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"

if [ -n "$TOKEN" ] && [ -f "${STATE_DIR}/credentials.json" ]; then
	bilgi "Yeni kayıt anahtarı verildiği için mevcut ajan kimliği yenilenecek."
	rm -f "${STATE_DIR}/credentials.json"
fi

bilgi "systemd hizmeti kuruluyor: ${SERVICE_NAME}"
install -m 0644 "$UNIT_SRC" "$UNIT_PATH"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

sleep 3
if systemctl is-active --quiet "$SERVICE_NAME"; then
	bilgi "Kurulum tamamlandı. Ajan çalışıyor ve sunucuya kaydoluyor."
	bilgi "Durum: systemctl status ${SERVICE_NAME}"
	bilgi "Kayıtlar: journalctl -u ${SERVICE_NAME} -f"
else
	hata "Ajan başlatılamadı. Ayrıntılar için: journalctl -u ${SERVICE_NAME} -n 50"
fi
