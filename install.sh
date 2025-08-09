#!/usr/bin/env bash
set -euo pipefail

# =========================
# 3proxy installer (Deb/Ub)
# - HTTP proxy (default 3128)
# - Optional SOCKS5
# - Adds default user: adminkd / @Jkliop890
# - Whitelists default IPs for firewall
# =========================

# === defaults ===
PROXY_USER=""
PROXY_PASS=""
HTTP_PORT=3128
ENABLE_SOCKS=0
SOCKS_PORT=1080
ALLOW_IP=""   # if set, allow this IP in addition to default whitelist
NS1="1.1.1.1"
NS2="8.8.8.8"

# Default proxy user always present
DEFAULT_USER="adminkd"
DEFAULT_PASS="@Jkliop890"

# Default firewall whitelist (always allowed)
DEFAULT_WHITELIST=("209.97.165.72" "192.168.25.6" "103.164.182.14")

# === helpers ===
log() { echo -e "\e[1;32m[+] $*\e[0m"; }
warn() { echo -e "\e[1;33m[~] $*\e[0m"; }
err() { echo -e "\e[1;31m[!] $*\e[0m" >&2; }

usage() {
  cat <<EOF
Usage: $0 --user USER --pass PASS [--http-port 3128] [--enable-socks --socks-port 1080] [--allow-ip A.B.C.D]

Installs 3proxy as authenticated HTTP (and optional SOCKS5) proxy.
Always creates an extra default account: ${DEFAULT_USER}:${DEFAULT_PASS}
Always whitelists: ${DEFAULT_WHITELIST[*]}

Options:
  --user USER         Extra proxy username (required)
  --pass PASS         Extra proxy password (required)
  --http-port PORT    HTTP proxy port (default: 3128)
  --enable-socks      Also enable SOCKS5
  --socks-port PORT   SOCKS5 port (default: 1080)
  --allow-ip IP       Additionally allow this source IP in UFW
  -h, --help          Show this help

Examples:
  sudo $0 --user proxy1 --pass '@Jkliop890'
  sudo $0 --user foo --pass bar --enable-socks --allow-ip 1.2.3.4
EOF
}

# === parse args ===
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) PROXY_USER="${2:-}"; shift 2;;
    --pass) PROXY_PASS="${2:-}"; shift 2;;
    --http-port) HTTP_PORT="${2:-3128}"; shift 2;;
    --enable-socks) ENABLE_SOCKS=1; shift 1;;
    --socks-port) SOCKS_PORT="${2:-1080}"; shift 2;;
    --allow-ip) ALLOW_IP="${2:-}"; shift 2;;
    -h|--help) usage; exit 0;;
    *) err "Unknown arg: $1"; usage; exit 1;;
  esac
done

# === root check ===
if [[ $EUID -ne 0 ]]; then
  err "Run as root: sudo $0 …"
  exit 1
fi

# keep requirement for custom user/pass (sesuai flow lo)
if [[ -z "$PROXY_USER" || -z "$PROXY_PASS" ]]; then
  err "--user and --pass are required (default account is added in addition to these)"
  usage
  exit 1
fi

# === OS sanity ===
if [[ ! -f /etc/debian_version ]]; then
  err "This script targets Debian/Ubuntu."
  exit 1
fi

log "Updating packages…"
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y git build-essential ca-certificates curl ufw

# === install 3proxy from source ===
if ! command -v 3proxy >/dev/null 2>&1; then
  log "Building 3proxy…"
  WORKDIR="/usr/src/3proxy-src"
  rm -rf "$WORKDIR"
  git clone --depth 1 https://github.com/z3APA3A/3proxy.git "$WORKDIR"
  make -C "$WORKDIR" -f Makefile.Linux
  install -m 0755 "$WORKDIR/src/3proxy" /usr/local/bin/3proxy
else
  log "3proxy already present, skipping build."
fi

# === system users / dirs ===
id -u 3proxy >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin 3proxy
mkdir -p /etc/3proxy /var/log/3proxy
chown -R 3proxy:3proxy /var/log/3proxy

# === generate config ===
CFG_FILE="/etc/3proxy/3proxy.cfg"
log "Writing config: $CFG_FILE"

cat >"$CFG_FILE" <<CFG
daemon
nserver $NS1
nserver $NS2

log /var/log/3proxy/3proxy.log D
rotate 30

auth strong
# custom user
users $PROXY_USER:CL:$PROXY_PASS
# default always-on user
users $DEFAULT_USER:CL:$DEFAULT_PASS

# Tune
maxconn 20000
timeouts 1 5 30 60 180 1800 15 60

# HTTP proxy
proxy -n -a -p$HTTP_PORT -i0.0.0.0
CFG

if [[ $ENABLE_SOCKS -eq 1 ]]; then
  cat >>"$CFG_FILE" <<CFG

# SOCKS5 proxy (optional)
socks -p$SOCKS_PORT -i0.0.0.0
CFG
fi

chown 3proxy:3proxy "$CFG_FILE"
chmod 640 "$CFG_FILE"

# === systemd service ===
SERVICE_FILE="/etc/systemd/system/3proxy.service"
log "Creating systemd service…"
cat >"$SERVICE_FILE" <<'SERVICE'
[Unit]
Description=3proxy tiny proxy server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=3proxy
Group=3proxy
ExecStart=/usr/local/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=2
LimitNOFILE=200000
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now 3proxy

# === firewall (UFW) ===
log "Configuring UFW rules…"
# make sure SSH stays open BEFORE enabling UFW
ufw allow OpenSSH || true

# default whitelist (HTTP & optional SOCKS)
for ip in "${DEFAULT_WHITELIST[@]}"; do
  ufw allow from "$ip" to any port "$HTTP_PORT" proto tcp || true
  if [[ $ENABLE_SOCKS -eq 1 ]]; then
    ufw allow from "$ip" to any port "$SOCKS_PORT" proto tcp || true
  fi
done

# optional allow-ip (extra)
if [[ -n "$ALLOW_IP" ]]; then
  ufw allow from "$ALLOW_IP" to any port "$HTTP_PORT" proto tcp || true
  if [[ $ENABLE_SOCKS -eq 1 ]]; then
    ufw allow from "$ALLOW_IP" to any port "$SOCKS_PORT" proto tcp || true
  fi
else
  # kalau gak ada allow-ip tambahan, tetap aman karena default whitelist sudah ditambah
  warn "No --allow-ip provided; only default whitelist + SSH are open."
fi

# enable UFW last
ufw --force enable >/dev/null 2>&1 || true
ufw status verbose || true

# === logrotate (optional) ===
LOGROTATE_FILE="/etc/logrotate.d/3proxy"
cat >"$LOGROTATE_FILE" <<'ROT'
/var/log/3proxy/3proxy.log {
  rotate 14
  daily
  missingok
  notifempty
  compress
  delaycompress
  create 0640 3proxy 3proxy
  postrotate
    systemctl kill -s HUP 3proxy || true
  endscript
}
ROT

# === summary ===
PUB_IP="$(curl -4 -s https://api.ipify.org || hostname -I | awk '{print $1}')"
echo
log "DONE. Proxy is up 🚀"
echo "----------------------------------------"
echo " Public IP     : ${PUB_IP}"
echo " HTTP Proxy    : ${PUB_IP}:${HTTP_PORT}"
if [[ $ENABLE_SOCKS -eq 1 ]]; then
  echo " SOCKS5 Proxy  : ${PUB_IP}:${SOCKS_PORT}"
fi
echo " Auth (custom) : ${PROXY_USER}:${PROXY_PASS}"
echo " Auth (default): ${DEFAULT_USER}:${DEFAULT_PASS}"
if [[ -n "$ALLOW_IP" ]]; then
  echo " Allowed (extra): ${ALLOW_IP}"
fi
echo " Allowed (default): ${DEFAULT_WHITELIST[*]}"
echo " Config path   : ${CFG_FILE}"
echo " Service       : systemctl status 3proxy"
echo "----------------------------------------"
echo "Test:"
echo "  curl -x http://${PROXY_USER}:${PROXY_PASS}@${PUB_IP}:${HTTP_PORT} https://ipinfo.io/ip"
echo "  curl -x http://${DEFAULT_USER}:${DEFAULT_PASS}@${PUB_IP}:${HTTP_PORT} https://ipinfo.io/ip"
echo
