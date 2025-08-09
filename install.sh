#!/usr/bin/env bash
set -euo pipefail

# === defaults ===
PROXY_USER=""
PROXY_PASS=""
HTTP_PORT=3128
ENABLE_SOCKS=0
SOCKS_PORT=1080
ALLOW_IP=""   # if set, ufw will only allow this IP to connect
NS1="1.1.1.1"
NS2="8.8.8.8"

# === helpers ===
log() { echo -e "\e[1;32m[+] $*\e[0m"; }
err() { echo -e "\e[1;31m[!] $*\e[0m" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { err "Missing $1"; exit 1; }; }

usage() {
  cat <<EOF
Usage: $0 --user USER --pass PASS [--http-port 3128] [--enable-socks --socks-port 1080] [--allow-ip A.B.C.D]
Installs 3proxy as authenticated HTTP (and optional SOCKS5) proxy.

Options:
  --user USER         Proxy username (required)
  --pass PASS         Proxy password (required)
  --http-port PORT    HTTP proxy port (default: 3128)
  --enable-socks      Also enable SOCKS5
  --socks-port PORT   SOCKS5 port (default: 1080)
  --allow-ip IP       Only allow this source IP (UFW rule). If omitted, opens to all.
  -h, --help          Show this help
EOF
}

# === parse args ===
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) PROXY_USER="$2"; shift 2;;
    --pass) PROXY_PASS="$2"; shift 2;;
    --http-port) HTTP_PORT="$2"; shift 2;;
    --enable-socks) ENABLE_SOCKS=1; shift 1;;
    --socks-port) SOCKS_PORT="$2"; shift 2;;
    --allow-ip) ALLOW_IP="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) err "Unknown arg: $1"; usage; exit 1;;
  esac
done

# === root check ===
if [[ $EUID -ne 0 ]]; then
  err "Run as root: sudo $0 …"
  exit 1
fi

if [[ -z "$PROXY_USER" || -z "$PROXY_PASS" ]]; then
  err "--user and --pass are required"
  usage
  exit 1
fi

# === OS sanity ===
if [[ -f /etc/debian_version ]]; then
  PKG_MGR="apt"
else
  err "This script targets Debian/Ubuntu."
  exit 1
fi

log "Updating packages…"
apt update -y
DEBIAN_FRONTEND=noninteractive apt install -y git build-essential ca-certificates

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
users $PROXY_USER:CL:$PROXY_PASS

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

sleep 1
systemctl --no-pager --full status 3proxy | sed -n '1,12p' || true

# === firewall (ufw) ===
if command -v ufw >/dev/null 2>&1; then
  log "Configuring UFW rules…"
  ufw --force enable >/dev/null 2>&1 || true
  if [[ -n "$ALLOW_IP" ]]; then
    ufw allow from "$ALLOW_IP" to any port "$HTTP_PORT" proto tcp || true
    if [[ $ENABLE_SOCKS -eq 1 ]]; then
      ufw allow from "$ALLOW_IP" to any port "$SOCKS_PORT" proto tcp || true
    fi
  else
    ufw allow "$HTTP_PORT"/tcp || true
    if [[ $ENABLE_SOCKS -eq 1 ]]; then
      ufw allow "$SOCKS_PORT"/tcp || true
    fi
  fi
else
  log "ufw not installed; skipping firewall rules."
fi

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
echo " Auth          : ${PROXY_USER}:${PROXY_PASS}"
if [[ -n "$ALLOW_IP" ]]; then
  echo " Allowed CIDR  : ${ALLOW_IP} (UFW)"
else
  echo " Allowed CIDR  : 0.0.0.0/0 (open to world) — consider --allow-ip"
fi
echo " Config path   : ${CFG_FILE}"
echo " Service       : systemctl status 3proxy"
echo "----------------------------------------"
echo "Test:"
echo "  curl -x http://${PROXY_USER}:${PROXY_PASS}@${PUB_IP}:${HTTP_PORT} https://ipinfo.io/ip"
echo
