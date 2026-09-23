#!/usr/bin/env bash
# Install or update a WireGuard VPN node on a fresh Ubuntu/Debian VPS.
#
#   curl -fsSL https://raw.githubusercontent.com/lantuyan/wg-vpn-node/main/install.sh | sudo bash -s -- \
#     --central http://CENTRAL_IP --node-id nd_xxx --node-secret SECRET [--wg-port 51820] [--wg-host IP]
#
# The same values may come from the environment instead: WGVPN_CENTRAL_URL,
# WGVPN_NODE_ID, WGVPN_NODE_SECRET, WG_PORT, WG_HOST. Re-running it is the
# update path: it pulls the latest code and rebuilds, keeping .env and data/
# (values not given again are kept from the existing .env).
set -euo pipefail

REPO_URL="${WGVPN_NODE_REPO:-https://github.com/lantuyan/wg-vpn-node.git}"
INSTALL_DIR="${WGVPN_NODE_DIR:-/opt/wg-vpn-node}"
PROJECT="wgvpn-node"

log()  { printf '\033[32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# Everything runs inside main(), called on the last line: with `curl | bash`
# the script arrives on stdin, and wrapping it makes bash read all of it
# before any command runs (so nothing can swallow the rest of the script).
main() {
  [[ $EUID -eq 0 ]] || die "run as root (the command pipes into: sudo bash -s -- ...)"

  # ---- arguments (flags win over env, env wins over an existing .env) --------
  central="${WGVPN_CENTRAL_URL:-}" node_id="${WGVPN_NODE_ID:-}" node_secret="${WGVPN_NODE_SECRET:-}"
  wg_port="${WG_PORT:-}" wg_host="${WG_HOST:-}"
  while (( $# )); do
    case "$1" in
      --central)     central="${2:?--central needs a value}"; shift 2 ;;
      --node-id)     node_id="${2:?--node-id needs a value}"; shift 2 ;;
      --node-secret) node_secret="${2:?--node-secret needs a value}"; shift 2 ;;
      --wg-port)     wg_port="${2:?--wg-port needs a value}"; shift 2 ;;
      --wg-host)     wg_host="${2:?--wg-host needs a value}"; shift 2 ;;
      *) die "unknown option: $1" ;;
    esac
  done

  env_value() { [[ -f "$INSTALL_DIR/.env" ]] && sed -n "s/^$1=//p" "$INSTALL_DIR/.env" | tail -1 || true; }
  central="${central:-$(env_value WGVPN_CENTRAL_URL)}"
  node_id="${node_id:-$(env_value WGVPN_NODE_ID)}"
  node_secret="${node_secret:-$(env_value WGVPN_NODE_SECRET)}"
  wg_port="${wg_port:-$(env_value WG_PORT)}"; wg_port="${wg_port:-51820}"
  wg_host="${wg_host:-$(env_value WG_HOST)}"

  [[ "$central" =~ ^https?://[^[:space:]]+$ ]] || die "--central must be a URL like http://1.2.3.4"
  [[ "$node_id" =~ ^nd_[0-9a-f]{12}$ ]] || die "--node-id must look like nd_<12 hex> (copy it from the dashboard)"
  [[ "$node_secret" =~ ^[A-Za-z0-9_-]{43}$ ]] || die "--node-secret must be the 43-character secret shown in the dashboard"
  [[ "$wg_port" =~ ^[0-9]+$ ]] && (( wg_port >= 1 && wg_port <= 65535 )) || die "--wg-port must be 1..65535"

  # ---- packages ---------------------------------------------------------------
  export DEBIAN_FRONTEND=noninteractive
  # A fresh VPS often runs apt (cloud-init, unattended-upgrades) for its first
  # minutes; installing now would fail on the dpkg lock, so wait for it.
  for (( i = 0; i < 120; i++ )); do
    pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null || break
    (( i == 0 )) && log "Waiting for another apt/dpkg process to finish (fresh VPS updating itself)"
    sleep 5
  done
  pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null && die "apt/dpkg is still busy after 10 minutes -- re-run this command later"
  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    log "Installing Docker Engine + compose plugin (get.docker.com)"
    command -v curl >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null; }
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  command -v git >/dev/null 2>&1 || { log "Installing git"; apt-get update -qq && apt-get install -y -qq git >/dev/null; }

  # The container drives wg0 but cannot load the host's kernel module itself.
  if [[ ! -e /sys/module/wireguard ]]; then
    log "Loading the wireguard kernel module"
    modprobe wireguard || die "modprobe wireguard failed -- this kernel has no WireGuard (Linux >= 5.6 needed)"
  fi
  echo wireguard > /etc/modules-load.d/wireguard.conf

  # ---- code ---------------------------------------------------------------------
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating $INSTALL_DIR"
    git -C "$INSTALL_DIR" fetch --depth 1 -q origin main
    git -C "$INSTALL_DIR" reset -q --hard FETCH_HEAD   # .env and data/ are untracked: kept
  else
    log "Cloning $REPO_URL into $INSTALL_DIR"
    git clone -q --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
  cd "$INSTALL_DIR"

  # ---- public IP (the Endpoint clients dial) ----------------------------------------
  is_public_ipv4() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    [[ ! "$1" =~ ^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]
  }
  if [[ -z "$wg_host" ]]; then
    wg_host="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
    is_public_ipv4 "$wg_host" || wg_host="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if is_public_ipv4 "$wg_host"; then
      log "Public IP: $wg_host"
    else
      wg_host=""
      warn "could not detect the public IP here; the node will ask an echo service at start (or pass --wg-host)"
    fi
  fi

  # ---- .env ---------------------------------------------------------------------
  umask 077
  printf 'WGVPN_CENTRAL_URL=%s\nWGVPN_NODE_ID=%s\nWGVPN_NODE_SECRET=%s\nWG_HOST=%s\nWG_PORT=%s\n' \
    "$central" "$node_id" "$node_secret" "$wg_host" "$wg_port" > .env
  chmod 600 .env
  mkdir -p data && chmod 700 data

  # ---- firewall (only if one is switched on) ----------------------------------------
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    log "ufw is active -- allowing ${wg_port}/udp"
    ufw allow "${wg_port}/udp" >/dev/null || true
  fi

  # ---- start ----------------------------------------------------------------------
  log "Starting the node (docker compose project '$PROJECT')"
  docker compose -p "$PROJECT" up -d --build

  log "Done. The node registers itself with $central and appears as online in the dashboard."
  log "Logs:   docker logs -f wgvpn-node"
  log "Also open ${wg_port}/udp in your provider's cloud firewall if it has one."
}

main "$@"
