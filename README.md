# wg-vpn-node

A WireGuard VPN **node** for [wg-vpn-server](https://github.com/lantuyan/wg-vpn-server).
A node is a VPS in some country that serves WireGuard tunnels. It has no
dashboard and no API of its own: it only makes outbound calls to the central
server, which decides which peers it serves. Only `WG_PORT/udp` is opened.

> This repository is generated from `wg-vpn-server` (`scripts/publish-node.sh`).
> Do not edit it by hand; changes go to wg-vpn-server.

## Install

1. In the central dashboard: **Nodes → Add node**. It shows a one-time install
   command with this node's id and secret.
2. On a fresh Ubuntu/Debian VPS (as root or with sudo), run that command:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/lantuyan/wg-vpn-node/main/install.sh | sudo bash -s -- \
     --central http://CENTRAL_IP --node-id nd_xxxxxxxxxxxx --node-secret SECRET
   ```

   Optional: `--wg-port 51820` (UDP port, default 51820) and `--wg-host IP`
   (public IP clients dial; auto-detected if omitted). The same values can be
   given as environment variables `WGVPN_CENTRAL_URL`, `WGVPN_NODE_ID`,
   `WGVPN_NODE_SECRET`, `WG_PORT`, `WG_HOST`.

It installs Docker if missing, loads the `wireguard` kernel module, puts the
code in `/opt/wg-vpn-node`, writes `/opt/wg-vpn-node/.env` (mode 600) and starts
the container `wgvpn-node`. Within a few seconds the node shows as online in
the dashboard. Open the UDP port in your provider's cloud firewall if it has one.

Requirements: Linux kernel with WireGuard (5.6+), a correct clock (NTP; requests
are rejected when off by more than 2 minutes), outbound HTTP to central.

## Update

Run the same command again, or without arguments (values are kept from `.env`):

```bash
curl -fsSL https://raw.githubusercontent.com/lantuyan/wg-vpn-node/main/install.sh | sudo bash
```

## Logs and status

```bash
docker logs -f wgvpn-node
docker exec wgvpn-node wg show
```

## Uninstall

```bash
cd /opt/wg-vpn-node && docker compose -p wgvpn-node down
rm -rf /opt/wg-vpn-node      # deletes the node's keys and cache too
```

Then revoke or delete the node in the dashboard.

## How it behaves

* If central is unreachable, existing tunnels keep working: the node keeps the
  last peer list it got (cached in `data/node-state.json`) and rebuilds `wg0`
  from it after a restart. Only new enrolments and changes wait for central.
* The node generates its own WireGuard key; the private key never leaves `data/`.
* Traffic counters are reported to central every 30 s; quota is enforced by
  central across all nodes.
* It can run on the same host as the central server if `WG_PORT` differs.
