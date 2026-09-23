# WireGuard VPN node (role=node): only the node agent, no HTTP server.
# Debian slim for the same iproute2/iptables/wireguard-tools builds the host
# distro uses (see wg-vpn-server/api/Dockerfile for the longer rationale).
FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Root by design: the agent owns wg0, iptables NAT and tc (CAP_NET_ADMIN).
ENV PYTHONUNBUFFERED=1 WGVPN_ROLE=node
CMD ["python", "-m", "app.node_agent"]
