"""Runtime configuration for wgvpn-api.

All values come from environment variables prefixed ``WGVPN_`` (see
docs/INTERNALS.md). This module has no dependency on any other app module —
it sits at the bottom of the import graph (``settings <- db <- store <- ...``).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ``env_ignore_empty``: an empty environment variable (``WGVPN_X=``, which
    # is what a docker-compose passthrough or an unfilled .env line produces)
    # means "not set" and falls back to the default, instead of failing
    # validation and taking the whole process down at startup.
    # ``env_parse_none_str``: the literal string ``none`` sets an optional
    # field to null, which is the only way to express "unlimited / disabled"
    # for the ``int | None`` settings (e.g. peer_idle_expire_hours) over env.
    model_config = SettingsConfigDict(
        env_prefix="WGVPN_",
        extra="ignore",
        env_ignore_empty=True,
        env_parse_none_str="none",
    )

    data_dir: Path = Path("/data")
    # Default is derived from data_dir when not explicitly set; see
    # _derive_db_path below.
    db_path: Path = Path("/data/wgvpn.sqlite3")

    # central | node | all (see docs/MULTI_NODE.md). "all" is central plus
    # the local wg0 as node nd_local, which is how a single VPS runs.
    role: Literal["central", "node", "all"] = "all"

    wg_interface: str = "wg0"
    # Required for central/all (the local endpoint and the default public
    # base URL). Optional for a node, which auto-detects its public IP.
    wg_host: str | None = None
    wg_port: int = 51820
    wg_subnet: str = "10.13.13.0/24"
    wg_dns: str = "1.1.1.1,8.8.8.8"
    wg_allowed_ips: str = "0.0.0.0/0,::/0"
    wg_mtu: int = 1420
    wg_keepalive: int = 25

    default_ttl_seconds: int = 604800
    renew_before_seconds: int = 86400
    default_quota_bytes: int | None = 53687091200
    quota_window: Literal["monthly", "daily", "lifetime"] = "monthly"
    quota_action: Literal["block", "throttle"] = "block"
    quota_throttle_kbps: int = 256
    default_rate_down_kbps: int | None = 20000
    default_rate_up_kbps: int | None = 10000
    default_max_peers: int = 3

    peer_retention_days: int = 7
    peer_idle_expire_hours: int | None = 168
    poll_interval_seconds: int = 30

    auth_skew_seconds: int = 120
    totp_window_steps: int = 1
    max_body_bytes: int = 16384

    rate_kid_burst: int = 20
    rate_kid_per_min: int = 20
    rate_ip_burst: int = 60
    rate_ip_per_min: int = 60
    trust_proxy: bool = True

    admin_token: str | None = None
    shaping_enabled: bool = True
    # Off by default: /docs, /redoc and /openapi.json would otherwise advertise
    # the whole admin API surface to anyone who finds the hostname.
    docs_enabled: bool = False
    log_level: str = "INFO"
    bootstrap_install_key_label: str | None = None

    # -- multi-node, central side -------------------------------------------
    # Node used by /enroll when the request carries no node_id (old clients).
    default_node_id: str = "nd_local"
    # Only used when the migration creates the nd_local row; edit it in the
    # dashboard afterwards.
    local_node_name: str = "Helsinki 1"
    local_node_country: str = "FI"
    local_node_city: str | None = "Helsinki"
    # Base URL a node uses to reach central, printed in the install command.
    # Default http://<wg_host>.
    public_base_url: str | None = None
    node_install_url: str = "https://raw.githubusercontent.com/lantuyan/wg-vpn-node/main/install.sh"
    # How often a node polls desired-state (sent to it at register).
    node_poll_seconds: int = 3
    # How long /enroll waits for a remote node to apply the change.
    node_apply_wait_seconds: float = 10.0

    # -- multi-node, node side (role=node) ------------------------------------
    central_url: str | None = None
    node_id: str | None = None
    node_secret: str | None = None

    @model_validator(mode="after")
    def _require_wg_host(self) -> "Settings":
        if self.role != "node" and not self.wg_host:
            raise ValueError("WGVPN_WG_HOST is required unless WGVPN_ROLE=node")
        return self

    @model_validator(mode="after")
    def _derive_db_path(self) -> "Settings":
        # db_path defaults to "<data_dir>/wgvpn.sqlite3"; if the caller
        # explicitly set WGVPN_DB_PATH we must not override it, even when
        # data_dir was also overridden.
        if "db_path" not in self.model_fields_set:
            self.db_path = self.data_dir / "wgvpn.sqlite3"
        return self

    @property
    def dns_list(self) -> list[str]:
        return _split_csv(self.wg_dns)

    @property
    def allowed_ips_list(self) -> list[str]:
        return _split_csv(self.wg_allowed_ips)

    @property
    def endpoint(self) -> str:
        return f"{self.wg_host}:{self.wg_port}"

    @property
    def public_base(self) -> str:
        return (self.public_base_url or f"http://{self.wg_host}").rstrip("/")

    @property
    def has_local_wg(self) -> bool:
        """True when this process owns a wg0 of its own as node nd_local."""
        return self.role == "all"

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.wg_subnet, strict=False)


def _split_csv(value: str) -> list[str]:
    """Split a comma-separated env value, tolerating spaces and empty entries."""
    return [part.strip() for part in value.split(",") if part.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
