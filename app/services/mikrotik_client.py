"""
app/services/mikrotik_client.py

HTTP client for the MikroTik RouterOS REST API.

Design decisions:
  - Uses httpx directly against the native REST API (no third-party RouterOS library).
  - All public methods are high-level; no raw URL paths are exposed to callers.
  - Dry-run mode (DRY_RUN=true) logs intent and returns mock data without touching the router.
  - RouterOS returns ALL values as strings; callers should not assume numeric types.
  - Record IDs use the RouterOS *hex format (e.g. "*1", "*A").
"""
from __future__ import annotations

import httpx
import ssl
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Typed exception
# ---------------------------------------------------------------------------

class MikroTikAPIError(Exception):
    """Raised when the MikroTik REST API returns an error response."""

    def __init__(self, status_code: int, message: str, detail: str = "") -> None:
        self.status_code = status_code
        self.message = message
        self.detail = detail
        super().__init__(f"MikroTik API error {status_code}: {message} — {detail}")


# ---------------------------------------------------------------------------
# Dry-run mock data
# ---------------------------------------------------------------------------

_MOCK_INTERFACES: list[dict] = [
    {".id": "*1", "name": "ether1", "type": "ether", "running": "true", "disabled": "false"},
    {".id": "*2", "name": "ether2", "type": "ether", "running": "true", "disabled": "false"},
    {".id": "*3", "name": "wlan1",  "type": "wlan",  "running": "true", "disabled": "false"},
]

_MOCK_FIREWALL_RULES: list[dict] = [
    {
        ".id": "*1",
        "chain": "input",
        "action": "accept",
        "protocol": "tcp",
        "dst-port": "22",
        "comment": "Allow SSH",
        "disabled": "false",
    },
    {
        ".id": "*2",
        "chain": "input",
        "action": "drop",
        "comment": "Drop all other input",
        "disabled": "false",
    },
]


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class MikroTikClient:
    """High-level wrapper for the MikroTik RouterOS REST API."""

    def __init__(self) -> None:
        self._base_url = settings.mikrotik_base_url
        self._auth = (settings.mikrotik_user, settings.mikrotik_password)
        self._verify_ssl = settings.mikrotik_verify_ssl
        self._dry_run = settings.dry_run

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.Client:
        verify = self._verify_ssl
        if not self._verify_ssl:
            # Create a permissive SSL context for older RouterOS versions
            # because OpenSSL 3 strictly rejects TLSv1/v1.1 and weak ciphers
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Enable legacy connect
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
            # Set minimum TLS version as low as possible for compatibility
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except Exception:
                pass
            
            # Set a very permissive cipher list (SECLEVEL=0 allows weaker keys)
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            except Exception:
                pass
                
            verify = ctx

        return httpx.Client(
            base_url=self._base_url,
            auth=self._auth,
            verify=verify,
            timeout=10.0,
        )

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.status_code >= 400:
            try:
                body = response.json()
                message = body.get("message", "Unknown error")
                detail = body.get("detail", "")
            except Exception:
                message = response.text
                detail = ""
            raise MikroTikAPIError(response.status_code, message, detail)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_interfaces(self) -> list[dict]:
        """Return all network interfaces (GET /rest/interface)."""
        if self._dry_run:
            logger.info("[DRY-RUN] get_interfaces → returning mock data")
            return _MOCK_INTERFACES

        logger.info("MikroTik: GET /interface")
        with self._client() as client:
            response = client.get("/interface")
            self._raise_for_status(response)
            return response.json()

    def get_firewall_rules(self) -> list[dict]:
        """Return all firewall filter rules (GET /rest/ip/firewall/filter)."""
        if self._dry_run:
            logger.info("[DRY-RUN] get_firewall_rules → returning mock data")
            return _MOCK_FIREWALL_RULES

        logger.info("MikroTik: GET /ip/firewall/filter")
        with self._client() as client:
            response = client.get("/ip/firewall/filter")
            self._raise_for_status(response)
            return response.json()

    def add_firewall_rule(self, rule: dict) -> dict:
        """Create a new firewall filter rule (PUT /rest/ip/firewall/filter)."""
        if self._dry_run:
            logger.info("[DRY-RUN] add_firewall_rule → would create: %s", rule)
            return {".id": "*DRY", **rule}

        logger.info("MikroTik: PUT /ip/firewall/filter — %s", rule)
        with self._client() as client:
            response = client.put("/ip/firewall/filter", json=rule)
            self._raise_for_status(response)
            return response.json()

    def delete_firewall_rule(self, rule_id: str) -> bool:
        """Delete a firewall filter rule by ID (DELETE /rest/ip/firewall/filter/{id}).

        Args:
            rule_id: RouterOS record ID in *hex format, e.g. "*1".
        """
        if self._dry_run:
            logger.info("[DRY-RUN] delete_firewall_rule → would delete id=%s", rule_id)
            return True

        logger.info("MikroTik: DELETE /ip/firewall/filter/%s", rule_id)
        with self._client() as client:
            response = client.delete(f"/ip/firewall/filter/{rule_id}")
            self._raise_for_status(response)
            return True


# Singleton — import this instead of instantiating directly
mikrotik_client = MikroTikClient()
