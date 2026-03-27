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


    # ------------------------------------------------------------------
    # System APIs
    # ------------------------------------------------------------------

    def get_system_info(self) -> dict | list:
        """Return system resources (GET /rest/system/resource)."""
        if self._dry_run:
            logger.info("[DRY-RUN] get_system_info")
            return [{"uptime": "1d00h00m", "version": "7.x", "cpu-load": "5"}]
        logger.info("MikroTik: GET /system/resource")
        with self._client() as client:
            response = client.get("/system/resource")
            self._raise_for_status(response)
            return response.json()

    def get_system_identity(self) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] get_system_identity")
            return [{"name": "MikroTik-DryRun"}]
        logger.info("MikroTik: GET /system/identity")
        with self._client() as client:
            response = client.get("/system/identity")
            self._raise_for_status(response)
            return response.json()

    def set_system_identity(self, name: str) -> dict | list:
        payload = {"name": name}
        if self._dry_run:
            logger.info("[DRY-RUN] set_system_identity -> %s", payload)
            return [payload]
        logger.info("MikroTik: PATCH /system/identity - %s", payload)
        with self._client() as client:
            response = client.patch("/system/identity", json=payload)
            self._raise_for_status(response)
            return response.json()

    def get_system_health(self) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] get_system_health")
            return [{"voltage": "24.0", "temperature": "40"}]
        logger.info("MikroTik: GET /system/health")
        with self._client() as client:
            response = client.get("/system/health")
            self._raise_for_status(response)
            return response.json()

    def get_system_uptime(self) -> dict:
        info = self.get_system_info()
        items = info if isinstance(info, list) else [info]
        if not items:
            return {"uptime": "unknown"}
        return {"uptime": items[0].get("uptime", "unknown")}

    def get_system_clock(self) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] get_system_clock")
            return [{"time": "12:00:00", "date": "Jan/01/2026", "time-zone-name": "UTC"}]
        logger.info("MikroTik: GET /system/clock")
        with self._client() as client:
            response = client.get("/system/clock")
            self._raise_for_status(response)
            return response.json()

    def set_system_clock(self, params: dict) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] set_system_clock -> %s", params)
            return [params]
        logger.info("MikroTik: PATCH /system/clock - %s", params)
        with self._client() as client:
            response = client.patch("/system/clock", json=params)
            self._raise_for_status(response)
            return response.json()

    def reboot_router(self) -> dict:
        if self._dry_run:
            logger.info("[DRY-RUN] reboot_router")
            return {"status": "rebooting (dry-run)"}
        logger.info("MikroTik: POST /system/reboot")
        with self._client() as client:
            response = client.post("/system/reboot")
            # /system/reboot often returns 200 empty, or times out if reboot is fast
            if response.status_code >= 400:
                self._raise_for_status(response)
            return {"status": "reboot initiated"}

    def shutdown_router(self) -> dict:
        if self._dry_run:
            logger.info("[DRY-RUN] shutdown_router")
            return {"status": "shutting down (dry-run)"}
        logger.info("MikroTik: POST /system/shutdown")
        with self._client() as client:
            response = client.post("/system/shutdown")
            if response.status_code >= 400:
                self._raise_for_status(response)
            return {"status": "shutdown initiated"}

    def create_system_backup(self, name: str, password: str | None = None) -> dict | list:
        payload = {"name": name}
        if password:
            payload["password"] = password
        if self._dry_run:
            logger.info("[DRY-RUN] create_system_backup -> %s", payload)
            return [{"status": "backup created (dry-run)", "name": name}]
        logger.info("MikroTik: POST /system/backup/save - %s", payload)
        with self._client() as client:
            response = client.post("/system/backup/save", json=payload)
            self._raise_for_status(response)
            # MikroTik might return empty array for action commands
            try:
                return response.json()
            except Exception:
                return {"status": "success", "name": name}

    def restore_system_backup(self, name: str, password: str | None = None) -> dict | list:
        payload = {"name": name}
        if password:
            payload["password"] = password
        if self._dry_run:
            logger.info("[DRY-RUN] restore_system_backup -> %s", payload)
            return [{"status": "backup restored (dry-run)", "name": name}]
        logger.info("MikroTik: POST /system/backup/load - %s", payload)
        with self._client() as client:
            response = client.post("/system/backup/load", json=payload)
            if response.status_code >= 400:
                self._raise_for_status(response)
            try:
                return response.json()
            except Exception:
                return {"status": "restore initiated", "name": name}

    def export_config(self) -> dict:
        if self._dry_run:
            logger.info("[DRY-RUN] export_config")
            return {"config": "# dry-run export\n/system identity set name=Router"}
        logger.info("MikroTik: GET /export")
        # /export can return text/plain or be an action
        # In recent RouterOS REST, it's GET /rest/export (but might return a .rsc string)
        with self._client() as client:
            response = client.get("/export")
            self._raise_for_status(response)
            try:
                # the REST API might pack it in json, or return raw string
                # If content type is text/plain or similar:
                if "application/json" in response.headers.get("Content-Type", ""):
                    return response.json()
                return {"config": response.text}
            except Exception:
                return {"config": response.text}

    def import_config(self, file_name: str) -> dict:
        payload = {"file-name": file_name}
        if self._dry_run:
            logger.info("[DRY-RUN] import_config -> %s", payload)
            return {"status": "imported (dry-run)", "file-name": file_name}
        logger.info("MikroTik: POST /import - %s", payload)
        with self._client() as client:
            response = client.post("/import", json=payload)
            self._raise_for_status(response)
            try:
                return response.json()
            except Exception:
                return {"status": "success", "file-name": file_name}

    def list_logs(self) -> list[dict]:
        if self._dry_run:
            logger.info("[DRY-RUN] list_logs")
            return [{"time": "Jan/01/2026 12:00:00", "topics": "system,info", "message": "router started"}]
        logger.info("MikroTik: GET /log")
        with self._client() as client:
            response = client.get("/log")
            self._raise_for_status(response)
            return response.json()

    def clear_logs(self) -> dict:
        # Note: RouterOS does not have a native REST endpoint for clearing logs easily.
        # This will attempt to use a CLI-like hack or inform the user it fails.
        if self._dry_run:
            logger.info("[DRY-RUN] clear_logs")
            return {"status": "logs cleared (dry-run)"}
        logger.warning("MikroTik: attempting to clear_logs")
        try:
            # We will just write a warning that it's difficult over REST, 
            # or try a script run
            return {"status": "warning", "message": "Clearing logs via REST is not natively supported by standard RouterOS. Requires script."}
        except Exception as e:
            raise MikroTikAPIError(500, "Failed to clear logs", str(e))

    # ------------------------------------------------------------------
    # Interface APIs (Extend MikroTik Tool Suite)
    # ------------------------------------------------------------------

    def _get_interface_id(self, name: str) -> str:
        """Helper to resolve an interface name to its internal RouterOS ID."""
        with self._client() as client:
            response = client.get(f"/interface?name={name}")
            self._raise_for_status(response)
            data = response.json()
            if not data:
                raise MikroTikAPIError(404, f"Interface '{name}' not found")
            return isinstance(data, list) and data[0].get(".id") or data.get(".id", "")

    def get_interface_details(self, name: str) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] get_interface_details -> %s", name)
            return [{"name": name, "type": "ether", "running": "true"}]
        logger.info("MikroTik: GET /interface?name=%s", name)
        with self._client() as client:
            response = client.get(f"/interface?name={name}")
            self._raise_for_status(response)
            return response.json()

    def get_interface_stats(self, name: str) -> dict | list:
        # Re-use details but potentially LLM wants specific fields
        details = self.get_interface_details(name)
        if isinstance(details, list) and details:
            d = details[0]
            return {
                "name": d.get("name"),
                "rx-byte": d.get("rx-byte"),
                "tx-byte": d.get("tx-byte"),
                "rx-packet": d.get("rx-packet"),
                "tx-packet": d.get("tx-packet"),
                "rx-drop": d.get("rx-drop"),
                "tx-drop": d.get("tx-drop"),
                "rx-error": d.get("rx-error"),
                "tx-error": d.get("tx-error"),
            }
        return {"error": "Interface not found"}

    def monitor_interface(self, name: str) -> dict | list:
        payload = {"interface": name, "once": True}
        if self._dry_run:
            logger.info("[DRY-RUN] monitor_interface -> %s", payload)
            return [{"name": name, "rx-bits-per-second": "1000", "tx-bits-per-second": "2000"}]
        logger.info("MikroTik: POST /interface/monitor-traffic - %s", payload)
        with self._client() as client:
            response = client.post("/interface/monitor-traffic", json=payload)
            self._raise_for_status(response)
            return response.json()

    def enable_interface(self, name: str) -> dict | list:
        payload = {"numbers": name}
        if self._dry_run:
            logger.info("[DRY-RUN] enable_interface -> %s", payload)
            return [{"status": "enabled (dry-run)", "interface": name}]
        logger.info("MikroTik: POST /interface/enable - %s", payload)
        with self._client() as client:
            response = client.post("/interface/enable", json=payload)
            self._raise_for_status(response)
            try:
                return response.json()
            except Exception:
                return {"status": "success", "interface": name}

    def disable_interface(self, name: str) -> dict | list:
        payload = {"numbers": name}
        if self._dry_run:
            logger.info("[DRY-RUN] disable_interface -> %s", payload)
            return [{"status": "disabled (dry-run)", "interface": name}]
        logger.info("MikroTik: POST /interface/disable - %s", payload)
        with self._client() as client:
            response = client.post("/interface/disable", json=payload)
            self._raise_for_status(response)
            try:
                return response.json()
            except Exception:
                return {"status": "success", "interface": name}

    def create_interface(self, type_: str, params: dict) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] create_interface type=%s -> %s", type_, params)
            return [{"status": "created (dry-run)", ".id": "*DRY"}]
        logger.info("MikroTik: PUT /interface/%s - %s", type_, params)
        with self._client() as client:
            response = client.put(f"/interface/{type_}", json=params)
            self._raise_for_status(response)
            return response.json()

    def delete_interface(self, type_: str, name: str) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] delete_interface type=%s name=%s", type_, name)
            return [{"status": "deleted (dry-run)", "interface": name}]
        logger.info("MikroTik: DELETE /interface/%s for %s", type_, name)
        # We need to resolve the ID first usually, though we can try type/id
        # Actually doing `GET /interface/{type_}?name={name}` is safer
        with self._client() as client:
            res = client.get(f"/interface/{type_}?name={name}")
            if res.status_code >= 400:
                self._raise_for_status(res)
            data = res.json()
            if not data:
                raise MikroTikAPIError(404, f"Interface '{name}' of type '{type_}' not found")
            target_id = data[0][".id"]

            response = client.delete(f"/interface/{type_}/{target_id}")
            self._raise_for_status(response)
            return {"status": "deleted", "interface": name}

    def rename_interface(self, old_name: str, new_name: str) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] rename_interface %s -> %s", old_name, new_name)
            return [{"status": "renamed", "old": old_name, "new": new_name}]
        target_id = self._get_interface_id(old_name)
        payload = {"name": new_name}
        logger.info("MikroTik: PATCH /interface/%s - %s", target_id, payload)
        with self._client() as client:
            response = client.patch(f"/interface/{target_id}", json=payload)
            self._raise_for_status(response)
            return response.json()

    def set_interface_comment(self, name: str, comment: str) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] set_interface_comment %s -> %s", name, comment)
            return [{"status": "comment set", "interface": name}]
        target_id = self._get_interface_id(name)
        payload = {"comment": comment}
        logger.info("MikroTik: PATCH /interface/%s - %s", target_id, payload)
        with self._client() as client:
            response = client.patch(f"/interface/{target_id}", json=payload)
            self._raise_for_status(response)
            return response.json()

    def set_interface_mtu(self, name: str, mtu: int) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] set_interface_mtu %s -> %s", name, mtu)
            return [{"status": "mtu set", "interface": name}]
        target_id = self._get_interface_id(name)
        payload = {"mtu": str(mtu)}
        logger.info("MikroTik: PATCH /interface/%s - %s", target_id, payload)
        with self._client() as client:
            response = client.patch(f"/interface/{target_id}", json=payload)
            self._raise_for_status(response)
            return response.json()

    # ------------------------------------------------------------------
    # IP Address APIs
    # ------------------------------------------------------------------

    def _get_ip_address_id(self, search_term: str) -> str:
        """Helper to resolve an IP address ID by address string or direct ID."""
        if search_term.startswith("*"):
            return search_term
        # Search by address string
        with self._client() as client:
            response = client.get(f"/ip/address?address={search_term}")
            if response.status_code >= 400:
                self._raise_for_status(response)
            data = response.json()
            if not data:
                raise MikroTikAPIError(404, f"IP Address '{search_term}' not found")
            return isinstance(data, list) and data[0].get(".id") or data.get(".id", "")

    def list_ip_addresses(self) -> list[dict]:
        if self._dry_run:
            logger.info("[DRY-RUN] list_ip_addresses")
            return [{"address": "192.168.88.1/24", "network": "192.168.88.0", "interface": "bridge", ".id": "*1"}]
        logger.info("MikroTik: GET /ip/address")
        with self._client() as client:
            response = client.get("/ip/address")
            self._raise_for_status(response)
            return response.json()

    def get_ip_address(self, id_or_address: str) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] get_ip_address -> %s", id_or_address)
            return [{"address": id_or_address, "interface": "bridge", ".id": "*1"}]
        logger.info("MikroTik: GET /ip/address for %s", id_or_address)
        target_id = self._get_ip_address_id(id_or_address)
        with self._client() as client:
            response = client.get(f"/ip/address/{target_id}")
            self._raise_for_status(response)
            return response.json()

    def add_ip_address(self, address: str, interface: str, params: dict | None = None) -> dict | list:
        payload = {"address": address, "interface": interface}
        if params:
            payload.update(params)
        
        if self._dry_run:
            logger.info("[DRY-RUN] add_ip_address -> %s", payload)
            return [{".id": "*DRY", **payload}]
            
        logger.info("MikroTik: PUT /ip/address - %s", payload)
        with self._client() as client:
            response = client.put("/ip/address", json=payload)
            self._raise_for_status(response)
            return response.json()

    def update_ip_address(self, id_or_address: str, params: dict) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] update_ip_address %s -> %s", id_or_address, params)
            return [{"status": "updated (dry-run)", "target": id_or_address, **params}]

        target_id = self._get_ip_address_id(id_or_address)
        logger.info("MikroTik: PATCH /ip/address/%s - %s", target_id, params)
        with self._client() as client:
            response = client.patch(f"/ip/address/{target_id}", json=params)
            self._raise_for_status(response)
            return response.json()

    def delete_ip_address(self, id_or_address: str) -> dict | list:
        if self._dry_run:
            logger.info("[DRY-RUN] delete_ip_address -> %s", id_or_address)
            return [{"status": "deleted (dry-run)", "target": id_or_address}]

        target_id = self._get_ip_address_id(id_or_address)
        logger.info("MikroTik: DELETE /ip/address/%s", target_id)
        with self._client() as client:
            response = client.delete(f"/ip/address/{target_id}")
            self._raise_for_status(response)
            return {"status": "deleted", "target": id_or_address}

    # ------------------------------------------------------------------
    # Wireguard VPN APIs
    # ------------------------------------------------------------------

    def list_wireguard_peers(self) -> list[dict]:
        """List all Wireguard peers (GET /interface/wireguard/peers)."""
        if self._dry_run:
            logger.info("[DRY-RUN] list_wireguard_peers")
            return [
                {".id": "*1", "interface": "wg0", "public-key": "base64key...", "allowed-address": "10.0.0.2/32"}
            ]
        
        logger.info("MikroTik: GET /interface/wireguard/peers")
        with self._client() as client:
            response = client.get("/interface/wireguard/peers")
            self._raise_for_status(response)
            return response.json()

    def create_wireguard_interface(self, name: str, listen_port: int = 51820) -> dict | list:
        """Create a new Wireguard interface (PUT /interface/wireguard)."""
        payload = {"name": name, "listen-port": listen_port}
        
        if self._dry_run:
            logger.info("[DRY-RUN] create_wireguard_interface -> %s", payload)
            return [{".id": "*DRY", "name": name, "listen-port": listen_port, "status": "created (dry-run)"}]
        
        logger.info("MikroTik: PUT /interface/wireguard - %s", payload)
        with self._client() as client:
            response = client.put("/interface/wireguard", json=payload)
            self._raise_for_status(response)
            return response.json()

    def add_wireguard_peer(
        self,
        interface: str,
        public_key: str,
        allowed_address: str,
        endpoint: str | None = None,
        persistent_keepalive: int | None = None,
        comment: str | None = None,
    ) -> dict | list:
        """Add a peer to a Wireguard interface (PUT /interface/wireguard/peers)."""
        payload = {
            "interface": interface,
            "public-key": public_key,
            "allowed-address": allowed_address,
        }
        if endpoint:
            payload["endpoint"] = endpoint
        if persistent_keepalive is not None:
            payload["persistent-keepalive"] = persistent_keepalive
        if comment:
            payload["comment"] = comment
        
        if self._dry_run:
            logger.info("[DRY-RUN] add_wireguard_peer -> %s", payload)
            return [{".id": "*DRY", **payload, "status": "added (dry-run)"}]
        
        logger.info("MikroTik: PUT /interface/wireguard/peers - %s", payload)
        with self._client() as client:
            response = client.put("/interface/wireguard/peers", json=payload)
            self._raise_for_status(response)
            return response.json()

    # ------------------------------------------------------------------
    # Routing APIs
    # ------------------------------------------------------------------

    def _get_route_id(self, id_or_dst: str) -> str:
        """Resolve a route ID from '*hex' format or destination address."""
        if id_or_dst.startswith("*"):
            return id_or_dst
        with self._client() as client:
            response = client.get(f"/ip/route?dst-address={id_or_dst}")
            if response.status_code >= 400:
                self._raise_for_status(response)
            data = response.json()
            if not data:
                raise MikroTikAPIError(404, f"Route '{id_or_dst}' not found")
            return data[0][".id"]

    def list_routes(self) -> list[dict]:
        """List all routes (GET /ip/route)."""
        if self._dry_run:
            logger.info("[DRY-RUN] list_routes")
            return [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "192.168.1.1", "distance": "1", "active": "true"},
                {".id": "*2", "dst-address": "192.168.1.0/24", "gateway": "ether1", "distance": "0", "active": "true"},
            ]
        logger.info("MikroTik: GET /ip/route")
        with self._client() as client:
            response = client.get("/ip/route")
            self._raise_for_status(response)
            return response.json()

    def get_route(self, id_or_dst: str) -> dict | list:
        """Get a specific route by ID or destination."""
        if self._dry_run:
            logger.info("[DRY-RUN] get_route -> %s", id_or_dst)
            return [{".id": "*1", "dst-address": id_or_dst, "gateway": "192.168.1.1"}]
        target_id = self._get_route_id(id_or_dst)
        logger.info("MikroTik: GET /ip/route/%s", target_id)
        with self._client() as client:
            response = client.get(f"/ip/route/{target_id}")
            self._raise_for_status(response)
            return response.json()

    def add_route(self, dst_address: str, gateway: str, distance: int | None = None, comment: str | None = None) -> dict | list:
        """Add a static route (PUT /ip/route)."""
        payload: dict = {"dst-address": dst_address, "gateway": gateway}
        if distance is not None:
            payload["distance"] = distance
        if comment:
            payload["comment"] = comment
        if self._dry_run:
            logger.info("[DRY-RUN] add_route -> %s", payload)
            return [{".id": "*DRY", **payload, "status": "added (dry-run)"}]
        logger.info("MikroTik: PUT /ip/route - %s", payload)
        with self._client() as client:
            response = client.put("/ip/route", json=payload)
            self._raise_for_status(response)
            return response.json()

    def update_route(self, id_or_dst: str, params: dict) -> dict | list:
        """Update an existing route (PATCH /ip/route/{id})."""
        if self._dry_run:
            logger.info("[DRY-RUN] update_route %s -> %s", id_or_dst, params)
            return [{"status": "updated (dry-run)", "target": id_or_dst, **params}]
        target_id = self._get_route_id(id_or_dst)
        logger.info("MikroTik: PATCH /ip/route/%s - %s", target_id, params)
        with self._client() as client:
            response = client.patch(f"/ip/route/{target_id}", json=params)
            self._raise_for_status(response)
            return response.json()

    def enable_route(self, id_or_dst: str) -> dict | list:
        """Enable a disabled route."""
        if self._dry_run:
            logger.info("[DRY-RUN] enable_route -> %s", id_or_dst)
            return [{"status": "enabled (dry-run)", "target": id_or_dst}]
        target_id = self._get_route_id(id_or_dst)
        logger.info("MikroTik: POST /ip/route/%s/enable", target_id)
        with self._client() as client:
            response = client.post(f"/ip/route/{target_id}/enable")
            self._raise_for_status(response)
            return {"status": "enabled", "target": id_or_dst}

    def disable_route(self, id_or_dst: str) -> dict | list:
        """Disable a route."""
        if self._dry_run:
            logger.info("[DRY-RUN] disable_route -> %s", id_or_dst)
            return [{"status": "disabled (dry-run)", "target": id_or_dst}]
        target_id = self._get_route_id(id_or_dst)
        logger.info("MikroTik: POST /ip/route/%s/disable", target_id)
        with self._client() as client:
            response = client.post(f"/ip/route/{target_id}/disable")
            self._raise_for_status(response)
            return {"status": "disabled", "target": id_or_dst}

    def delete_route(self, id_or_dst: str) -> dict | list:
        """Delete a route (DELETE /ip/route/{id})."""
        if self._dry_run:
            logger.info("[DRY-RUN] delete_route -> %s", id_or_dst)
            return [{"status": "deleted (dry-run)", "target": id_or_dst}]
        target_id = self._get_route_id(id_or_dst)
        logger.info("MikroTik: DELETE /ip/route/%s", target_id)
        with self._client() as client:
            response = client.delete(f"/ip/route/{target_id}")
            self._raise_for_status(response)
            return {"status": "deleted", "target": id_or_dst}

    # ------------------------------------------------------------------
    # NAT APIs
    # ------------------------------------------------------------------

    def list_nat_rules(self) -> list[dict]:
        """List all NAT rules (GET /ip/firewall/nat)."""
        if self._dry_run:
            logger.info("[DRY-RUN] list_nat_rules")
            return [
                {".id": "*1", "chain": "srcnat", "action": "masquerade", "out-interface": "ether1", "disabled": "false"},
            ]
        logger.info("MikroTik: GET /ip/firewall/nat")
        with self._client() as client:
            response = client.get("/ip/firewall/nat")
            self._raise_for_status(response)
            return response.json()

    def get_nat_rule(self, rule_id: str) -> dict | list:
        """Get a specific NAT rule by ID."""
        if self._dry_run:
            logger.info("[DRY-RUN] get_nat_rule -> %s", rule_id)
            return [{".id": rule_id, "chain": "srcnat", "action": "masquerade"}]
        logger.info("MikroTik: GET /ip/firewall/nat/%s", rule_id)
        with self._client() as client:
            response = client.get(f"/ip/firewall/nat/{rule_id}")
            self._raise_for_status(response)
            return response.json()

    def create_nat_rule(self, payload: dict) -> dict | list:
        """Create a NAT rule (PUT /ip/firewall/nat)."""
        if self._dry_run:
            logger.info("[DRY-RUN] create_nat_rule -> %s", payload)
            return [{".id": "*DRY", **payload, "status": "created (dry-run)"}]
        logger.info("MikroTik: PUT /ip/firewall/nat - %s", payload)
        with self._client() as client:
            response = client.put("/ip/firewall/nat", json=payload)
            self._raise_for_status(response)
            return response.json()

    def update_nat_rule(self, rule_id: str, params: dict) -> dict | list:
        """Update a NAT rule (PATCH /ip/firewall/nat/{id})."""
        if self._dry_run:
            logger.info("[DRY-RUN] update_nat_rule %s -> %s", rule_id, params)
            return [{"status": "updated (dry-run)", "rule_id": rule_id, **params}]
        logger.info("MikroTik: PATCH /ip/firewall/nat/%s - %s", rule_id, params)
        with self._client() as client:
            response = client.patch(f"/ip/firewall/nat/{rule_id}", json=params)
            self._raise_for_status(response)
            return response.json()

    def enable_nat_rule(self, rule_id: str) -> dict | list:
        """Enable a disabled NAT rule."""
        if self._dry_run:
            logger.info("[DRY-RUN] enable_nat_rule -> %s", rule_id)
            return [{"status": "enabled (dry-run)", "rule_id": rule_id}]
        logger.info("MikroTik: POST /ip/firewall/nat/%s/enable", rule_id)
        with self._client() as client:
            response = client.post(f"/ip/firewall/nat/{rule_id}/enable")
            self._raise_for_status(response)
            return {"status": "enabled", "rule_id": rule_id}

    def disable_nat_rule(self, rule_id: str) -> dict | list:
        """Disable a NAT rule."""
        if self._dry_run:
            logger.info("[DRY-RUN] disable_nat_rule -> %s", rule_id)
            return [{"status": "disabled (dry-run)", "rule_id": rule_id}]
        logger.info("MikroTik: POST /ip/firewall/nat/%s/disable", rule_id)
        with self._client() as client:
            response = client.post(f"/ip/firewall/nat/{rule_id}/disable")
            self._raise_for_status(response)
            return {"status": "disabled", "rule_id": rule_id}

    def move_nat_rule(self, rule_id: str, destination: int) -> dict | list:
        """Move a NAT rule to a specific position."""
        if self._dry_run:
            logger.info("[DRY-RUN] move_nat_rule %s -> position %d", rule_id, destination)
            return [{"status": "moved (dry-run)", "rule_id": rule_id, "destination": destination}]
        logger.info("MikroTik: POST /ip/firewall/nat/%s/move destination=%d", rule_id, destination)
        with self._client() as client:
            response = client.post(
                f"/ip/firewall/nat/{rule_id}/move",
                json={"destination": destination},
            )
            self._raise_for_status(response)
            return {"status": "moved", "rule_id": rule_id, "destination": destination}

    def delete_nat_rule(self, rule_id: str) -> dict | list:
        """Delete a NAT rule (DELETE /ip/firewall/nat/{id})."""
        if self._dry_run:
            logger.info("[DRY-RUN] delete_nat_rule -> %s", rule_id)
            return [{"status": "deleted (dry-run)", "rule_id": rule_id}]
        logger.info("MikroTik: DELETE /ip/firewall/nat/%s", rule_id)
        with self._client() as client:
            response = client.delete(f"/ip/firewall/nat/{rule_id}")
            self._raise_for_status(response)
            return {"status": "deleted", "rule_id": rule_id}

# Singleton — import this instead of instantiating directly
mikrotik_client = MikroTikClient()

