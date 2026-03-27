"""
app/mcp/tools.py

MCP tool definitions exposed to the LLM via FastMCP.

Design decisions:
  - Every tool passes through the policy engine BEFORE touching the MikroTik client.
  - Tools return plain dicts / lists (JSON-serialisable) so the LLM can interpret them.
  - The MikroTik client singleton is imported here; in tests it can be monkey-patched.
"""
import base64
import ipaddress
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from mcp.server.fastmcp import FastMCP

from app.services import mikrotik_client as _mk
from app.services import policy_engine
from app.models.schemas import FirewallRule

# FastMCP server instance — mounted into the FastAPI app in main.py
mcp = FastMCP("mikrotik-agent")


@mcp.tool()
def list_interfaces() -> list[dict]:
    """List all network interfaces on the MikroTik router."""
    policy_engine.evaluate("list_interfaces")
    return _mk.mikrotik_client.get_interfaces()


@mcp.tool()
def list_firewall_rules() -> list[dict]:
    """List all IP firewall filter rules."""
    policy_engine.evaluate("list_firewall_rules")
    return _mk.mikrotik_client.get_firewall_rules()


@mcp.tool()
def create_firewall_rule(
    action: str,
    chain: str,
    protocol: str | None = None,
    src_address: str | None = None,
    dst_address: str | None = None,
    dst_port: str | None = None,
    comment: str | None = None,
    disabled: bool = False,
) -> dict:
    """Create a new firewall filter rule on the MikroTik router.

    Args:
        action:      accept, drop, or reject
        chain:       input, forward, or output
        protocol:    tcp, udp, icmp, etc. (optional)
        src_address: Source IP/prefix (optional)
        dst_address: Destination IP/prefix (optional)
        dst_port:    Destination port or port range (optional)
        comment:     Human-readable note (optional)
        disabled:    Create the rule in disabled state (default False)
    """
    policy_engine.evaluate("create_firewall_rule")

    # Build the RouterOS-style dict (uses kebab-case keys)
    rule = FirewallRule(
        action=action,
        chain=chain,
        protocol=protocol,
        **{"src-address": src_address} if src_address else {},
        **{"dst-address": dst_address} if dst_address else {},
        **{"dst-port": dst_port} if dst_port else {},
        comment=comment,
        disabled=disabled,
    )
    # Serialise using aliases so RouterOS receives e.g. "src-address", not "src_address"
    payload = rule.model_dump(by_alias=True, exclude_none=True)
    return _mk.mikrotik_client.add_firewall_rule(payload)


@mcp.tool()
def delete_firewall_rule(confirm: bool = False, rule_id: str | None = None, comment: str | None = None) -> dict:
    """Delete a firewall filter rule by its RouterOS ID (e.g. '*1') or exact comment.

    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    Either rule_id OR comment must be provided.

    Args:
        confirm: Must be True to authorise deletion.
        rule_id: RouterOS record ID in *hex format, e.g. '*1'. (optional)
        comment: The exact comment of the rule to delete. (optional)
    """
    if not rule_id and not comment:
        raise ValueError("Must provide either rule_id or comment to delete a rule.")
        
    policy_engine.evaluate("delete_firewall_rule", confirm=confirm)
    
    # If deleting by comment, we must look up the ID first
    target_id = rule_id
    if not target_id:
        rules = _mk.mikrotik_client.get_firewall_rules()
        matches = [r for r in rules if r.get("comment") == comment]
        if not matches:
            return {"deleted": False, "error": f"No rule found with comment '{comment}'"}
        if len(matches) > 1:
            return {"deleted": False, "error": f"Multiple rules found with comment '{comment}'. Please use rule_id."}
        target_id = matches[0][".id"]

    success = _mk.mikrotik_client.delete_firewall_rule(target_id)
    return {"deleted": success, "rule_id": target_id}

# ---------------------------------------------------------------------------
# System Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_system_info() -> dict | list:
    """Get system resources, version, CPU load, memory, and uptime."""
    policy_engine.evaluate("get_system_info")
    return _mk.mikrotik_client.get_system_info()

@mcp.tool()
def get_system_identity() -> dict | list:
    """Get the identity (hostname) of the MikroTik router."""
    policy_engine.evaluate("get_system_identity")
    return _mk.mikrotik_client.get_system_identity()

@mcp.tool()
def set_system_identity(name: str) -> dict | list:
    """Set the identity (hostname) of the MikroTik router."""
    policy_engine.evaluate("set_system_identity")
    return _mk.mikrotik_client.set_system_identity(name)

@mcp.tool()
def get_system_health() -> dict | list:
    """Get system health information (voltage, temperature)."""
    policy_engine.evaluate("get_system_health")
    return _mk.mikrotik_client.get_system_health()

@mcp.tool()
def get_system_uptime() -> dict:
    """Get the current uptime of the MikroTik router."""
    policy_engine.evaluate("get_system_uptime")
    return _mk.mikrotik_client.get_system_uptime()

@mcp.tool()
def get_system_clock() -> dict | list:
    """Get system clock, date, and timezone."""
    policy_engine.evaluate("get_system_clock")
    return _mk.mikrotik_client.get_system_clock()

@mcp.tool()
def set_system_clock(
    time: str | None = None,
    date: str | None = None,
    time_zone_name: str | None = None,
) -> dict | list:
    """Set the system clock, date, or timezone."""
    policy_engine.evaluate("set_system_clock")
    params = {}
    if time:
        params["time"] = time
    if date:
        params["date"] = date
    if time_zone_name:
        params["time-zone-name"] = time_zone_name
    return _mk.mikrotik_client.set_system_clock(params)

@mcp.tool()
def reboot_router(confirm: bool = False) -> dict:
    """Reboot the MikroTik router.
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    """
    policy_engine.evaluate("reboot_router", confirm=confirm)
    return _mk.mikrotik_client.reboot_router()

@mcp.tool()
def shutdown_router(confirm: bool = False) -> dict:
    """Shut down the MikroTik router.
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    """
    policy_engine.evaluate("shutdown_router", confirm=confirm)
    return _mk.mikrotik_client.shutdown_router()

@mcp.tool()
def create_system_backup(name: str, password: str | None = None) -> dict | list:
    """Create a system backup file (.backup)."""
    policy_engine.evaluate("create_system_backup")
    return _mk.mikrotik_client.create_system_backup(name, password)

@mcp.tool()
def restore_system_backup(confirm: bool = False, name: str = "", password: str | None = None) -> dict | list:
    """Restore a system backup file (.backup).
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    """
    if not name:
        raise ValueError("Must provide the backup file name to restore.")
    policy_engine.evaluate("restore_system_backup", confirm=confirm)
    return _mk.mikrotik_client.restore_system_backup(name, password)

@mcp.tool()
def export_config() -> dict:
    """Export the router configuration script (.rsc format)."""
    policy_engine.evaluate("export_config")
    return _mk.mikrotik_client.export_config()

@mcp.tool()
def import_config(confirm: bool = False, file_name: str = "") -> dict:
    """Import a router configuration script (.rsc format).
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    """
    if not file_name:
        raise ValueError("Must provide the file_name to import.")
    policy_engine.evaluate("import_config", confirm=confirm)
    return _mk.mikrotik_client.import_config(file_name)

@mcp.tool()
def list_logs() -> list[dict]:
    """List system logs."""
    policy_engine.evaluate("list_logs")
    return _mk.mikrotik_client.list_logs()

@mcp.tool()
def clear_logs(confirm: bool = False) -> dict:
    """Clear the system logs in memory.
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    """
    policy_engine.evaluate("clear_logs", confirm=confirm)
    return _mk.mikrotik_client.clear_logs()

# ---------------------------------------------------------------------------
# Interface Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_interface_details(name: str) -> dict | list:
    """Get detailed settings for a specific network interface."""
    policy_engine.evaluate("get_interface_details")
    return _mk.mikrotik_client.get_interface_details(name)

@mcp.tool()
def get_interface_stats(name: str) -> dict | list:
    """Get traffic statistics (tx/rx bytes and packets) for an interface."""
    policy_engine.evaluate("get_interface_stats")
    return _mk.mikrotik_client.get_interface_stats(name)

@mcp.tool()
def monitor_interface(name: str) -> dict | list:
    """Monitor real-time traffic (bits-per-second) for an interface."""
    policy_engine.evaluate("monitor_interface")
    return _mk.mikrotik_client.monitor_interface(name)

@mcp.tool()
def enable_interface(name: str) -> dict | list:
    """Enable a disabled network interface."""
    policy_engine.evaluate("enable_interface")
    return _mk.mikrotik_client.enable_interface(name)

@mcp.tool()
def disable_interface(name: str) -> dict | list:
    """Disable a network interface."""
    policy_engine.evaluate("disable_interface")
    return _mk.mikrotik_client.disable_interface(name)

@mcp.tool()
def create_interface(type_: str, params: dict) -> dict | list:
    """Create a new interface.
    
    Args:
        type_: The type of interface to create (e.g. 'vlan', 'bridge', 'wireguard').
        params: Key-value parameters for the interface configuration.
    """
    policy_engine.evaluate("create_interface")
    return _mk.mikrotik_client.create_interface(type_, params)

@mcp.tool()
def delete_interface(confirm: bool = False, type_: str = "", name: str = "") -> dict | list:
    """Delete a network interface.
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    
    Args:
        confirm: Must be True.
        type_: The type of interface (e.g. 'vlan', 'bridge').
        name: The name of the interface to delete.
    """
    if not type_ or not name:
        raise ValueError("Must provide both type_ and name to delete an interface.")
    policy_engine.evaluate("delete_interface", confirm=confirm)
    return _mk.mikrotik_client.delete_interface(type_, name)

@mcp.tool()
def rename_interface(old_name: str, new_name: str) -> dict | list:
    """Rename a network interface."""
    policy_engine.evaluate("rename_interface")
    return _mk.mikrotik_client.rename_interface(old_name, new_name)

@mcp.tool()
def set_interface_comment(name: str, comment: str) -> dict | list:
    """Set a descriptive comment on an interface."""
    policy_engine.evaluate("set_interface_comment")
    return _mk.mikrotik_client.set_interface_comment(name, comment)

@mcp.tool()
def set_interface_mtu(name: str, mtu: int) -> dict | list:
    """Set the Maximum Transmission Unit (MTU) of an interface."""
    policy_engine.evaluate("set_interface_mtu")
    return _mk.mikrotik_client.set_interface_mtu(name, mtu)

# ---------------------------------------------------------------------------
# IP Address Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_ip_addresses() -> list[dict]:
    """List all IP addresses on the router."""
    policy_engine.evaluate("list_ip_addresses")
    return _mk.mikrotik_client.list_ip_addresses()

@mcp.tool()
def get_ip_address(id_or_address: str) -> dict | list:
    """Get a specific IP address by its address or ID."""
    policy_engine.evaluate("get_ip_address")
    return _mk.mikrotik_client.get_ip_address(id_or_address)

@mcp.tool()
def add_ip_address(address: str, interface: str, params: dict | None = None) -> dict | list:
    """Add a new IP address to an interface.
    
    Args:
        address: The IP address (e.g. '192.168.1.1/24').
        interface: The name of the interface.
        params: Optional dictionary of additional parameters.
    """
    policy_engine.evaluate("add_ip_address")
    return _mk.mikrotik_client.add_ip_address(address, interface, params)

@mcp.tool()
def update_ip_address(id_or_address: str, params: dict) -> dict | list:
    """Update an existing IP address.
    
    Args:
        id_or_address: The IP address string or RouterOS ID.
        params: Fields to update.
    """
    policy_engine.evaluate("update_ip_address")
    return _mk.mikrotik_client.update_ip_address(id_or_address, params)

@mcp.tool()
def delete_ip_address(confirm: bool = False, id_or_address: str = "") -> dict | list:
    """Delete an IP address.
    
    This is a DESTRUCTIVE action. The caller must pass confirm=True.
    
    Args:
        confirm: Must be True.
        id_or_address: The IP address string or RouterOS ID to delete.
    """
    if not id_or_address:
        raise ValueError("Must provide id_or_address to delete an IP address.")
    policy_engine.evaluate("delete_ip_address", confirm=confirm)
    return _mk.mikrotik_client.delete_ip_address(id_or_address)

# ---------------------------------------------------------------------------
# Wireguard VPN Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_wireguard_peers() -> list[dict]:
    """List all Wireguard peers configured on the MikroTik router."""
    policy_engine.evaluate("list_wireguard_peers")
    return _mk.mikrotik_client.list_wireguard_peers()

@mcp.tool()
def generate_wireguard_keypair() -> dict:
    """Generate a new Wireguard X25519 keypair using pure Python cryptography.
    
    Returns a dict with both private and public keys base64-encoded, ready for use.
    """
    policy_engine.evaluate("generate_wireguard_keypair")
    
    # Generate a new X25519 private key
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize both to bytes using Raw format
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    
    private_key_b64 = base64.b64encode(private_bytes).decode("ascii")
    public_key_b64 = base64.b64encode(public_bytes).decode("ascii")
    
    return {
        "private_key": private_key_b64,
        "public_key": public_key_b64,
    }

@mcp.tool()
def generate_wireguard_client_config(
    client_private_key: str,
    server_public_key: str,
    server_endpoint: str,
    client_address: str,
    dns_servers: str | None = None,
) -> dict:
    """Generate a ready-to-use Wireguard client configuration (.conf format).
    
    Args:
        client_private_key: Base64-encoded client private key.
        server_public_key: Base64-encoded server public key.
        server_endpoint: Server endpoint (IP:port, e.g. '203.0.113.1:51820').
        client_address: Client VPN address (e.g. '10.0.0.2/32').
        dns_servers: Comma-separated DNS servers (optional).
    """
    policy_engine.evaluate("generate_wireguard_client_config")
    
    conf_lines = [
        "[Interface]",
        f"PrivateKey = {client_private_key}",
        f"Address = {client_address}",
    ]
    
    if dns_servers:
        conf_lines.append(f"DNS = {dns_servers}")
    
    conf_lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"Endpoint = {server_endpoint}",
        "AllowedIPs = 0.0.0.0/0",
    ])
    
    config_text = "\n".join(conf_lines)
    
    return {
        "config": config_text,
        "format": "wireguard-conf",
    }

@mcp.tool()
def create_wireguard_interface(name: str, listen_port: int | None = None) -> dict | list:
    """Create a new Wireguard interface on the MikroTik router.
    
    Args:
        name: Name for the interface (e.g. 'wg0').
        listen_port: UDP port to listen on (default: 51820).
    """
    policy_engine.evaluate("create_wireguard_interface")
    if listen_port is None:
        listen_port = 51820
    return _mk.mikrotik_client.create_wireguard_interface(name, listen_port)

@mcp.tool()
def add_wireguard_peer(
    interface: str,
    public_key: str,
    allowed_address: str,
    endpoint: str | None = None,
    persistent_keepalive: int | None = None,
) -> dict | list:
    """Add a peer to an existing Wireguard interface.
    
    Args:
        interface: Wireguard interface name.
        public_key: Peer's base64-encoded public key.
        allowed_address: Allowed address(es) for peer (CIDR notation).
        endpoint: Peer endpoint (IP:port, optional).
        persistent_keepalive: Keepalive interval in seconds (optional).
    """
    policy_engine.evaluate("add_wireguard_peer")
    return _mk.mikrotik_client.add_wireguard_peer(
        interface=interface,
        public_key=public_key,
        allowed_address=allowed_address,
        endpoint=endpoint,
        persistent_keepalive=persistent_keepalive,
    )

@mcp.tool()
def assign_ip_to_wireguard_interface(interface: str, address: str) -> dict | list:
    """Assign an IP address to a Wireguard interface.
    
    Args:
        interface: Wireguard interface name.
        address: IP address with subnet (e.g. '10.0.0.1/24').
    """
    policy_engine.evaluate("assign_ip_to_wireguard_interface")
    return _mk.mikrotik_client.add_ip_address(address, interface)

@mcp.tool()
def allow_wireguard_port(port: int | None = None) -> dict:
    """Create a firewall rule to allow UDP traffic on the Wireguard port.
    
    Args:
        port: UDP port for Wireguard (default: 51820).
    """
    policy_engine.evaluate("allow_wireguard_port")
    if port is None:
        port = 51820
    
    # Use create_firewall_rule to add an accept rule for the port
    rule = FirewallRule(
        action="accept",
        chain="input",
        protocol="udp",
        **{"dst-port": str(port)},
        comment=f"Allow Wireguard UDP {port}",
        disabled=False,
    )
    payload = rule.model_dump(by_alias=True, exclude_none=True)
    return _mk.mikrotik_client.add_firewall_rule(payload)

@mcp.tool()
def setup_wireguard_server(
    interface_name: str,
    server_ip: str,
    listen_port: int | None = None,
    lan_subnet: str = "192.168.1.0/24",
    is_primary_router: bool = True,
) -> dict:
    """Complete Wireguard server setup in one call.

    Orchestrates:
      1. Creates a Wireguard interface
      2. Assigns an IP address to it
      3. Opens the firewall input port (UDP)
      4. Adds a forward firewall rule allowing VPN clients to reach the LAN
      5. If is_primary_router=False: adds a srcnat masquerade rule so LAN hosts
         reply to the MikroTik (needed when MikroTik is NOT the default gateway)

    Returns a port_forward_required notice with the steps the user must do on
    their upstream/ISP router to forward the WireGuard UDP port to this device.

    Args:
        interface_name:    Name for the server Wireguard interface (e.g. 'wg0').
        server_ip:         Server VPN IP with subnet (e.g. '10.0.0.1/24').
        listen_port:       UDP port (default: 51820).
        lan_subnet:        LAN subnet to allow VPN clients to reach (default: '192.168.1.0/24').
        is_primary_router: True if MikroTik is the default gateway for LAN devices.
                           False if there is an upstream router (e.g. ISP modem/WiFi router)
                           that is the default gateway — srcnat masquerade will be added.
    """
    policy_engine.evaluate("setup_wireguard_server")

    if listen_port is None:
        listen_port = 51820

    # Derive VPN subnet from server_ip (e.g. '10.0.0.1/24' → '10.0.0.0/24')
    vpn_subnet = str(ipaddress.ip_interface(server_ip).network)

    # Step 1: Create the interface
    interface_result = _mk.mikrotik_client.create_wireguard_interface(interface_name, listen_port)

    # Step 2: Assign IP
    ip_result = _mk.mikrotik_client.add_ip_address(server_ip, interface_name)

    # Step 3: Allow firewall input port (UDP)
    input_rule = FirewallRule(
        action="accept",
        chain="input",
        protocol="udp",
        **{"dst-port": str(listen_port)},
        comment=f"WireGuard UDP {listen_port}",
        disabled=False,
    )
    firewall_input_result = _mk.mikrotik_client.add_firewall_rule(
        input_rule.model_dump(by_alias=True, exclude_none=True)
    )

    # Step 4: Forward rule — VPN clients → LAN
    forward_rule = FirewallRule(
        action="accept",
        chain="forward",
        **{"src-address": vpn_subnet},
        **{"dst-address": lan_subnet},
        comment="VPN to LAN",
        disabled=False,
    )
    firewall_forward_result = _mk.mikrotik_client.add_firewall_rule(
        forward_rule.model_dump(by_alias=True, exclude_none=True)
    )

    # Step 5 (secondary router only): srcnat masquerade so LAN hosts reply to MikroTik
    nat_result = None
    if not is_primary_router:
        nat_result = _mk.mikrotik_client.create_nat_rule({
            "chain": "srcnat",
            "action": "masquerade",
            "src-address": vpn_subnet,
            "dst-address": lan_subnet,
            "comment": "VPN clients masquerade on LAN",
        })

    return {
        "status": "server_setup_complete",
        "interface": interface_name,
        "server_ip": server_ip,
        "vpn_subnet": vpn_subnet,
        "lan_subnet": lan_subnet,
        "listen_port": listen_port,
        "is_primary_router": is_primary_router,
        "interface_result": interface_result,
        "ip_result": ip_result,
        "firewall_input_result": firewall_input_result,
        "firewall_forward_result": firewall_forward_result,
        "nat_masquerade_result": nat_result,
        "port_forward_required": {
            "notice": (
                "You must forward the WireGuard port on your upstream router/ISP modem."
                if not is_primary_router
                else "If your ISP modem is NOT in bridge mode, you must forward the WireGuard port to this router."
            ),
            "protocol": "UDP",
            "external_port": listen_port,
            "internal_port": listen_port,
            "internal_ip": "(this router's WAN/LAN IP as seen by the upstream device)",
        },
    }

@mcp.tool()
def add_wireguard_client(
    server_interface: str,
    server_public_key: str,
    client_name: str,
    client_address: str,
    server_endpoint: str,
    dns_servers: str | None = None,
    client_public_key: str | None = None,
) -> dict:
    """Complete Wireguard client setup: register peer and return client configuration.

    Supports two workflows:
      - App-generated keys (default): generates a keypair, registers the peer, and
        returns a ready-to-import .conf file. Use when the app manages keys.
      - Device-generated keys: supply the device's existing public key via
        client_public_key. The peer is registered with that key and no .conf is
        generated (the device already has its private key). Use for phones/devices
        that generate their own keys (e.g. the WireGuard app on Android/iOS).

    Orchestrates:
      1. Generates a new keypair (skipped if client_public_key is provided)
      2. Registers the client as a peer on the server interface
      3. Generates a ready-to-use .conf file (skipped if client_public_key is provided)

    Args:
        server_interface:   Name of the server's Wireguard interface.
        server_public_key:  Server's base64-encoded public key.
        client_name:        Descriptive name/comment for the peer.
        client_address:     VPN address for client (e.g. '10.0.0.2/32').
        server_endpoint:    Server public endpoint in host:port format (e.g. '1.2.3.4:51820').
        dns_servers:        Comma-separated DNS servers for the .conf (optional).
        client_public_key:  Existing base64 public key from the device. When provided,
                            the app skips key generation and does NOT return a .conf —
                            the device already holds its private key.
    """
    policy_engine.evaluate("add_wireguard_client")

    device_generated_keys = client_public_key is not None

    if device_generated_keys:
        # Use the key provided by the device — no keypair generation needed
        resolved_public_key = client_public_key
        client_private_key = None
    else:
        # Step 1: Generate keypair for client
        keypair = generate_wireguard_keypair()
        client_private_key = keypair["private_key"]
        resolved_public_key = keypair["public_key"]

    # Step 2: Register the peer on the server
    peer_result = _mk.mikrotik_client.add_wireguard_peer(
        interface=server_interface,
        public_key=resolved_public_key,
        allowed_address=client_address,
        comment=client_name,
    )

    # Step 3: Generate client config (only when the app generated the keys)
    if device_generated_keys:
        return {
            "status": "client_setup_complete",
            "client_name": client_name,
            "client_public_key": resolved_public_key,
            "peer_result": peer_result,
            "config": None,
            "note": (
                "Peer registered using device-provided public key. "
                "No .conf generated — the device already holds its private key."
            ),
        }

    config_result = generate_wireguard_client_config(
        client_private_key=client_private_key,
        server_public_key=server_public_key,
        server_endpoint=server_endpoint,
        client_address=client_address,
        dns_servers=dns_servers,
    )

    return {
        "status": "client_setup_complete",
        "client_name": client_name,
        "client_private_key": client_private_key,
        "client_public_key": resolved_public_key,
        "peer_result": peer_result,
        "config": config_result["config"],
    }

# ---------------------------------------------------------------------------
# Routing Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_routes() -> list[dict]:
    """List all IP routes in the routing table."""
    policy_engine.evaluate("list_routes")
    return _mk.mikrotik_client.list_routes()

@mcp.tool()
def get_route(id_or_dst: str) -> dict | list:
    """Get details of a specific route by its RouterOS ID or destination address."""
    policy_engine.evaluate("get_route")
    return _mk.mikrotik_client.get_route(id_or_dst)

@mcp.tool()
def add_route(
    dst_address: str,
    gateway: str,
    distance: int | None = None,
    comment: str | None = None,
) -> dict | list:
    """Add a static IP route.

    Args:
        dst_address: Destination subnet (e.g. '192.168.1.0/24' or '0.0.0.0/0').
        gateway:     Next-hop IP or outgoing interface name (e.g. '192.168.1.1' or 'wg0').
        distance:    Administrative distance / metric (optional, default 1).
        comment:     Human-readable note (optional).
    """
    policy_engine.evaluate("add_route")
    return _mk.mikrotik_client.add_route(dst_address, gateway, distance, comment)

@mcp.tool()
def update_route(id_or_dst: str, **params) -> dict | list:
    """Update an existing static route.

    Args:
        id_or_dst: RouterOS ID (e.g. '*1') or destination address.
        **params:  Fields to update (gateway, distance, comment, etc.).
    """
    policy_engine.evaluate("update_route")
    return _mk.mikrotik_client.update_route(id_or_dst, params)

@mcp.tool()
def enable_route(id_or_dst: str) -> dict | list:
    """Enable a disabled static route."""
    policy_engine.evaluate("enable_route")
    return _mk.mikrotik_client.enable_route(id_or_dst)

@mcp.tool()
def disable_route(id_or_dst: str) -> dict | list:
    """Disable a static route without deleting it."""
    policy_engine.evaluate("disable_route")
    return _mk.mikrotik_client.disable_route(id_or_dst)

@mcp.tool()
def delete_route(confirm: bool = False, id_or_dst: str = "") -> dict | list:
    """Delete a static route permanently.

    This is a DESTRUCTIVE action. The caller must pass confirm=True.

    Args:
        confirm:   Must be True to authorise deletion.
        id_or_dst: RouterOS ID or destination address of the route to delete.
    """
    if not id_or_dst:
        raise ValueError("Must provide id_or_dst to delete a route.")
    policy_engine.evaluate("delete_route", confirm=confirm)
    return _mk.mikrotik_client.delete_route(id_or_dst)

# ---------------------------------------------------------------------------
# NAT Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_nat_rules() -> list[dict]:
    """List all IP NAT rules (srcnat and dstnat)."""
    policy_engine.evaluate("list_nat_rules")
    return _mk.mikrotik_client.list_nat_rules()

@mcp.tool()
def get_nat_rule(rule_id: str) -> dict | list:
    """Get details of a specific NAT rule by RouterOS ID."""
    policy_engine.evaluate("get_nat_rule")
    return _mk.mikrotik_client.get_nat_rule(rule_id)

@mcp.tool()
def create_nat_rule(
    chain: str,
    action: str,
    src_address: str | None = None,
    dst_address: str | None = None,
    in_interface: str | None = None,
    out_interface: str | None = None,
    protocol: str | None = None,
    dst_port: str | None = None,
    to_addresses: str | None = None,
    to_ports: str | None = None,
    comment: str | None = None,
) -> dict | list:
    """Create a new NAT rule.

    Args:
        chain:         'srcnat' for masquerade/outbound NAT, 'dstnat' for port forwarding.
        action:        'masquerade', 'src-nat', 'dst-nat', or 'accept'.
        src_address:   Source IP/subnet to match (optional).
        dst_address:   Destination IP/subnet to match (optional).
        in_interface:  Incoming interface (optional, e.g. 'wg0').
        out_interface: Outgoing interface (optional, e.g. 'ether1').
        protocol:      Protocol to match (optional, e.g. 'tcp', 'udp').
        dst_port:      Destination port(s) for dstnat (optional).
        to_addresses:  For dst-nat: target IP (optional).
        to_ports:      For dst-nat: target port (optional).
        comment:       Human-readable note (optional).
    """
    policy_engine.evaluate("create_nat_rule")
    payload: dict = {"chain": chain, "action": action}
    if src_address:
        payload["src-address"] = src_address
    if dst_address:
        payload["dst-address"] = dst_address
    if in_interface:
        payload["in-interface"] = in_interface
    if out_interface:
        payload["out-interface"] = out_interface
    if protocol:
        payload["protocol"] = protocol
    if dst_port:
        payload["dst-port"] = dst_port
    if to_addresses:
        payload["to-addresses"] = to_addresses
    if to_ports:
        payload["to-ports"] = to_ports
    if comment:
        payload["comment"] = comment
    return _mk.mikrotik_client.create_nat_rule(payload)

@mcp.tool()
def update_nat_rule(rule_id: str, params: dict) -> dict | list:
    """Update an existing NAT rule by its RouterOS ID.

    Args:
        rule_id: RouterOS ID, e.g. '*1'.
        params:  Fields to update as key-value pairs.
    """
    policy_engine.evaluate("update_nat_rule")
    return _mk.mikrotik_client.update_nat_rule(rule_id, params)

@mcp.tool()
def enable_nat_rule(rule_id: str) -> dict | list:
    """Enable a disabled NAT rule."""
    policy_engine.evaluate("enable_nat_rule")
    return _mk.mikrotik_client.enable_nat_rule(rule_id)

@mcp.tool()
def disable_nat_rule(rule_id: str) -> dict | list:
    """Disable a NAT rule without deleting it."""
    policy_engine.evaluate("disable_nat_rule")
    return _mk.mikrotik_client.disable_nat_rule(rule_id)

@mcp.tool()
def move_nat_rule(rule_id: str, destination: int) -> dict | list:
    """Move a NAT rule to a specific position in the chain.

    Args:
        rule_id:     RouterOS ID of the rule to move.
        destination: Target 0-based position index.
    """
    policy_engine.evaluate("move_nat_rule")
    return _mk.mikrotik_client.move_nat_rule(rule_id, destination)

@mcp.tool()
def delete_nat_rule(confirm: bool = False, rule_id: str = "") -> dict | list:
    """Delete a NAT rule permanently.

    This is a DESTRUCTIVE action. The caller must pass confirm=True.

    Args:
        confirm:  Must be True to authorise deletion.
        rule_id:  RouterOS ID, e.g. '*1'.
    """
    if not rule_id:
        raise ValueError("Must provide rule_id to delete a NAT rule.")
    policy_engine.evaluate("delete_nat_rule", confirm=confirm)
    return _mk.mikrotik_client.delete_nat_rule(rule_id)

