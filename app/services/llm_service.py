"""
app/services/llm_service.py

Communicates with the OpenAI API to translate a user message into a structured tool call.

Design decisions:
  - The LLM is given a fixed set of tool schemas; it cannot invent new ones.
  - Only the tool name and arguments are extracted — no free-form code execution.
  - If the LLM does not produce a tool call, a clear error is raised rather than
    silently falling back to arbitrary execution.
  - Prepares for future "advisor mode" by injecting a system prompt hint when
    read_only=True is passed.
"""
import json
from openai import OpenAI
from app.core.config import settings
from app.core.logging import get_logger
from app.models.schemas import ToolCall

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Tool schemas exposed to the LLM
# These mirror the MCP tool definitions and must be kept in sync.
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "list_interfaces",
            "description": "List all network interfaces on the MikroTik router.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_firewall_rules",
            "description": "List all IP firewall filter rules on the MikroTik router.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_firewall_rule",
            "description": "Add a new firewall filter rule to the MikroTik router.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action":      {"type": "string", "description": "accept, drop, or reject"},
                    "chain":       {"type": "string", "description": "input, forward, or output"},
                    "protocol":    {"type": "string", "description": "tcp, udp, icmp, etc."},
                    "src-address": {"type": "string", "description": "Source IP/prefix"},
                    "dst-address": {"type": "string", "description": "Destination IP/prefix"},
                    "dst-port":    {"type": "string", "description": "Destination port(s)"},
                    "comment":     {"type": "string", "description": "Human-readable note"},
                    "disabled":    {"type": "boolean", "description": "Create as disabled"},
                },
                "required": ["action", "chain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_firewall_rule",
            "description": (
                "Delete a firewall filter rule by its RouterOS ID (e.g. '*1') or exact comment. "
                "This is a destructive action and requires user confirmation. "
                "You must provide EITHER rule_id OR comment."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "RouterOS record ID in *hex format, e.g. '*1'",
                    },
                    "comment": {
                        "type": "string",
                        "description": "The exact comment of the rule to delete.",
                    }
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_info",
            "description": "Get system resources, version, CPU load, memory, and uptime.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_identity",
            "description": "Get the identity (hostname) of the MikroTik router.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_system_identity",
            "description": "Set the identity (hostname) of the MikroTik router.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The new identity/hostname for the router"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_health",
            "description": "Get system health information (voltage, temperature).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_uptime",
            "description": "Get the current uptime of the MikroTik router.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_system_clock",
            "description": "Get system clock, date, and timezone.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_system_clock",
            "description": "Set the system clock, date, or timezone.",
            "parameters": {
                "type": "object",
                "properties": {
                    "time": {"type": "string", "description": "Time in HH:MM:SS format"},
                    "date": {"type": "string", "description": "Date in mmm/DD/YYYY format"},
                    "time_zone_name": {"type": "string", "description": "Timezone name, e.g. UTC, Europe/London"}
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reboot_router",
            "description": "Reboot the MikroTik router. Destructive action requiring confirmation.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shutdown_router",
            "description": "Shut down the MikroTik router. Destructive action requiring confirmation.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_system_backup",
            "description": "Create a system backup file (.backup).",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the backup file"},
                    "password": {"type": "string", "description": "Optional password to encrypt the backup"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "restore_system_backup",
            "description": "Restore a system backup file (.backup). Destructive action requiring confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the backup file to restore"},
                    "password": {"type": "string", "description": "Password to decrypt the backup if it was encrypted"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "export_config",
            "description": "Export the router configuration script (.rsc format).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "import_config",
            "description": "Import a router configuration script (.rsc format). Destructive action requiring confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_name": {"type": "string", "description": "The name of the script file to import"}
                },
                "required": ["file_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_logs",
            "description": "List system logs.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "clear_logs",
            "description": "Clear the system logs in memory. Destructive action requiring confirmation.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_interface_details",
            "description": "Get detailed settings for a specific network interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_interface_stats",
            "description": "Get traffic statistics (tx/rx bytes and packets) for an interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "monitor_interface",
            "description": "Monitor real-time traffic (bits-per-second) for an interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enable_interface",
            "description": "Enable a disabled network interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface to enable"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disable_interface",
            "description": "Disable an active network interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface to disable"}
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_interface",
            "description": "Create a new network interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "type_": {"type": "string", "description": "The type of interface: vlan, bridge, vrrp, wireguard, etc."},
                    "params": {"type": "object", "description": "Key-value arguments for interface creation."}
                },
                "required": ["type_", "params"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_interface",
            "description": "Delete a network interface. Destructive action requiring confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "type_": {"type": "string", "description": "The type of interface: vlan, bridge, vrrp, wireguard, etc."},
                    "name": {"type": "string", "description": "The name of the interface to delete"}
                },
                "required": ["type_", "name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_interface",
            "description": "Rename a network interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "old_name": {"type": "string", "description": "The current name of the interface"},
                    "new_name": {"type": "string", "description": "The new name for the interface"}
                },
                "required": ["old_name", "new_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_interface_comment",
            "description": "Set a descriptive comment on an interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface"},
                    "comment": {"type": "string", "description": "The comment to set"}
                },
                "required": ["name", "comment"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_interface_mtu",
            "description": "Set the Maximum Transmission Unit (MTU) of an interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "The name of the interface"},
                    "mtu": {"type": "integer", "description": "The new MTU size in bytes"}
                },
                "required": ["name", "mtu"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_ip_addresses",
            "description": "List all IP addresses on the router.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ip_address",
            "description": "Get a specific IP address by its address or ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_address": {"type": "string", "description": "The IP address string or RouterOS ID"}
                },
                "required": ["id_or_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_ip_address",
            "description": "Add a new IP address to an interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "The IP address (e.g. '192.168.1.1/24')"},
                    "interface": {"type": "string", "description": "The name of the interface"},
                    "params": {"type": "object", "description": "Optional dictionary of additional parameters"}
                },
                "required": ["address", "interface"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_ip_address",
            "description": "Update an existing IP address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_address": {"type": "string", "description": "The IP address string or RouterOS ID"},
                    "params": {"type": "object", "description": "Fields to update"}
                },
                "required": ["id_or_address", "params"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_ip_address",
            "description": "Delete an IP address. Destructive action requiring confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_address": {"type": "string", "description": "The IP address string or RouterOS ID to delete"}
                },
                "required": ["id_or_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_wireguard_peers",
            "description": "List all Wireguard peers configured on the MikroTik router.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_wireguard_keypair",
            "description": "Generate a new Wireguard X25519 keypair (private and public keys) using cryptography library. Returns both keys base64-encoded.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_wireguard_client_config",
            "description": "Generate a ready-to-use Wireguard client configuration (.conf format) for connecting to a server.",
            "parameters": {
                "type": "object",
                "properties": {
                    "client_private_key": {"type": "string", "description": "Base64-encoded client private key"},
                    "server_public_key": {"type": "string", "description": "Base64-encoded server public key"},
                    "server_endpoint": {"type": "string", "description": "Server endpoint (IP:port, e.g. '203.0.113.1:51820')"},
                    "client_address": {"type": "string", "description": "Client VPN address with subnet (e.g. '10.0.0.2/32')"},
                    "dns_servers": {"type": "string", "description": "Comma-separated DNS servers (optional)"},
                },
                "required": ["client_private_key", "server_public_key", "server_endpoint", "client_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_wireguard_interface",
            "description": "Create a new Wireguard interface on the MikroTik router.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name for the Wireguard interface (e.g. 'wg0')"},
                    "listen_port": {"type": "integer", "description": "UDP port to listen on (default 51820)"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_wireguard_peer",
            "description": "Add a peer to an existing Wireguard interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Wireguard interface name"},
                    "public_key": {"type": "string", "description": "Peer's base64-encoded public key"},
                    "allowed_address": {"type": "string", "description": "Allowed address(es) for peer (CIDR notation, e.g. '10.0.0.2/32')"},
                    "endpoint": {"type": "string", "description": "Peer endpoint (optional, IP:port)"},
                    "persistent_keepalive": {"type": "integer", "description": "Persistent keepalive interval in seconds (optional)"},
                },
                "required": ["interface", "public_key", "allowed_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "assign_ip_to_wireguard_interface",
            "description": "Assign an IP address to a Wireguard interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Wireguard interface name"},
                    "address": {"type": "string", "description": "IP address with subnet (e.g. '10.0.0.1/24')"},
                },
                "required": ["interface", "address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "allow_wireguard_port",
            "description": "Create a firewall rule to allow UDP traffic on the Wireguard port.",
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "UDP port for Wireguard (default 51820)"},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "setup_wireguard_server",
            "description": (
                "Complete WireGuard server setup in one call: creates the interface, assigns an IP, "
                "opens the firewall UDP input port, adds a forward rule allowing VPN clients to reach the LAN, "
                "and (when is_primary_router=false) adds a srcnat masquerade rule so LAN hosts reply "
                "back through the MikroTik when it is not the default gateway. "
                "Always returns a port_forward_required notice for the upstream router."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "interface_name": {"type": "string", "description": "Name for the server WireGuard interface (e.g. 'wg0')"},
                    "server_ip": {"type": "string", "description": "Server VPN IP with subnet (e.g. '10.0.0.1/24')"},
                    "listen_port": {"type": "integer", "description": "UDP listen port (default 51820)"},
                    "lan_subnet": {"type": "string", "description": "LAN subnet VPN clients should reach (default '192.168.1.0/24')"},
                    "is_primary_router": {
                        "type": "boolean",
                        "description": (
                            "True (default) if the MikroTik IS the default gateway for all LAN devices — "
                            "no srcnat masquerade is needed. "
                            "False if there is an upstream router (e.g. ISP modem or WiFi router) that is "
                            "the default gateway — srcnat masquerade will be added so LAN hosts reply "
                            "to the MikroTik instead of the upstream router."
                        ),
                    },
                },
                "required": ["interface_name", "server_ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_wireguard_client",
            "description": (
                "Register a WireGuard peer and optionally return a client .conf file. "
                "Two workflows: "
                "(1) App-generated keys — omit client_public_key; the app generates a keypair and returns a "
                "ready-to-import .conf (use for devices that don't manage their own keys). "
                "(2) Device-generated keys — provide client_public_key with the device's existing public key; "
                "the peer is registered and no .conf is returned (use for phones running the WireGuard app "
                "that already generated their own keypair)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "server_interface": {"type": "string", "description": "Name of the server's WireGuard interface (e.g. 'wg0')"},
                    "server_public_key": {"type": "string", "description": "Server's base64-encoded public key"},
                    "client_name": {"type": "string", "description": "Descriptive name/comment for this peer"},
                    "client_address": {"type": "string", "description": "VPN address for client (e.g. '10.0.0.2/32')"},
                    "server_endpoint": {"type": "string", "description": "Server public endpoint in host:port format (e.g. '1.2.3.4:51820')"},
                    "dns_servers": {"type": "string", "description": "Comma-separated DNS servers for the .conf file (optional)"},
                    "client_public_key": {
                        "type": "string",
                        "description": (
                            "Existing base64 public key from the device (e.g. copied from the WireGuard app). "
                            "When provided, skips keypair generation and does NOT return a .conf — "
                            "the device already holds its private key. Omit to let the app generate keys."
                        ),
                    },
                },
                "required": ["server_interface", "server_public_key", "client_name", "client_address", "server_endpoint"],
            },
        },
    },

    # -----------------------------------------------------------------------
    # Routing tools
    # -----------------------------------------------------------------------
    {
        "type": "function",
        "function": {
            "name": "list_routes",
            "description": "List all IP routes in the routing table.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_route",
            "description": "Get details of a specific route by its RouterOS ID or destination address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_dst": {"type": "string", "description": "RouterOS ID (e.g. '*1') or destination address (e.g. '192.168.1.0/24')"},
                },
                "required": ["id_or_dst"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_route",
            "description": (
                "Add a static IP route. "
                "Use this to allow Wireguard VPN clients to reach local subnets (e.g. dst-address=192.168.1.0/24, gateway=wg0 interface). "
                "For routing VPN traffic to local network: dst-address is the local subnet, gateway is the router's LAN IP or the Wireguard interface."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "dst_address": {"type": "string", "description": "Destination subnet (e.g. '192.168.1.0/24' or '0.0.0.0/0' for default route)"},
                    "gateway": {"type": "string", "description": "Next-hop IP or outgoing interface name (e.g. '192.168.1.1' or 'wg0')"},
                    "distance": {"type": "integer", "description": "Administrative distance / metric (default 1)"},
                    "comment": {"type": "string", "description": "Human-readable note"},
                },
                "required": ["dst_address", "gateway"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_route",
            "description": "Update an existing route by its RouterOS ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_dst": {"type": "string", "description": "RouterOS ID (e.g. '*1') or destination address"},
                    "gateway": {"type": "string", "description": "New gateway IP or interface"},
                    "distance": {"type": "integer", "description": "New administrative distance"},
                    "comment": {"type": "string", "description": "New comment"},
                },
                "required": ["id_or_dst"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enable_route",
            "description": "Enable a disabled static route.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_dst": {"type": "string", "description": "RouterOS ID or destination address"},
                },
                "required": ["id_or_dst"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disable_route",
            "description": "Disable a static route without deleting it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_dst": {"type": "string", "description": "RouterOS ID or destination address"},
                },
                "required": ["id_or_dst"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_route",
            "description": "Delete a static route permanently. Destructive action requiring confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "id_or_dst": {"type": "string", "description": "RouterOS ID or destination address of the route to delete"},
                },
                "required": ["id_or_dst"],
            },
        },
    },

    # -----------------------------------------------------------------------
    # NAT tools
    # -----------------------------------------------------------------------
    {
        "type": "function",
        "function": {
            "name": "list_nat_rules",
            "description": "List all IP NAT rules (srcnat and dstnat).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_nat_rule",
            "description": "Get details of a specific NAT rule by RouterOS ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "RouterOS ID, e.g. '*1'"},
                },
                "required": ["rule_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_nat_rule",
            "description": (
                "Create a new NAT rule. "
                "Use action=masquerade with chain=srcnat and in-interface=<wireguard_iface> to allow VPN clients to reach the local network. "
                "Use action=dst-nat for port forwarding."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "chain": {"type": "string", "description": "'srcnat' for outbound NAT/masquerade, 'dstnat' for port forwarding"},
                    "action": {"type": "string", "description": "'masquerade', 'src-nat', 'dst-nat', or 'accept'"},
                    "src_address": {"type": "string", "description": "Source IP/subnet to match (optional)"},
                    "dst_address": {"type": "string", "description": "Destination IP/subnet to match (optional)"},
                    "in_interface": {"type": "string", "description": "Incoming interface to match (e.g. 'wg0')"},
                    "out_interface": {"type": "string", "description": "Outgoing interface to match (e.g. 'ether1')"},
                    "protocol": {"type": "string", "description": "Protocol to match (e.g. 'tcp', 'udp')"},
                    "dst_port": {"type": "string", "description": "Destination port(s) for dstnat port forwarding"},
                    "to_addresses": {"type": "string", "description": "For dst-nat: target IP to forward to"},
                    "to_ports": {"type": "string", "description": "For dst-nat: target port to forward to"},
                    "comment": {"type": "string", "description": "Human-readable note"},
                },
                "required": ["chain", "action"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_nat_rule",
            "description": "Update an existing NAT rule by its RouterOS ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "RouterOS ID, e.g. '*1'"},
                    "params": {"type": "object", "description": "Fields to update as key-value pairs"},
                },
                "required": ["rule_id", "params"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enable_nat_rule",
            "description": "Enable a disabled NAT rule.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "RouterOS ID, e.g. '*1'"},
                },
                "required": ["rule_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disable_nat_rule",
            "description": "Disable a NAT rule without deleting it.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "RouterOS ID, e.g. '*1'"},
                },
                "required": ["rule_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "move_nat_rule",
            "description": "Move a NAT rule to a different position in the chain.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "RouterOS ID of the rule to move"},
                    "destination": {"type": "integer", "description": "Target position index (0-based)"},
                },
                "required": ["rule_id", "destination"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_nat_rule",
            "description": "Delete a NAT rule permanently. Destructive action requiring confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "RouterOS ID, e.g. '*1'"},
                },
                "required": ["rule_id"],
            },
        },
    },
]

_BASE_SYSTEM_PROMPT = (
    "You are an AI assistant that manages a MikroTik router. "
    "You must use one of the provided tools to fulfil the user's request. "
    "Do not make up tool names. Do not execute arbitrary commands. "
    "If the request is ambiguous, pick the safest matching tool."
)

_ADVISOR_SYSTEM_PROMPT = (
    _BASE_SYSTEM_PROMPT
    + " You are in READ-ONLY advisor mode. Only suggest read tools (list_interfaces, list_firewall_rules)."
)


class LLMService:
    def __init__(self) -> None:
        self._client = OpenAI(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
        )
        self._model = settings.openai_model

    def get_tool_call(self, message: str, read_only: bool = False) -> ToolCall:
        """Send a user message to the LLM and return the tool call it selects.

        Args:
            message:   Natural-language instruction from the user.
            read_only: When True, the system prompt biases the LLM toward read-only tools.

        Returns:
            ToolCall with the selected tool name and arguments.

        Raises:
            ValueError: If the LLM does not return a tool call.
        """
        system_prompt = _ADVISOR_SYSTEM_PROMPT if read_only else _BASE_SYSTEM_PROMPT

        logger.info("LLM request | model=%s | message=%r | read_only=%s", self._model, message, read_only)

        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message},
            ],
            tools=TOOL_SCHEMAS,
            tool_choice="required",  # Force the LLM to always pick a tool
        )

        choice = response.choices[0]
        tool_calls = choice.message.tool_calls

        if not tool_calls:
            raise ValueError(
                "LLM did not return a tool call. "
                f"Finish reason: {choice.finish_reason}. Content: {choice.message.content}"
            )

        # Use the first tool call (we only support single-tool responses for now)
        raw = tool_calls[0]
        name = raw.function.name
        arguments = json.loads(raw.function.arguments or "{}")

        logger.info("LLM selected tool | name=%s | args=%s", name, arguments)
        return ToolCall(name=name, arguments=arguments)

    def get_next_action(
        self,
        messages: list[dict],
        read_only: bool = False,
    ) -> "LLMResponse":
        """Multi-turn ReAct loop: return either a tool call or final text response.

        Args:
            messages: List of message dicts in OpenAI format. Should include system, user, assistant, and tool messages.
            read_only: When True, biases toward read-only tools.

        Returns:
            LLMResponse with is_tool_call=True (contains tool_call) or False (contains text_response).
        """
        from app.models.schemas import LLMResponse
        
        system_prompt = _ADVISOR_SYSTEM_PROMPT if read_only else _BASE_SYSTEM_PROMPT

        logger.info("LLM ReAct | model=%s | message_count=%d | read_only=%s", 
                    self._model, len(messages), read_only)

        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",  # Let LLM decide: tool call or text response
        )

        choice = response.choices[0]
        finish_reason = choice.finish_reason

        # Case 1: LLM decided to call a tool
        if finish_reason == "tool_calls" and choice.message.tool_calls:
            raw = choice.message.tool_calls[0]
            name = raw.function.name
            arguments = json.loads(raw.function.arguments or "{}")
            logger.info("LLM selected tool | name=%s | args=%s", name, arguments)

            return LLMResponse(
                is_tool_call=True,
                tool_call=ToolCall(name=name, arguments=arguments),
                text_response=None,
            )

        # Case 2: LLM decided to respond with text (end of reasoning loop)
        elif finish_reason == "stop":
            text = choice.message.content or "(no response)"
            logger.info("LLM finished reasoning | text=%r", text[:100])

            return LLMResponse(
                is_tool_call=False,
                tool_call=None,
                text_response=text,
            )

        # Case 3: Unexpected finish reason
        else:
            raise ValueError(
                f"Unexpected LLM finish_reason: {finish_reason}. "
                f"Content: {choice.message.content}"
            )


# Singleton
llm_service = LLMService()
