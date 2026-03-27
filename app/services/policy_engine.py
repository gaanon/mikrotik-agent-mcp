"""
app/services/policy_engine.py

Validates every tool call before execution.

Design decisions:
  - Actions are classified into three tiers: read, write, destructive.
  - Read actions are always allowed.
  - Write actions are always allowed (could be restricted in future advisor mode).
  - Destructive actions require the caller to pass confirm=True.
  - Nothing in the codebase executes a tool without passing through this engine first.
"""
from app.models.schemas import ActionType, PolicyDecision
from app.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Tool → action type mapping
# Update this table whenever new tools are added.
# ---------------------------------------------------------------------------

_TOOL_ACTION_TYPES: dict[str, ActionType] = {
    "list_interfaces":     ActionType.READ,
    "list_firewall_rules": ActionType.READ,
    "create_firewall_rule": ActionType.WRITE,
    "delete_firewall_rule": ActionType.DESTRUCTIVE,

    # System tools (Extend MikroTik Tool Suite)
    "get_system_info":       ActionType.READ,
    "get_system_identity":   ActionType.READ,
    "get_system_health":     ActionType.READ,
    "get_system_uptime":     ActionType.READ,
    "get_system_clock":      ActionType.READ,
    "list_logs":             ActionType.READ,
    "export_config":         ActionType.READ,

    "set_system_identity":   ActionType.WRITE,
    "set_system_clock":      ActionType.WRITE,
    "create_system_backup":  ActionType.WRITE,

    "reboot_router":         ActionType.DESTRUCTIVE,
    "shutdown_router":       ActionType.DESTRUCTIVE,
    "restore_system_backup": ActionType.DESTRUCTIVE,
    "import_config":         ActionType.DESTRUCTIVE,
    "clear_logs":            ActionType.DESTRUCTIVE,

    # Interfaces tools
    "get_interface_details": ActionType.READ,
    "get_interface_stats":   ActionType.READ,
    "monitor_interface":     ActionType.READ,

    "enable_interface":      ActionType.WRITE,
    "disable_interface":     ActionType.WRITE,
    "create_interface":      ActionType.WRITE,
    "rename_interface":      ActionType.WRITE,
    "set_interface_comment": ActionType.WRITE,
    "set_interface_mtu":     ActionType.WRITE,

    "delete_interface":      ActionType.DESTRUCTIVE,

    # IP address tools
    "list_ip_addresses":     ActionType.READ,
    "get_ip_address":        ActionType.READ,

    "add_ip_address":        ActionType.WRITE,
    "update_ip_address":     ActionType.WRITE,

    "delete_ip_address":     ActionType.DESTRUCTIVE,

    # Wireguard VPN tools
    "list_wireguard_peers":                ActionType.READ,
    "generate_wireguard_keypair":          ActionType.READ,
    "generate_wireguard_client_config":    ActionType.READ,

    "create_wireguard_interface":          ActionType.WRITE,
    "add_wireguard_peer":                  ActionType.WRITE,
    "assign_ip_to_wireguard_interface":    ActionType.WRITE,
    "allow_wireguard_port":                ActionType.WRITE,
    "setup_wireguard_server":              ActionType.WRITE,
    "add_wireguard_client":                ActionType.WRITE,

    # Routing tools
    "list_routes":    ActionType.READ,
    "get_route":      ActionType.READ,

    "add_route":      ActionType.WRITE,
    "update_route":   ActionType.WRITE,
    "enable_route":   ActionType.WRITE,
    "disable_route":  ActionType.WRITE,

    "delete_route":   ActionType.DESTRUCTIVE,

    # NAT tools
    "list_nat_rules":   ActionType.READ,
    "get_nat_rule":     ActionType.READ,

    "create_nat_rule":  ActionType.WRITE,
    "update_nat_rule":  ActionType.WRITE,
    "enable_nat_rule":  ActionType.WRITE,
    "disable_nat_rule": ActionType.WRITE,
    "move_nat_rule":    ActionType.WRITE,

    "delete_nat_rule":  ActionType.DESTRUCTIVE,
}


class PolicyViolationError(Exception):
    """Raised when a tool call is blocked by the policy engine."""


def evaluate(tool_name: str, confirm: bool = False) -> PolicyDecision:
    """Evaluate whether a tool call is permitted.

    Args:
        tool_name: The name of the MCP tool requested.
        confirm:   True if the user has explicitly confirmed the action.

    Returns:
        PolicyDecision with allowed=True if the call may proceed.

    Raises:
        PolicyViolationError if the call is blocked (destructive without confirm).
        ValueError if the tool name is unknown.
    """
    action_type = _TOOL_ACTION_TYPES.get(tool_name)
    if action_type is None:
        raise ValueError(f"Unknown tool: '{tool_name}'. Update _TOOL_ACTION_TYPES.")

    if action_type == ActionType.DESTRUCTIVE and not confirm:
        reason = (
            f"Tool '{tool_name}' is a destructive action and requires explicit confirmation. "
            "Retry with confirm=true."
        )
        logger.warning("POLICY BLOCK | tool=%s | action_type=%s | confirm=%s", tool_name, action_type, confirm)
        decision = PolicyDecision(action_type=action_type, allowed=False, reason=reason)
        raise PolicyViolationError(reason)

    reason = f"Action '{action_type}' — permitted."
    logger.info("POLICY ALLOW | tool=%s | action_type=%s", tool_name, action_type)
    return PolicyDecision(action_type=action_type, allowed=True, reason=reason)
