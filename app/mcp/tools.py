"""
app/mcp/tools.py

MCP tool definitions exposed to the LLM via FastMCP.

Design decisions:
  - Every tool passes through the policy engine BEFORE touching the MikroTik client.
  - Tools return plain dicts / lists (JSON-serialisable) so the LLM can interpret them.
  - The MikroTik client singleton is imported here; in tests it can be monkey-patched.
"""
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
