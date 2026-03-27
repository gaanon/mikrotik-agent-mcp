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
