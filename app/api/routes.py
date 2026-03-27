"""
app/api/routes.py

FastAPI route definitions.

POST /chat — main chat endpoint.

Flow:
  1. Receive ChatRequest (message + optional confirm flag)
  2. LLM selects a tool call
  3. Policy engine validates the call
  4. If allowed → dispatch to the appropriate MCP tool function
  5. Return ChatResponse
"""
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse, ToolCall
from app.services.llm_service import llm_service
from app.services.policy_engine import PolicyViolationError
from app.services.mikrotik_client import MikroTikAPIError
from app.core.config import settings
from app.core.logging import get_logger

# Import MCP tool functions directly so we can dispatch to them
from app.mcp.tools import (
    list_interfaces,
    list_firewall_rules,
    create_firewall_rule,
    delete_firewall_rule,
)

logger = get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Tool dispatcher
# Maps tool name → callable. Arguments are forwarded from the LLM's tool call.
# ---------------------------------------------------------------------------

def _dispatch(tool_call: ToolCall, confirm: bool) -> object:
    """Call the appropriate tool function with the LLM-supplied arguments.

    The confirm flag from the original request is injected for destructive tools.
    """
    name = tool_call.name
    args = tool_call.arguments

    if name == "list_interfaces":
        return list_interfaces()

    if name == "list_firewall_rules":
        return list_firewall_rules()

    if name == "create_firewall_rule":
        return create_firewall_rule(**args)

    if name == "delete_firewall_rule":
        # Inject the confirm flag from the request — the LLM cannot override it
        return delete_firewall_rule(confirm=confirm, **args)

    raise ValueError(f"Unknown tool name: '{name}'")


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """Main chat endpoint.

    Send a natural-language message to control the MikroTik router.
    Destructive actions (e.g. deleting rules) require confirm=true.
    """
    logger.info("POST /chat | message=%r | confirm=%s", request.message, request.confirm)

    # Step 1: Ask the LLM which tool to call
    try:
        tool_call: ToolCall = llm_service.get_tool_call(request.message)
    except Exception as exc:
        logger.exception("LLM error")
        raise HTTPException(status_code=502, detail=f"LLM error: {exc}") from exc

    # Step 2 & 3: Policy engine + tool execution
    try:
        result = _dispatch(tool_call, confirm=request.confirm)
        policy_outcome = f"Allowed ({tool_call.name})"
    except PolicyViolationError as exc:
        logger.warning("Policy violation: %s", exc)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except MikroTikAPIError as exc:
        logger.error("MikroTik API error: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        logger.error("Dispatch error: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return ChatResponse(
        result=result,
        action_taken=tool_call.name,
        policy_outcome=policy_outcome,
        dry_run=settings.dry_run,
    )
