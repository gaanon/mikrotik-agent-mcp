"""
app/api/routes.py

FastAPI route definitions.

POST /chat — main chat endpoint with ReAct loop support.

Flow (ReAct loop):
  1. Initialize conversation with system prompt + user message
  2. LLM decides: tool call or final text?
  3. If tool call: execute, append result, loop to step 2
  4. If final text: return response with full history
  5. Safety limits: max 10 iterations, then force finish
"""
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse, ToolCall, MessageTurn, LLMResponse
from app.services.llm_service import llm_service, TOOL_SCHEMAS
from app.services.policy_engine import PolicyViolationError
from app.services.mikrotik_client import MikroTikAPIError
from app.core.config import settings
from app.core.logging import get_logger
import json

# Import MCP tool functions directly so we can dispatch to them
from app.mcp.tools import (
    list_interfaces,
    list_firewall_rules,
    create_firewall_rule,
    delete_firewall_rule,
    get_system_info,
    get_system_identity,
    set_system_identity,
    get_system_health,
    get_system_uptime,
    get_system_clock,
    set_system_clock,
    reboot_router,
    shutdown_router,
    create_system_backup,
    restore_system_backup,
    export_config,
    import_config,
    list_logs,
    clear_logs,
    get_interface_details,
    get_interface_stats,
    monitor_interface,
    enable_interface,
    disable_interface,
    create_interface,
    delete_interface,
    rename_interface,
    set_interface_comment,
    set_interface_mtu,
    list_ip_addresses,
    get_ip_address,
    add_ip_address,
    update_ip_address,
    delete_ip_address,
    list_wireguard_peers,
    generate_wireguard_keypair,
    generate_wireguard_client_config,
    create_wireguard_interface,
    add_wireguard_peer,
    assign_ip_to_wireguard_interface,
    allow_wireguard_port,
    setup_wireguard_server,
    add_wireguard_client,
    list_routes,
    get_route,
    add_route,
    update_route,
    enable_route,
    disable_route,
    delete_route,
    list_nat_rules,
    get_nat_rule,
    create_nat_rule,
    update_nat_rule,
    enable_nat_rule,
    disable_nat_rule,
    move_nat_rule,
    delete_nat_rule,
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

    # -----------------------------------------------------------------------
    # System APIs
    # -----------------------------------------------------------------------
    if name == "get_system_info":
        return get_system_info()
    if name == "get_system_identity":
        return get_system_identity()
    if name == "set_system_identity":
        return set_system_identity(**args)
    if name == "get_system_health":
        return get_system_health()
    if name == "get_system_uptime":
        return get_system_uptime()
    if name == "get_system_clock":
        return get_system_clock()
    if name == "set_system_clock":
        return set_system_clock(**args)
    if name == "reboot_router":
        return reboot_router(confirm=confirm)
    if name == "shutdown_router":
        return shutdown_router(confirm=confirm)
    if name == "create_system_backup":
        return create_system_backup(**args)
    if name == "restore_system_backup":
        return restore_system_backup(confirm=confirm, **args)
    if name == "export_config":
        return export_config()
    if name == "import_config":
        return import_config(confirm=confirm, **args)
    if name == "list_logs":
        return list_logs()
    if name == "clear_logs":
        return clear_logs(confirm=confirm)

    # -----------------------------------------------------------------------
    # Interface APIs
    # -----------------------------------------------------------------------
    if name == "get_interface_details":
        return get_interface_details(**args)
    if name == "get_interface_stats":
        return get_interface_stats(**args)
    if name == "monitor_interface":
        return monitor_interface(**args)
    if name == "enable_interface":
        return enable_interface(**args)
    if name == "disable_interface":
        return disable_interface(**args)
    if name == "create_interface":
        return create_interface(**args)
    if name == "delete_interface":
        return delete_interface(confirm=confirm, **args)
    if name == "rename_interface":
        return rename_interface(**args)
    if name == "set_interface_comment":
        return set_interface_comment(**args)
    if name == "set_interface_mtu":
        return set_interface_mtu(**args)

    # -----------------------------------------------------------------------
    # IP Address APIs
    # -----------------------------------------------------------------------
    if name == "list_ip_addresses":
        return list_ip_addresses()
    if name == "get_ip_address":
        return get_ip_address(**args)
    if name == "add_ip_address":
        return add_ip_address(**args)
    if name == "update_ip_address":
        return update_ip_address(**args)
    if name == "delete_ip_address":
        return delete_ip_address(confirm=confirm, **args)

    # -----------------------------------------------------------------------
    # Wireguard VPN APIs
    # -----------------------------------------------------------------------
    if name == "list_wireguard_peers":
        return list_wireguard_peers()
    if name == "generate_wireguard_keypair":
        return generate_wireguard_keypair()
    if name == "generate_wireguard_client_config":
        return generate_wireguard_client_config(**args)
    if name == "create_wireguard_interface":
        return create_wireguard_interface(**args)
    if name == "add_wireguard_peer":
        return add_wireguard_peer(**args)
    if name == "assign_ip_to_wireguard_interface":
        return assign_ip_to_wireguard_interface(**args)
    if name == "allow_wireguard_port":
        return allow_wireguard_port(**args)
    if name == "setup_wireguard_server":
        return setup_wireguard_server(**args)
    if name == "add_wireguard_client":
        return add_wireguard_client(**args)

    # -----------------------------------------------------------------------
    # Routing APIs
    # -----------------------------------------------------------------------
    if name == "list_routes":
        return list_routes()
    if name == "get_route":
        return get_route(**args)
    if name == "add_route":
        return add_route(**args)
    if name == "update_route":
        return update_route(**args)
    if name == "enable_route":
        return enable_route(**args)
    if name == "disable_route":
        return disable_route(**args)
    if name == "delete_route":
        return delete_route(confirm=confirm, **args)

    # -----------------------------------------------------------------------
    # NAT APIs
    # -----------------------------------------------------------------------
    if name == "list_nat_rules":
        return list_nat_rules()
    if name == "get_nat_rule":
        return get_nat_rule(**args)
    if name == "create_nat_rule":
        return create_nat_rule(**args)
    if name == "update_nat_rule":
        return update_nat_rule(**args)
    if name == "enable_nat_rule":
        return enable_nat_rule(**args)
    if name == "disable_nat_rule":
        return disable_nat_rule(**args)
    if name == "move_nat_rule":
        return move_nat_rule(**args)
    if name == "delete_nat_rule":
        return delete_nat_rule(confirm=confirm, **args)

    raise ValueError(f"Unknown tool name: '{name}'")


# ---------------------------------------------------------------------------
# ReAct Loop Implementation
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are an AI assistant that manages a MikroTik router. "
    "You must use one of the provided tools to fulfil the user's request. "
    "Do not make up tool names. Do not execute arbitrary commands. "
    "If the request is ambiguous, pick the safest matching tool. "
    "If you have completed the user's goal, provide a clear final response instead of calling more tools."
)


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """Main chat endpoint with ReAct (Reason + Act) loop.

    Send a natural-language message to control the MikroTik router.
    Destructive actions require confirm=true.
    
    The LLM can execute multiple tools in sequence, building a conversation history,
    and will return a final response when it determines the task is complete.
    """
    logger.info("POST /chat | message=%r | confirm=%s", request.message, request.confirm)

    # Initialize conversation history
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": request.message},
    ]

    actions_taken: list[str] = []
    results: list[object] = []
    turns: list[MessageTurn] = [
        MessageTurn(role="user", content=request.message),
    ]

    max_iterations = 10
    iteration = 0

    # ReAct Loop
    while iteration < max_iterations:
        iteration += 1
        logger.info("ReAct loop iteration %d/%d", iteration, max_iterations)

        # Step 1: Get next action from LLM
        try:
            llm_response: LLMResponse = llm_service.get_next_action(
                messages=messages,
                read_only=False,
            )
        except Exception as exc:
            logger.exception("LLM error during ReAct loop")
            raise HTTPException(status_code=502, detail=f"LLM error: {exc}") from exc

        # Step 2: Check if LLM wants to finish or call a tool
        if not llm_response.is_tool_call:
            # LLM decided to finish — return final response
            final_response = llm_response.text_response or "(no response)"
            logger.info("ReAct loop finished after %d iterations", iteration)

            return ChatResponse(
                final_response=final_response,
                actions_taken=actions_taken,
                results=results,
                turns=turns,
                dry_run=settings.dry_run,
            )

        # Step 3: Execute the tool call
        tool_call = llm_response.tool_call
        logger.info("ReAct loop: executing tool %s", tool_call.name)

        try:
            tool_result = _dispatch(tool_call, confirm=request.confirm)
            success = True
            error_msg = None
        except PolicyViolationError as exc:
            logger.warning("Policy violation: %s", exc)
            tool_result = {"error": str(exc)}
            success = False
            error_msg = str(exc)
        except MikroTikAPIError as exc:
            logger.error("MikroTik API error: %s", exc)
            tool_result = {"error": str(exc)}
            success = False
            error_msg = str(exc)
        except ValueError as exc:
            logger.error("Dispatch error: %s", exc)
            tool_result = {"error": str(exc)}
            success = False
            error_msg = str(exc)

        # Track action and result
        actions_taken.append(tool_call.name)
        results.append(tool_result)
        turns.append(MessageTurn(role="assistant", content=json.dumps({
            "tool": tool_call.name,
            "arguments": tool_call.arguments,
        })))

        # Step 4: Append tool result back to conversation
        tool_result_str = (
            json.dumps(tool_result) if isinstance(tool_result, (dict, list))
            else str(tool_result)
        )
        messages.append({
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"call_{len(actions_taken)}",
                    "type": "function",
                    "function": {
                        "name": tool_call.name,
                        "arguments": json.dumps(tool_call.arguments),
                    },
                }
            ],
        })
        messages.append({
            "role": "tool",
            "tool_call_id": f"call_{len(actions_taken)}",
            "content": tool_result_str,
        })

        turns.append(MessageTurn(role="tool", content={
            "tool": tool_call.name,
            "success": success,
            "data": tool_result,
            "error": error_msg,
        }))

    # If we hit max iterations, force a finish
    logger.warning("ReAct loop hit max iterations (%d), forcing finish", max_iterations)
    final_response = (
        "I've completed multiple operations but reached the iteration limit. "
        f"Actions taken: {', '.join(actions_taken)}. "
        "Please review the results above."
    )

    return ChatResponse(
        final_response=final_response,
        actions_taken=actions_taken,
        results=results,
        turns=turns,
        dry_run=settings.dry_run,
    )
