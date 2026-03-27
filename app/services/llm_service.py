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


# Singleton
llm_service = LLMService()
