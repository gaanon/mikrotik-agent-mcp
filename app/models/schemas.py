"""
app/models/schemas.py

Pydantic models for API requests, responses, and domain objects.
All data flowing through the system is validated via these schemas.
"""
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    """Classification of the impact of a tool call."""
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class PolicyDecision(BaseModel):
    action_type: ActionType
    allowed: bool
    reason: str


# ---------------------------------------------------------------------------
# MikroTik domain objects
# ---------------------------------------------------------------------------

class FirewallRule(BaseModel):
    """Represents a single /ip/firewall/filter entry."""
    action: str = Field(..., description="e.g. accept, drop, reject")
    chain: str = Field(..., description="e.g. input, forward, output")
    protocol: str | None = Field(None, description="e.g. tcp, udp, icmp")
    src_address: str | None = Field(None, alias="src-address")
    dst_address: str | None = Field(None, alias="dst-address")
    dst_port: str | None = Field(None, alias="dst-port")
    comment: str | None = None
    disabled: bool = False

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Chat API
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str = Field(..., description="Natural-language instruction from the user")
    confirm: bool = Field(
        False,
        description="Must be True to authorise destructive actions (e.g. deleting rules)",
    )


class ToolCall(BaseModel):
    """Structured tool call produced by the LLM."""
    name: str
    arguments: dict[str, Any] = {}


class ToolResult(BaseModel):
    """Result of executing a tool, passed back to LLM in ReAct loop."""
    tool_name: str = Field(..., description="Name of the tool that was executed")
    success: bool = Field(True, description="Whether the tool succeeded")
    data: Any = Field(..., description="The result or error message")


class LLMResponse(BaseModel):
    """Response from LLM in ReAct loop - either a tool call or final text."""
    is_tool_call: bool = Field(..., description="True if this is a tool call, False if final text response")
    tool_call: ToolCall | None = Field(None, description="Tool call details (if is_tool_call=True)")
    text_response: str | None = Field(None, description="Final text response (if is_tool_call=False)")


class MessageTurn(BaseModel):
    """Single turn in the ReAct conversation."""
    role: str = Field(..., description="'user', 'assistant', or 'tool'")
    content: str | dict[str, Any] = Field(..., description="Message content or tool result")


class ChatResponse(BaseModel):
    """Response from /chat endpoint - may include multi-turn history."""
    final_response: str = Field(..., description="Final text response from the LLM")
    actions_taken: list[str] = Field(default_factory=list, description="List of tool calls made (in order)")
    results: list[Any] = Field(default_factory=list, description="Results from each tool call")
    turns: list[MessageTurn] = Field(default_factory=list, description="Full conversation history (ReAct loop)")
    dry_run: bool = Field(False, description="True when no real command was sent to the router")
