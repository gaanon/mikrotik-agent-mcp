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


class ChatResponse(BaseModel):
    result: Any = Field(..., description="Data returned by the executed tool")
    action_taken: str = Field(..., description="Name of the MCP tool that was called")
    policy_outcome: str = Field(..., description="Policy decision summary")
    dry_run: bool = Field(False, description="True when no real command was sent to the router")
