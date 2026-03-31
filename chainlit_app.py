"""
chainlit_app.py

Chainlit frontend for the MikroTik AI assistant.

Responsibilities:
  - Render chat UI via Chainlit
  - Forward messages to the FastAPI backend (POST /chat)
  - Detect destructive-action confirmation requirements and present Confirm/Cancel buttons
  - Format structured responses (tool calls, JSON results, dry-run badge) into readable Markdown

It does NOT contain any router logic — that all lives in the backend.

Run:
    chainlit run chainlit_app.py -w
"""

import json
import os

import chainlit as cl
import httpx
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Backend URL is configurable so this can point at any deployed instance.
BACKEND_URL: str = os.environ.get("BACKEND_URL", "http://localhost:8000")

# Generous timeout — router operations (backup, reboot, VPN setup) can be slow.
BACKEND_TIMEOUT: float = float(os.environ.get("BACKEND_TIMEOUT", "60"))

# Text fragment emitted by the policy engine when confirmation is required.
_POLICY_BLOCK_PHRASE = "requires explicit confirmation"

# Quick-action button labels and the natural-language messages they send.
_QUICK_ACTIONS = [
    ("🛡️ Show firewall rules",  "Show all firewall rules"),
    ("🌐 Show interfaces",       "Show all interfaces"),
    ("🔒 Set up WireGuard VPN",  "Set up a WireGuard VPN server"),
    ("📋 Show system info",      "Show system info and health"),
]


# ---------------------------------------------------------------------------
# Lifecycle hooks
# ---------------------------------------------------------------------------

@cl.on_chat_start
async def on_chat_start() -> None:
    """Send the welcome message and quick-action buttons when a session opens."""
    # Initialise session storage for the confirmation flow.
    cl.user_session.set("last_message", None)

    welcome = (
        "**Welcome to your MikroTik AI assistant.**\n\n"
        "You can ask me to manage your router, configure VPNs, review firewall rules, "
        "or improve security.\n\n"
        "Use the buttons below for common tasks, or just type a message."
    )

    actions = [
        cl.Action(
            name="quick_action",
            label=label,
            payload={"message": message},
            description=message,
        )
        for label, message in _QUICK_ACTIONS
    ]

    await cl.Message(content=welcome, actions=actions).send()


@cl.on_message
async def on_message(message: cl.Message) -> None:
    """Handle every user-typed message."""
    await _handle_message(message.content, confirm=False)


# ---------------------------------------------------------------------------
# Action callbacks
# ---------------------------------------------------------------------------

@cl.action_callback("quick_action")
async def on_quick_action(action: cl.Action) -> None:
    """Handle a quick-action button click."""
    await action.remove()
    await _handle_message(action.payload["message"], confirm=False)


@cl.action_callback("confirm_action")
async def on_confirm_action(action: cl.Action) -> None:
    """User clicked ✅ Confirm — resend the original message with confirm=True."""
    await action.remove()
    last_message: str | None = cl.user_session.get("last_message")
    if not last_message:
        await cl.Message(content="⚠️ Could not find the original message to confirm.").send()
        return
    await _handle_message(last_message, confirm=True)


@cl.action_callback("cancel_action")
async def on_cancel_action(action: cl.Action) -> None:
    """User clicked ❌ Cancel — acknowledge and do nothing."""
    await action.remove()
    await cl.Message(content="Action cancelled.").send()


# ---------------------------------------------------------------------------
# Core message handler
# ---------------------------------------------------------------------------

async def _handle_message(user_input: str, confirm: bool) -> None:
    """Send *user_input* to the backend and render the response.

    When a destructive action is blocked by the policy engine the response
    will contain the policy error phrase.  In that case we display the LLM's
    explanation together with Confirm / Cancel buttons instead of a plain reply.

    Args:
        user_input: The natural-language instruction from the user.
        confirm:    True when the user has explicitly clicked the Confirm button.
    """
    # Persist the most recent user input so the confirm callback can reuse it.
    cl.user_session.set("last_message", user_input)

    # Show a loading placeholder while the backend (and potentially the router) responds.
    msg = cl.Message(content="⏳ Thinking…")
    await msg.send()

    # ------------------------------------------------------------------
    # Call the backend
    # ------------------------------------------------------------------
    try:
        async with httpx.AsyncClient(timeout=BACKEND_TIMEOUT) as client:
            response = await client.post(
                f"{BACKEND_URL}/api/chat",
                json={"message": user_input, "confirm": confirm},
            )
            response.raise_for_status()
            data: dict = response.json()

    except httpx.TimeoutException:
        msg.content = (
            "⚠️ **Request timed out.** "
            "The router may be busy or unreachable. Please try again."
        )
        await msg.update()
        return

    except httpx.HTTPStatusError as exc:
        # Try to surface a meaningful detail from the JSON error body.
        detail = _extract_error_detail(exc)
        msg.content = f"⚠️ **Backend error {exc.response.status_code}:** {detail}"
        await msg.update()
        return

    except Exception as exc:  # noqa: BLE001 — catch-all for network failures
        msg.content = f"⚠️ **Unexpected error:** {exc}"
        await msg.update()
        return

    # ------------------------------------------------------------------
    # Detect whether this response requires a confirmation step
    # ------------------------------------------------------------------
    needs_confirmation = _requires_confirmation(data)

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------
    msg.content = _format_response(data)

    if needs_confirmation and not confirm:
        # Present Confirm / Cancel buttons so the user can authorise the action.
        msg.actions = [
            cl.Action(
                name="confirm_action",
                label="✅ Confirm",
                payload={"action": "confirm"},
                description="Proceed with the destructive action",
            ),
            cl.Action(
                name="cancel_action",
                label="❌ Cancel",
                payload={"action": "cancel"},
                description="Abort the action",
            ),
        ]

    await msg.update()


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _requires_confirmation(data: dict) -> bool:
    """Return True when the backend signals that a confirmation is needed.

    There are two ways this surfaces:
    1. One of the tool *results* contains the policy engine's block phrase.
    2. The LLM's *final_response* paraphrases the requirement (fallback).
    """
    # Check raw tool results first — most reliable signal.
    for result in data.get("results", []):
        if isinstance(result, dict):
            error_text = result.get("error", "")
            if _POLICY_BLOCK_PHRASE in error_text:
                return True

    # Fallback: the LLM may relay the requirement in its own words.
    final = data.get("final_response", "").lower()
    confirmation_phrases = ("requires confirmation", "confirm=true", "please confirm", "need confirmation")
    if any(phrase in final for phrase in confirmation_phrases):
        return True

    return False


def _format_response(data: dict) -> str:
    """Convert a ChatResponse dict into a readable Markdown string.

    Sections (only rendered when non-empty):
    - Dry-run badge
    - Actions taken
    - Final LLM response
    - Structured JSON results (collapsed for large payloads)
    """
    parts: list[str] = []

    # Dry-run badge — prominently warn when nothing was actually applied.
    if data.get("dry_run"):
        parts.append("⚠️ **Dry-run mode** — no changes were applied to the router.\n")

    # Summary of tool calls.
    actions: list[str] = data.get("actions_taken", [])
    if actions:
        action_list = ", ".join(f"`{a}`" for a in actions)
        parts.append(f"**Actions taken:** {action_list}\n")

    # Main LLM reply.
    final_response: str = data.get("final_response", "")
    if final_response:
        parts.append(final_response)

    # Structured results — one JSON block per tool result, skipped if too large.
    results: list = data.get("results", [])
    non_trivial = [r for r in results if isinstance(r, (dict, list))]
    if non_trivial:
        parts.append("\n---\n**Details:**")
        for idx, result in enumerate(non_trivial, start=1):
            label = actions[idx - 1] if idx - 1 < len(actions) else f"result {idx}"
            serialised = json.dumps(result, indent=2)
            # Skip very large payloads to avoid flooding the chat window.
            if len(serialised) <= 2048:
                parts.append(f"\n`{label}`\n```json\n{serialised}\n```")
            else:
                parts.append(f"\n`{label}` *(result too large to display inline)*")

    return "\n".join(parts) if parts else "(no response)"


def _extract_error_detail(exc: httpx.HTTPStatusError) -> str:
    """Best-effort extraction of a human-readable detail from an HTTP error response."""
    try:
        body = exc.response.json()
        return body.get("detail", str(exc))
    except Exception:  # noqa: BLE001
        return str(exc)
