# Goal

Build a Python application that acts as an AI-powered chat interface to manage a MikroTik router via its API. The system must be safe, modular, and extensible.

# Context

* The app will run in a home lab environment.
* It will use:

  * Python
  * FastAPI (for API backend)
  * FastMCP (to expose tools to the LLM)
  * OpenAI API (LLM for reasoning)
  * MikroTik RouterOS API (for router interaction)
* The system should follow a layered architecture:

  1. Chat interface
  2. LLM (decision making)
  3. MCP tool layer
  4. Policy engine (validation + safety)
  5. MikroTik API client

# Requirements

## 1. Project structure

Create a clean, production-style Python project with:

* `/app`

  * `/api` (FastAPI routes)
  * `/mcp` (tool definitions)
  * `/services`

    * `mikrotik_client.py`
    * `policy_engine.py`
    * `llm_service.py`
  * `/models` (pydantic schemas)
  * `/core` (config, logging)
* `main.py`
* `requirements.txt`

## 2. MikroTik client

* Implement a wrapper for RouterOS API
* Methods should be high-level, NOT raw commands
* Example methods:

  * `get_interfaces()`
  * `get_firewall_rules()`
  * `add_firewall_rule(rule: dict)`
  * `delete_firewall_rule(rule_id: str)`

## 3. MCP tools

Expose safe, structured tools for the LLM:

* `list_interfaces`
* `list_firewall_rules`
* `create_firewall_rule`
* `delete_firewall_rule`

Each tool must:

* Have a clear schema
* Call the MikroTik client
* Return structured JSON

## 4. Policy engine (CRITICAL)

Implement a validation layer before executing any action:

* Classify actions as:

  * "read"
  * "write"
  * "destructive"
* Enforce rules:

  * Read actions: always allowed
  * Write actions: allowed
  * Destructive actions: require confirmation flag

Example:

* deleting firewall rule → requires confirmation

## 5. LLM service

* Integrate OpenAI API
* The LLM must:

  * Decide which tool to call
  * Return structured tool calls (JSON)
* Do NOT allow direct execution of arbitrary commands

## 6. Chat endpoint

Create a FastAPI endpoint:
POST /chat

Input:
{
"message": "string",
"confirm": optional bool
}

Flow:

1. Send message to LLM
2. LLM selects tool + arguments
3. Pass request through policy engine
4. If allowed → execute tool
5. Return result to user

## 7. Safety features

* Dry-run mode (no real execution)
* Logging of all actions
* Clear error handling

## 8. Future extensibility (design only)

Prepare interfaces for:

* "advisor mode" (read-only analysis of config)
* recommendation engine

# Constraints

* Use type hints everywhere
* Use Pydantic for validation
* Keep functions small and testable
* No hardcoded credentials
* Code must be readable and production-quality

# Output format

* Generate full project scaffold
* Include key files with working code
* Add comments explaining design decisions
* Do not skip critical parts (policy engine, MCP tools)

# Completion criteria

* The app can:

  * Receive a chat message
  * Decide an action via LLM
  * Validate via policy engine
  * Execute via MikroTik client (mocked if needed)
* Code runs without syntax errors
