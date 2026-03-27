# Pending Improvements

## 1. HTTPS / Port 443 Support für older RouterOS (SSL Handshake fix)

Currently, the application defaults to using port 80 (plain HTTP) for local testing.

When connecting to an older MikroTik RouterOS over HTTPS (`MIKROTIK_PORT=443`), Python's extremely strict modern OpenSSL 3 configuration (default on macOS) actively rejects the TLS handshake (`ssl/tls alert handshake failure`) due to legacy ciphers/protocols used by the router's `www-ssl` service.

**To-Do:**
- Investigate alternative HTTP clients (e.g. `urllib3` with custom OpenSSL bindings) or force a lower security level cipher string that macOS OpenSSL respects when `MIKROTIK_VERIFY_SSL=false`.
- Alternatively, write a guide for configuring the MikroTik router to use a modern, strong TLS certificate with modern ciphers so we don't need weak SSL contexts at all.

## 2. ReAct Agent Loop in Chat Endpoint

The `/chat` endpoint is currently a single-turn architecture: the LLM is forced to pick exactly one tool and return immediately. To make the interface more flexible ("agentic"), implement a multi-turn ReAct (Reason + Act) loop:
1. LLM predicts a tool.
2. The endpoint executes the tool internally.
3. The endpoint appends the tool's returning data back to the LLM context.
4. The LLM then generates either another tool call or a final text response.

## 3. Extend MikroTik Tool Suite

Add additional tools to manage the router based on user needs:
- `get_dns_servers`
- `get_dhcp_leases`
- `add_static_route`

## 4. Advisor Mode

Implement the read-only advisor mode hinted at in the LLM service configuration, which would dynamically filter out `WRITE` and `DESTRUCTIVE` tools from the schemas sent to OpenAI entirely, ensuring a read-only token output loop.
