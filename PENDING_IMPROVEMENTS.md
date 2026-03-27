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


### Bridge
- list_bridges
- create_bridge
- delete_bridge
- add_interface_to_bridge
- remove_interface_from_bridge
- list_bridge_ports
- set_bridge_vlan_filtering
- list_bridge_vlans
- create_bridge_vlan
- delete_bridge_vlan

### Routing
- list_routes
- get_route
- add_route
- update_route
- delete_route
- enable_route
- disable_route

### Firewall
- list_firewall_rules
- get_firewall_rule
- create_firewall_rule
- update_firewall_rule
- delete_firewall_rule
- enable_firewall_rule
- disable_firewall_rule
- move_firewall_rule

### NAT
- list_nat_rules
- get_nat_rule
- create_nat_rule
- update_nat_rule
- delete_nat_rule
- enable_nat_rule
- disable_nat_rule
- move_nat_rule

### Address lists
- list_address_lists
- add_address_list_entry
- remove_address_list_entry
- clear_address_list

### DHCP
- list_dhcp_servers
- create_dhcp_server
- delete_dhcp_server
- list_dhcp_leases
- get_dhcp_lease
- add_dhcp_lease
- remove_dhcp_lease
- make_dhcp_lease_static
- release_dhcp_lease

### DNS
- get_dns_settings
- set_dns_servers
- list_dns_records
- add_dns_record
- delete_dns_record
- flush_dns_cache
- list_dns_cache

### WIFI
- list_wifi_interfaces
- get_wifi_interface
- enable_wifi
- disable_wifi
- set_wifi_ssid
- set_wifi_password
- set_wifi_channel
- monitor_wifi_clients
- disconnect_wifi_client

### Users and security
- list_users
- get_user
- create_user
- delete_user
- set_user_password
- enable_user
- disable_user
- list_user_groups
- add_user_to_group
- remove_user_from_group

### Services
- list_services
- enable_service
- disable_service
- set_service_port
- set_service_address

### Monitoring
- get_resource_usage
- get_interface_traffic
- get_cpu_usage
- get_memory_usage
- get_disk_usage

### Diagnostics
- ping_host
- traceroute
- bandwidth_test
- dns_lookup

### Discovery
- list_neighbors
- scan_network

## 4. Advisor Mode

Implement the read-only advisor mode hinted at in the LLM service configuration, which would dynamically filter out `WRITE` and `DESTRUCTIVE` tools from the schemas sent to OpenAI entirely, ensuring a read-only token output loop.
