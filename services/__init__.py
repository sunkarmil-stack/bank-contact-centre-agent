"""Independently deployable services around the agent:

* ``gateway``          — API gateway (edge): token validation, routing, rate limits, header hygiene
* ``customer_service`` — system of record for client profile, transactions and card status
* ``case_service``     — case management (complaints, disputes, fraud referrals)

The agent API (``ccagent.api``) and the MCP tool service (``ccagent.mcp_server``)
are the other two services. ``python -m scripts.run_all`` starts all five.
"""
