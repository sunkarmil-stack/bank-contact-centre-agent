"""Run the enterprise tool server standalone over MCP Streamable HTTP.

    python -m ccagent.mcp_server            # http://127.0.0.1:8765/mcp

Then point the orchestrator at it:  CCAGENT_MCP_MODE=http CCAGENT_MCP_URL=http://127.0.0.1:8765/mcp
In production this runs as its own container behind API Management (mTLS),
so tool access is isolated, separately scaled and separately audited.
"""

from __future__ import annotations

import os

import uvicorn

from ..config import Settings
from ..container import build_tool_backends, open_audit, open_database
from ..secrets import build_secret_provider
from ..security.tokens import InternalTokens
from .server import ToolServices, build_mcp_server


def main() -> None:
    settings = Settings.from_env()
    secrets = build_secret_provider(settings)
    db = open_database(settings, secrets)
    audit = open_audit(settings, secrets, "mcp-tool-service", db)
    customers, cases, retriever = build_tool_backends(settings, secrets, db, audit)
    services = ToolServices(customers=customers, cases=cases, retriever=retriever,
                            tokens=InternalTokens(secrets), audit=audit)
    server = build_mcp_server(services)
    app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=True, json_response=True)
    uvicorn.run(app, host=os.getenv("MCP_HOST", "127.0.0.1"), port=int(os.getenv("MCP_PORT", "8765")))


if __name__ == "__main__":
    main()
