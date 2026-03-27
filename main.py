"""
main.py

Application entry point.

Starts the FastAPI server and wires together:
  - Structured logging
  - The /api router (chat endpoint)
  - The FastMCP server (MCP tools, mounted at /mcp)

Run with:
    uvicorn main:app --reload
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.logging import setup_logging, get_logger
from app.api.routes import router as api_router
from app.mcp.tools import mcp

# Initialise logging before anything else
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("MikroTik Agent starting up")
    yield
    logger.info("MikroTik Agent shutting down")


app = FastAPI(
    title="MikroTik AI Agent",
    description=(
        "AI-powered chat interface for managing a MikroTik router via its REST API. "
        "All actions pass through a policy engine before execution."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Mount the chat API
app.include_router(api_router, prefix="/api", tags=["chat"])

# Mount the MCP server (exposes tools for LLM / MCP clients)
# FastMCP provides an ASGI app we can mount directly via sse_app()
app.mount("/mcp", mcp.sse_app())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
