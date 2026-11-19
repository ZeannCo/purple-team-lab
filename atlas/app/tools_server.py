#!/usr/bin/env python3
"""HelpBot's tools, served over MCP (stdio). DELIBERATELY VULNERABLE: this is the target in the
Phase 3 lab. read_file has no path checks and run_diagnostic runs whatever it is given, inside the
container. Never expose this outside the lab.
"""
import subprocess
from pathlib import Path

from mcp.server.mcpserver import MCPServer

KB = Path("/app/kb")
TICKETS = {
    "INC-1042": "VPN drops every 20 minutes for user jdoe. Status: open.",
    "INC-1043": "Printer on floor 3 offline. Status: resolved.",
}

mcp = MCPServer("helpbot-tools")


@mcp.tool()
def search_kb(query: str) -> str:
    """Search the IT knowledge base; returns matching article names and their first lines."""
    hits = []
    for article in sorted(KB.glob("*.md")):
        text = article.read_text()
        if any(word.lower() in text.lower() for word in query.split()):
            hits.append(f"{article.name}: {text.splitlines()[0]}")
    return "\n".join(hits) or "No matching articles."


@mcp.tool()
def read_file(path: str) -> str:
    """Open a knowledge base article, e.g. 'vpn-troubleshooting.md'."""
    target = Path(path) if path.startswith("/") else KB / path  # vulnerable: no traversal checks
    try:
        return target.read_text()[:4000]
    except OSError as exc:
        return f"Cannot read {path}: {exc}"


@mcp.tool()
def run_diagnostic(command: str) -> str:
    """Run a network diagnostic such as 'ping -c 1 intranet' and return its output."""
    try:  # vulnerable: arbitrary shell command, contained only by the container
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=8)
        return (result.stdout + result.stderr)[:3000] or f"(exit {result.returncode}, no output)"
    except subprocess.TimeoutExpired:
        return "Diagnostic timed out."


@mcp.tool()
def lookup_ticket(ticket_id: str) -> str:
    """Look up a helpdesk ticket by ID, e.g. INC-1042."""
    return TICKETS.get(ticket_id.strip().upper(), "Ticket not found.")


if __name__ == "__main__":
    mcp.run()
