"""
Playwright MCP-based browser manager for IDOR testing.

Uses @playwright/mcp server via the Python MCP SDK.
Browser launches in HEADED mode by default.
"""

import asyncio
import json
import os
import shutil

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from django.conf import settings


def _find_npx() -> str:
    """Locate npx binary, preferring the one on PATH."""
    npx = shutil.which("npx")
    if npx:
        return npx
    # Fallback common locations on Windows
    for candidate in [
        os.path.expandvars(r"%APPDATA%\npm\npx.cmd"),
        os.path.expandvars(r"%ProgramFiles%\nodejs\npx.cmd"),
    ]:
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError(
        "npx not found. Install Node.js (https://nodejs.org) and ensure npx is on PATH."
    )


class PlaywrightMCPBrowser:
    """
    Manages a Playwright MCP server process and exposes its tools.

    The MCP server is started as a subprocess via `npx @playwright/mcp@latest`.
    All browser interaction goes through MCP tool calls.
    """

    def __init__(self, headless: bool = None):
        self.headless = headless if headless is not None else getattr(settings, "BROWSER_HEADLESS", False)
        self._session: ClientSession = None
        self._client_ctx = None      # stdio_client context manager
        self._session_ctx = None     # ClientSession context manager
        self._tools: dict = {}       # name -> tool schema
        self._read = None
        self._write = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self):
        """Launch the Playwright MCP server and initialise the session."""
        npx = _find_npx()

        # `-y` skips npx's interactive "Ok to proceed?" prompt on first run.
        # Without it, npx writes the prompt to stdout, which corrupts the
        # MCP stdio JSON-RPC stream and the server closes the connection.
        args = ["-y", "@playwright/mcp@latest"]
        # @playwright/mcp now runs headed by default; only --headless is a flag.
        if self.headless:
            args.append("--headless")

        server_params = StdioServerParameters(
            command=npx,
            args=args,
            env={**os.environ},
        )

        # stdio_client returns an async context manager yielding (read, write)
        self._client_ctx = stdio_client(server_params)
        self._read, self._write = await self._client_ctx.__aenter__()

        # Open an MCP session over those streams
        self._session_ctx = ClientSession(self._read, self._write)
        self._session = await self._session_ctx.__aenter__()

        # Handshake
        await self._session.initialize()

        # Cache available tools
        tools_result = await self._session.list_tools()
        for tool in tools_result.tools:
            self._tools[tool.name] = tool
        return list(self._tools.keys())

    async def stop(self):
        """Shut down the MCP session and server process."""
        if self._session_ctx:
            try:
                await self._session_ctx.__aexit__(None, None, None)
            except Exception:
                pass
        if self._client_ctx:
            try:
                await self._client_ctx.__aexit__(None, None, None)
            except Exception:
                pass
        self._session = None

    # ── Tool Discovery ───────────────────────────────────────────────

    def get_tools(self) -> list[dict]:
        """Return all MCP tools in a plain-dict format."""
        result = []
        for tool in self._tools.values():
            result.append({
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema if hasattr(tool, "inputSchema") else {},
            })
        return result

    def get_openai_tools(self) -> list[dict]:
        """
        Convert MCP tools into OpenAI function-calling format so the LLM
        agent can decide which browser actions to invoke.
        """
        openai_tools = []
        for tool in self._tools.values():
            schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}
            # Ensure schema is a valid JSON Schema object
            if not isinstance(schema, dict):
                schema = {"type": "object", "properties": {}}
            # OpenAI requires "type": "object" at the top level
            if "type" not in schema:
                schema["type"] = "object"
            if "properties" not in schema:
                schema["properties"] = {}

            openai_tools.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": (tool.description or "")[:1024],
                    "parameters": schema,
                },
            })
        return openai_tools

    # ── Tool Execution ───────────────────────────────────────────────

    async def call_tool(self, name: str, arguments: dict = None) -> dict:
        """
        Call an MCP tool by name with the given arguments.
        Returns {"content": [...], "isError": bool}.
        """
        if not self._session:
            raise RuntimeError("MCP session not started. Call start() first.")

        if name not in self._tools:
            return {
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
                "isError": True,
            }

        result = await self._session.call_tool(name, arguments or {})

        # Normalise result into a simple dict
        content_items = []
        for item in (result.content or []):
            if hasattr(item, "text"):
                content_items.append({"type": "text", "text": item.text})
            elif hasattr(item, "data"):
                content_items.append({"type": "image", "data": item.data[:200] + "..."})
            else:
                content_items.append({"type": "text", "text": str(item)})

        return {
            "content": content_items,
            "isError": getattr(result, "isError", False),
        }

    # ── Convenience Wrappers ─────────────────────────────────────────
    # These provide a simpler API for common operations while still
    # routing through MCP under the hood.

    async def navigate(self, url: str) -> dict:
        return await self.call_tool("browser_navigate", {"url": url})

    async def click(self, element: str, ref: str = None) -> dict:
        args = {"element": element}
        if ref:
            args["ref"] = ref
        return await self.call_tool("browser_click", args)

    async def fill(self, element: str, value: str, ref: str = None) -> dict:
        args = {"element": element, "value": value}
        if ref:
            args["ref"] = ref
        return await self.call_tool("browser_type", args)

    async def snapshot(self) -> dict:
        return await self.call_tool("browser_snapshot", {})

    async def screenshot(self) -> dict:
        return await self.call_tool("browser_take_screenshot", {})

    async def console_exec(self, expression: str) -> dict:
        return await self.call_tool("browser_console_exec", {"expression": expression})

    async def network_request(
        self, url: str, method: str = "GET", body: str = None, headers: str = None,
    ) -> dict:
        """Execute a fetch() call inside the browser via console_exec."""
        fetch_js = f"""
        (async () => {{
            const opts = {{ method: "{method}", credentials: "include" }};
            const headers = {headers or "{}"};
            opts.headers = {{ "Content-Type": "application/json", ...headers }};
            {"opts.body = JSON.stringify(" + json.dumps(body) + ");" if body else ""}
            try {{
                const r = await fetch("{url}", opts);
                const text = await r.text();
                return JSON.stringify({{ status: r.status, body: text.substring(0, 5000), url: r.url }});
            }} catch(e) {{
                return JSON.stringify({{ status: 0, body: e.message, url: "{url}" }});
            }}
        }})()
        """
        return await self.console_exec(fetch_js)

    async def get_cookies(self) -> dict:
        return await self.console_exec("document.cookie")

    async def get_local_storage(self) -> dict:
        return await self.console_exec("JSON.stringify(localStorage)")

    async def new_tab(self) -> dict:
        """Open a new tab (if MCP server supports it)."""
        if "browser_tab_new" in self._tools:
            return await self.call_tool("browser_tab_new", {})
        return {"content": [{"type": "text", "text": "new tab not supported"}], "isError": True}

    async def close_tab(self) -> dict:
        if "browser_tab_close" in self._tools:
            return await self.call_tool("browser_tab_close", {})
        return {"content": [], "isError": False}

    async def select_tab(self, index: int) -> dict:
        if "browser_tab_select" in self._tools:
            return await self.call_tool("browser_tab_select", {"index": index})
        return {"content": [], "isError": False}

    async def list_tabs(self) -> dict:
        if "browser_tab_list" in self._tools:
            return await self.call_tool("browser_tab_list", {})
        return {"content": [], "isError": False}
