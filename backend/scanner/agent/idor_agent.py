"""
Core IDOR Testing Agent — OpenAI function-calling + Playwright MCP.

Architecture:
  OpenAI (gpt-4o) ←→ Agent loop ←→ Playwright MCP server (headed browser)

Flow:
  1. Start Playwright MCP server (headed by default)
  2. Agent uses OpenAI tool_calls to drive the browser via MCP
  3. Login as User A & User B through the real browser
  4. Collect resource IDs from each user's endpoints
  5. LLM generates comprehensive IDOR test plan
  6. Execute tests: User B tries to access User A's resources
  7. LLM analyzes responses for authorization bypass
  8. Generate report with findings + remediation
"""

import asyncio
import json
import re
import base64
import hashlib
import traceback
from urllib.parse import quote

from openai import OpenAI
from django.conf import settings
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from ..models import Scan, Finding, ScanLog
from .browser import PlaywrightMCPBrowser
from .prompts import (
    SYSTEM_PROMPT,
    PLAN_TESTS_PROMPT,
    ANALYZE_RESPONSE_PROMPT,
    SUMMARIZE_SCAN_PROMPT,
)

# Maximum iterations for the agentic tool-call loop (prevents runaway)
MAX_AGENT_STEPS = 50


class IDORAgent:
    """Orchestrates IDOR vulnerability testing using OpenAI + Playwright MCP."""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.scan: Scan = None
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self.model = settings.OPENAI_MODEL
        self.browser: PlaywrightMCPBrowser = None
        self.channel_layer = get_channel_layer()
        self.total_tests = 0
        self.vulnerabilities = 0

    # ── Logging ──────────────────────────────────────────────────────

    def _log(self, level: str, message: str, details: dict = None):
        log = ScanLog.objects.create(
            scan_id=self.scan_id,
            level=level,
            message=message,
            details=details,
        )
        if self.channel_layer:
            try:
                async_to_sync(self.channel_layer.group_send)(
                    f"scan_{self.scan_id}",
                    {
                        "type": "scan_log",
                        "data": {
                            "level": level,
                            "message": message,
                            "details": details,
                            "created_at": str(log.created_at),
                        },
                    },
                )
            except Exception:
                pass

    def log_info(self, msg, details=None):
        self._log("info", msg, details)

    def log_warning(self, msg, details=None):
        self._log("warning", msg, details)

    def log_error(self, msg, details=None):
        self._log("error", msg, details)

    def log_success(self, msg, details=None):
        self._log("success", msg, details)

    def log_debug(self, msg, details=None):
        self._log("debug", msg, details)

    # ── OpenAI + MCP Agentic Loop ────────────────────────────────────

    async def _run_agent_loop(self, task_prompt: str, extra_system: str = "") -> str:
        """
        Send a prompt to OpenAI with the Playwright MCP tools available.
        The LLM can call browser tools iteratively until it returns a text
        response (no more tool_calls).

        Returns the final assistant text content.
        """
        openai_tools = self.browser.get_openai_tools()
        system = SYSTEM_PROMPT
        if extra_system:
            system += "\n\n" + extra_system

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": task_prompt},
        ]

        for step in range(MAX_AGENT_STEPS):
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=openai_tools if openai_tools else None,
                temperature=0.2,
                max_tokens=4096,
            )
            choice = response.choices[0]
            msg = choice.message

            # If no tool calls, we're done
            if not msg.tool_calls:
                return msg.content or ""

            # Append the assistant message with tool_calls
            messages.append(msg.model_dump())

            # Execute each tool call via MCP
            for tc in msg.tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    fn_args = {}

                self.log_debug(f"MCP tool: {fn_name}({json.dumps(fn_args)[:200]})")

                result = await self.browser.call_tool(fn_name, fn_args)

                # Flatten content into a string for OpenAI
                result_text = "\n".join(
                    item.get("text", str(item)) for item in result.get("content", [])
                )
                if result.get("isError"):
                    result_text = f"[ERROR] {result_text}"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text[:8000],  # Truncate for context window
                })

        return "[Agent reached maximum steps without completing]"

    # ── Simple LLM Call (no tools) ───────────────────────────────────

    def _ask_llm(self, user_prompt: str, temperature: float = 0.2) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=4096,
        )
        return response.choices[0].message.content.strip()

    def _parse_json_response(self, text: str):
        text = re.sub(r"```json\s*", "", text)
        text = re.sub(r"```\s*", "", text)
        text = text.strip()
        return json.loads(text)

    # ── ID Manipulation Utilities ────────────────────────────────────

    @staticmethod
    def _generate_id_variants(original_id: str) -> list[dict]:
        variants = []
        try:
            num_id = int(original_id)
            variants.extend([
                {"id": str(num_id + 1), "technique": "sequential_increment"},
                {"id": str(num_id - 1), "technique": "sequential_decrement"},
                {"id": str(num_id + 100), "technique": "large_offset"},
                {"id": "0", "technique": "zero_id"},
                {"id": "-1", "technique": "negative_id"},
                {"id": str(num_id * 2), "technique": "doubled_id"},
            ])
        except ValueError:
            pass

        variants.append({"id": base64.b64encode(original_id.encode()).decode(), "technique": "base64_encoded"})
        try:
            decoded = base64.b64decode(original_id).decode()
            variants.append({"id": decoded, "technique": "base64_decoded"})
        except Exception:
            pass

        variants.append({"id": original_id.encode().hex(), "technique": "hex_encoded"})
        variants.append({"id": quote(original_id, safe=""), "technique": "url_encoded"})
        variants.extend([
            {"id": "null", "technique": "null_value"},
            {"id": "undefined", "technique": "undefined_value"},
            {"id": "true", "technique": "boolean_true"},
            {"id": "[]", "technique": "empty_array"},
            {"id": "*", "technique": "wildcard"},
            {"id": "all", "technique": "keyword_all"},
            {"id": "admin", "technique": "keyword_admin"},
            {"id": "../" + original_id, "technique": "path_traversal"},
            {"id": f"[{original_id}]", "technique": "array_wrapped"},
        ])
        for val in ["1", "admin", "test"]:
            variants.append({"id": hashlib.md5(val.encode()).hexdigest(), "technique": f"md5_hash_{val}"})
        return variants

    # ── Browser Login via Agent Loop ─────────────────────────────────

    async def _login_user(self, label: str, credentials: dict, base_url: str) -> str:
        """
        Use the OpenAI agent loop to perform a real browser login.
        The LLM autonomously navigates, fills forms, and clicks buttons
        via Playwright MCP tools.
        """
        auth_type = credentials.get("auth_type", "form")

        if auth_type == "bearer":
            # For bearer auth, inject the header via console
            token = credentials["bearer_token"]
            await self.browser.console_exec(
                f"window._authToken = '{token}'; "
                f"window._origFetch = window.fetch; "
                f"window.fetch = (url, opts = {{}}) => {{ "
                f"  opts.headers = {{...(opts.headers || {{}}), 'Authorization': 'Bearer {token}'}}; "
                f"  return window._origFetch(url, opts); "
                f"}};"
            )
            return f"Bearer token injected for {label}"

        if auth_type == "custom":
            headers = credentials.get("custom_headers", {})
            header_js = json.dumps(headers)
            await self.browser.console_exec(
                f"window._customHeaders = {header_js}; "
                f"window._origFetch = window._origFetch || window.fetch; "
                f"window.fetch = (url, opts = {{}}) => {{ "
                f"  opts.headers = {{...(opts.headers || {{}}), ...window._customHeaders}}; "
                f"  return window._origFetch(url, opts); "
                f"}};"
            )
            return f"Custom headers injected for {label}"

        # Form-based login — let the agent drive the browser
        login_url = credentials.get("login_url", "/login")
        if not login_url.startswith("http"):
            from urllib.parse import urljoin
            login_url = urljoin(base_url, login_url)

        prompt = f"""You are logging in to a web application as {label}.

Target login URL: {login_url}
Username: {credentials['username']}
Password: {credentials['password']}
Username field selector/name: {credentials.get('username_field', 'username')}
Password field selector/name: {credentials.get('password_field', 'password')}
Submit button selector: {credentials.get('submit_selector', 'auto-detect')}

Steps:
1. Navigate to the login URL using browser_navigate
2. Take a snapshot to see the page structure
3. Fill in the username field using browser_type
4. Fill in the password field using browser_type
5. Click the submit/login button using browser_click
6. Wait briefly, then take another snapshot to confirm login succeeded
7. Report whether login was successful

Use the element references from the snapshot to interact with elements.
If a field name like "username" is given (not a CSS selector), look for it
in the snapshot's form elements.

IMPORTANT: After each action, take a snapshot to see the updated page state.
"""
        result = await self._run_agent_loop(prompt)
        return result

    # ── Resource Collection via Agent ────────────────────────────────

    async def _collect_resources_via_agent(
        self, base_url: str, endpoints: list, label: str,
    ) -> dict:
        """
        Ask the agent to visit each endpoint and extract resource IDs.
        """
        endpoints_json = json.dumps(endpoints, indent=2)
        prompt = f"""You are collecting resource IDs for {label} from the following endpoints.
The browser is already logged in as {label}.

Base URL: {base_url}
Endpoints:
{endpoints_json}

For each endpoint:
1. Navigate to the full URL (base_url + endpoint path)
2. Take a snapshot of the page
3. Look for resource IDs in the page content — these could be:
   - Numeric IDs in links, data attributes, table rows
   - UUIDs in URLs or content
   - IDs in JSON responses (if the page shows raw JSON)
   - Any identifiers that reference specific resources

After visiting ALL endpoints, return your findings as JSON:
{{
    "/endpoint/path": {{
        "ids": ["id1", "id2", ...],
        "status": 200,
        "sample_response": "first 500 chars of page content"
    }},
    ...
}}

Return ONLY the JSON object. No markdown fences, no explanation.
"""
        result = await self._run_agent_loop(prompt)

        try:
            resources = self._parse_json_response(result)
        except (json.JSONDecodeError, ValueError):
            self.log_warning(f"Could not parse resource collection for {label}, using fallback")
            resources = {}
            # Fallback: navigate and snapshot each endpoint directly
            for ep in endpoints:
                path = ep["path"]
                full_url = base_url.rstrip("/") + path
                nav_result = await self.browser.navigate(full_url)
                snap_result = await self.browser.snapshot()
                snap_text = "\n".join(
                    item.get("text", "") for item in snap_result.get("content", [])
                )
                ids = self._extract_ids_from_text(snap_text, path)
                if ep.get("sample_id") and ep["sample_id"] not in ids:
                    ids.insert(0, str(ep["sample_id"]))
                resources[path] = {
                    "ids": ids[:20],
                    "status": 200,
                    "sample_response": snap_text[:2000],
                }

        return resources

    @staticmethod
    def _extract_ids_from_text(text: str, path: str) -> list[str]:
        ids = set()
        for match in re.findall(r'/(\d+)(?:/|$|\?)', text):
            ids.add(match)
        for match in re.findall(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            text, re.IGNORECASE,
        ):
            ids.add(match)
        for match in re.findall(r'data-id=["\']([^"\']+)["\']', text):
            ids.add(match)
        for match in re.findall(r'href=["\'][^"\']*?/(\d+)["\']', text):
            ids.add(match)
        # Also try to find "id": <value> patterns in text
        for match in re.findall(r'"id"\s*:\s*"?(\w+)"?', text):
            ids.add(match)
        return list(ids)

    # ── IDOR Test Execution via Agent ────────────────────────────────

    async def _execute_idor_test(
        self, base_url: str, test_case: dict, baseline_snapshot: str,
    ) -> Finding:
        """Execute a single IDOR test using the agent-driven browser."""
        endpoint = test_case.get("endpoint", "")
        method = test_case.get("method", "GET")
        body = test_case.get("request_body")
        headers = test_case.get("custom_headers")

        self.log_info(f"Testing: {method} {endpoint} — {test_case.get('description', '')}")

        full_url = base_url.rstrip("/") + endpoint if not endpoint.startswith("http") else endpoint

        # Execute the request via browser
        if method == "GET":
            await self.browser.navigate(full_url)
            snap_result = await self.browser.snapshot()
        else:
            # For non-GET, use fetch via console_exec
            headers_json = json.dumps(headers or {})
            body_json = json.dumps(body) if body else "null"
            fetch_js = f"""
            (async () => {{
                const opts = {{
                    method: "{method}",
                    credentials: "include",
                    headers: {{ "Content-Type": "application/json", ...{headers_json} }},
                }};
                if ({body_json} !== null) opts.body = JSON.stringify({body_json});
                try {{
                    const r = await fetch("{full_url}", opts);
                    const text = await r.text();
                    return JSON.stringify({{ status: r.status, body: text.substring(0, 5000), url: r.url }});
                }} catch(e) {{
                    return JSON.stringify({{ status: 0, body: e.message, url: "{full_url}" }});
                }}
            }})()
            """
            snap_result = await self.browser.console_exec(fetch_js)

        attack_text = "\n".join(
            item.get("text", str(item)) for item in snap_result.get("content", [])
        )

        self.total_tests += 1

        # Ask LLM to analyze
        analysis_prompt = ANALYZE_RESPONSE_PROMPT.format(
            test_description=test_case.get("description", ""),
            attack_type=test_case.get("attack_type", "horizontal"),
            endpoint=endpoint,
            method=method,
            baseline_status="200 (from snapshot)",
            baseline_body=baseline_snapshot[:3000],
            attack_status="see response below",
            attack_body=attack_text[:3000],
        )

        try:
            analysis_text = self._ask_llm(analysis_prompt)
            analysis = self._parse_json_response(analysis_text)
        except Exception as e:
            self.log_warning(f"LLM analysis failed: {e}")
            analysis = self._fallback_analysis(attack_text, baseline_snapshot)

        is_vulnerable = analysis.get("is_vulnerable", False)
        if is_vulnerable:
            self.vulnerabilities += 1
            self.log_success(
                f"VULNERABILITY FOUND: {method} {endpoint} — {analysis.get('severity', 'unknown')}"
            )
        else:
            self.log_debug(f"No vulnerability: {method} {endpoint}")

        attack_type = test_case.get("attack_type", "horizontal")
        idor_type_map = {
            "horizontal": Finding.IDORType.HORIZONTAL,
            "vertical": Finding.IDORType.VERTICAL,
            "data_leak": Finding.IDORType.DATA_LEAK,
        }
        if method in ("PUT", "PATCH"):
            idor_type = Finding.IDORType.UNAUTHORIZED_MODIFY
        elif method == "DELETE":
            idor_type = Finding.IDORType.UNAUTHORIZED_DELETE
        else:
            idor_type = idor_type_map.get(attack_type, Finding.IDORType.HORIZONTAL)

        finding = Finding.objects.create(
            scan_id=self.scan_id,
            endpoint=endpoint,
            method=method,
            severity=analysis.get("severity", "info"),
            idor_type=idor_type,
            description=analysis.get("explanation", ""),
            evidence={
                "request": {"url": endpoint, "method": method, "body": body, "headers": headers},
                "attack_response": attack_text[:1000],
                "baseline_snapshot": baseline_snapshot[:1000],
            },
            remediation=analysis.get("remediation", ""),
            original_id=test_case.get("original_id", ""),
            tested_id=test_case.get("tested_id", ""),
            id_location=test_case.get("id_location", "path"),
            is_vulnerable=is_vulnerable,
            ai_analysis=json.dumps(analysis, indent=2),
        )
        return finding

    @staticmethod
    def _fallback_analysis(attack_text: str, baseline_text: str) -> dict:
        """Heuristic when LLM is unavailable."""
        if "401" in attack_text or "403" in attack_text or "Unauthorized" in attack_text:
            return {
                "is_vulnerable": False, "severity": "info", "confidence": "high",
                "explanation": "Server returned authorization error — endpoint appears protected.",
                "data_exposed": "None", "remediation": "N/A",
            }

        # Check similarity
        b_words = set(baseline_text.split())
        a_words = set(attack_text.split())
        if b_words and a_words:
            overlap = len(b_words & a_words) / max(len(b_words), 1)
            if overlap > 0.7:
                return {
                    "is_vulnerable": True, "severity": "high", "confidence": "medium",
                    "explanation": f"Attack response is {overlap:.0%} similar to baseline. Likely IDOR.",
                    "data_exposed": "Response matches authorised user's data",
                    "remediation": "Implement proper authorization checks.",
                }

        return {
            "is_vulnerable": False, "severity": "info", "confidence": "low",
            "explanation": "Could not conclusively determine vulnerability.",
            "data_exposed": "Unknown", "remediation": "Manual review recommended.",
        }

    # ── Main Run ─────────────────────────────────────────────────────

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_async())
        except Exception as e:
            self.log_error(f"Scan failed: {str(e)}", {"traceback": traceback.format_exc()})
            Scan.objects.filter(id=self.scan_id).update(status=Scan.Status.FAILED)
        finally:
            loop.close()

    async def _run_async(self):
        self.scan = Scan.objects.get(id=self.scan_id)
        if self.scan.status == Scan.Status.CANCELLED:
            return

        self.log_info("=" * 60)
        self.log_info(f"Starting IDOR Scan: {self.scan.name}")
        self.log_info(f"Target: {self.scan.target_url}")
        self.log_info("=" * 60)

        base_url = self.scan.target_url.rstrip("/")

        # ── Step 1: Start Playwright MCP server (headed) ─────────────
        self.log_info("Starting Playwright MCP server (headed mode)...")
        self.browser = PlaywrightMCPBrowser()
        available_tools = await self.browser.start()
        self.log_success(f"Playwright MCP ready — {len(available_tools)} tools available")
        self.log_debug(f"Tools: {', '.join(available_tools)}")

        try:
            # ── Step 2: Login as User A ──────────────────────────────
            self.log_info("Logging in as User A...")
            login_a_result = await self._login_user("User A", self.scan.user_a_credentials, base_url)
            self.log_success(f"User A login: {login_a_result[:200]}")

            # Capture User A's cookies/state
            cookies_a = await self.browser.get_cookies()
            self.log_debug("User A cookies captured")

            # ── Step 3: Collect User A's resources ───────────────────
            self.log_info("Collecting User A's resources...")
            user_a_resources = await self._collect_resources_via_agent(
                base_url, self.scan.endpoints, "User A",
            )
            self.log_info(
                f"User A resources collected from {len(user_a_resources)} endpoints",
                {k: v.get("ids", [])[:5] for k, v in user_a_resources.items()},
            )

            # Capture baseline snapshots for each endpoint (User A's view)
            baselines = {}
            for ep in self.scan.endpoints:
                path = ep["path"]
                full_url = base_url + path
                await self.browser.navigate(full_url)
                snap = await self.browser.snapshot()
                baselines[path] = "\n".join(
                    item.get("text", "") for item in snap.get("content", [])
                )

            # ── Step 4: Switch to User B ─────────────────────────────
            # Open a new tab for User B to get a fresh session
            self.log_info("Opening new tab for User B...")
            await self.browser.new_tab()

            self.log_info("Logging in as User B...")
            login_b_result = await self._login_user("User B", self.scan.user_b_credentials, base_url)
            self.log_success(f"User B login: {login_b_result[:200]}")

            # ── Step 5: Collect User B's resources ───────────────────
            self.log_info("Collecting User B's resources...")
            user_b_resources = await self._collect_resources_via_agent(
                base_url, self.scan.endpoints, "User B",
            )
            self.log_info(
                f"User B resources collected from {len(user_b_resources)} endpoints",
                {k: v.get("ids", [])[:5] for k, v in user_b_resources.items()},
            )

            # Check cancellation
            self.scan.refresh_from_db()
            if self.scan.status == Scan.Status.CANCELLED:
                self.log_warning("Scan cancelled by user.")
                return

            # ── Step 6: Generate test plan via LLM ───────────────────
            self.log_info("Generating IDOR test plan via LLM...")
            plan_prompt = PLAN_TESTS_PROMPT.format(
                target_url=base_url,
                endpoints=json.dumps(self.scan.endpoints, indent=2),
                user_a_resources=json.dumps(user_a_resources, indent=2, default=str),
                user_b_resources=json.dumps(user_b_resources, indent=2, default=str),
            )

            test_plan_text = self._ask_llm(plan_prompt, temperature=0.3)
            try:
                test_plan = self._parse_json_response(test_plan_text)
            except json.JSONDecodeError:
                self.log_warning("LLM returned invalid JSON for test plan. Using fallback.")
                test_plan = self._generate_fallback_plan(
                    base_url, self.scan.endpoints, user_a_resources, user_b_resources,
                )
            self.log_info(f"Generated {len(test_plan)} test cases")

            # ── Step 7: Add edge-case tests ──────────────────────────
            edge_tests = self._generate_edge_case_tests(
                base_url, self.scan.endpoints, user_a_resources, user_b_resources,
            )
            test_plan.extend(edge_tests)
            self.log_info(f"Added {len(edge_tests)} edge-case tests. Total: {len(test_plan)}")

            # ── Step 8: Execute all tests (as User B in the browser) ─
            self.log_info("=" * 60)
            self.log_info("EXECUTING IDOR TESTS")
            self.log_info("=" * 60)

            findings = []
            for i, tc in enumerate(test_plan):
                if i % 5 == 0:
                    self.scan.refresh_from_db()
                    if self.scan.status == Scan.Status.CANCELLED:
                        self.log_warning("Scan cancelled.")
                        break

                self.log_info(f"Test {i + 1}/{len(test_plan)}")
                ep_path = tc.get("endpoint", "")
                # Find matching baseline
                baseline_key = None
                for key in baselines:
                    if key in ep_path or ep_path.startswith(key.split("{")[0]):
                        baseline_key = key
                        break
                baseline_snap = baselines.get(baseline_key or "", "No baseline available")

                finding = await self._execute_idor_test(base_url, tc, baseline_snap)
                findings.append(finding)

            # ── Step 9: Test with no auth ────────────────────────────
            self.log_info("Testing endpoints with NO authentication...")
            # Open new tab for unauthenticated context
            await self.browser.new_tab()
            # Clear cookies by navigating to about:blank first
            await self.browser.navigate("about:blank")
            await self.browser.console_exec(
                "document.cookie.split(';').forEach(c => { "
                "document.cookie = c.trim().split('=')[0] + '=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/'; });"
            )

            for ep in self.scan.endpoints:
                path = ep["path"]
                method = ep.get("method", "GET")
                full_url = base_url + path

                await self.browser.navigate(full_url)
                snap = await self.browser.snapshot()
                snap_text = "\n".join(item.get("text", "") for item in snap.get("content", []))

                # If we get meaningful content (not a redirect to login), flag it
                if "login" not in snap_text.lower()[:500] and "sign in" not in snap_text.lower()[:500]:
                    self.log_warning(f"Endpoint may be accessible without auth: {method} {path}")
                    tc = {
                        "endpoint": path, "method": method,
                        "description": f"Accessing {path} without any authentication",
                        "attack_type": "vertical",
                        "original_id": "", "tested_id": "", "id_location": "path",
                    }
                    baseline_snap = baselines.get(path, "No baseline")
                    finding = await self._execute_idor_test(base_url, tc, baseline_snap)
                    findings.append(finding)

            # ── Step 10: Generate summary ────────────────────────────
            vuln_findings = [f for f in findings if f.is_vulnerable]

            if vuln_findings:
                self.log_info("Generating scan summary...")
                findings_data = [
                    {
                        "endpoint": f.endpoint, "method": f.method,
                        "severity": f.severity, "type": f.idor_type,
                        "description": f.description,
                    }
                    for f in vuln_findings
                ]
                try:
                    summary_text = self._ask_llm(SUMMARIZE_SCAN_PROMPT.format(
                        target_url=base_url,
                        total_tests=self.total_tests,
                        vuln_count=len(vuln_findings),
                        findings_json=json.dumps(findings_data, indent=2),
                    ))
                    summary = self._parse_json_response(summary_text)
                    self.log_success(f"Summary: {summary.get('executive_summary', '')}")
                except Exception:
                    pass

            # ── Step 11: Finalise ────────────────────────────────────
            self.scan.total_tests = self.total_tests
            self.scan.vulnerabilities_found = self.vulnerabilities
            self.scan.status = Scan.Status.COMPLETED
            self.scan.save()

            self.log_info("=" * 60)
            self.log_success(
                f"Scan completed. {self.total_tests} tests run, "
                f"{self.vulnerabilities} vulnerabilities found."
            )
            self.log_info("=" * 60)

        finally:
            await self.browser.stop()

    # ── Fallback & Edge-Case Test Generation ─────────────────────────

    def _generate_fallback_plan(self, base_url, endpoints, user_a_res, user_b_res):
        tests = []
        for ep in endpoints:
            path = ep["path"]
            method = ep.get("method", "GET")
            a_ids = user_a_res.get(path, {}).get("ids", [])

            for aid in a_ids[:5]:
                test_path = self._substitute_id_in_path(path, aid)
                tests.append({
                    "endpoint": test_path, "method": method,
                    "description": f"User B accessing User A's resource (ID: {aid})",
                    "attack_type": "horizontal",
                    "original_id": aid, "tested_id": aid,
                    "id_location": ep.get("id_location", "path"),
                })
                for alt in ["GET", "PUT", "DELETE", "PATCH"]:
                    if alt != method:
                        tests.append({
                            "endpoint": test_path, "method": alt,
                            "description": f"Method switch: {alt} on User A's resource (ID: {aid})",
                            "attack_type": "horizontal",
                            "original_id": aid, "tested_id": aid,
                            "id_location": ep.get("id_location", "path"),
                        })
        return tests

    def _generate_edge_case_tests(self, base_url, endpoints, user_a_res, user_b_res):
        tests = []
        for ep in endpoints:
            path = ep["path"]
            method = ep.get("method", "GET")
            a_ids = user_a_res.get(path, {}).get("ids", [])

            for aid in a_ids[:3]:
                for variant in self._generate_id_variants(aid)[:8]:
                    test_path = self._substitute_id_in_path(path, variant["id"])
                    tests.append({
                        "endpoint": test_path, "method": method,
                        "description": f"Edge case ({variant['technique']}): {test_path}",
                        "attack_type": "horizontal",
                        "id_manipulation": variant["technique"],
                        "original_id": aid, "tested_id": variant["id"],
                        "id_location": ep.get("id_location", "path"),
                    })

            if "?" in path or ep.get("id_location") == "query":
                id_param = ep.get("id_param", "id")
                for aid in a_ids[:2]:
                    sep = "&" if "?" in path else "?"
                    tests.append({
                        "endpoint": f"{path}{sep}{id_param}={aid}",
                        "method": method,
                        "description": f"Parameter pollution with duplicate {id_param}",
                        "attack_type": "horizontal",
                        "original_id": aid, "tested_id": aid, "id_location": "query",
                    })

            if method in ("POST", "PUT", "PATCH"):
                for aid in a_ids[:2]:
                    tests.append({
                        "endpoint": path, "method": method,
                        "description": f"JSON body ID injection (ID: {aid})",
                        "attack_type": "horizontal",
                        "request_body": {ep.get("id_param", "id"): aid, "user_id": aid},
                        "original_id": aid, "tested_id": aid, "id_location": "body",
                    })

            for aid in a_ids[:1]:
                test_path = self._substitute_id_in_path(path, aid)
                for ct in ["application/xml", "text/plain", "application/x-www-form-urlencoded"]:
                    tests.append({
                        "endpoint": test_path, "method": method,
                        "description": f"Content-Type manipulation: {ct}",
                        "attack_type": "horizontal",
                        "custom_headers": {"Content-Type": ct},
                        "original_id": aid, "tested_id": aid, "id_location": "path",
                    })
        return tests

    @staticmethod
    def _substitute_id_in_path(path: str, new_id: str) -> str:
        result = re.sub(r'\{[^}]*id[^}]*\}', new_id, path, flags=re.IGNORECASE)
        result = re.sub(r':(\w*id\w*)', new_id, result, flags=re.IGNORECASE)
        result = re.sub(r'<[^>]*id[^>]*>', new_id, result, flags=re.IGNORECASE)
        if result == path:
            result = re.sub(r'/(\d+)(?=/|$)', f'/{new_id}', result)
        if result == path:
            result = re.sub(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                new_id, result, flags=re.IGNORECASE,
            )
        return result
