SYSTEM_PROMPT = """You are an expert security researcher specializing in IDOR (Insecure Direct Object Reference) vulnerability testing.
You analyze web application endpoints and HTTP responses to identify authorization bypass vulnerabilities.

Your responsibilities:
1. Analyze endpoint structures to identify potential IDOR attack vectors
2. Generate intelligent test cases including ID manipulation strategies
3. Analyze HTTP responses to determine if unauthorized access occurred
4. Provide detailed findings with severity ratings and remediation advice

Always be thorough and consider edge cases like:
- Sequential numeric IDs (increment/decrement)
- UUIDs (substitution between users)
- Base64-encoded IDs (decode, modify, re-encode)
- Hex-encoded IDs
- Hashed IDs (MD5, SHA variants)
- Composite IDs (user_id + resource_id combinations)
- Nested resource references in JSON bodies
- IDs in query parameters, path segments, headers, and cookies
- Bulk/batch endpoints that accept multiple IDs
- GraphQL queries with variable ID injection
- Wildcard and array parameter manipulation
"""

PLAN_TESTS_PROMPT = """Given these endpoints and the authentication context, generate a comprehensive IDOR test plan.

Target URL: {target_url}

Endpoints to test:
{endpoints}

User A resources collected:
{user_a_resources}

User B resources collected:
{user_b_resources}

For each endpoint, generate test cases as a JSON array. Each test case should have:
- endpoint: the full path with any ID substitutions
- method: HTTP method
- description: what this test checks
- attack_type: "horizontal" or "vertical"
- id_manipulation: what ID transformation was applied
- expected_behavior: what should happen if properly secured
- request_body: (optional) JSON body if needed
- custom_headers: (optional) additional headers

Consider these edge cases:
1. Direct ID substitution (use User B's token to access User A's resource)
2. Sequential ID enumeration (try ID+1, ID-1, ID+100)
3. ID encoding tricks (base64 encode/decode, hex, URL encoding)
4. Parameter pollution (duplicate parameters with different IDs)
5. HTTP method switching (GET vs POST vs PUT vs DELETE on same endpoint)
6. Changing content-type headers
7. Removing authorization entirely
8. Using null/empty/zero/negative IDs
9. Array wrapping: id[] = [target_id]
10. JSON body manipulation for POST/PUT requests
11. Path traversal in ID parameters (../../other_user/resource)
12. Wildcard IDs (*, all, 0)
13. Bulk operations with mixed IDs

Return ONLY valid JSON array. No markdown, no explanation.
"""

ANALYZE_RESPONSE_PROMPT = """Analyze this HTTP response to determine if an IDOR vulnerability exists.

Test Description: {test_description}
Attack Type: {attack_type}
Endpoint: {endpoint} ({method})

Request made by User B trying to access User A's resource.

User A's original response (baseline):
Status: {baseline_status}
Body preview: {baseline_body}

User B's attack response:
Status: {attack_status}
Body preview: {attack_body}

Determine:
1. Is this an IDOR vulnerability? (true/false)
2. Severity: critical/high/medium/low/info
3. Confidence: high/medium/low
4. Explanation of why this is or isn't a vulnerability
5. What data was exposed/accessible
6. Remediation recommendation

Consider these indicators:
- 200 OK with User A's data = VULNERABLE
- 200 OK with different/empty data = likely SAFE (server returned user B's data or nothing)
- 403/401 = SAFE (proper authorization check)
- 404 = LIKELY SAFE (but could be information leak if behavior differs)
- 500 = investigate (might indicate broken access control logic)
- Response body similarity to baseline > 80% with sensitive data = VULNERABLE
- Identical error messages for existing vs non-existing resources = INFO (enumeration protection)

Return JSON only:
{{
    "is_vulnerable": boolean,
    "severity": "critical|high|medium|low|info",
    "confidence": "high|medium|low",
    "explanation": "detailed explanation",
    "data_exposed": "what data was leaked",
    "remediation": "how to fix this"
}}
"""

SUMMARIZE_SCAN_PROMPT = """Summarize the IDOR scan results for a security report.

Target: {target_url}
Total tests run: {total_tests}
Vulnerabilities found: {vuln_count}

Findings:
{findings_json}

Provide a professional security assessment summary including:
1. Executive summary (2-3 sentences)
2. Risk rating (Critical/High/Medium/Low)
3. Key findings overview
4. Common patterns observed
5. Priority remediation steps

Format as JSON:
{{
    "executive_summary": "...",
    "risk_rating": "...",
    "key_findings": ["..."],
    "patterns": ["..."],
    "remediation_priority": ["..."]
}}
"""
