"""Original, non-destructive web application security review checklist."""


WEB_TEST_CATALOG = [
    {
        "id": "mapping-and-configuration",
        "title": "Application mapping and configuration",
        "checks": [
            ("application-map", "Map entry points, roles, workflows, and trust boundaries"),
            ("http-methods", "Review supported methods and ensure sensitive routes reject unintended methods"),
            ("security-headers", "Review security headers, content types, caching, and browser policy"),
            ("tls-and-certificates", "Review HTTPS enforcement, certificate validity, and mixed content"),
            ("error-disclosure", "Check error responses for stack traces, secrets, and internal details"),
            ("default-content", "Look for exposed documentation, backups, source maps, and default pages"),
            ("cross-origin-policy", "Review CORS and cross-origin resource policies against intended origins"),
            ("cache-behavior", "Check whether private responses are stored or shared across users"),
        ],
    },
    {
        "id": "identity-and-authentication",
        "title": "Identity and authentication",
        "checks": [
            ("account-lifecycle", "Review registration, invitation, recovery, and account deletion flows"),
            ("credential-policy", "Review password policy, reuse controls, and breached-password handling"),
            ("login-enumeration", "Compare login and recovery responses for account enumeration"),
            ("mfa-coverage", "Check MFA enrollment, enforcement, recovery, and bypass resistance"),
            ("rate-limits", "Review throttling and lockout controls on authentication endpoints"),
            ("federated-login", "Review OAuth/OIDC state, nonce, redirect URI, and account-linking behavior"),
            ("reauthentication", "Confirm sensitive changes require recent authentication where appropriate"),
        ],
    },
    {
        "id": "sessions",
        "title": "Session management",
        "checks": [
            ("cookie-flags", "Review Secure, HttpOnly, SameSite, path, domain, and lifetime attributes"),
            ("session-rotation", "Confirm session identifiers rotate after login and privilege changes"),
            ("logout-invalidation", "Verify logout and account recovery invalidate prior sessions"),
            ("concurrent-sessions", "Review session listing, revocation, and concurrent login behavior"),
            ("csrf-protection", "Check state-changing requests for anti-CSRF protections and origin checks"),
            ("token-storage", "Review browser token storage, expiration, audience, and revocation"),
        ],
    },
    {
        "id": "access-control",
        "title": "Access control and authorization",
        "checks": [
            ("horizontal-access", "Compare access to another test account's objects and records"),
            ("vertical-access", "Verify lower-privileged roles cannot invoke higher-privilege actions"),
            ("object-identifiers", "Check server-side authorization for every object identifier"),
            ("function-level-access", "Review direct access to administrative and hidden functions"),
            ("tenant-isolation", "Check tenant boundaries across reads, writes, exports, and search"),
            ("workflow-authorization", "Recheck authorization at each step of multi-step workflows"),
            ("field-level-access", "Review mass assignment and sensitive fields in API requests/responses"),
        ],
    },
    {
        "id": "input-processing",
        "title": "Input handling and injection resistance",
        "checks": [
            ("input-validation", "Review server-side validation, canonicalization, and type constraints"),
            ("sql-injection", "Review database query construction and verify parameterized query use"),
            ("command-injection", "Review OS command boundaries and avoid shell interpretation of input"),
            ("template-injection", "Review template contexts and ensure untrusted values remain data"),
            ("html-injection-xss", "Review output encoding for HTML, attributes, scripts, and URLs"),
            ("file-paths", "Review path handling, traversal resistance, and storage boundaries"),
            ("file-upload", "Review upload type validation, storage, naming, and download handling"),
            ("deserialization", "Review parsers and ensure untrusted serialized data cannot instantiate objects"),
            ("header-injection", "Review response header values derived from user-controlled input"),
        ],
    },
    {
        "id": "server-side-request-and-parsing",
        "title": "Server-side requests and parser boundaries",
        "checks": [
            ("ssrf", "Review URL-fetching features for destination allowlists and redirect revalidation"),
            ("redirects", "Check redirect parameters against an explicit same-origin or allowlist policy"),
            ("xxe", "Review XML parsers with external entity resolution disabled"),
            ("request-smuggling", "Compare proxy and application parsing rules using approved test tooling"),
            ("host-header", "Review trusted-host configuration and host-derived links or reset URLs"),
            ("dns-rebinding", "Revalidate resolved destinations immediately before outbound connections"),
        ],
    },
    {
        "id": "business-logic",
        "title": "Business logic and workflow integrity",
        "checks": [
            ("workflow-order", "Check whether steps can be skipped, repeated, or completed out of order"),
            ("value-tampering", "Review server-side recalculation of prices, quantities, and entitlements"),
            ("limits-and-quotas", "Check limits for race conditions, resets, and alternate request paths"),
            ("state-transitions", "Verify invalid or unauthorized state transitions are rejected"),
            ("duplicate-actions", "Review replay and idempotency behavior for payments and submissions"),
            ("time-dependencies", "Check expiry, scheduling, and time-zone assumptions in sensitive flows"),
            ("abuse-cases", "Review signup, referral, voting, messaging, and resource-consumption abuse controls"),
        ],
    },
    {
        "id": "client-side",
        "title": "Client-side security",
        "checks": [
            ("dom-xss", "Trace untrusted data into DOM sinks and use safe text-oriented APIs"),
            ("client-secrets", "Review bundles, source maps, and browser storage for credentials or keys"),
            ("postmessage", "Validate message origin, source, and schema in cross-window messaging"),
            ("clickjacking", "Review frame-embedding policy for sensitive authenticated pages"),
            ("client-side-controls", "Confirm UI restrictions are enforced again by the server"),
            ("browser-storage", "Review local/session storage and IndexedDB for sensitive data retention"),
            ("service-workers", "Review service-worker scope, cache contents, and update behavior"),
        ],
    },
    {
        "id": "api-and-data",
        "title": "APIs and data exposure",
        "checks": [
            ("api-authz", "Check authorization on each API operation and object reference"),
            ("api-schema", "Review schema validation, unknown fields, and response field exposure"),
            ("api-pagination", "Check pagination limits, filtering, sorting, and bulk export authorization"),
            ("graphql", "Review GraphQL authorization, depth/complexity limits, and introspection policy"),
            ("websocket", "Review WebSocket authentication, origin checks, and per-message authorization"),
            ("sensitive-data", "Review response bodies and logs for unnecessary personal or secret data"),
            ("secrets-management", "Check credentials, signing keys, and tokens are not exposed or reused"),
        ],
    },
    {
        "id": "deployment-and-components",
        "title": "Deployment, dependencies, and resilience",
        "checks": [
            ("dependency-inventory", "Inventory direct and transitive dependencies and review known advisories"),
            ("debug-surfaces", "Check that debug consoles, test routes, and diagnostics are disabled in production"),
            ("cloud-storage", "Review storage permissions and public exposure of uploaded or backup data"),
            ("secrets-in-repository", "Review repository history and build artifacts for committed credentials"),
            ("resource-exhaustion", "Review request size, concurrency, timeouts, and expensive operations"),
            ("logging-and-audit", "Confirm security events are recorded without storing secrets or full credentials"),
            ("backup-and-recovery", "Review backup access controls, retention, and restore procedures"),
        ],
    },
]


def get_web_test_catalog() -> list[dict]:
    """Return a JSON-safe catalog with normalized check records."""
    return [
        {
            "id": category["id"],
            "title": category["title"],
            "checks": [{"id": check_id, "title": title, "mode": "review"}
                       for check_id, title in category["checks"]],
        }
        for category in WEB_TEST_CATALOG
    ]
