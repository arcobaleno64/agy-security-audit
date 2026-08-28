# Component × Vulnerability Family Discovery Specification

## 1. Core Principles
Aligned with systematic component × vulnerability family matrix discovery, vulnerability discovery must NOT rely on naïve global sink grepping (e.g. `grep "eval"` and hope the model catches everything).
Instead, discovery systematically maps **Identified Components** against **Vulnerability Families**.

---

## 2. Standard Component Classes
1. **API / Routing (`API`)**: HTTP endpoints, RPC routers, GraphQL resolvers, WebSocket handlers.
2. **Authentication & Authorization (`Auth`)**: Identity verification, session tokens, JWTs, OAuth handlers, RBAC/ABAC middleware.
3. **Persistence & Data Storage (`Persistence`)**: SQL databases, NoSQL stores, ORMs, key-value caches, migration scripts.
4. **File & Archive Handling (`FileHandling`)**: File upload/download endpoints, archive unpackers, temp file generators, MIME sniffers.
5. **Background Jobs & Queues (`Jobs`)**: Asynchronous workers, cron tasks, message brokers, queue payload deserializers.
6. **Administrative & Internal Tools (`Admin`)**: Debug endpoints, metrics handlers, internal admin panels, maintenance scripts.
7. **Import / Export Handlers (`ImportExport`)**: CSV/Excel parsers, XML processors, backup restore utilities.
8. **Plugin & Extension Architecture (`PluginSystem`)**: Dynamic module loaders, hook runners, customization registries.
9. **Frontend Trust Boundary (`FrontendBoundary`)**: SSR renderers, template interpolation, CORS handlers, CSP directives.

---

## 3. Standard Vulnerability Families
1. **`auth/authz/tenancy`**: Broken object-level auth (BOLA/IDOR), missing function level auth, tenant boundary cross-contamination.
2. **`injection/query/template/eval`**: SQL/NoSQL injection, OS command injection, server-side template injection (SSTI), code eval.
3. **`network/SSRF`**: Server-side request forgery, DNS rebinding, internal network egress, webhook tampering.
4. **`filesystem/path/archive`**: Path traversal (`../`), zip slip, symlink poisoning, arbitrary file overwrite.
5. **`parser/deserialization`**: Insecure object deserialization, prototype pollution, XML external entity (XXE), YAML unsafe loading.
6. **`secrets/crypto`**: Hardcoded credentials, insecure PRNG, weak hashing (MD5/SHA1 for passwords), CBC padding oracles.
7. **`state/business-logic`**: Race conditions (TOCTOU), integer overflow/underflow, double-spend, idempotency failures.
8. **`dangerous-defaults/config`**: Permissive CORS (`*`), exposed debug flags, insecure TLS options, default credentials.
9. **`native-memory-safety`**: Buffer over-reads, use-after-free, unsafe C/C++ bindings (FFI / N-API).
10. **`ai/agent-trust-boundaries`**: Prompt injection into tool calls, untrusted workspace execution, unauthorized file modifications.

---

## 4. Discovery Execution Matrix & Cell Outcomes
During Stage 2, discovery subagents systematically inspect non-empty intersections across components and vulnerability families:

```text
               Auth   API   Persistence   FileHandling   Jobs   PluginSystem
auth/authz      [X]   [X]       [X]            [ ]        [ ]       [X]
injection       [X]   [X]       [X]            [ ]        [ ]       [X]
filesystem      [ ]   [X]       [ ]            [X]        [X]       [X]
parser          [X]   [X]       [X]            [X]        [X]       [X]
secrets/crypto  [X]   [ ]       [X]            [ ]        [ ]       [ ]
```

### Cell Outcome State Machine
Every matrix intersection must resolve to an explicit machine-readable status:
- **`PENDING`**: Cell awaiting assignment or inspection.
- **`REVIEWED_NO_CANDIDATE`**: Thoroughly inspected; existing mitigations, architectural patterns, or absence of dangerous sinks prevent vulnerability. **This is a successful, legitimate review outcome.**
- **`CANDIDATE`**: Concrete, unverified hypothesis with valid source, sink, and taint path.
- **`NOT_APPLICABLE`**: Component has no relevant code implementing features for this family.
- **`UNRESOLVED`**: Inspected but ambiguous; marked for manual assessment.

### No Finding Quota Rule
> [!IMPORTANT]
> **There is no finding quota.**
> A reviewed cell may legitimately produce zero candidates. Do not formulate a vulnerability hypothesis unless concrete repository evidence supports a plausible violated security property.
> Coverage completeness is judged by whether declared cells were reviewed (`cell reviewed?`), NOT by how many candidates were generated.

### Cell Schema Example
```json
{
  "component": "Auth",
  "family": "auth/authz/tenancy",
  "status": "REVIEWED_NO_CANDIDATE",
  "reviewedEvidence": [
    { "path": "src/auth/authorize.ts", "line": 18 }
  ],
  "notes": "Authorization middleware enforces tenant isolation on all routes."
}
```


