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
1. **`auth/authz/tenancy`**: Broken object-level auth (BOLA/IDOR), missing function level auth, tenant boundary cross-contamination, delegated authority confusion and credential forwarding to untrusted endpoints (CWE-441).
2. **`injection/query/template/eval`**: SQL/NoSQL injection, OS command injection, server-side template injection (SSTI), code eval.
3. **`network/SSRF`**: Server-side request forgery, DNS rebinding, internal network egress, webhook tampering, outbound HTTP relay and ambient token forwarding (CWE-441 / CWE-918).
4. **`filesystem/path/archive`**: Path traversal (`../`), zip slip, symlink poisoning, arbitrary file overwrite.
5. **`parser/deserialization`**: Insecure object deserialization, prototype pollution, XML external entity (XXE), YAML unsafe loading.
6. **`secrets/crypto`**: Hardcoded credentials, insecure PRNG, weak hashing (MD5/SHA1 for passwords), CBC padding oracles.
7. **`state/business-logic`**: Race conditions (TOCTOU), integer overflow/underflow, double-spend, idempotency failures.
8. **`dangerous-defaults/config`**: Permissive CORS (`*`), exposed debug flags, insecure TLS options, default credentials.
9. **`native-memory-safety`**: Native C/C++ memory and loader safety, including NULL dereference (CWE-476), classic buffer overflow (CWE-120), out-of-bounds read/write (CWE-125 / CWE-787), uncontrolled DLL/search-path resolution (CWE-427), parser resource exhaustion (CWE-400), and exceptional-condition/state-machine handling failures (CWE-703).
10. **`ai/agent-trust-boundaries`**: Instruction-integrity risk affecting tool invocation, untrusted workspace execution, unauthorized file modifications.

### Native Parser, State Machine & Loader Inspection
When the target profile is `native`, discovery MUST derive its threat model from physical input boundaries rather than Web/OWASP assumptions:

1. **CWE-476 NULL pointer dereference**: inspect unchecked returns from string/search APIs (`strchr`, `strstr`, parser delimiter lookups), allocation failures, optional object lookups, and pointer-producing helper functions before dereference.
2. **CWE-120 / CWE-125 / CWE-787 memory bounds**: trace source buffer length, destination capacity, pointer arithmetic, integer conversions, sliding-window offsets, `memcpy`/`memmove`/string copies, and terminator assumptions end-to-end.
3. **CWE-427 DLL hijacking/search path**: inspect `LoadLibrary*`, plugin/codec loading, CWD-relative module names, PATH-dependent resolution, and whether safe absolute/system search semantics are enforced.
4. **CWE-400 / CWE-703 protocol state handling**: inspect incremental socket-buffer growth, delimiter splits across receives, parser retries, state transitions, exceptional inputs, and bounded progress/resource consumption.

#### Full-Module Context Rule for Protocol Parsers
For custom protocol parsers or state machines (including HTTP, RTSP, FTP, WebSocket, media/container parsers, and equivalent native protocol code), load the **entire parser implementation module** and its directly coupled declarations before drawing conclusions. Do not review these modules as arbitrary 100-150 line windows. The objective is to preserve buffer lifetime, sliding-window offsets, delimiter splits, and state transitions across the complete implementation.

Dangerous-API searches (`CreateProcess`, `LoadLibrary`, `memcpy`, etc.) are discovery aids only. They MUST NOT substitute for end-to-end parser and trust-boundary analysis.

### Outbound Dispatch & Confused Deputy Pattern (CWE-441 / CWE-918)
- **Vulnerable Pattern**: A proxy or relay forwards client requests to arbitrary caller-controlled destinations while attaching ambient credentials (e.g., internal service mesh token, mutual TLS cert, internal bearer tokens) without allowlisting:
  ```javascript
  // VULNERABLE: Confused deputy forwarding internal vault token to caller URL
  router.post('/proxy/forward', async (req, res) => {
    const { targetUrl, payload } = req.body;
    return await fetch(targetUrl, {
      method: 'POST',
      headers: { 'X-Service-Auth': INTERNAL_VAULT_TOKEN },
      body: JSON.stringify(payload)
    });
  });
  ```
- **Secure Pattern**: Enforces strict destination allowlisting (`ALLOWED_HOSTS`), protocol restriction (`https:`), and credential stripping:
  ```javascript
  // SECURE: Destination strictly allowlisted; ambient credentials confined
  const ALLOWED_DESTINATIONS = new Set(['https://api.internal.service.mesh/v1/event']);
  router.post('/proxy/forward', async (req, res) => {
    const { targetUrl, payload } = req.body;
    const url = new URL(targetUrl);
    if (!ALLOWED_DESTINATIONS.has(url.origin + url.pathname)) {
      return res.status(403).json({ error: 'Destination not permitted' });
    }
    return await fetch(targetUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }, // ambient credentials stripped
      body: JSON.stringify(payload)
    });
  });
  ```

### Object Mutation & Prototype Pollution Pattern (CWE-1321)
- **Vulnerable Pattern**: A utility recursively merges or copies properties from untrusted user input without sanitizing prototype keys (`__proto__`, `constructor`, `prototype`), allowing callers to pollute `Object.prototype`:
  ```javascript
  // VULNERABLE: Recursive merge without prototype property validation
  function recursiveMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        recursiveMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  ```
- **Secure Pattern**: Blocks access to prototype keys or uses null-prototype objects / `Map`:
  ```javascript
  // SECURE: Strict key validation blocks prototype pollution vectors
  const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
  function safeRecursiveMerge(target, source) {
    for (const key of Object.keys(source)) {
      if (DANGEROUS_KEYS.has(key)) continue;
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        safeRecursiveMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  ```

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


