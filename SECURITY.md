# Security Policy & Trust Model

## 1. Supported Defensive Scopes & Trust Boundary

The `security-audit` plugin is strictly designed for defensive security assurance of software artifacts. It operates exclusively within authorized repository boundaries:

### 1.1 Supported Target Scopes
- `OWNED_REPOSITORY`: Repositories authored, owned, and maintained by the user or organization.
- `CONTROLLED_REPOSITORY`: Infrastructure, internal services, and pipelines under direct administrative control.
- `AUTHORIZED_INTERNAL_REPOSITORY`: Workspaces explicitly authorized for security review and assurance.
- `LOCAL_TEST_FIXTURE`: Benign unit tests, integration test suites, and controlled evaluation fixtures.
- `LOCAL_ADVERSARIAL_FIXTURE`: Hardened regression test cases (e.g. `evals/`) executed locally to verify scanner resilience against hostile inputs (e.g. malformed git configs, prompt injection, report breakouts).

### 1.2 Explicitly Unsupported & Prohibited Scopes
- **No Third-Party Probing**: Auditing third-party websites, external APIs, or unauthorized repositories is strictly prohibited.
- **No Bug-Bounty Targets**: The plugin is not designed or authorized for external bug-bounty target hunting or remote penetration testing.
- **No Harmful Exploitation**: Execution never attempts live exploitation, credential stuffing, denial-of-service, data exfiltration, or persistence.

### 1.3 Authorized Defensive Use Only & Safe Proof Policy
- **Authorized Scope**: `security-audit` is designed strictly for defensive security assurance of repositories owned, controlled, or explicitly authorized by the user or organization.
- **Non-Destructive Guarantee**: The plugin never conducts live remote penetration testing, third-party network egress probing, credential stuffing, data exfiltration, persistence, or destructive commands.
- **Safe Proof Standards**: Vulnerability verification prioritizes static taint traces, local unit-test fixtures, and benign proof-of-concept indicators. Live harmful exploitation is explicitly prohibited and never required to establish a reportable code vulnerability.

---

## 2. Hardening & Guardrails (v1.0.0 / Production)

### 2.1 Presumption of Non-Pass (Default-Deny on Authority Claims)
- Under Default-Deny, all authority claims (candidate findings, remediation patches, and coverage claims) begin in an unverified state.
- Audited components are not presumed vulnerable; a completed review may legitimately produce zero candidates.
- Candidates cannot self-assert `CONFIRMED` or `REPORTABLE` status.
- Zero votes, lack of verifier quorum (< 2 independent votes), or missing consensus automatically forces candidates into `DEFERRED` (NEEDS_MANUAL_REVIEW).
- If coverage is `PARTIAL` or `UNCHECKABLE`, the audit engine is mathematically barred from certifying the repository as clean ("no vulnerabilities found").
- A clean audit result represents bounded assurance that declared coverage was reconciled completely with zero reportable findings, not a universal certification of flawless code.

### 2.2 Git Provenance Hardening
- Target repository `.git/config` settings such as `diff.external`, `core.fsmonitor`, textconv, or hooks can execute arbitrary binaries.
- All Git operations are executed through `safe-git.mjs` with hardened environment variables (`GIT_CONFIG_GLOBAL=NUL`, `GIT_CONFIG_SYSTEM=NUL`, `PAGER=cat`, `GIT_TERMINAL_PROMPT=0`) and safe flags (`-c core.fsmonitor=false`, `--no-ext-diff`, `--no-textconv`).
- No shell string interpolation is permitted.

### 2.3 Pre-Context Secret Protection & Anti-Leakage
- **Mandated Shadow Context Pipeline**: Review contexts are prepared by `prepare-review-context.mjs` into a dedicated sanitized shadow directory (`scratch/context/`). All agent file inspections, sink searches, and code snippets are mandated by orchestrator protocol to read exclusively from this prepared context. When runtime filesystem sandboxing telemetry is available, context isolation is attested as `OBSERVED`, otherwise truthfully attested as `MANDATED`.
- **Pre-Context Tokenization**: Raw plaintext secrets (AWS access keys, GitHub tokens, Bearer tokens, private keys, passwords, JWTs) are detected and tokenized locally before source code text is supplied to LLM inspection contexts (`tokenizeSecretsForContext`).
- **Structure-Preserving Placeholders**: Secrets are replaced with structured identifiers (`<SECRET:class=...:hash=...>`) that preserve exact line numbers, line counts, and syntactic layout so dataflow continuity is maintained without exposing real secrets to model contexts.
- **No Secret Map Leakage**: The secret resolution map is held strictly in ephemeral memory and is never serialized into agent-accessible files or review context artifacts.
- **No Detokenization in Model/Report Path**: `detokenizeSecrets()` is strictly excluded from all model prompts, agent transcripts, SARIF outputs, and Markdown reports.
- **Deterministic Finalizer Masking**: Reports and SARIF files emitted by `finalize-scan.mjs` redact any residual or tokenized secrets, suppressing line snippets for credential leaks (`CWE-798`) and outputting only safe fingerprints and location metadata.

### 2.4 Markdown & Output Injection Defenses
- Untrusted repository text (file names, code comments, payload strings) can contain ANSI escape sequences, Bidi override Unicode characters, Markdown heading injections (`#`), or code fence breakouts (```` ``` ```).
- Reports are processed through dedicated context-aware encoders (`sanitizeInlineText`, `sanitizeTableCell`, `sanitizeBlockText`, `sanitizeCodeSnippet`) to eliminate presentation-layer breakouts.

### 2.5 Prompt Injection Boundaries
- Code inspected by LLM agents is enclosed in XML data delimiters (`<untrusted_code_data>`).
- While this mitigates simple instruction confusion, prompt boundaries are a policy guidance mechanism rather than a cryptographic guarantee. For hostile repositories, containerized sandboxing is essential.

### 2.6 Strict Path Containment & Sibling Prefix Enclosure (R7-P0-01)
- Context preparation (`prepare-review-context.mjs`), snapshot binding (`finalize-scan.mjs`), and attack path verification (`validate-attack-path.mjs`) enforce strict containment via `isPathContained()`.
- Containment relies on `path.relative()` containment algebra (`relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))`) rather than string-prefix matching (`startsWith`), strictly preventing parent directory traversals (`../outside`) and sibling directory confusion (e.g. `scratch/context` vs `scratch/context-evil`).

### 2.7 Deterministic SAST Ingestion & Funnel Corroboration (R7-P0-02, R7-P1-02)
- **Multi-Tool Corroboration**: The plugin ingests external deterministic SAST reports (Gitleaks -> Semgrep CE -> CodeQL) via `ingestExternalEvidence()`, normalizing cross-platform URI representations (Windows `\`, POSIX `/`, percent-encoded segments, `file://` schemes).
- **Granular Evidence Binding**: External findings are classified into authoritative binding states: `BOUND` (source line and hash verified), `UNBOUND_PATH` (line beyond EOF or syntax issue), `UNBOUND_MISSING_FILE` (target file missing), `GENERATED_DUPLICATE` (findings from generated shadow contexts such as `scratch/context/`), and `OUTSIDE_SCOPE` (paths outside repository root).
- **Filesystem Race (TOCTOU) Analysis**: Static analysis flags like CodeQL `js/file-system-race` regarding sequential `fs.existsSync` and `fs.readFileSync` checks in CLI scripts are tracked as non-blocking evidence-consistency hardening. In single-threaded CLI batch execution, these checks are safe; future iterations will adopt atomic file descriptor reads for concurrent agent sandboxes.

---

## 3. Reporting Vulnerabilities

If you discover a potential security vulnerability within `agy-security-audit`, please **do not** open a public GitHub issue.

Instead, report it responsibly via either of:
- **Private Security Disclosure** (preferred): Submit via [GitHub Security Advisories](https://github.com/arcobaleno64/agy-security-audit/security/advisories/new). It keeps the report, the discussion, and the eventual advisory in one place.
- **Email**: <arcobaleno830623@gmail.com>, for anyone who cannot or would rather not use GitHub. This address is monitored by the maintainer; it is not a team inbox, so expect one person's response times.

### Response Expectations
- **Initial Response**: Within 48 hours.
- **Status Update**: Within 7 business days.
- **Fix & Patch Advisory**: Released in a timely patch release.

### Supported Versions

Only the current MINOR line is supported. Update this table with every MINOR bump.

| Version | Supported |
|---|---|
| 1.0.x | :white_check_mark: |
| < 1.0.0 | :x: |
