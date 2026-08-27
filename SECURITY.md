# Security Policy & Trust Model

## 1. Supported Trust Models

The `security-audit` plugin operates under two explicit trust models:

### 1.1 `trusted-workspace`
- **Target**: Code repositories fully authored or audited by the user/organization.
- **Assumptions**: Local `.git/config`, build configurations, and project instructions contain no adversarial logic intended to exploit local tooling.
- **Allowed Operations**: Static audit, hardened git provenance extraction, and local deterministic report finalization.

### 1.2 `untrusted-workspace`
- **Target**: Third-party code, open-source pull requests, or adversarial bug-bounty samples.
- **Requirement**: Execution must occur under Antigravity terminal sandboxing (`agy --sandbox`).
- **Boundaries**: All tool invocations require strict authorization; dynamic command execution outside isolated containers is prohibited.

---

## 2. Hardening & Guardrails (v1.0.0 / Production)


### 2.1 Presumption of Non-Pass (Default-Deny)
- Under Default-Deny, all candidate findings, coverage records, and patches begin in an unverified state.
- Candidates cannot self-assert `CONFIRMED` or `REPORTABLE` status.
- Zero votes, lack of verifier quorum (< 2 independent votes), or missing consensus automatically forces candidates into `DEFERRED` (NEEDS_MANUAL_REVIEW).
- If coverage is `PARTIAL` or `UNCHECKABLE`, the audit engine is mathematically barred from certifying the repository as clean ("no vulnerabilities found").

### 2.2 Git Provenance Hardening
- Target repository `.git/config` settings such as `diff.external`, `core.fsmonitor`, textconv, or hooks can execute arbitrary binaries.
- All Git operations are executed through `safe-git.mjs` with hardened environment variables (`GIT_CONFIG_GLOBAL=NUL`, `GIT_CONFIG_SYSTEM=NUL`, `PAGER=cat`, `GIT_TERMINAL_PROMPT=0`) and safe flags (`-c core.fsmonitor=false`, `--no-ext-diff`, `--no-textconv`).
- No shell string interpolation is permitted.

### 2.3 Secret Handling & Anti-Leakage
- Plaintext secrets (AWS access keys, Bearer tokens, private keys, passwords, JWTs) are intercepted and masked by the deterministic finalizer (`finalize-scan.mjs`).
- Credential leaks (`CWE-798`, secret tokens) automatically suppress source code line snippets in rendered reports, emitting only redacted fingerprints and location metadata.

### 2.4 Markdown & Output Injection Defenses
- Untrusted repository text (file names, code comments, payload strings) can contain ANSI escape sequences, Bidi override Unicode characters, Markdown heading injections (`#`), or code fence breakouts (```` ``` ```).
- Reports are processed through dedicated context-aware encoders (`sanitizeInlineText`, `sanitizeTableCell`, `sanitizeBlockText`, `sanitizeCodeSnippet`) to eliminate presentation-layer breakouts.

### 2.5 Prompt Injection Boundaries
- Code inspected by LLM agents is enclosed in XML data delimiters (`<untrusted_code_data>`).
- While this mitigates simple instruction confusion, prompt boundaries are a policy guidance mechanism rather than a cryptographic guarantee. For hostile repositories, containerized sandboxing is essential.

---

## 3. Reporting Vulnerabilities

If you discover a security vulnerability or design flaw in this plugin, please open a private security advisory or report it responsibly to the project maintainers.
