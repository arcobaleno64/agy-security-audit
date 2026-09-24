# Contributing to agy-security-audit

Thank you for your interest in contributing to `agy-security-audit`.

This project implements an evidence-driven, formal security assurance and vulnerability verification architecture for Antigravity CLI (`agy`). Because this tool makes cryptographic and evidentiary claims, all contributions must strictly adhere to our core architectural invariants.

---

## 1. Core Architectural Axioms

### 1.1 Presumption of Non-Pass (Default-Deny on Authority Claims)
- All authority claims (candidate findings, patch remediations, and coverage completeness claims) are unverified by default.
- Zero findings is a legitimate and normal review outcome; there are no finding quotas.
- Code under security review must always be treated as untrusted data under review, never as prompt instructions.

### 1.2 Invariant Preservation Discipline
- The Section 24 Automated Invariants suite currently enforces **121 Section 24 invariants**.
- Contributions must not modify, suppress, or increment this count without an accepted RFC and formal mathematical justification.
- All 121 invariants must pass cleanly (`npm test`).

### 1.3 Zero External Dependencies (0 npm Dependencies)
- `agy-security-audit` operates with strictly **0 external npm dependencies**.
- All functionality, parsers, and verifiers must be implemented using pure Node.js built-in modules (`node:fs`, `node:path`, `node:crypto`, `node:child_process`, etc.).
- Do not introduce `dependencies` in `package.json`.

### 1.4 Patch Jail Perimeter
- Remediation patches must strictly adhere to the Patch Jail boundary: mutations are confined to `scratch/patches/` and must only modify the vulnerable target file itself.
- Never modify CI/CD workflows (`.github/*`), git history, or repository manifests during an automated remediation.

### 1.5 Subprocess Calling Contract
Scripts that operate as hooks or subprocesses must follow the contract:
1. Non-blocking stdin with unref'd timer (never block indefinitely).
2. Explicit LF line endings (no CRLF conversion on Windows).
3. Strict schema adherence (only emit protocol-specified JSON fields).

---

## 2. Development & Verification Workflow

### 2.1 Prerequisites
- **Node.js**: `>= 20.0.0`
- **Git**: `>= 2.30.0`
- **Antigravity CLI**: `>= 1.2.0` (for live integration testing)

### 2.2 Local Verification Suite
Before opening a pull request, run all deterministic validation suites:

```bash
# 1. Automated 121 Section 24 Invariants Gate
npm test

# 2. Adversarial and Boundary Regression Suite (50 cases)
npm run test:evals

# 3. L1.5 Disposition Ground-Truth Suite (20 paired cases)
npm run test:semantic

# 4. Agent Discovery Harness
npm run test:discovery

# 5. Synthetic Stability Harness
npm run test:stability

# 6. Provenance Policy Test Suite (19/19 checks)
npm run test:provenance

# 7. Release Specifications & Invariants Gate
npm run check:release

# 8. Documentation Integrity & Drift Gate
npm run check:docs
```

---

## 3. Pull Request Guidelines

1. **Focused Scopes**: Keep PRs focused on a single concern. Do not bundle refactorings with bug fixes.
2. **Deterministic Evidence**: If proposing a new rule or detector, include corresponding test fixtures in `evals/`.
3. **No Secret Commits**: Never commit actual secrets, API keys, or live tokens. Use synthetic placeholders or test fixtures under `evals/secret-leak/`.
4. **CI Green**: All PRs must pass the 3-platform matrix (Ubuntu, Windows, macOS) in GitHub Actions.
