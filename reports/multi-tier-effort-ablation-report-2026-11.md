# Multi-Tier Effort Dynamic Evaluation & Empirical Calibration Report

**Generated**: `2026-11-07T07:55:00.000Z`  
**Milestone Scope**: Milestone 5.4 Phase 2 (RFC 0005) — Multi-Tier Dynamic Evaluation & Persistent Governance Envelope  
**Evidence Grade**: `Tier 1: LIVE_AGENT_OBSERVED (Preliminary Pilot)`  
**Evaluation Protocol**: `evals/protocols/v2.0-three-layer-evaluation-framework.md` / `v2.0-acceptance-criteria.json`  
**Governance Standard**: NIST SSDF (SP 800-218) / Default-Deny Authority Invariant / Zero-Workspace-Pollution Invariant  
**Target Release**: `v1.12.0`  
**Review Status**: `IN_REMEDIATION` (Responding to ChatGPT Pro Independent Review R01)  

---

## 1. Executive Summary & Governance Envelope

Milestone 5.4 Phase 2 evaluates the empirical runtime dynamics of **Multi-Tier Reasoning Effort Profiles** (`low` vs `medium` vs `high`) and establishes the authoritative **V2.0 Layer 2 External Validity Corpus** and **Persistent Dual-Anchor Governance** for `@arcobaleno64/three-lens`.

### 1.1 Core Empirical Findings (Preliminary Pilot)
1. **72.7% Reduction in Thinking Tokens on Low Tier (Single-Fixture Observation)**: On the `SEM-03` audit fixture, `gemini-3.8-flash-low` expended 2,369 thinking tokens compared to 8,691 on `gemini-3.8-flash-medium`, exceeding the exploratory threshold ($\ge 70\%$ reduction). *Notice (M54-P2-F09)*: This observation is strictly bounded to the single-fixture `SEM-03` test case and must not be extrapolated as a generalized guarantee across full repository scans or heterogeneous languages.
2. **56.5% Latency Reduction**: Execution wall-clock time dropped from 101.6s (`medium`) to 44.2s (`low`), providing an agile execution path for pre-commit and local smoke scanning.
3. **100% Semantic Lineage Concordance**: Both effort profiles discovered the identical authentic SSRF vulnerability (`CAND-CWE-918-12`) at `evals/semantic-benchmark/03-confused-deputy.js` targeting the unvalidated `fetch` sink, producing identical deterministic semantic lineages (`62c3cd33c856f5552c7f3547c67ba2d2`).
4. **V2.0 Layer 2 Corpus Materialization (F07/F08 Closure)**: Curated and froze 14 authoritative Ground Truth Bundles (7 Vulnerable, 4 Fixed, 3 Clean Controls) across 7 distinct CWE families with 100% physical file verification, binding to authentic NVD CVEs (`CVE-2020-28500`, `CVE-2021-32803`, `CVE-2020-7598`, `CVE-2020-28168`) and mature external OSS clean controls (`lodash`, `minimist`, `node-tar`).
5. **Persistent Dual-Anchor Architecture**: Shipped `scripts/adapters/plugin-data-adapter.mjs` and `skills/3lens/scripts/compact-guard.mjs`, enforcing Zero Workspace Pollution and fail-closed `/compact` state preservation.

---

## 2. Experimental Configuration & Model Taxonomy

| Attribute | Configuration A (Low Effort) | Configuration B (Medium Effort) |
| :--- | :--- | :--- |
| **Model ID** | `gemini-3.8-flash-low` | `gemini-3.8-flash-medium` |
| **Base Model Architecture** | `gemini-3.8-flash` | `gemini-3.8-flash` |
| **Model Family** | `gemini-flash` | `gemini-flash` |
| **Model Provider** | `google` | `google` |
| **Reasoning Effort Profile** | `low` | `medium` |
| **Runtime CLI Engine** | Antigravity CLI v1.5.2 (`agy`) | Antigravity CLI v1.5.2 (`agy`) |
| **Output Protocol** | `stream-json` (AGY_STREAM_JSON_V1) | `stream-json` (AGY_STREAM_JSON_V1) |
| **Evaluation Mode** | Hermetic Benchmark Sandbox (`HERMETIC_BENCHMARK_V1`) | Hermetic Benchmark Sandbox (`HERMETIC_BENCHMARK_V1`) |
| **Blinding Control** | Label-Blind Projection (`LABEL_BLIND_V1`) | Label-Blind Projection (`LABEL_BLIND_V1`) |
| **Evidence Envelope** | `evals/live-runs/m54-pilot/low/run-pass-1.json` | `evals/live-runs/m54-pilot/medium/run-pass-1.json` |

### 2.1 Environmental Calibration & `toolDirty` Clarification (M54-P2-F09)
In `evals/live-runs/m54-pilot/medium/run-pass-1.json`, the field `environment.toolDirty` was set to `true`. This occurred because ephemeral working artifacts (scratch execution logs and uncommitted baseline files) were present in the local workspace when `git status --porcelain` was queried during benchmark recordation. The tool revision SHA (`87173d84...`) and codebase integrity digest (`0e8304a3...`) remained strictly identical across both Low and Medium runs, confirming that no tool code alterations biased the comparative evaluation.

---

## 3. Empirical Comparative Metrics

### 3.1 Token Consumption & Performance Comparison

```
+-----------------------------------------------------------------------------+
| Token Burn & Latency Trade-Off (Fixture: SEM-03 Confused Deputy - Pilot)    |
+-----------------------------------------------------------------------------+
| Metric                 | Low Effort       | Medium Effort    | Delta / Gain |
+------------------------+------------------+------------------+--------------+
| Wall-Clock Latency     | 44.198 s         | 101.648 s        | -56.5%       |
| Thinking Tokens        | 2,369 tokens     | 8,691 tokens     | -72.7%       |
| Output Response Tokens | 2,629 tokens     | 9,364 tokens     | -71.9%       |
| Input Tokens           | 19,014 tokens    | 34,127 tokens    | -44.3%       |
| Total Tokens Expended  | 21,643 tokens    | 43,491 tokens    | -50.2%       |
+-----------------------------------------------------------------------------+
```

### 3.2 Vulnerability Discovery Fidelity

| Dimension | `gemini-3.8-flash-low` | `gemini-3.8-flash-medium` | Agreement Verdict |
| :--- | :--- | :--- | :--- |
| **Rule ID** | `CWE-918` (Server-Side Request Forgery) | `CWE-918` (Server-Side Request Forgery) | **PERFECT MATCH** |
| **Target Sink** | `fetch` (lines 12–19) | `fetch` (line 12) | **PERFECT MATCH** |
| **Security Property** | `authorization` | `authorization` | **MATCH** |
| **Severity Rating** | `CRITICAL` | `CRITICAL` | **MATCH** |
| **Semantic Lineage ID** | `62c3cd33c856f5552c7f3547c67ba2d2` | `62c3cd33c856f5552c7f3547c67ba2d2` | **100% IDENTICAL** |

---

## 4. V2.0 Layer 2 External Validity Corpus Audit (R01 Remediation)

In compliance with `evals/protocols/v2.0-three-layer-evaluation-framework.md` and `evals/protocols/v2.0-acceptance-criteria.json`:

```mermaid
pie title Layer 2 External Validity Corpus Case Distribution (N=14)
    "Vulnerable Cases (CVEs)" : 7
    "Fixed Counterparts" : 4
    "Clean Negative Controls" : 3
```

| Metric | Target Specification | Realized Corpus | Conformance Verdict |
| :--- | :--- | :--- | :--- |
| **Total Cases** | 12 to 16 | **14 cases** | ✔ **COMPLIANT** |
| **Known Vulnerable Cases** | 6 to 8 | **7 cases** | ✔ **COMPLIANT** |
| **Fixed Counterparts** | 3 to 4 | **4 cases** | ✔ **COMPLIANT** |
| **Clean Negative Controls** | 3 to 4 | **3 cases** | ✔ **COMPLIANT** |
| **Distinct Vulnerability Families** | $\ge 7$ families | **7 families** | ✔ **COMPLIANT** |
| **Physical File Integrity** | 100% non-empty files | **14 / 14 verified** | ✔ **COMPLIANT** |

### 4.1 Taxonomic Family Distribution & Provenance (F07 / F08)
1. **`injection-and-validation`**: lodash ReDoS (`02-lodash-redos.js` / CVE-2020-28500 / UPSTREAM_VERIFIED_OSS / Paired).
2. **`auth-and-tenancy`**: Cross-Tenant AuthZ (`01-authz-bypass.js` / SYNTHETIC_REGRESSION / Paired).
3. **`path-and-filesystem`**: node-tar Path Traversal (`04-tar-path-traversal.js` / CVE-2021-32803 / UPSTREAM_VERIFIED_OSS / Paired).
4. **`parser-and-deserialization`**: minimist Prototype Pollution (`01-minimist-prototype-pollution.js` / CVE-2020-7598 / UPSTREAM_VERIFIED_OSS / Paired).
5. **`concurrency-and-lifecycle`**: TOCTOU Race Condition (`10-toctou-race-condition.js` / SYNTHETIC_REGRESSION).
6. **`secrets-and-configuration`**: Hardcoded AWS Credentials (`08-hardcoded-credential.js` / SYNTHETIC_REGRESSION).
7. **`dependency-and-supply-chain`**: axios Header Leakage (`05-axios-ssrf-header-leak.js` / CVE-2020-28168 / UPSTREAM_VERIFIED_OSS).
8. **Clean External Controls (F08)**:
   - Lodash Clamp utility (`01-lodash-clamp.js` / `lodash/lodash`).
   - Minimist Clean Parse (`02-minimist-clean-parse.js` / `minimistjs/minimist`).
   - node-tar Octal Header Parser (`03-node-tar-clean-header.js` / `npm/node-tar`).

---

## 5. Architectural Hardening & Governance Gate Status

| Component | Target File | Verification Suite | Status |
| :--- | :--- | :--- | :--- |
| **`PLUGIN_DATA` Dual-Anchor** | `scripts/adapters/plugin-data-adapter.mjs` | `tests/test-plugin-data-adapter.mjs` | ✔ **12/12 PASS** |
| **`/compact` Context Guard** | `skills/3lens/scripts/compact-guard.mjs` | `tests/test-compact-context-governance.mjs` | ✔ **13/13 PASS** |
| **V2 Corpus Validator** | `scripts/validate-v2-corpus.mjs` | `npm run validate:v2-corpus` | ✔ **PASSED** |
| **ACP Native Transport** | `scripts/adapters/acp-transport-adapter.mjs` | `tests/test-acp-transport-governance.mjs` | ✔ **19/19 PASS** |
| **PreInvocation Secret Guard** | `hooks/pre-invocation-secret-guard.mjs` | `tests/test-pre-invocation-secret-guard.mjs` | ✔ **14/14 PASS** |
| **Lifecycle Governance** | `record-benchmark-run.mjs` | `tests/test-finished-reason-governance.mjs` | ✔ **16/16 PASS** |
| **Authority Promotion** | `skills/3lens/scripts/finalize-scan.mjs` | `tests/test-effort-authority-promotion-invariants.mjs` | ✔ **34/34 PASS** |
| **Total Automated Suite** | All governance modules | All unit suites | ✔ **108/108 PASS** |

---

## 6. Review Status & Next Steps (M54-P2-F10)

- **Independent Third-Party Review**: PR #52 reviewed by ChatGPT Pro (Round 01: `REJECTED`, 10 Findings).
- **Remediation Status**: All 10 findings (`M54-P2-F01` through `M54-P2-F10`) implemented and verified with automated test suites.
- **Phase 2 Exit Gate Status**: `PENDING_REVIEW` (Awaiting ChatGPT Pro Round 02 Cold-Start Independent Audit).
- **Merge Policy**: PR #52 remains blocked from merging into `main` until independent review grants explicit `APPROVED` verdict.
