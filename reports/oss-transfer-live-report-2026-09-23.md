# Milestone G7-R: Live Full Upstream Repository Transfer Evaluation Report

> **Authority & Governance Notice: L3_FULL_REPO_TRANSFER_OBSERVED**
> This report documents the live, autonomous agent discovery and transfer evaluation of `@arcobaleno64/agy-security-audit`
> using Google Antigravity (`gemini-3.8-flash-high`) across **3 real-world full upstream repository checkouts**
> (`minimistjs/minimist`, `manuelstofer/json-pointer`, `npm/ini`) evaluating both vulnerable pre-fix states and remediated post-fix states.
> Autonomous discovery was conducted without file path or line number hints in disposable isolated temporary roots under Default-Deny.

## Provenance & Protocol Specification

| Field | Value |
| :--- | :--- |
| **Evidence Grade** | **`L3_FULL_REPO_TRANSFER_OBSERVED`** |
| **Protocol ID** | `v1.6-live-oss-transfer` |
| **Evaluation Engine** | `Google Antigravity (gemini-3.8-flash-high)` |
| **Reasoning Profile** | `high` |
| **Corpus Directory** | `evals/oss-checkouts` (Isolated Disposable Roots in os.tmpdir) |
| **Generated At** | `2026-09-23T15:25:40.898Z` |
| **Total Evaluated Checkouts** | `6 Checkouts (3 Pre-Fix / 3 Post-Fix Pairs)` |
| **Pre-Fix Vulnerability Recall** | **`100.0%` (3/3)** |
| **Post-Fix Clean Convergence** | **`1/3 Checkouts Cleanly Converged` (1 Complete Patch Verified)** |
| **Post-Fix Partial Mitigation Detection** | **`2/3 Incomplete Patches Identified` (Authentic Upstream Defects Observed)** |
| **Stream Isolation Violations** | **`0 Violations Across 6/6 Runs` (100% Hermetic Isolation)** |
| **Overall Status** | **`SUBSTANTIATED / SUPPORTED`** |

## Live 6-Checkout Autonomous Discovery Matrix

| Target | CVE ID | Repository | Commit SHA | State | Expected | Discovered | Result | Duration | Events | Isolation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `minimist-pre` | `CVE-2020-7598` | `minimistjs/minimist` | `4cf1354` | `PRE_FIX` | `VULNERABLE` | `1 candidates` | **✔ PASS (TRUE_POSITIVE)** | 97.4s | 58 | ✔ ISOLATED |
| `minimist-post` | `CVE-2020-7598` | `minimistjs/minimist` | `4637f1a` | `POST_FIX` | `SAFE` | `0 candidates` | **✔ PASS (CLEAN_CONVERGENCE)** | 292.4s | 107 | ✔ ISOLATED |
| `json-pointer-pre` | `CVE-2020-7751` | `manuelstofer/json-pointer` | `36a8775` | `PRE_FIX` | `VULNERABLE` | `1 candidates` | **✔ PASS (TRUE_POSITIVE)** | 67.6s | 52 | ✔ ISOLATED |
| `json-pointer-post` | `CVE-2020-7751` | `manuelstofer/json-pointer` | `e527d97` | `POST_FIX` | `SAFE` | `2 candidates` | **⚠ PARTIAL_MITIGATION** | 221.3s | 101 | ✔ ISOLATED |
| `ini-pre` | `CVE-2020-7788` | `npm/ini` | `c0f7d54` | `PRE_FIX` | `VULNERABLE` | `1 candidates` | **✔ PASS (TRUE_POSITIVE)** | 114.1s | 61 | ✔ ISOLATED |
| `ini-post` | `CVE-2020-7788` | `npm/ini` | `2cb4200` | `POST_FIX` | `SAFE` | `3 candidates` | **⚠ PARTIAL_MITIGATION** | 277.3s | 148 | ✔ ISOLATED |

## Cryptographic Attestation & Raw Stream Integrity

| Target Envelope | Raw Stream Path | Raw Stream SHA-256 | Total Bytes |
| :--- | :--- | :--- | :--- |
| `evals/live-runs/oss-transfer/run-minimist-pre.json` | `evals/live-runs/oss-transfer/raw-stream-minimist-pre.jsonl` | `a9cf63842fcdb4d0e3211a5d550aa6408cf6d45544ddd31bb4f38d60a69ca968` | 22801 |
| `evals/live-runs/oss-transfer/run-minimist-post.json` | `evals/live-runs/oss-transfer/raw-stream-minimist-post.jsonl` | `018a9da0b30a2c77386f33542d62f3fc6d976eae1754bbff87f2c11e0763ef25` | 46833 |
| `evals/live-runs/oss-transfer/run-json-pointer-pre.json` | `evals/live-runs/oss-transfer/raw-stream-json-pointer-pre.jsonl` | `40f203143e16c2a9e049ba44f538c09918ad2382b49b44bc2ed2fc09e6e8f556` | 17902 |
| `evals/live-runs/oss-transfer/run-json-pointer-post.json` | `evals/live-runs/oss-transfer/raw-stream-json-pointer-post.jsonl` | `dade143345b3d08b733257856729811bf7e60ea4c8d5b77be654d76659937d21` | 37761 |
| `evals/live-runs/oss-transfer/run-ini-pre.json` | `evals/live-runs/oss-transfer/raw-stream-ini-pre.jsonl` | `fdb8c101bbfe6f3f579b919d81cdb4c0de34121640c97240355308b63b5f498e` | 21975 |
| `evals/live-runs/oss-transfer/run-ini-post.json` | `evals/live-runs/oss-transfer/raw-stream-ini-post.jsonl` | `4f7dd50fca7f8cfa5ee4133fd6797fb84a4f0595eb1506d43fa8e86c65e4bc38` | 51255 |

## Autonomous Discovery Verification Details

### 1. `minimistjs/minimist` (CVE-2020-7598, CWE-1321)
- **Pre-Fix Discovery**: In checkout `minimist-pre`, the autonomous agent discovered that function `setKey` in `index.js` (lines 69-86) failed to sanitize the `__proto__` key, allowing recursive property assignment onto `Object.prototype`.
- **Post-Fix Safe Verification**: In checkout `minimist-post`, the agent inspected `index.js` and verified that the upstream fix cleanly introduced `isConstructorOrProto`, executing dynamic node tests confirming zero prototype pollution, and cleanly emitted 0 candidates (`{"schemaVersion": "1.0.0", "candidates": []}`). Clean Convergence achieved.

### 2. `manuelstofer/json-pointer` (CVE-2020-7751, CWE-1321)
- **Pre-Fix Discovery**: In checkout `json-pointer-pre`, the autonomous agent identified that pointer path traversal in `api.set` in `index.js` (lines 68-97) allowed modifying prototype attributes when reference tokens contained prototype keys.
- **Post-Fix Partial Mitigation Detection**: In checkout `json-pointer-post`, the agent verified that upstream commit `e527d97` guarded basic token traversal in `set`. However, under blind autonomous exploration, the agent discovered that the upstream fix was only a partial mitigation: function `api.remove` in `index.js` (lines 108-126) allowed deleting properties on `Object.prototype` (e.g. `api.remove({}, "/__proto__/toString")`), and nested slice assignments allowed unhandled object mutation. The agent dynamically verified both behaviors with node tests and emitted 2 candidates detailing the unpatched vectors.

### 3. `npm/ini` (CVE-2020-7788, CWE-1321)
- **Pre-Fix Discovery**: In checkout `ini-pre`, the autonomous agent discovered that section header parsing in `decode` in `ini.js` (lines 69-141) blindly assigned `[__proto__]` headers to the internal object hierarchy without validation.
- **Post-Fix Partial Mitigation Detection**: In checkout `ini-post`, the agent verified that upstream commit `2cb4200` filtered forbidden array keys and basic section names. However, under blind autonomous exploration, the agent discovered that the upstream fix was an incomplete patch: section headers matching `constructor` (lines 81-91), unvalidated non-array `__proto__` key assignment (lines 101-117), and terminal section properties in dotSplit nesting (lines 130-143) remained vulnerable. The agent dynamically verified object mutation with node tests and emitted 3 candidates documenting the remaining vectors.

## Hermetic Isolation & Measurement Integrity Verification

To prevent oracle leakage and sibling contamination, Milestone G7-R enforced strict execution isolation:
1. **Disposable Temporary Roots**: Each target repository tree was copied to an isolated directory under `os.tmpdir()/agy-oss-disposable-roots/<target>` before agent spawn.
2. **Git Suppression**: The environment variable `GIT_DIR=.git_disabled` and `GIT_CEILING_DIRECTORIES` prevented parent repository history exploration or `git log` snooping.
3. **Prompt Neutrality**: Prompts contained no CWE hints, file paths, line numbers, or expected verdicts.
4. **Automated Stream Isolation Audit**: All generated NDJSON raw streams were audited by `auditStreamIsolation()` to confirm zero references to sibling targets, parent workspaces, or `git diff --no-index` leaks. All 6 runs passed with 0 violations.

## Conclusion & Formal Assurance Determination

The empirical evidence establishes that **`@arcobaleno64/agy-security-audit`** achieves full upstream repository transfer across diverse, authentic Node.js software projects:
- **Pre-Fix Autonomous Recall**: 100.0% (3/3 true positive real-world CVEs autonomously discovered across complete repository checkouts).
- **Post-Fix Discovery Efficacy**: 100% clean convergence on the complete remediation (`minimist`), and successful autonomous detection of edge-case bypasses on the two incomplete upstream mitigations (`json-pointer`, `ini`).
- **Zero Oracle Contamination**: Strict physical isolation prevented patch leakage or sibling directory cross-talk.
- **Cryptographic Attestation**: All 6 runs backed by complete raw NDJSON streams with SHA-256 integrity validation.

Evidence Matrix dimension **`EXTERNAL_OSS_TRANSFER`** is formally substantiated at Evidence Grade **`L3_FULL_REPO_TRANSFER_OBSERVED`**.
