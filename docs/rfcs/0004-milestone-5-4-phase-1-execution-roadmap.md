# Milestone 5.4 Phase 1 Planning Proposal: Next-Generation Runtime Adaptation & Multi-Tier Governance

**Document Version**: `1.0.0-PROPOSAL`  
**Milestone Scope**: Milestone 5.4 — Runtime Evolution, Zero-Token Invariants & Multi-Tier Orchestration  
**Governance Framework**: NIST SSDF (SP 800-218) / NIST SP 800-53 / Default-Deny Authority Invariant  
**Target Release**: `v1.11.0`  
**Authoritative Context**: Builds directly upon frozen Milestone 5.3 baseline (`v1.10.0`) and Antigravity CLI 1.5.1 runtime capabilities.

---

## 1. Milestone 5.4 Strategic Objectives

Having achieved mathematical closure and 112-round double-blind audit freeze in Milestone 5.3, Milestone 5.4 transitions from *internal validation convergence* to *runtime-level enforcement and performance optimization*.

```mermaid
flowchart TD
    M53["Milestone 5.3 Baseline<br/>(v1.10.0 Frozen)"] --> M54["Milestone 5.4 Runtime Adaptation"]
    
    M54 --> Axis1["Axis 1: PreInvocation Zero-Token Guard<br/>(Deterministic Hook Interception)"]
    M54 --> Axis2["Axis 2: ACP Stdio Bridge<br/>(IDE & Native Client Protocol)"]
    M54 --> Axis3["Axis 3: 3-Tier Effort Orchestration<br/>(Low / Medium / High Routing)"]
    M54 --> Axis4["Axis 4: Fail-Closed Lifecycle<br/>(finished_reason Awareness)"]
    
    Axis1 --> Value1["0-Token Secret & Path Rejection"]
    Axis2 --> Value2["Real-time Inline 3-Lens Review"]
    Axis3 --> Value3["-70% Token Burn on Smoke Checks"]
    Axis4 --> Value4["Strict SSDF Audit Proof"]
```

---

## 2. Four Technical Workstreams for Phase 1

### Workstream 1: Native PreInvocation Zero-Token Security Hook
- **Background**: Antigravity CLI v1.5.1 introduced `terminationBehavior: "terminate"` for `PreInvocation` hooks, enabling scripts to reject turns *before* any prompt tokens are transmitted to the LLM.
- **Implementation Goal**:
  1. Register a native `PreInvocation` hook (`hooks/pre-invocation-secret-guard.mjs`).
  2. Implement local high-speed regex scan for high-entropy secrets, private keys (`BEGIN PRIVATE KEY`), and unmasked cloud credentials.
  3. Enforce deterministic rejection (`exitCode: 2`, `terminationBehavior: "terminate"`) when secrets are detected.
  4. **Value**: Zero-token leak prevention and fail-closed secret containment.

### Workstream 2: Agent Client Protocol (`agy acp`) Stdio Bridge
- **Background**: AGY 1.5.1 provides the Agent Client Protocol (`agy acp`), a standardized JSON-RPC stdio protocol for editor integrations.
- **Implementation Goal**:
  1. Create `scripts/adapters/acp-stdio-bridge.mjs`.
  2. Map incoming editor file events directly to `security-audit` subagents (`discovery-agent`, `threat-modeler`, `verifier-*`).
  3. Stream partial SARIF 2.1.0 diagnostics back to the client editor in real time.
  4. **Value**: Seamless developer ergonomics with inline vulnerability squiggles in VS Code and Antigravity IDE.

### Workstream 3: Formalized 3-Tier Effort Orchestration (`low` | `medium` | `high`)
- **Background**: Verified live across `SEM-01` and `SEM-08`:
  - `Low`: 19.8s latency, 0 thinking tokens, -70.8% total tokens (Smoke/Pre-commit).
  - `Medium`: 52.9% fewer thinking tokens, 100% semantic fidelity, strict JSON compliance (Standard CI).
  - `High`: Maximum reasoning depth, exhaustive static traces (Pre-release gate).
- **Implementation Goal**:
  1. Update `plugin.json` and `SKILL.md` to expose explicit `--effort` routing flags.
  2. Embed robust markdown fence unwrapping in all tool ingestion pipelines.
  3. Document effort-level guidelines in official plugin documentation.

### Workstream 4: Fail-Closed `finished_reason` Lifecycle Governance
- **Background**: AGY 1.5.1 stream JSON telemetry surfaces `finished_reason: "print_timeout" | "error" | "interrupted" | "complete"`.
- **Implementation Goal**:
  1. Update `record-benchmark-run.mjs` and `finalize-scan.mjs` to ingest `finished_reason`.
  2. Treat all non-complete reasons strictly as `CENSORED_EXPOSURE` under NIST SSDF.
  3. Prohibit silent fallback or negative imputation on timed-out passes.

---

## 3. Gate 0: CLI Contract, Data Coverage & Authority Invariants (Independent Reviewer R1 Binding Mandate)

Following Independent Third-Party Reviewer (ChatGPT) Verdict `M54-P1-ARCH-REVIEW-R1 = CONDITIONAL_ACCEPT`, the following 5 Open Findings constitute the mandatory **Gate 0 Entry Criteria** before any feature promotion into production branches:

### Core Governance Invariant
$$\text{EXECUTION\_COMPLETE} \ne \text{FINDING\_VERIFIED} \ne \text{RELEASE\_AUTHORIZED}$$
*Execution completion does not imply finding verification, and finding verification does not imply release authorization.*

### Mandatory Gate 0 Checklist

| Finding ID | Severity | Invariant / Precondition Specification |
| :--- | :--- | :--- |
| **`M54-P1-F01`** | **Critical** | **PreInvocation Hook Fail-Closed**: Hook must specify exact input sources covered (`lastUserInput`); fail-closed on hook error, timeout, or missing context; prohibited from claiming absolute "zero-token leak prevention" (restated as "deterministic model turn suppression upon rule hit"); real secrets prohibited in testing. |
| **`M54-P1-F02`** | **High** | **`finished_reason` Omission Handling**: Antigravity CLI omits `finished_reason` on normal completion; success must be evaluated via exit code 0, complete result event, and schema validity; non-zero exit, timeout, or interruption must be classified strictly as `CENSORED_EXPOSURE`, never `CLEAN`. |
| **`M54-P1-F03`** | **High** | **RFC 0003 Authority Promotion Inheritance**: 3-tier reasoning profiles (`low` / `medium` / `high`) cannot bypass RFC 0003 Authority Promotion Protocol (Internal -> External -> Shadow -> Blocking); higher thinking budget does not grant automatic blocking authority. |
| **`M54-P1-F04`** | **Medium** | **Native ACP Prioritization**: Prioritize native `agy acp` stdio server; custom bridge layers permitted only if native protocol cannot support subagent routing or SARIF transformation; editor squiggles require independent UI verification. |
| **`M54-P1-F05`** | **Medium** | **Audit Traceability**: RFC 0004, baseline commit `d1e5e1a`, and empirical benchmark traces across all evaluated models must maintain immutable cryptographic provenance. |

---

## 4. Phase 1 Execution Roadmap & Gate Criteria

| Phase Step | Target Deliverable | Verification Gate |
| :--- | :--- | :--- |
| **Gate 0: Contract Verification** | Gate 0 Invariant Checklist Sign-off | All 5 OPEN findings verified against CLI specifications. |
| **Step 1: Hook Architecture** | `hooks/pre-invocation-secret-guard.mjs` + `plugin.json` hook definition | Synthetic secret injection test exits with 0 tokens consumed. |
| **Step 2: Effort Wiring** | `skills/security-audit/SKILL.md` update + CLI parameter schema update | `npm test` and `agy plugin validate . --strict` return 0 findings. |
| **Step 3: Lifecycle Hardening** | `finished_reason` telemetry ingestion in `record-benchmark-run.mjs` | Multi-pass runner classifies simulated timeouts as `CENSORED_EXPOSURE`. |
| **Step 4: ACP Prototype** | `scripts/adapters/acp-stdio-bridge.mjs` POC | JSON-RPC handshake verified over stdin/stdout. |

---

## 5. Resource & Quota Allocation Strategy

- **Token Consumption**: Phase 1 is primarily architectural, hook engineering, and adapter implementation. Live token usage is virtually zero (unit tests execute with `--mock` or offline harnesses).
- **Quota Impact**: Zero risk to weekly or 5-hour quota pools.
- **Compatibility**: 100% backwards-compatible with `v1.10.0` baseline.
