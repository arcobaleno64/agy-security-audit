# RFC 0003: Track E - Empirical Validation Framework, Ground Truth Hierarchy & Authority Promotion Protocol

* **RFC Number**: 0003
* **Title**: Track E - Empirical Validation Framework, Ground Truth Hierarchy & Authority Promotion Protocol
* **Status**: Accepted
* **Authors**: Maintainers & Antigravity Security Engine
* **Created**: 2026-10-08
* **Baseline**: `agy-security-audit v1.9.2`
* **Depends On**:
  - RFC 0001: Track C - Supply-Chain Provenance & Cryptographic Assurance
  - RFC 0002: Track D - External Reproducibility, Real-World Transfer & Adoption Readiness
* **Primary Objective**: Establish a rigorous, non-circular empirical validation protocol and measurement contract to determine whether `agy-security-audit` can reliably discriminate between vulnerable, remediated, clean, and insufficient-evidence states across heterogeneous codebases while preventing unwarranted authority promotion.

---

## 1. Executive Summary & Problem Statement

### 1.1 Beyond Cycle Rituals & Producer-Side Proofs

`agy-security-audit` v1.8 through v1.9 demonstrated total deterministic invariant integrity (Section 24 121/121 invariants, 40 authoritative security invariants), hermetic build reproducibility (SLSA Build Level 2, Sigstore, Rekor), and clean-room external adoption readiness (Track D).

However, empirical evaluation of frontier AI defensive systems faces a distinct methodological risk: **the trap of synthetic cycle rituals and pseudo-evaluations**. Forcing arbitrary cycle counts (such as copying 20–30 cycles from unrelated review agents like Triad-Flow) generates volume without producing defensive validity. Two systems with divergent research questions cannot be flattened into uniform repetition benchmarks.

### 1.2 The Core Axiom: Default-Deny on Authority Promotion

Extending the system's foundational principle:

> **A security assurance system is not authorized to block production pull requests or releases simply because it completed internal test suites or accumulated sample volume. All claims of blocking authority default to `DENIED` until conclusive, affirmative, multi-stage empirical proof is established against an external Ground Truth hierarchy.**

---

## 2. Formal Research Proposition

The governing research objective of `agy-security-audit` is codified as:

> **Can `agy-security-audit` reliably discriminate between `vulnerable`, `remediated`, `clean`, and `insufficient-evidence` states across heterogeneous codebases and vulnerability families, maintaining strict fail-closed discipline when evidence is insufficient, without generating unacceptable false positives or asserting unwarranted `CLEAN` authority claims?**

---

## 3. Four-Stage Validation Escalation Ladder

Empirical assurance must progress across four distinct escalation tiers. Transition between tiers requires explicit milestone completion, and blocking authority remains withheld until Tier 4.

| Tier | 階段名稱 (Stage) | 建議規模 (Scale) | 驗證標的 (What It Proves) | 是否可支撐 Blocking Authority |
|---|---|---:|---|:---:|
| **Tier 1** | **Deterministic / Contract Regression** | 持續全量 (100% CI) | Invariant、Schema、Default-Deny、SARIF 2.1.0、Provenance 不退化 | **否** |
| **Tier 2** | **External Validity Corpus** | 12–16 案例 (8 配對組) | Paired known vuln / fixed pair / clean control 的二元辨識與抑制能力 | **否** |
| **Tier 3** | **Fresh Shadow Cohort** | 10–15 案例 | 對未見真實變更的泛化能力、不確定性校準與 Fail-closed 降級行為 | **否** |
| **Tier 4** | **Blocking Promotion Cohort** | 20–30+ 真實變更 | False Advance 極低，可承受生產環境 merge/release blocker 權限 | **是 (需獨立 Gate)** |

### 3.1 Tier Boundaries & Non-Promotion Guarantees

- **Tier 1 & Tier 2 Non-Authority**: Passing deterministic suites and curated corpus cases proves that the engine's internal logic is functional; it provides zero evidence of fitness for production blocking authority.
- **Tier 3 Non-Authority**: Running shadow audits on real PRs proves operational telemetry and uncertainty handling; it does NOT grant release gating powers.
- **Tier 4 Gating Requirement**: Blocking authority is never granted retrospectively or automatically by sample volume; it requires a dedicated, pre-adjudicated Promotion Gate.

---

## 4. Ground Truth Hierarchy & Strict Non-Circular Validation

To prevent "AI circular validation" (models validating other models or subjective outputs), Ground Truth must adhere to a strict objective hierarchy:

```text
Level 1: Published CVE / Security Advisory
  └── Level 2: Official Fixing Commit / Vulnerable-Fixed Diff Pair
       └── Level 3: Reproducible Exploit / Deterministic Negative Control
            └── Level 4: Human Security Expert Oracle
                 └── Level 5: Triad-Flow / Multi-Agent Review Dynamics (次要觀測，禁止當 Oracle)
```

### 4.1 Role of External Companion Frameworks (e.g. Triad-Flow)
External agent frameworks serve exclusively as **secondary observation instruments** to measure multi-agent disagreement, reviewer dynamics, and provider variance. Under no circumstances may companion agent outputs be treated as Ground Truth or used to validate `agy-security-audit` findings.

### 4.2 Missing Human Oracle Invariant
When a Human Oracle is pending, disputed, or unavailable:
- The case status MUST remain `PENDING_REVIEW`, `DISPUTED`, or `UNAVAILABLE`.
- **Strict Prohibition**: It is strictly forbidden to default a missing or inconclusive Human Oracle to `CLEAN`.
- Any evaluation outcome with an unresolved oracle is classified as `UNRESOLVED_PENDING_ORACLE`.

---

## 5. Paired Design Principle & Explicit Coverage Gaps (External Validity Corpus)

The External Validity Corpus prioritized in [`evals/external-validity-corpus.json`](../../evals/external-validity-corpus.json) focuses on **paired design** over raw case count:

$$\text{Paired Vulnerable / Fixed Cases} > \text{Clean Negative Controls} > \text{Fresh Random PR Volume}$$

### 5.1 Dual-Hypothesis Testing
Each vulnerability family is structured as an explicit pair:
1. **Vulnerable Version**: Evaluates *Must-detect Recall* — does the engine reliably detect the confirmed vulnerability?
2. **Remediated Version**: Evaluates *False-Alarm Suppression* — does the engine recognize the applied security barrier and refrain from flagging false alarms on resolved code?

### 5.2 Recorded Coverage Gaps & Clean-Control Limitations
The initial 8-pair (16-case) skeleton evaluates paired discrimination only. The following facets are formally recorded as **coverage gaps** and MUST NOT be claimed as proven:
1. **Independent Clean Negative Controls**: Codebases with zero vulnerability history or changes are pending inclusion (planned count: 4). Clean-control capability remains `NOT_ESTABLISHED`.
2. **Native Parsers**: C/C++ memory safety, pointer bounds, and sliding-window protocol parsing are unrepresented in this cohort.
3. **Secrets & Infrastructure**: Hardcoded secrets, cloud IAM misconfigurations, and IaC permission creep are unrepresented.
4. **Supply Chain**: Dependency confusion, lockfile poisoning, and CI/CD workflow tampering are unrepresented.

Cases lacking verified CVEs or commit SHAs are designated `[PENDING_SELECTION]` and remain strictly `UNVERIFIED`.

---

## 6. Two-Layer Authority Semantics & Cross-Field Constraints

To prevent confusing the tool's raw output with authoritative safety, RFC 0003 enforces a clear distinction between **Tool Claimed State** and **Evaluator Adjudication**:

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 1. Tool Claimed State (工具實際輸出的狀態)                                       │
│    - CLEAN                     (Tool asserts authority-grade clean)             │
│    - UNVERIFIED                (Tool failed-closed due to degraded execution)   │
│    - NO_FINDING_OBSERVED       (Tool found no findings in current pass)         │
│    - VULNERABILITIES_REPORTED  (Tool flagged candidate reportable findings)     │
├─────────────────────────────────────────────────────────────────────────────────┤
│ 2. Evaluator Adjudication (評估者最終裁定)                                       │
│    - CLEAN                     (Proven clean under complete evidence)           │
│    - UNVERIFIED                (Evidence incomplete or execution degraded)      │
│    - NO_FINDING_OBSERVED       (Observation only; non-authority)                │
│    - CONFIRMED_VULNERABLE      (Confirmed vulnerable against Ground Truth)      │
│    - DISPUTED                  (Ground Truth under active dispute)              │
│    - PENDING_ORACLE            (Awaiting human security expert review)          │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 6.1 Strict Anti-Upgrade & Fail-Closed Rules
- `NO_FINDING_OBSERVED` cannot morph into `CLEAN`.
- Any unanalyzed file, skipped stage, or degraded verifier instantly disqualifies `CLEAN` and forces `UNVERIFIED`.
- If a tool erroneously asserts `CLEAN` on a confirmed vulnerable repository, the evaluation preserves this as an unambiguous failure (`toolClaimedState = CLEAN`, `evaluatorAdjudication = CONFIRMED_VULNERABLE`).

---

## 7. Partitioned Scorecard Architecture

Metrics are divided into three non-overlapping groups. Technical accuracy and evidence quality must never be blended into a single composite score.

### 7.1 Security Decision Metrics (Blocker Core)
These metrics determine whether the system is safe to act as an automated gatekeeper:
1. **Must-Detect Recall**: Ratio of confirmed ground-truth vulnerabilities correctly flagged.
2. **False-Advance Rate (P0 Blocker)**: Frequency of tool asserting `CLEAN` on confirmed vulnerable code. This catastrophic failure mode is tracked independently from passive false negatives.
3. **False-Negative Rate**: Frequency of failing to observe vulnerabilities without claiming authority.
4. **False-Positive Rate**: Frequency of flagging benign or remediated code as vulnerable.
5. **UNVERIFIED Correctness**: Frequency of correctly downgrading to `UNVERIFIED` when evidence is ambiguous or incomplete.
6. **Fail-Closed Correctness**: Frequency of refusing authority claims when timeouts, parsing errors, or runtime degradation occur.

### 7.2 Evidence Quality Metrics
These metrics measure report readability and forensic provenance:
1. **Severity Agreement**: Concordance between predicted CVSS v4 vector and authoritative advisory severity.
2. **Finding Provenance**: Verifiable line binding integrity and exclusion of fabricated snippets.
3. **SARIF Fidelity**: Strict conformance with SARIF 2.1.0 schema and zero schema deviation.

### 7.3 External Validity (Cross-Project Generalization)
Evaluated across distinct programming languages, architectures, and repository sizes. Reported independently from single-finding accuracy.

---

## 8. Small-Sample Statistical Discipline (N = 12–16 / 10–15)

Small cohorts ($N < 30$) lack statistical power to support point percentage claims (e.g. asserting "95% recall" on 12 cases is mathematically unsound).

### 8.1 Qualitative & Sentinel Evaluation Rules
For Tier 2 ($N = 12\text{--}16$) and Tier 3 ($N = 10\text{--}15$), evaluations MUST report:
- **Sentinel Failures**: Any catastrophic failure (e.g., claiming `CLEAN` on a known CVE, or unhandled tool crash).
- **Paired Discrimination Stability**: Consistent distinction between vulnerable and fixed states in paired fixtures.
- **Clean Control Misclassification**: Zero tolerance for false positives on canonical clean controls.
- **Evidence Insufficiency Degradation**: Consistent transition to `UNVERIFIED` when partial context is supplied.
- **Repeating Failure Modes**: Clustering and root-cause analysis of observed misses.

### 8.2 Proportion & Confidence Interval Trigger
Binomial proportions, 95% Wilson score confidence intervals, and statistical promotion thresholds are strictly deferred until Tier 4 ($N \ge 30$).

---

## 9. Fresh Shadow Cohort Measurement Contract

All Tier 3 and Tier 4 shadow observations must conform to the 8-field measurement contract defined in [`schemas/shadow-cohort-record.schema.json`](../../schemas/shadow-cohort-record.schema.json):

```text
1. targetChange                - Target repo, PR ref, commit SHA, and change kind.
2. humanOracle                 - Ground truth adjudication (strictly non-defaulting).
3. expectedSecurityRelevance   - Expected impact level.
4. toolFinding                 - Findings observed by agy-security-audit.
5. confidenceState             - Derived multi-lens confidence level.
6. evidenceProvenance          - Completeness of review scope and execution trace.
7. toolClaimedState            - CLEAN | UNVERIFIED | NO_FINDING_OBSERVED | VULNERABILITIES_REPORTED.
8. evaluatorAdjudication       - CLEAN | UNVERIFIED | NO_FINDING_OBSERVED | CONFIRMED_VULNERABLE |
                                 DISPUTED | PENDING_ORACLE.
9. outcomeClassification       - TRUE_POSITIVE | TRUE_NEGATIVE | FALSE_POSITIVE |
                                 FALSE_NEGATIVE | FALSE_ADVANCE |
                                 UNRESOLVED_PENDING_ORACLE | UNRESOLVED_EVIDENCE_GAP |
                                 FAIL_CLOSED_DEGRADED.
```

### 9.1 Cross-Field Schema Validation Constraints
The JSON Schema deterministically enforces:
- Pending or unavailable Human Oracle **strictly forbids** `evaluatorAdjudication = CLEAN` and resolved classifications (`TP/TN/FP/FN/FA`).
- Incomplete review scope, unresolved evidence gaps, or degraded execution **strictly forbids** `evaluatorAdjudication = CLEAN` and `outcomeClassification = TRUE_NEGATIVE`.
- Vulnerable Oracle + Tool Claimed `CLEAN` **strictly forces** `outcomeClassification = FALSE_ADVANCE`.
- Evaluator `CLEAN` adjudication strictly requires `humanOracle = CONFIRMED_CLEAN` and 100% complete evidence provenance.

---

## 10. Boundary Locks & Invariant Preservation

1. **Baseline Preservation**: `agy-security-audit` remains pinned at `v1.9.2`.
2. **Section 24 Discipline**: 121/121 Section 24 invariants and 40 security invariants remain unmodified and authoritative.
3. **Zero External Dependencies**: All validation scripts, manifests, and schemas rely strictly on Node.js built-ins.
4. **No Premature Promotion**: This RFC establishes the validation framework and protocol; it does not grant blocking authority.
