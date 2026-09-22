> [!WARNING] **SUPERSEDED REPORT -- DO NOT CITE AS PRIMARY EVIDENCE**
> This historical baseline report has been formally superseded by [`reports/reasoning-ablation-report-2026-09-17-corrected.md`](./reasoning-ablation-report-2026-09-17-corrected.md) and [`reports/cross-provider-replication-report-2026-09-22.md`](./cross-provider-replication-report-2026-09-22.md) under Milestones G5-CR1 and G8.
> **Correction & Retraction Rationale**:
> 1. **Benchmark Oracle Defect Correction**: Safe control fixture `HLD-08-SAFE` (`evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js`) contains an authentic DNS rebinding TOCTOU SSRF flaw. The uncorrected 30/30 (100.0%) safe-control metric in this historical baseline conflated a missed detection of an authentic vulnerability with safe-control specificity.
> 2. **Corrected Specificity Baseline**: Evaluated across the 9 genuinely safe control fixtures (`HLD-01-SAFE` through `HLD-07-SAFE`, `HLD-09-SAFE`, `HLD-10-SAFE`), the empirical specificity is 100.0% (0/27 false-positive exposures). `HLD-08-SAFE` is reclassified as `GROUND_TRUTH_DISPUTE` / `DISPUTED_INVALIDATED`.
> 3. **Canonical Reference**: Refer to the corrected ablation report and cross-provider replication report for active publication metrics and censored-exposure analysis.

# Empirical Baseline Evaluation Report: Model-Dependent Stochastic Discovery (N=3)

**Evaluation Harness**: Antigravity Security Audit Plugin (`@arcobaleno64/agy-security-audit`)  
**Publication Date**: 2026-09-17  
**Corpus**: `evals/holdout-benchmark` (20-fixture paired holdout benchmark)  
**Governance Standard**: NIST SSDF (SP 800-218) / OWASP ASVS 5.0.0 / Section 21 Benchmark Protocol  
**Principle**: Default-Deny Presumption of Non-Pass; strictly uncalibrated Holdout Generalization Set (`HLD-01..HLD-10`) per Section 21 Holdout Covenant.

---

## 1. Executive Summary & Provenance Attestation

This evaluation establishes the project's first authentic, model-dependent empirical baseline across $N=3$ independent execution passes on the holdout vulnerability benchmark. Unlike synthetic harness self-tests that yield an invariant 100%, this report records genuine stochastic LLM discovery behavior, measuring finding-set Jaccard similarity, lineage stability, and generalization beyond calibration fixtures.

| Provenance Property | Value / Attestation |
| :--- | :--- |
| **Evaluation Mode** | `RECORDED_EMPIRICAL` |
| **Model-Dependent Run** | `YES (Observed Multi-Pass)` |
| **Evaluated Model ID** | `gemini-3.8-flash-high` |
| **Model Provider** | `google` |
| **Antigravity CLI Version** | `1.2.4` |
| **Node.js Runtime** | `v24.14.1` |
| **OS Architecture** | `win32 (x64)` |
| **Security Audit Plugin Version** | `1.4.1` |
| **TCB Integrity Digest** | `a1672eaa288b5cdd73186b5ead62dfb06f0d661e63cc9f433e86bedc40b1e569` |
| **Tool Dirty State** | `CLEAN (false)` |
| **Repository Revision (SHA)** | `d98b017a8db25eda58122f4caa97963efd3c5d64` |
| **Total Evaluation Passes (N)** | `3` |
| **Safe Controls Audited** | `YES (10 paired safe controls)` |

### Key Benchmark Metrics
- **Mean Pairwise Jaccard Similarity**: **25.3%**
- **Unique Semantic Lineages Discovered**: **14**
- **Consistently Recurrent Lineages (100% Passes)**: **1 / 14**
- **Mean Candidate Recall**: **63.3%**
- **Mean Discovery Precision**: **100.0%**

---

## 2. Multi-Pass Stochastic Stability & Jaccard Matrix (N=3)

The pairwise Jaccard similarity metric $J(A, B) = rac{|A cap B|}{|A cup B|}$ measures candidate finding-set invariance across independent discovery passes on identical codebases.

### Pairwise Comparison Matrix
| Pass Comparison | Jaccard Similarity | Status (Threshold ≥ 80.0%) |
| :--- | :--- | :--- |
| Pass 1 ↔ Pass 2 | 50.0% | WARN |
| Pass 1 ↔ Pass 3 | 16.7% | WARN |
| Pass 2 ↔ Pass 3 | 9.1% | WARN |

- **Aggregate Mean Jaccard**: **25.3%**
- **Pairwise Comparisons Evaluated**: 3

---

## 3. Fixture Partitioning & Generalization Analysis

Under Section 21 governance, holdout benchmark fixtures are strictly segregated from calibration or training data to measure authentic out-of-distribution model generalization:
1. **Development Set**: Uncalibrated (0 fixtures; Section 21 covenant forbids prompt heuristics for holdout fixtures).
2. **Holdout Generalization Set (`HLD-01..HLD-10`)**: Evaluated without targeted per-case prompt tuning to measure authentic out-of-distribution model generalization across 10 distinct CWE vulnerability classes.

### Partition Metrics Summary
| Partition Split | Fixture Count | Lineages Found | Mean Recurrence Rate | Role & Governance |
| :--- | :--- | :--- | :--- | :--- |
| **Development Set** | 0 | 0 | **0.0%** | Uncalibrated (0 Fixtures per Section 21 Covenant) |
| **Holdout Generalization Set** | 10 | 14 | **52.4%** | Unbiased Out-of-Distribution Generalization |

### Lineage Recurrence Breakdown
| Lineage Digest | Fixture / Symbol | CWE Rule | Passes Observed | Reliability Rate | Stability Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `9130d72b31...` | `parseXmlReport` | `CWE-611` | 2/3 | 66.7% | MODERATE |
| `c3b27fdb7f...` | `Object.assign` | `CWE-915` | 1/3 | 33.3% | SPORADIC |
| `53529aa322...` | `http.get` | `CWE-918` | 2/3 | 66.7% | MODERATE |
| `04f6916026...` | `path.join` | `CWE-22` | 2/3 | 66.7% | MODERATE |
| `b1b747caae...` | `router.post` | `CWE-362` | 1/3 | 33.3% | SPORADIC |
| `fcb4964249...` | `renderDynamicTemplate` | `CWE-94` | 2/3 | 66.7% | MODERATE |
| `5b2dfcf52c...` | `jwt.verify` | `CWE-347` | 3/3 | 100.0% | PERFECT |
| `dfc83efd73...` | `createCipheriv` | `CWE-329` | 2/3 | 66.7% | MODERATE |
| `c5a3c9701c...` | `VULN_EMAIL_REGEX.test` | `CWE-1333` | 2/3 | 66.7% | MODERATE |
| `60c9b20a43...` | `res.setHeader` | `CWE-113` | 1/3 | 33.3% | SPORADIC |
| `73b813d529...` | `router.post` | `CWE-367` | 1/3 | 33.3% | SPORADIC |
| `958392a7d8...` | `crypto.createCipheriv` | `CWE-329` | 1/3 | 33.3% | SPORADIC |
| `d593b68c24...` | `renderDynamicTemplate` | `CWE-1336` | 1/3 | 33.3% | SPORADIC |
| `bf979cc7cc...` | `setHeader` | `CWE-113` | 1/3 | 33.3% | SPORADIC |

---

## 4. Safe Control Specificity Baseline (Controlled Ground Truth)

The benchmark harness audited all 10 paired safe controls (`evals/holdout-benchmark/safe/*.js`) across all $N=3$ independent passes (30 safe exposures) under label-blind materialization (`LABEL_BLIND_V1`).

### Safe-Control Specificity Metrics (Controlled Dual Ground Truth)
| Metric | Observed Value | Definition & Formula |
| :--- | :--- | :--- |
| **Controlled Safe Fixtures Evaluated** | `10` | Distinct safe baseline control fixtures ($K$) |
| **Total Safe Exposures ($K \times N$)** | `30` | Total independent model exposures across passes |
| **Fixture False-Positive Rate** | **0.0%** (0/10) | Fraction of safe fixtures with $\ge 1$ spurious candidate |
| **Run-Exposure False-Positive Rate** | **0.0%** (0/30) | Fraction of $(fixture, pass)$ exposures with $\ge 1$ spurious candidate |
| **Exposure Specificity** | **100.0%** | $1 - \text{Run-Exposure FP Rate}$ ($TN / (TN + FP)$) |
| **FP Candidate Density** | **0.000** | Spurious candidates per safe exposure ($C_{spurious} / (K \times N)$) |
| **Max Lineage Recurrence** | **0 / 3** (0.0%) | Maximum recurrence of any single spurious lineage |

> [!IMPORTANT]
> 0 reportable false positives observed across 3 valid runs on 10 controlled safe fixtures. This result is corpus- and configuration-bounded and does not imply false-positive immunity.


---

## 5. Failure Analysis & Boundary Edge Cases

Under Default-Deny, any candidate missed during discovery or exhibiting low recurrence is analyzed rather than masked:
1. **Stochastic Line Variance**: Slight variations in reported start/end line bounds across runs are automatically normalized by the semantic lineage algorithm (`computeLineageFingerprint`), ensuring line-shift invariance.
2. **Subtle Flaws & Multi-Step Logic**: Vulnerabilities involving complex multi-step taint tracking (e.g. `SEM-08` async message broker boundaries) or prototype pollution (`SEM-09`) exhibit the highest stochastic variance across model iterations.
3. **Defensive Verification Protocol**: Candidate generation on complex codebases produces hypotheses that require multi-stage verification. Downstream 3-lens verifier panels and finalization under Default-Deny ensure unevidenced candidate hypotheses are eliminated prior to reporting.

---

## 6. Comparison: Authentic Empirical Baseline vs. Synthetic Benchmark

| Dimension | Synthetic Harness Baseline | Authentic Empirical Baseline (This Run) |
| :--- | :--- | :--- |
| **Evidence Origin** | `SYNTHETIC` | `MODEL_OBSERVED` |
| **Execution Kind** | `SIMULATED_HARNESS` | `LIVE_AGENT` |
| **Jaccard Similarity** | Fixed 100.0% (deterministic) | **25.3%** (authentic empirical) |
| **Stochastic Variance** | Zero (simulated line shifts only) | Genuine model output variance |
| **Scientific Value** | Invariant regression gate | Real-world capability and reliability measurement |

---

*Report generated automatically by `scripts/run-live-model-benchmark.mjs`.*
