> [!WARNING] **SUPERSEDED REPORT -- DO NOT CITE AS PRIMARY EVIDENCE**
> This report has been formally superseded by [`reports/reasoning-ablation-report-2026-09-17-corrected.md`](./reasoning-ablation-report-2026-09-17-corrected.md) under Milestone G5-CR1.
> **Correction Rationale**:
> 1. **Censoring Rectification**: Unexposed fixtures (16 in High, 9 in Medium) due to timeouts/schema violations were inappropriately conflated with negative findings.
> 2. **Benchmark Oracle Flaw Retraction**: `HLD-08-SAFE` contains an authentic DNS rebinding SSRF flaw detected by Medium (TP); the prior conclusion that Medium exhibits lower specificity is **retracted**.
> 3. **Level-2 Key Normalization**: Freeform text hashing was de-fuzzed to canonical CWE mapping, raising recurrent semantic consensus from 5 to 9 shared vulnerability families (90.0% clean oracle Jaccard).
> 4. **Paired Efficiency Calibration**: Paired 37 mutually completed exposures demonstrate 24.5% total token and 45.1% thinking token savings with 21.4s faster median latency.

# Cross-Model & Ablation Comparative Validation Report

**Generated**: `2026-09-22T02:27:53.838Z`  
**Evidence Grade**: `Tier 1A: HISTORICAL_REFERENCE_ABLATION`  
**Protocol ID**: `v1.5-cross-model-1`  
**Protocol Digest**: `9ca44ee1fdb617e3fa36f90c2184bef857ec82b1ed40e660d31a6b5ba282aeb5`  
**Governance Standard**: NIST SSDF / Section 21 Holdout Covenant / Default-Deny Authority Invariant

> [!NOTE] **EVALUATION EVIDENCE GRADE: Tier 1A: HISTORICAL_REFERENCE_ABLATION**
> **EXPERIMENT TAXONOMY: TIER 1 (REASONING_PROFILE_ABLATION)**
> Inference effort / thinking budget ablation on identical base model and runtime.

## 1. Experimental Configuration & Model Taxonomy

| Attribute | Configuration A | Configuration B |
| :--- | :--- | :--- |
| **Raw Model ID** | `gemini-3.8-flash-high` | `gemini-3.8-flash-medium` |
| **Canonical Model** | `gemini-3.8-flash` | `gemini-3.8-flash` |
| **Base Model** | `gemini-3.8-flash` | `gemini-3.8-flash` |
| **Model Family** | `gemini-flash` | `gemini-flash` |
| **Provider** | `google` | `google` |
| **Reasoning Profile** | `high` | `medium` |
| **Runtime Engine** | `agy` (native) | `agy` (native) |
| **Identity Authority** | `CONFIG_DECLARED` (`HIGH`) | `CONFIG_DECLARED` (`HIGH`) |
| **Passes Evaluated (N)** | 3 | 3 |

## 2. Comparability Preflight & Temporal-Confound Disclosure

### 2.1 Comparability Preflight Audit

| Comparability Dimension | Configuration A | Configuration B | Preflight Verdict |
| :--- | :--- | :--- | :--- |
| **Base Model Architecture** | `gemini-3.8-flash` | `gemini-3.8-flash` | **MATCH** |
| **Model Provider** | `google` | `google` | **MATCH** |
| **Evaluation Corpus** | `evals/holdout-benchmark` | `evals/holdout-benchmark` | **MATCH** |
| **Ground Truth Oracle** | `93dfd88dbae5c44e...` | `93dfd88dbae5c44e...` | **MATCH** |
| **Evaluation Isolation** | Hermetic Sandbox (`HERMETIC_BENCHMARK_V1`) | Hermetic Sandbox (`HERMETIC_BENCHMARK_V1`) | **MATCH** |
| **Blinding Control** | Label-Blind Projection (`LABEL_BLIND_V1`) | Label-Blind Projection (`LABEL_BLIND_V1`) | **MATCH** |
| **Evaluation Passes (N)** | 3 passes | 3 passes | **MATCH** |
| **Attestation Authority** | `CONFIG_DECLARED` (`HIGH`) | `CONFIG_DECLARED` (`HIGH`) | **VERIFIED** |

### 2.2 Temporal-Confound Disclosure

Configuration A (`gemini-3.8-flash-high`) serves as the frozen historical reference baseline recorded at repository commit `d98b017a8db25eda58122f4caa97963efd3c5d64`. Configuration B (`gemini-3.8-flash-medium`) was evaluated during a subsequent independent session. While both configurations execute under identical hermetic isolation, deterministic shuffle seed (`20260917`), and fixed throttle delay (2000ms), temporal non-concurrency may introduce upstream provider API dynamics or latency variations. In accordance with Default-Deny reporting principles, this ablation is formally classified under **Tier 1A: HISTORICAL_REFERENCE_ABLATION** rather than a simultaneous interleaved trial.

## 3. Dual-Tier Jaccard Lineage Stability Matrix

Strict recurrence threshold: $\lceil 0.60 \times N \rceil$ ($N_A=3 \implies \ge 2$, $N_B=3 \implies \ge 2$).

| Lineage Level | Metric | Pool A | Pool B | Shared Overlap | Jaccard Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Level 1 (Cryptographic Lineage) | $J_{any}$ | 14 | 14 | 12 | **75.0%** |
| Level 1 (Cryptographic Lineage) | $J_{strict}$ (Recurrent) | 7 | 11 | 5 | **38.5%** |
| Level 2 (Ground-Truth Semantic) | $J_{any}$ | 15 | 17 | 9 | **39.1%** |
| Level 2 (Ground-Truth Semantic) | $J_{strict}$ (Recurrent) | 5 | 8 | 4 | **44.4%** |

## 4. Replicated Consensus Lineages & Dispositions

Consensus lineages observed in $\ge \lceil 0.60 \times N \rceil$ passes across both configurations:

- **Replicated True Positives (TP)**: 5
- **Replicated False Positives (FP)**: 0
- **Replicated Unresolved (No Oracle)**: 0

| Level 1 Lineage ID | Rule | Recurrence (A) | Recurrence (B) | Disposition | Ground Truth Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `9130d72b31c7` | `CWE-611` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-02 |
| `53529aa322b3` | `CWE-918` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-08 |
| `fcb49642493d` | `CWE-94` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-01 |
| `5b2dfcf52c1e` | `CWE-347` | 3/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-06 |
| `c5a3c9701c91` | `CWE-1333` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-04 |

## 5. Efficiency Metrics, Token Deltas & Incremental Compute Cost

| Metric Dimension | Configuration A | Configuration B | Paired Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Median Per-Fixture Latency** | - | - | **-42.69s** | -42693 ms |
| **P95 Per-Fixture Latency** | - | - | **1.93s** | +1932 ms |
| **Mean Total Tokens / Pass** | 2,827,255 | 2,194,218 | **-633,038** | -22.4% |
| **Mean Thinking Tokens / Pass** | 148,989 | 89,147 | **-59,842** | -40.2% |
| **Mean Execution Duration / Pass** | 2919.4s | 3524.8s | **+605.4s** | 20.7% |

### Incremental Compute Cost per Replicated True Positive

- **Replicated True Positives ($TP_{replicated}$)**: 5
- **Incremental Total Tokens per Replicated TP**: -126,608 tokens
- **Incremental Thinking Tokens per Replicated TP**: -11,968 tokens
- **Incremental Execution Duration per Replicated TP**: +121.08s

## 6. Safe Control Specificity & Suppression Agreement

| Configuration | Observed False-Positive Exposures | Mean FP per Run | Neutral Exposure Observation |
| :--- | :--- | :--- | :--- |
| **Configuration A** | 0 | 0.00 | **0 observed false-positive exposures across 30 controlled safe exposures** |
| **Configuration B** | 2 | 0.67 | **2 observed false-positive exposures across 30 controlled safe exposures** |
| **Suppression Agreement** | **DIVERGENT** | - | Evaluated across controlled safe exposures |

> [!NOTE] **Neutral Safe-Control Finding Disclosure**
> - Configuration A: 0 observed false-positive exposures across 30 controlled safe exposures.
> - Configuration B: 2 observed false-positive exposures across 30 controlled safe exposures.

## 7. Model-Specific Divergent Lineages

- Unique to Configuration A (Recurrent): 2 lineage(s)
- Unique to Configuration B (Recurrent): 6 lineage(s)

