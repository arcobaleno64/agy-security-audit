# Cross-Model & Ablation Comparative Validation Report

**Generated**: `2026-09-22T05:56:38.358Z`  
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

### 2.3 Execution Exposure & Censoring Audit

Failures (`TIMEOUT`, `SCHEMA_VIOLATION`) represent unexposed fixtures and are treated strictly as `CENSORED_EXPOSURE`, not negative findings. Metrics are calculated over completed exposures rather than assuming negative outcomes for unexposed runs.

| Exposure Metric | Configuration A (`gemini-3.8-flash-high`) | Configuration B (`gemini-3.8-flash-medium`) | Delta / Comparison |
| :--- | :--- | :--- | :--- |
| **Total Attempted Exposures** | 60 | 60 | - |
| **Successfully Completed Exposures** | 44 | 51 | **+7 exposures** |
| **Censored Exposures (Timeout / Schema Violation)** | 16 | 9 | **-7 exposures** |
| **Vulnerable Fixtures Completed / Attempted** | 22 / 30 | 26 / 30 | - |
| **Vulnerable Fixture Completed Exposure Recall** | 100.0% (22/22) | 100.0% (26/26) | **100.0% Recall across completed exposures** |
| **Controlled Safe Exposures Completed / Attempted** | 22 / 30 | 25 / 30 | - |

## 3. Dual-Tier Jaccard Lineage Stability Matrix

Strict recurrence threshold: $\lceil 0.60 \times N \rceil$ ($N_A=3 \implies \ge 2$, $N_B=3 \implies \ge 2$).

| Lineage Level | Metric | Pool A | Pool B | Shared Overlap | Jaccard Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Level 1 (Cryptographic Lineage) | $J_{any}$ | 14 | 14 | 12 | **75.0%** |
| Level 1 (Cryptographic Lineage) | $J_{strict}$ (Recurrent) | 7 | 11 | 5 | **38.5%** |
| Level 2 (Ground-Truth Semantic) | $J_{any}$ | 10 | 11 | 10 | **90.9%** |
| Level 2 (Ground-Truth Semantic) | $J_{strict}$ (Recurrent) | 9 | 11 | 9 | **81.8%** |
| Level 2 (Semantic - Clean Oracle) | $J_{any}$ | 10 | 10 | 10 | **100.0%** |
| Level 2 (Semantic - Clean Oracle) | $J_{strict}$ (Recurrent) | 9 | 10 | 9 | **90.0%** |

*Semantic Normalization Note*: Level-2 semantic equivalence is de-fuzzed and keyed by canonical fixture ID and normalized CWE family (`${fixtureId}:${canonicalCwe}`). Model-generated freeform text and subjective security properties are excluded from lineage hashing to eliminate artificial semantic fragmentation.

## 4. Replicated Consensus Lineages & Dispositions

Consensus lineages observed in $\ge \lceil 0.60 \times N \rceil$ passes across both configurations:

- **Replicated True Positives (TP)**: 5
- **Replicated False Positives (FP)**: 0
- **Ground Truth Oracle Disputes (Disputed Benchmarks)**: 0
- **Replicated Unresolved (No Oracle)**: 0

| Level 1 Lineage ID | Rule | Recurrence (A) | Recurrence (B) | Disposition | Ground Truth Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `9130d72b31c7` | `CWE-611` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-02 |
| `53529aa322b3` | `CWE-918` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-08 |
| `fcb49642493d` | `CWE-94` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-01 |
| `5b2dfcf52c1e` | `CWE-347` | 3/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-06 |
| `c5a3c9701c91` | `CWE-1333` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-04 |

## 5. Efficiency Metrics, Token Deltas & Incremental Compute Cost

### 5.1 Paired Exposure Telemetry (37 Mutually Completed Exposures)

Paired analysis isolates compute efficiency on the 37 mutually completed fixture exposures across identical seeds, filtering out distorted averages caused by timeouts and execution censoring.

| Token / Latency Dimension | Configuration A (`gemini-3.8-flash-high`) | Configuration B (`gemini-3.8-flash-medium`) | Paired Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Total Tokens (37 Pairs)** | 6,870,460 | 5,186,767 | **-1,683,693** | **-24.5%** |
| **Thinking Tokens (37 Pairs)** | 355,897 | 195,539 | **-160,358** | **-45.1%** |
| **Input Tokens (37 Pairs)** | 6,434,064 | 4,934,434 | **-1,499,630** | **-23.3%** |
| **Output Tokens (37 Pairs)** | 436,396 | 252,333 | **-184,063** | **-42.2%** |
| **Cache Read Tokens (37 Pairs)** | 27,421,343 | 15,086,192 | **-12,335,151** | **-45.0%** |
| **Median Per-Exposure Latency Delta** | - | - | **-21.39s** | -21393 ms |
| **P95 Per-Exposure Latency Delta** | - | - | **+25.81s** | +25814 ms |

### 5.2 Pass-Level Aggregate Telemetry (Unadjusted)

*Note: Pass-level aggregate metrics reflect unadjusted pass totals where timeouts and schema violations skew raw run averages.*

| Metric Dimension | Configuration A | Configuration B | Aggregate Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Mean Total Tokens / Pass** | 2,827,255 | 2,194,218 | **-633,038** | -22.4% |
| **Mean Thinking Tokens / Pass** | 148,989 | 89,147 | **-59,842** | -40.2% |
| **Mean Execution Duration / Pass** | 2919.4s | 3524.8s | **+605.4s** | 20.7% |

### 5.3 Incremental Compute Cost per Replicated True Positive

- **Replicated True Positives ($TP_{replicated}$)**: 5
- **Incremental Total Tokens per Replicated TP**: -336,739 tokens
- **Incremental Thinking Tokens per Replicated TP**: -32,072 tokens
- **Incremental Execution Duration per Replicated TP**: +121.08s

## 6. Safe Control Specificity & Oracle Defect Disclosure

### 6.1 Clean Safe Control Specificity (Excluding Disputed Fixture)

Evaluated across genuine safe control fixtures (`HLD-01-SAFE` through `HLD-07-SAFE`, `HLD-09-SAFE`, `HLD-10-SAFE`):

| Configuration | Observed False-Positive Exposures | Completed Genuine Safe Exposures | Empirical Specificity (%) | Mean FP per Run |
| :--- | :--- | :--- | :--- | :--- |
| **Configuration A** (`gemini-3.8-flash-high`) | 0 | 19 | **100.0%** | 0.00 |
| **Configuration B** (`gemini-3.8-flash-medium`) | 0 | 23 | **100.0%** | 0.00 |
| **Clean Control Agreement** | **100.0% (Clean Controls)** | - | **Identical 100% Specificity** | - |

> [!NOTE] **Neutral Safe-Control Finding Disclosure**
> - Configuration A: 0 observed false-positive exposures across 19 completed genuinely-safe exposures.
> - Configuration B: 0 observed false-positive exposures across 23 completed genuinely-safe exposures.

### 6.2 Benchmark Oracle Defect Disclosure (`HLD-08-SAFE`)

Investigation into the candidate detections on `evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js` revealed a defect in the benchmark oracle itself:

| Disputed Fixture | Ground Truth Label | Actual Code Property | Configuration A Detections | Configuration B Detections | Final Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HLD-08-SAFE` | `SAFE` (Defective Oracle) | Vulnerable to DNS TOCTOU / Rebinding SSRF | 0 / 3 (Missed flaw) | 2 / 2 (Detected SSRF) | **GROUND_TRUTH_DISPUTE** |

**Flaw Mechanism**: In `08-ssrf-dns-rebinding.js`, `dns.lookup()` validates the resolved IP of the input hostname, but the subsequent `http.get(targetUrl)` call triggers a secondary, unpinned DNS resolution. A DNS server configured with TTL=0 returning a public IP on the first resolution and `127.0.0.1` on the second resolution bypasses the validation. Configuration B (Medium) accurately identified this authentic vulnerability in 2 out of 2 completed exposures. The prior conclusion asserting that Medium exhibits lower specificity is **formally retracted**.

## 7. Model-Specific Divergent Lineages

- Unique to Configuration A (Recurrent): 2 lineage(s)
- Unique to Configuration B (Recurrent): 6 lineage(s)

