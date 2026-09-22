# Cross-Model & Ablation Comparative Validation Report

**Generated**: `2026-09-22T13:26:48.492Z`  
**Evidence Grade**: `Tier 1A: HISTORICAL_REFERENCE_ABLATION`  
**Protocol ID**: `v1.5-cross-model-1`  
**Protocol Digest**: `9ca44ee1fdb617e3fa36f90c2184bef857ec82b1ed40e660d31a6b5ba282aeb5`  
**Governance Standard**: NIST SSDF / Section 21 Holdout Covenant / Default-Deny Authority Invariant

> [!NOTE] **EXPERIMENT TAXONOMY: TIER 3 (CROSS_PROVIDER_MODEL_REPLICATION)**
> True independent cross-model replication across distinct model providers.

## 1. Experimental Configuration & Model Taxonomy

| Attribute | Configuration A | Configuration B |
| :--- | :--- | :--- |
| **Raw Model ID** | `gemini-3.8-flash-high` | `claude-5-sonnet` |
| **Canonical Model** | `gemini-3.8-flash` | `claude-5-sonnet` |
| **Base Model** | `gemini-3.8-flash` | `claude-5-sonnet` |
| **Model Family** | `gemini-flash` | `claude-sonnet` |
| **Provider** | `google` | `anthropic` |
| **Reasoning Profile** | `high` | `high` |
| **Runtime Engine** | `agy` (native) | `agy` (native) |
| **Identity Authority** | `CONFIG_DECLARED` (`HIGH`) | `CONFIG_DECLARED` (`HIGH`) |
| **Passes Evaluated (N)** | 3 | 3 |

## 2. Comparability Preflight & Temporal-Confound Disclosure

### 2.1 Comparability Preflight Audit

| Comparability Dimension | Configuration A | Configuration B | Preflight Verdict |
| :--- | :--- | :--- | :--- |
| **Base Model Architecture** | `gemini-3.8-flash` | `claude-5-sonnet` | **DIVERGENT** |
| **Model Provider** | `google` | `anthropic` | **DIVERGENT** |
| **Evaluation Corpus** | `evals/holdout-benchmark` | `evals/holdout-benchmark` | **MATCH** |
| **Ground Truth Oracle** | `93dfd88dbae5c44e...` | `93dfd88dbae5c44e...` | **MATCH** |
| **Evaluation Isolation** | Hermetic Sandbox (`HERMETIC_BENCHMARK_V1`) | Hermetic Sandbox (`HERMETIC_BENCHMARK_V1`) | **MATCH** |
| **Blinding Control** | Label-Blind Projection (`LABEL_BLIND_V1`) | Label-Blind Projection (`LABEL_BLIND_V1`) | **MATCH** |
| **Evaluation Passes (N)** | 3 passes | 3 passes | **MATCH** |
| **Attestation Authority** | `CONFIG_DECLARED` (`HIGH`) | `CONFIG_DECLARED` (`HIGH`) | **VERIFIED** |

### 2.2 Temporal-Confound Disclosure

Configuration A (`gemini-3.8-flash-high`) serves as the frozen historical reference baseline recorded at repository commit `d98b017a8db25eda58122f4caa97963efd3c5d64`. Configuration B (`claude-5-sonnet`) was evaluated during a subsequent independent session. While both configurations execute under identical hermetic isolation, deterministic shuffle seed (`20260917`), and fixed throttle delay (2000ms), temporal non-concurrency may introduce upstream provider API dynamics or latency variations. In accordance with Default-Deny reporting principles, this ablation is formally classified under **Tier 1A: HISTORICAL_REFERENCE_ABLATION** rather than a simultaneous interleaved trial.

### 2.3 Execution Exposure & Censoring Audit

Failures (`TIMEOUT`, `SCHEMA_VIOLATION`) represent unexposed fixtures and are treated strictly as `CENSORED_EXPOSURE`, not negative findings. Metrics are calculated over completed exposures rather than assuming negative outcomes for unexposed runs.

| Exposure Metric | Configuration A (`gemini-3.8-flash-high`) | Configuration B (`claude-5-sonnet`) | Delta / Comparison |
| :--- | :--- | :--- | :--- |
| **Total Attempted Exposures** | 60 | 60 | - |
| **Successfully Completed Exposures** | 44 | 60 | **+16 exposures** |
| **Censored Exposures (Timeout / Schema Violation)** | 16 | 0 | **-16 exposures** |
| **Vulnerable Fixtures Completed / Attempted** | 22 / 30 | 30 / 30 | - |
| **Vulnerable Fixture Completed Exposure Recall** | 100.0% (22/22) | 90.0% (27/30) | **100.0% Recall across completed exposures** |
| **Controlled Safe Exposures Completed / Attempted** | 22 / 30 | 30 / 30 | - |

## 3. Dual-Tier Jaccard Lineage Stability Matrix

Strict recurrence threshold: $\lceil 0.60 \times N \rceil$ ($N_A=3 \implies \ge 2$, $N_B=3 \implies \ge 2$).

| Lineage Level | Metric | Pool A | Pool B | Shared Overlap | Jaccard Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Level 1 (Cryptographic Lineage) | $J_{any}$ | 14 | 11 | 10 | **66.7%** |
| Level 1 (Cryptographic Lineage) | $J_{strict}$ (Recurrent) | 7 | 11 | 6 | **50.0%** |
| Level 2 (Ground-Truth Semantic) | $J_{any}$ | 10 | 11 | 10 | **90.9%** |
| Level 2 (Ground-Truth Semantic) | $J_{strict}$ (Recurrent) | 9 | 11 | 9 | **81.8%** |
| Level 2 (Semantic - Clean Oracle) | $J_{any}$ | 10 | 10 | 10 | **100.0%** |
| Level 2 (Semantic - Clean Oracle) | $J_{strict}$ (Recurrent) | 9 | 10 | 9 | **90.0%** |

*Semantic Normalization Note*: Level-2 semantic equivalence is de-fuzzed and keyed by canonical fixture ID and normalized CWE family (`${fixtureId}:${canonicalCwe}`). Model-generated freeform text and subjective security properties are excluded from lineage hashing to eliminate artificial semantic fragmentation.

## 4. Replicated Consensus Lineages & Dispositions

Consensus lineages observed in $\ge \lceil 0.60 \times N \rceil$ passes across both configurations:

- **Replicated True Positives (TP)**: 6
- **Replicated False Positives (FP)**: 0
- **Ground Truth Oracle Disputes (Disputed Benchmarks)**: 0
- **Replicated Unresolved (No Oracle)**: 0

| Level 1 Lineage ID | Rule | Recurrence (A) | Recurrence (B) | Disposition | Ground Truth Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `9130d72b31c7` | `CWE-611` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-02 |
| `53529aa322b3` | `CWE-918` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-08 |
| `04f6916026f5` | `CWE-22` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-07 |
| `5b2dfcf52c1e` | `CWE-347` | 3/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-06 |
| `dfc83efd73b1` | `CWE-329` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-05 |
| `c5a3c9701c91` | `CWE-1333` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-04 |

## 5. Efficiency Metrics, Token Deltas & Incremental Compute Cost

### 5.1 Paired Exposure Telemetry (44 Mutually Completed Exposures)

Paired analysis isolates compute efficiency on the 44 mutually completed fixture exposures across identical seeds, filtering out distorted averages caused by timeouts and execution censoring.

| Token / Latency Dimension | Configuration A (`gemini-3.8-flash-high`) | Configuration B (`claude-5-sonnet`) | Paired Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Total Tokens (44 Pairs)** | 8,278,286 | 4,172,180 | **-4,106,106** | **-49.6%** |
| **Thinking Tokens (44 Pairs)** | 436,520 | 175,260 | **-261,260** | **-59.9%** |
| **Input Tokens (44 Pairs)** | 7,744,373 | 3,952,480 | **-3,791,893** | **-49.0%** |
| **Output Tokens (44 Pairs)** | 533,913 | 219,700 | **-314,213** | **-58.9%** |
| **Cache Read Tokens (44 Pairs)** | 32,252,611 | 10,992,000 | **-21,260,611** | **-65.9%** |
| **Median Per-Exposure Latency Delta** | - | - | **-33.92s** | -33917 ms |
| **P95 Per-Exposure Latency Delta** | - | - | **+16.50s** | +16496 ms |

### 5.2 Pass-Level Aggregate Telemetry (Unadjusted)

*Note: Pass-level aggregate metrics reflect unadjusted pass totals where timeouts and schema violations skew raw run averages.*

| Metric Dimension | Configuration A | Configuration B | Aggregate Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Mean Total Tokens / Pass** | 2,827,255 | 1,871,800 | **-955,455** | -33.8% |
| **Mean Thinking Tokens / Pass** | 148,989 | 78,533 | **-70,455** | -47.3% |
| **Mean Execution Duration / Pass** | 2919.4s | 1478.9s | **-1440.6s** | -49.3% |

### 5.3 Incremental Compute Cost per Replicated True Positive

- **Replicated True Positives ($TP_{replicated}$)**: 6
- **Incremental Total Tokens per Replicated TP**: -684,351 tokens
- **Incremental Thinking Tokens per Replicated TP**: -43,543 tokens
- **Incremental Execution Duration per Replicated TP**: -240.09s

## 6. Safe Control Specificity & Oracle Defect Disclosure

### 6.1 Clean Safe Control Specificity (Excluding Disputed Fixture)

Evaluated across genuine safe control fixtures (`HLD-01-SAFE` through `HLD-07-SAFE`, `HLD-09-SAFE`, `HLD-10-SAFE`):

| Configuration | Observed False-Positive Exposures | Completed Genuine Safe Exposures | Empirical Specificity (%) | Mean FP per Run |
| :--- | :--- | :--- | :--- | :--- |
| **Configuration A** (`gemini-3.8-flash-high`) | 0 | 19 | **100.0%** | 0.00 |
| **Configuration B** (`claude-5-sonnet`) | 0 | 27 | **100.0%** | 0.00 |
| **Clean Control Agreement** | **100.0% (Clean Controls)** | - | **Identical 100% Specificity** | - |

> [!NOTE] **Neutral Safe-Control Finding Disclosure**
> - Configuration A: 0 observed false-positive exposures across 19 completed genuinely-safe exposures.
> - Configuration B: 0 observed false-positive exposures across 27 completed genuinely-safe exposures.

### 6.2 Benchmark Oracle Defect Disclosure (`HLD-08-SAFE`)

Investigation into candidate detections revealed defective benchmark oracle(s) within the safe control corpus:

| Disputed Fixture | Ground Truth Label | Actual Code Property | Disputed Detections (A) | Disputed Detections (B) | Final Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HLD-08-SAFE` | `SAFE` (Defective Oracle) | DNS_REBINDING_SSRF | 0 | 2 | **GROUND_TRUTH_DISPUTE** |

**Flaw Mechanism (`HLD-08-SAFE` in `evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js`)**: Verified benchmark oracle defect: hostname is resolved and verified, but subsequent http.get(url) executes a second independent DNS resolution, allowing an attacker to rebind hostname to loopback/private IP. **Adjudication**: Oracle invalidated; fixture is genuinely vulnerable to CWE-918 SSRF via DNS rebinding.

## 7. Model-Specific Divergent Lineages

- Unique to Configuration A (Recurrent): 1 lineage(s)
- Unique to Configuration B (Recurrent): 5 lineage(s)

