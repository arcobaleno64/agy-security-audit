# Cross-Model & Ablation Comparative Validation Report

**Generated**: `2026-09-23T03:38:45.948Z`  
**Evidence Grade**: `L3_CROSS_PROVIDER_OBSERVED`  
**Protocol ID**: `v1.6-g8r-cross-provider`  
**Protocol Digest**: `7c4410c2427663f45be2163fc74cca3dcca924b6f1ab75920e25bf78bb02f7d5`  
**Governance Standard**: NIST SSDF / Section 21 Holdout Covenant / Default-Deny Authority Invariant

> [!NOTE] **EXPERIMENT TAXONOMY: TIER 4 (CROSS_SYSTEM_REPLICATION)**
> Replication across divergent agent runtimes / system prompts / tool environments.

## 1. Experimental Configuration & Model Taxonomy

| Attribute | Configuration A | Configuration B |
| :--- | :--- | :--- |
| **Raw Model ID** | `gemini-3.8-flash-high` | `claude-sonnet-5` |
| **Canonical Model** | `gemini-3.8-flash` | `claude-sonnet-5` |
| **Base Model** | `gemini-3.8-flash` | `claude-5-sonnet` |
| **Model Family** | `gemini-flash` | `claude-sonnet` |
| **Provider** | `google` | `anthropic` |
| **Reasoning Profile** | `high` | `high` |
| **Runtime Engine** | `agy` (native) | `claude` (cli) |
| **Identity Authority** | `RUNTIME_ATTESTED` (`HIGH`) | `RUNTIME_ATTESTED` (`HIGH`) |
| **Passes Evaluated (N)** | 3 | 3 |

## 2. Comparability Preflight & Temporal-Confound Disclosure

### 2.1 Comparability Preflight Audit

| Comparability Dimension | Configuration A | Configuration B | Preflight Verdict |
| :--- | :--- | :--- | :--- |
| **Base Model Architecture** | `gemini-3.8-flash` | `claude-5-sonnet` | **DIVERGENT** |
| **Model Provider** | `google` | `anthropic` | **DIVERGENT** |
| **Evaluation Corpus** | `evals/holdout-benchmark` | `evals/holdout-benchmark` | **MATCH** |
| **Ground Truth Oracle** | `77e6d7a71de9ad90...` | `77e6d7a71de9ad90...` | **MATCH** |
| **Evaluation Isolation** | Hermetic Sandbox (`HERMETIC_BENCHMARK_V1`) | Hermetic Sandbox (`HERMETIC_BENCHMARK_V1`) | **MATCH** |
| **Blinding Control** | Label-Blind Projection (`LABEL_BLIND_V1`) | Label-Blind Projection (`LABEL_BLIND_V1`) | **MATCH** |
| **Evaluation Passes (N)** | 3 passes | 3 passes | **MATCH** |
| **Attestation Authority** | `RUNTIME_ATTESTED` (`HIGH`) | `RUNTIME_ATTESTED` (`HIGH`) | **VERIFIED** |

### 2.2 Temporal-Confound Disclosure

Evaluation was executed under strict contemporaneous interleaved pass ordering (`A1 -> B1 -> A2 -> B2 -> A3 -> B3`) across both Provider A (`gemini-3.8-flash-high`) and Provider B (`claude-sonnet-5`). Both configurations operated under identical hermetic sandbox isolation (`HERMETIC_SANDBOX_V1`), label-blind projection (`LABEL_BLIND_V1`), and verified runtime telemetry attestation. The contemporaneous interleaved trial design eliminates temporal non-concurrency and temporal confounding between provider evaluations, The contemporaneous interleaved trial design eliminates temporal non-concurrency and temporal confounding between evaluations across orthogonal axes: Provider Axis (CROSS_PROVIDER: Google vs Anthropic) and Runtime Axis (CROSS_RUNTIME: AGY native vs Claude CLI), establishing an authentic CROSS_SYSTEM_REPLICATION trial.

### 2.3 Execution Exposure & Censoring Audit

Failures (`TIMEOUT`, `SCHEMA_VIOLATION`) represent unexposed fixtures and are treated strictly as `CENSORED_EXPOSURE`, not negative findings. Metrics are calculated over completed exposures rather than assuming negative outcomes for unexposed runs.

| Exposure Metric | Configuration A (`gemini-3.8-flash-high`) | Configuration B (`claude-sonnet-5`) | Delta / Comparison |
| :--- | :--- | :--- | :--- |
| **Total Attempted Exposures** | 60 | 60 | - |
| **Successfully Completed Exposures** | 53 | 50 | **-3 exposures** |
| **Censored Exposures (Timeout / Schema Violation)** | 7 | 10 | **+3 exposures** |
| **Vulnerable Fixtures Completed / Attempted** | 25 / 30 | 30 / 30 | - |
| **Vulnerable Fixture Completed Exposure Recall** | 96.0% (24/25) | 96.7% (29/30) | **+0.7% Recall across completed exposures** |
| **Controlled Safe Exposures Completed / Attempted** | 28 / 30 | 20 / 30 | - |

## 3. Dual-Tier Jaccard Lineage Stability Matrix

Strict recurrence threshold: $\lceil 0.60 \times N \rceil$ ($N_A=3 \implies \ge 2$, $N_B=3 \implies \ge 2$).

| Lineage Level | Metric | Pool A | Pool B | Shared Overlap | Jaccard Score |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Level 1 (Cryptographic Lineage) | $J_{any}$ | 13 | 23 | 3 | **9.1%** |
| Level 1 (Cryptographic Lineage) | $J_{strict}$ (Recurrent) | 9 | 12 | 3 | **16.7%** |
| Level 2 (Ground-Truth Semantic) | $J_{any}$ | 11 | 18 | 10 | **52.6%** |
| Level 2 (Ground-Truth Semantic) | $J_{strict}$ (Recurrent) | 10 | 13 | 8 | **53.3%** |
| Level 2 (Semantic - Clean Oracle) | $J_{any}$ | 10 | 17 | 9 | **50.0%** |
| Level 2 (Semantic - Clean Oracle) | $J_{strict}$ (Recurrent) | 10 | 12 | 8 | **57.1%** |

*Semantic Normalization Note*: Level-2 semantic equivalence is de-fuzzed and keyed by canonical fixture ID and normalized CWE family (`${fixtureId}:${canonicalCwe}`). Model-generated freeform text and subjective security properties are excluded from lineage hashing to eliminate artificial semantic fragmentation.

## 4. Replicated Consensus Lineages & Dispositions

Consensus lineages observed in $\ge \lceil 0.60 \times N \rceil$ passes across both configurations:

- **Replicated True Positives (TP)**: 3
- **Replicated False Positives (FP)**: 0
- **Ground Truth Oracle Disputes (Disputed Benchmarks)**: 0
- **Replicated Unresolved (No Oracle)**: 0

| Level 1 Lineage ID | Rule | Recurrence (A) | Recurrence (B) | Disposition | Ground Truth Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `5cfdbbca200d` | `CWE-94` | 2/3 | 3/3 | **REPLICATED_TRUE_POSITIVE** | HLD-01 |
| `ca61995ee6d5` | `CWE-611` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-02 |
| `1d3587d69215` | `CWE-347` | 2/3 | 2/3 | **REPLICATED_TRUE_POSITIVE** | HLD-06 |

## 5. Efficiency Metrics, Token Deltas & Incremental Compute Cost

### 5.1 Paired Exposure Telemetry (44 Mutually Completed Exposures)

Paired analysis isolates compute efficiency on the 44 mutually completed fixture exposures across identical seeds, filtering out distorted averages caused by timeouts and execution censoring.

| Token / Latency Dimension | Configuration A (`gemini-3.8-flash-high`) | Configuration B (`claude-sonnet-5`) | Paired Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Total Tokens (44 Pairs)** | 928,540 | 7,451,910 | **+6,523,370** | **702.5%** |
| **Thinking Tokens (44 Pairs)** | 265,311 | 14,608 | **-250,703** | **-94.5%** |
| **Input Tokens (44 Pairs)** | 654,934 | 270 | **-654,664** | **-100.0%** |
| **Output Tokens (44 Pairs)** | 273,606 | 32,613 | **-240,993** | **-88.1%** |
| **Cache Read Tokens (44 Pairs)** | 1,360,824 | 7,419,027 | **+6,058,203** | **445.2%** |
| **Median Per-Exposure Latency Delta** | - | - | **-10.67s** | -10670 ms |
| **P95 Per-Exposure Latency Delta** | - | - | **+99.57s** | +99570 ms |

### 5.2 Pass-Level Aggregate Telemetry (Unadjusted)

*Note: Pass-level aggregate metrics reflect unadjusted pass totals where timeouts and schema violations skew raw run averages.*

| Metric Dimension | Configuration A | Configuration B | Aggregate Delta (B - A) | Relative Change |
| :--- | :--- | :--- | :--- | :--- |
| **Mean Total Tokens / Pass** | 397,309 | 2,798,779 | **+2,401,470** | 604.4% |
| **Mean Thinking Tokens / Pass** | 95,230 | 5,157 | **-90,073** | -94.6% |
| **Mean Execution Duration / Pass** | 675.1s | 505.3s | **-169.8s** | -25.1% |

### 5.3 Incremental Compute Cost per Replicated True Positive

- **Replicated True Positives ($TP_{replicated}$)**: 3
- **Incremental Total Tokens per Replicated TP**: +2,174,457 tokens
- **Incremental Thinking Tokens per Replicated TP**: -83,568 tokens
- **Incremental Execution Duration per Replicated TP**: -56.60s

## 6. Safe Control Specificity & Oracle Defect Disclosure

### 6.1 Clean Safe Control Specificity (Excluding Disputed Fixture)

Evaluated across genuine safe control fixtures (`HLD-01-SAFE` through `HLD-07-SAFE`, `HLD-09-SAFE`, `HLD-10-SAFE`):

| Configuration | Observed False-Positive Exposures | Completed Genuine Safe Exposures | Empirical Specificity (%) | Mean FP per Run |
| :--- | :--- | :--- | :--- | :--- |
| **Configuration A** (`gemini-3.8-flash-high`) | 0 | 25 | **100.0%** | 0.00 |
| **Configuration B** (`claude-sonnet-5`) | 8 | 18 | **55.6%** | 0.44 |
| **Clean Control Agreement** | **DIVERGENT** | - | **Divergent (100.0% vs 55.6%)** | - |

> [!NOTE] **Neutral Safe-Control Finding Disclosure**
> - Configuration A: 0 observed false-positive exposures across 25 completed genuinely-safe exposures.
> - Configuration B: 8 observed false-positive exposures across 18 completed genuinely-safe exposures.

### 6.2 Benchmark Oracle Defect Disclosure (`HLD-08-SAFE`)

Investigation into candidate detections revealed defective benchmark oracle(s) within the safe control corpus:

| Disputed Fixture | Ground Truth Label | Actual Code Property | Disputed Detections (A) | Disputed Detections (B) | Final Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HLD-08-SAFE` | `SAFE` (Defective Oracle) | DNS_REBINDING_SSRF | 1 | 2 | **GROUND_TRUTH_DISPUTE** |

**Flaw Mechanism (`HLD-08-SAFE` in `evals/holdout-benchmark/safe/08-ssrf-dns-rebinding.js`)**: Verified benchmark oracle defect: hostname is resolved and verified, but subsequent http.get(url) executes a second independent DNS resolution, allowing an attacker to rebind hostname to loopback/private IP. **Adjudication**: Oracle invalidated; fixture is genuinely vulnerable to CWE-918 SSRF via DNS rebinding.

## 7. Model-Specific Divergent Lineages

- Unique to Configuration A (Recurrent): 6 lineage(s)
- Unique to Configuration B (Recurrent): 9 lineage(s)

