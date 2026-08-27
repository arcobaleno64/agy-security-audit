# Job Specification: Multi-Run Deep Scan (`deep`)

## Overview
The `deep` job executes multi-pass stochastic exploration across the **Component × Vulnerability Family Discovery Matrix**, designed to eliminate single-pass blindness and discover complex, multi-hop vulnerability chains.

## Workflow

### 1. Multi-Pass Discovery Execution
- Parameter `--runs N` (default: 3 runs, minimum: 2).
- Each run independently dispatches discovery subagents (`agents/discovery-agent.md`) across the Component × Family matrix.
- Each run produces a candidate set: $C_1, C_2, \dots, C_N$.

### 2. Candidate Union & Fingerprint Deduplication
- Compute stable SHA-256 fingerprint for each candidate:
  $$\text{Fingerprint} = \text{SHA256}(\text{ruleId} \mathbin{\Vert} \text{uri} \mathbin{\Vert} \text{startLine})$$
- Form the unified candidate set:
  $$C_{\text{union}} = \bigcup_{k=1}^N C_k$$
- Merge hypotheses, preserving all candidate dataflow steps, sources, and sinks.
- Calculate candidate discovery recurrence frequency across runs.

### 3. Proof-Gap Tracking
For each candidate in $C_{\text{union}}$:
- Map intermediate dataflow steps from entrypoint to sink.
- If an intermediate step has unresolved control-flow branch or unvalidated transformation, record:
  ```json
  "proofGaps": [
    {
      "stepIndex": 2,
      "unprovenProperty": "Session state validity across async dispatch",
      "location": "src/queue/consumer.ts:54"
    }
  ]
  ```
- Any candidate with unclosed proof gaps cannot achieve `CONFIRMED` and is deferred to `NEEDS_MANUAL_REVIEW`.

### 4. 3-Lens Verification & Authority Finalization
- Pass $C_{\text{union}}$ through the Fixed 3-Lens Verifier Panel.
- Execute `finalize-scan.mjs` to generate authoritative SARIF and Markdown audit reports.

