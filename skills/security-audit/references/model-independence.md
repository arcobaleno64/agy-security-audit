# Model & Provider Independence Specification (R2-P2-03)

## 1. Overview & Architecture

The `security-audit` plugin is architected strictly around **declarative, verifiable data contracts** rather than model-specific prompting behaviors or provider-dependent features. This guarantees that:
1. Any high-capability frontier model (Claude 3.7 Sonnet / Opus, Gemini 1.5 / 2.0 Pro / Ultra, GPT-4o / o3, DeepSeek R1, or calibrated open-weights models) can execute Coordinator, Discovery, or Verifier roles without altering verification invariants.
2. Verification decisions, evidence binding, consensus calculations, CVSS derivation, and SARIF/Markdown rendering are executed by **deterministic, model-independent JavaScript code** in `finalize-scan.mjs`, `validate-patch.mjs`, and `standards-mapping.mjs`.
3. The plugin supports **Triad-Flow Multi-Provider Orchestration**, allowing discovery subagents, verification subagents, and coordinator processes to run on completely separate models or providers without breaking task correlation.

---

## 2. Standardized Role & Capability Contracts

Every subagent contract in `agents/*.md` and `skills/security-audit/jobs/*.md` conforms to standard schema definitions:

### 2.1 Threat Modeler (`agents/threat-modeler.md`)
- **Capability Requirements**: Read-only repository traversal (`view_file`, `list_dir`, `grep_search`, `find_by_name`). Command execution disabled (`commandExecutionPolicy: off`).
- **Input Contract**: Repository inventory manifest (`scan-manifest.schema.json`).
- **Output Contract**: Conforms to `schemas/threat-model.schema.json`. Every component must be bound to verifiable file paths and manifests (`originManifest`); unevidenced boundaries must be marked `ASSUMPTION`.

### 2.2 Discovery Agent (`agents/discovery-agent.md`)
- **Capability Requirements**: Read-only repository exploration (`view_file`, `list_dir`, `grep_search`, `find_by_name`). Command execution disabled.
- **Input Contract**: Threat model components x vulnerability families matrix cell.
- **Output Contract**: Conforms to `schemas/candidate.schema.json`.
  - There is no finding quota. Cells without evidence must return `REVIEWED_NO_CANDIDATE` with verified reviewed paths.
  - Candidate hypotheses must specify `securityProperty`, `findingType`, `proofKind`, and unbroken `location`.

### 2.3 Fixed 3-Lens Verifiers (`agents/verifier-*.md`)
- **Capability Requirements**: Least-privilege read-only inspection. No filesystem write or command execution capabilities.
- **Input Contract**: Candidate finding tuple + task correlation nonce.
- **Output Contract**: Conforms to `schemas/verifier-ballot.schema.json`:
  ```xml
  <audit_verdict nonce="NONCE_UUID">
    <findingId>SEC-001</findingId>
    <lens>REACHABILITY | DEFENSES | IMPACT</lens>
    <decision>SUPPORTS | REFUTES</decision>
    <proofKind>STATIC_TRACE | UNIT_TEST | ...</proofKind>
    <rationale>Detailed analysis</rationale>
    <evidence>
      <location path="src/file.js" line="42" />
    </evidence>
  </audit_verdict>
  ```
  - Double-blind structured return directly to Coordinator.
  - Verifiers are prohibited from writing files or self-certifying findings.

---

## 3. Model Behavior Provenance (R2-P2-04)

To ensure audit trail integrity without asserting unobservable model internals:
1. **Reported Metadata**:
   - `modelProvider`: Provider identifier (e.g. `anthropic`, `google`, `openai`, `local`).
   - `modelIdentifier`: Specific model name (e.g. `claude-3-7-sonnet`, `gemini-2.0-pro`).
   - `executionDate`: ISO-8601 timestamp.
   - `toolVersion`: Plugin release version (`1.0.0`).
   - `promptContractVersion`: Specification version (`1.0.0`).
2. **System Prompt Integrity**:
   - Runtime cannot independently verify internal proprietary system instructions without cryptographically signed provider attestations.
   - Therefore, `systemPromptIntegrity` is truthfully reported as `UNKNOWN` rather than claiming unverifiable perfection.

---

## 4. Multi-Provider Orchestration Invariants

1. **Deterministic Authority**: No model output is authoritative by itself. All candidates, votes, and patch validations pass through deterministic schema validators (`validateCanonicalFindings`, `validateAttackPath`, `verifyRemediation`).
2. **Anti-Confusion Nonces**: Task nonces prevent cross-finding hallucination or ballot injection across diverse LLM threads.
3. **Evidence-Binding Priority**: An LLM verdict unsupported by physical file paths and line hashes is downgraded to `DEFERRED fail-closed` regardless of which model emitted it.
