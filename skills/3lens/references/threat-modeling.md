# Threat Modeling & Directory Accounting Specification

## 1. Directory Accounting & Reconciliation Manifest (NIST SSDF SP 800-218 & Bounded Assurance)

Under the **Presumption of Non-Pass (Default-Deny)** axiom, a codebase scan cannot be declared complete unless every single top-level and major sub-directory in the repository is explicitly accounted for in a **Directory Reconciliation Manifest** (`directory-manifest.json`).

### Mandatory Directory Categories
Every directory and file discovered in the repository must be reconciled into one of these authoritative coverage categories (R2-P0-10):

| Status / Classification | Attack Surface Scope | Validation / Reconciliation Requirement |
| :--- | :--- | :--- |
| `SCANNED_RUNTIME` | Active application business logic, APIs, and runtime components. | Must be indexed and audited through the 3-Lens verification pipeline. |
| `SCANNED_BUILD` | Project build manifests, bundlers, compilers (`package.json`, `Cargo.toml`, etc.). | Scanned for dependency confusion, malicious lifecycle scripts, and pin tampering. |
| `SCANNED_CI` | CI/CD workflows and deployment automation (`.github/`, Dockerfiles). | Scanned for pipeline integrity failure, runner command injection, and secret disclosure risk. |
| `SCANNED_AGENT_CONTEXT` | Agent skills, rules, and prompt orchestration instructions (`AGENTS.md`, `SKILL.md`). | Scanned for prompt injection, instruction-integrity risk affecting tool invocation, and trust-boundary evasion. |
| `SCANNED_TEST_EXECUTABLE` | Test suites, test runners, and test helpers. | **NOT blanket excluded**; scanned for unsafe process execution, injection, and secrets. |
| `EXCLUDED_VENDORED` | Third-party dependencies (`node_modules/`, `vendor/`). | Must match package manager declarations (`package-lock.json`, `Cargo.lock`, etc.). |
| `EXCLUDED_GENERATED_VERIFIED` | Build output artifacts confirmed as generated from source (`dist/`, `build/`). | Verified against compiler build output configuration. |
| `EXCLUDED_STATIC_ASSET` | Static images, media, documentation markdown, or binary assets. | Verified to contain no executable scripts or server templates. |

> [!CAUTION]
> **UNACCOUNTED_DIRECTORY_ERROR**: If any directory or file exists in the tree that is not explicitly assigned to one of the above categories with an auditable reason, the scan fails closed to `PARTIAL` under Default-Deny.

### 1.2 Multi-Profile & Multi-Language Threat Modeling Pipeline (R2-P0-09)
To prevent framework bias, threat modeling executes in a strict 3-stage pipeline:
1. **Stage A — Deterministic Inventory Facts**:
   - Detects languages: JS/TS, Python, Go, Rust, Java, C#, C/C++, Terraform, etc.
   - Detects entrypoints with verifiable file paths and lines.
   - Classifies target profile: `web-api`, `web-app`, `cli`, `library`, `agent-plugin`, `infra`, `native`, `mixed`.
2. **Stage B — Semantic Component Discovery**:
   - Maps architectural components with verified file-level evidence: `{ path, manifestOrigin, confidence }`.
3. **Stage C — Fact vs. Assumption Reconciliation**:
   - Every actor, asset, entrypoint, and trust boundary must be grounded in physical code evidence (`status: 'FACT'`).
   - Any claim lacking concrete evidence is strictly classified as `status: 'ASSUMPTION'`.

---

## 2. CVSS v4.0 Base Metric Vector Specification (FIRST Standard)

All findings must be calibrated against the official **FIRST CVSS v4.0** standard. Findings without a valid CVSS v4.0 Base Metric Vector are rejected.

> [!IMPORTANT]
> **Base Metric Vector vs MacroVector**:
> The 11 Base metrics form the foundational Base Metric Vector. MacroVectors are an internal lookup structure within the official FIRST scoring algorithm and must not be confused with the raw 11-dimension metric vector. If an official score calculator or verified external score is not available, the finding is assigned `score: null` and qualitative severity `UNRATED` without guessing or fabricating scores.

### Base Metric Vector Structure (11 Dimensions)
```text
CVSS:4.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]
```

1. **Attack Vector (AV)**: Network (`N`), Adjacent (`A`), Local (`L`), Physical (`P`)
2. **Attack Complexity (AC)**: Low (`L`), High (`H`)
3. **Attack Requirements (AT)**: None (`N`), Present (`P`)
4. **Privileges Required (PR)**: None (`N`), Low (`L`), High (`H`)
5. **User Interaction (UI)**: None (`N`), Passive (`P`), Active (`A`)
6. **Vulnerable System Impact (VC / VI / VA)**: Confidentiality, Integrity, Availability (`H` / `L` / `N`)
7. **Subsequent System Impact (SC / SI / SA)**: Confidentiality, Integrity, Availability (`H` / `L` / `N`)

### Severity Calibration Matrix
- **CRITICAL** ($9.0 - 10.0$): Remotely exploitable without credentials; arbitrary code execution, SQLi with full DB write/read, remote privilege takeover.
- **HIGH** ($7.0 - 8.9$): Exploitable with low privileges or network access; SSRF to cloud metadata, stored XSS in admin panel, high-impact auth bypass.
- **MEDIUM** ($4.0 - 6.9$): Exploitable under complex preconditions; reflected XSS with modern browser protection, path traversal with restricted read.
- **LOW** ($0.1 - 3.9$): Informational risk, defense-in-depth gaps, verbose error disclosure, weak cookie attributes.

---

## 3. Three-Tier Triage Protocol (1M Token Context Optimization)

To prevent the **Lost in the Middle** attention-decay phenomenon in large repositories, code discovery is staged in three strict tiers:

```
[Tier 1: Directory Accounting] -> [Tier 2: High-Risk Sink Triage] -> [Tier 3: 50k-Token Chunk Review]
```

### Tier 1: Directory Accounting Pre-Filter
Filter out verified vendored/generated/non-code directories according to the manifest.

### Tier 2: High-Risk Sink Triage (`grep_search`)
Rapidly map all call sites of high-risk sinks using native grep:
- **Command / Shell Sinks**: `child_process`, `exec`, `execFile`, `spawn`, `Process.Start`, `os.system`
- **Dynamic Eval / Deserialization**: `eval`, `Function(`, `vm.runInContext`, `pickle.loads`, `yaml.load`
- **Filesystem & Path Sinks**: `fs.readFile`, `fs.writeFile`, `path.join`, `File.Open`, `send_file`
- **SQL / NoSQL Query Sinks**: `rawQuery`, `db.query`, `execSQL`, `$where`, unescaped string interpolation
- **DOM / Output Sinks**: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, unescaped template tags
- **Credential / Secret Signatures**: High-entropy strings, `AKIA[0-9A-Z]{16}`, `ghp_[0-9a-zA-Z]{36}`, private keys

### Tier 3: 50k-Token Modular Chunking
Group identified sinks and their input flow pathways into cohesive batches:
- Maximum 15 interrelated files per batch.
- Maximum 50,000 tokens per subagent inspection turn.
- Untrusted code is strictly encapsulated within XML data boundaries.
