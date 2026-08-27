# Threat Modeling & Directory Accounting Specification

## 1. Directory Accounting & Reconciliation Manifest (NIST SP 800-115 & Claude Security Standard)

Under the **Presumption of Non-Pass (Default-Deny)** axiom, a codebase scan cannot be declared complete unless every single top-level and major sub-directory in the repository is explicitly accounted for in a **Directory Reconciliation Manifest** (`directory-manifest.json`).

### Mandatory Directory Categories
Every directory discovered in the repository must be reconciled into exactly one of these five statuses:

| Status | Definition | Validation / Reconciliation Requirement |
| :--- | :--- | :--- |
| `SCANNED` | Active application business logic, APIs, and components under security review. | Must be indexed and audited through the triage pipeline. |
| `EXCLUDED_VENDORED` | Third-party dependencies and managed external packages. | Must match package manager declarations (e.g. `package-lock.json`, `pnpm-lock.yaml`, `go.sum`, `Cargo.lock`). |
| `EXCLUDED_GENERATED` | Build artifacts, compiled binaries, minified bundles, or transpiled code. | Must be defined in build system configs (e.g. `tsconfig.json`, `vite.config.js`, `webpack.config.js`). |
| `EXCLUDED_NON_CODE` | Static assets, documentation, design mockups, and localization markdown. | Must be verified to contain no executable scripts or server templates. |
| `EXCLUDED_TEST` | Unit tests, mock suites, and fixtures. | Verified as test attack surface. Fixtures are scanned ONLY for committed credentials. |

> [!CAUTION]
> **UNACCOUNTED_DIRECTORY_ERROR**: If any directory exists in the tree that is not explicitly assigned to one of the above 5 categories with an auditable reason, the scan is blocked and marked unverified.

---

## 2. CVSS v4.0 Base MacroVector Specification (FIRST Standard)

All findings must be calibrated against the official **FIRST CVSS v4.0** standard. Findings without a valid CVSS v4.0 MacroVector are rejected.

### MacroVector Structure (11 Dimensions)
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
