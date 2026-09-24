# Platform Compatibility & Transparency Matrix

> **Acceptance Criterion D-AC-07**: Platform support explicitly broken down into empirical evidence grades.

`@arcobaleno64/agy-security-audit` rejects ambiguous claims of "cross-platform support". Instead, platform capability is categorized into five strict, testable **Evidence Grades**:

```text
Evidence Grades:
1. LIVE_RUNTIME_VALIDATED : Confirmed through end-to-end execution of real LLM / AGY CLI sessions.
2. CI_TESTED              : Verified on every commit and PR across multi-platform GitHub Actions runners.
3. DECLARED               : Architecturally supported and conforming to standards, but not continuously tested in CI.
4. UNKNOWN                : Non-standard environments with unverified runtime behaviors.
5. UNSUPPORTED            : Explicitly blocked or failing minimum capability prerequisites.
```

---

## 1. Operating Systems & Hardware Architectures

| Platform | Architecture | Evidence Grade | Verification Source | Doctor Check ID |
|---|---|---|---|---|
| **Ubuntu Linux 22.04 / 24.04** | `x64` | `LIVE_RUNTIME_VALIDATED` | CI Matrix + G7-R/G8-R evaluation runs | `platform`, `node`, `git` |
| **Microsoft Windows 10 / 11** | `x64` | `LIVE_RUNTIME_VALIDATED` | Windows CI + Track D Tier 2 live canary runs | `platform`, `node`, `git` |
| **Apple macOS 14 (Sonoma) / 15 (Sequoia)** | `ARM64` (Apple Silicon) | `CI_TESTED` | Multi-OS GitHub Actions CI workflow | `platform`, `node`, `git` |
| **Apple macOS 13 / 14** | `x64` (Intel) | `CI_TESTED` | Multi-OS GitHub Actions CI workflow | `platform`, `node`, `git` |
| **Debian / RedHat / Fedora Linux** | `ARM64` | `DECLARED` | Conforms to Linux POSIX / Node.js ESM standards | `platform`, `node` |
| **Alpine Linux** | `x64` | `UNKNOWN` | musl libc runtime differences not yet qualified | `platform` |
| **32-bit Systems (x86, ARM32)** | Any | `UNSUPPORTED` | Blocked by 64-bit memory and AST parsing requirements | `platform` |
| **FreeBSD / OpenBSD / NetBSD** | Any | `UNSUPPORTED` | Not currently targeted by Antigravity CLI | `platform` |
| **Mobile / Android / iOS** | Any | `UNSUPPORTED` | CLI and subprocess model incompatible | `platform` |

---

## 2. Shell & Terminal Environments

| Shell | Platform | Evidence Grade | Notes |
|---|---|---|---|
| **PowerShell Core (`pwsh`)** | Windows, Linux, macOS | `LIVE_RUNTIME_VALIDATED` | Subprocess calling contract verified without CRLF corruption. |
| **Windows PowerShell (`powershell.exe` 5.1)** | Windows | `CI_TESTED` | Standard Windows runner shell on GitHub Actions. |
| **Bash (`bash` >= 4.0)** | Linux, macOS | `LIVE_RUNTIME_VALIDATED` | Standard environment for CI runners and clean-room containers. |
| **Z Shell (`zsh`)** | macOS, Linux | `DECLARED` | Standard macOS interactive default shell. |
| **Windows Command Prompt (`cmd.exe`)** | Windows | `DECLARED` | Works for direct `npm run` commands, but pwsh recommended. |

---

## 3. Runtime & Tooling Prerequisites

| Dependency | Minimum Version | Evidence Grade | Failure Status | Failure Impact |
|---|---|---|---|---|
| **Node.js** | `>= 20.18.0` | `LIVE_RUNTIME_VALIDATED` | `UNSUPPORTED` | Execution blocked. Built-in crypto and ESM required. |
| **Git** | `>= 2.30.0` | `LIVE_RUNTIME_VALIDATED` | `UNSUPPORTED` | Execution blocked. Git diff inspection required. |
| **Antigravity CLI (`agy`)** | `>= 1.2.0` | `LIVE_RUNTIME_VALIDATED` | `DEGRADED` (Tier 1) / `UNSUPPORTED` (Tier 2) | Tier 1 passes offline; Tier 2 live audit blocked. |
| **GitHub CLI (`gh`)** | `>= 2.50.0` | `LIVE_RUNTIME_VALIDATED` | `DEGRADED` | Local integrity passes; Sigstore attestation verification disabled. |
| **npm** | `>= 10.0.0` | `LIVE_RUNTIME_VALIDATED` | `UNSUPPORTED` | Script execution blocked. |

---

## 4. Verification via Deterministic Environment Doctor

To determine your host's exact compatibility and capability status, execute:

```bash
npm run doctor
```

Or for machine-readable JSON output:

```bash
npm run doctor -- --json
```

The Doctor automatically maps your host's environment against this compatibility matrix:
- **`READY`**: Host satisfies all required prerequisites for Tier 1 and Tier 2.
- **`DEGRADED`**: Host can run Tier 1 deterministic gates, but lacks non-essential tools (e.g. `gh` CLI).
- **`UNSUPPORTED`**: Host lacks essential prerequisites (e.g. Node.js < 20.18.0 or unsupported OS architecture).
- **`UNVERIFIABLE`**: Host configuration is present (e.g. sandbox permissions JSON) but live sandbox enforcement has not yet been directly observed.
