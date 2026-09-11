# agy-security-audit (plugin ID: `security-audit`) v1.1.1

以證據為本、多階段的安全保證與弱點驗證外掛，專為 **Google Antigravity (AGY)** 打造，對齊 **NIST SSDF (SP 800-218)**、**OWASP ASVS 5.0.0**、**OWASP SAMM**、**CWE 分類法**、**CVSS v4.0** 與 **SARIF 2.1.0**，並融入 Anthropic Claude Security 與 OpenAI Codex Security 研究等前沿代理安全框架的防禦性架構概念。

[English →](README.md)

`agy-plugin-cc` 的姊妹專案：`agy-plugin-cc` 負責把審查工作從 Claude Code 委派給 AGY 作為跨模型審查者，`agy-security-audit` 則是原生跑在 AGY 內部的安全保證外掛。[`agy-plugin-cc`](https://github.com/arcobaleno64/agy-plugin-cc)

## 核心公理：權威聲明以不通過為前提 (Default-Deny on Authority Claims)

所有權威聲明（弱點候選項目、補丁修復與覆蓋率完整性）預設為 **`UNVERIFIED`**。受審代碼本身不預設存在漏洞，審查合理產生 0 候選項（Zero Findings，無配額壓力）；候選項目無法自行宣告 `CONFIRMED` 或 `REPORTABLE`；在無驗證者共識、法定人數不足（< 2 票）或 0 票狀態下一律強制歸類為 `DEFERRED` (`NEEDS_MANUAL_REVIEW`)。當目錄核算覆蓋率不完整時，系統嚴格禁止宣告代碼庫為乾淨（Clean Claim Fail-Closed）。宣告乾淨（Clean）代表在界定範圍內無已驗證且未修復之實質弱點與證據缺口，屬於有界保證（Bounded Assurance），而非萬無一失的絕對認證。

---

## 審查意圖與收斂語義 (Audit Intents)

1. **`DISCOVERY`**: 開放式探索代碼庫組件與弱點家族矩陣，產生附帶客觀證據之候選假說。無發現配額，0 弱點為合法常態。
2. **`VALIDATION`**: 針對特定候選項進行獨立 3-Lens 面板審核，判定最終處置。
3. **`REGRESSION`**: 補丁驗證與覆蓋收斂模式。重跑時僅重審受變更影響的攻擊面，防止無止盡的發散探索。

---

## 支援工作合約 (Operational Job Modes)

1. **`scan`**: 全代碼庫弱點掃描，採用嚴格確定性目錄會計制度 (`Directory Accounting`)。
2. **`review`**: 針對 Git commit/PR 變更之增量審查，100% 核對變更與刪除檔案，並透過安全 pre-image 檢視歷史原貌。
3. **`validate`**: 針對現有弱點報告進行獨立驗證，無需全庫重掃即可檢驗單一候選項。
4. **`deep`**: 多輪隨機發現 (`Multi-Run Deep Scan`)，採用長度前綴確定性指紋去重並統計再現次數 (`recurrenceCount`)。
5. **`remediate`**: 於獨立 `scratch/patches/` 沙箱內生成最小手術式補丁，受 Patch Jail 周界防護。
6. **`verify-fix`**: 補丁驗證合約，結合 3-Lens 驗證專家團（DEFENSES、REACHABILITY、IMPACT）與基準過期檢測 (`detectStalePatch`)，嚴格防止迴歸與後門。

---

## 3-Lens 驗證面板 (Conjunctive 3-Lens Verifier Panel)

採用合取邏輯 (Conjunctive Logic)，防止 2-to-1 民主式投票覆蓋具體技術事實：
- **Reachability Lens**: 檢驗呼叫圖與污點路徑可達性；若反駁 (`REFUTES`) 則判定不可達。
- **Defenses Lens**: 檢驗消毒器與安全不變量；反駁必須附帶行號與證據 (`mitigationProofLine` + `mitigationReason`)，阻斷民主投票碾壓。
- **Impact Lens**: 驗證 CVSS v4 11 維向量與實質危害；反駁必須證明無實質危害。

---

## 目錄結構

```text
security-audit/
├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (1.0.1)
├── plugin.json                           # Antigravity 外掛清單 (含 schema，無 BOM)
├── hooks.json                            # Antigravity PreToolUse 生命週期勾點註冊
├── hooks/                                # 生命週期勾點實作
│   └── shadow-context-guard.mjs          # PreToolUse 執行期透明路徑重導向至 scratch/context/
├── SECURITY.md                           # 誠實信任模型與沙箱邊界說明
├── agents/                               # 專責子代理定義 (位於外掛根目錄)
│   ├── threat-modeler.md                 # 威脅建模專員
│   ├── discovery-agent.md                # 9x10 矩陣探索專員
│   ├── verifier-reachability.md          # 3-Lens 可達性檢驗專家
│   ├── verifier-defenses.md              # 3-Lens 防禦機制檢驗專家
│   └── verifier-impact.md                # 3-Lens 危害校準檢驗專家
├── evals/                                # 測試語料庫與語意基準
│   ├── vulnerable/                       # 10 大地面真值漏洞 (True Positives)
│   ├── safe/                             # 10 大修復對照組防禦屏障 (False Positive Guards)
│   ├── prompt-injection/                 # 5 大提示詞注入穿透測試
│   ├── report-injection/                 # 5 大報告投毒與控制字元測試
│   ├── secret-leak/                      # 5 大機密憑證脫敏測試
│   ├── coverage-gap/                     # 5 大會計覆蓋邊界測試
│   ├── git-config/                       # 5 大惡意 Git 配置隔離測試
│   ├── patch-regression/                 # 5 大惡意補丁與陳舊基準測試
│   └── semantic-benchmark/               # L1.5 配置地面真值基準 (12 決策不變量對照組)
├── schemas/                              # R2-P1-08 版本化 JSON 綱要 (Draft-07)
│   ├── scan-manifest.schema.json         # 目錄會計清單綱要
│   ├── threat-model.schema.json          # 威脅模型綱要
│   ├── candidate.schema.json             # 候選弱點綱要 (Security Property & Lineage)
│   ├── verifier-ballot.schema.json       # 檢驗選票綱要 (3-Lens 證據綁定)
│   ├── canonical-finding.schema.json     # 權威規範弱點綱要 (分類法與原因碼)
│   ├── execution-attestation.schema.json # 執行證明綱要 (階段覆蓋完整性)
│   ├── audit-baseline.schema.json        # 審查基準狀態綱要 (歷史狀態基準)
│   └── empirical-benchmark-run.schema.json # 實證基準執行封套綱要
├── rules/
│   └── AGENTS.md                         # 全域零信任與資料審查邊界規則
└── skills/
    └── security-audit/
        ├── SKILL.md                      # 主技能入口與工作流調度
        ├── standards/                    # R2-P1-01 標準映射層
        │   ├── standards-map.json        # CWE -> ASVS 5.0 / SSDF / OWASP 映射
        │   └── applicability-profiles.json # 專案類型適用性設定檔
        ├── jobs/                         # 6 大標準工作合約規格
        │   ├── scan.md                   # 全庫會計審查合約
        │   ├── review.md                 # 差異與 pre-image 審查合約
        │   ├── validate.md               # 獨立弱點校驗合約
        │   ├── deep.md                   # 多輪隨機發現與聯集合約
        │   ├── remediate.md              # 最小手術補丁生成合約
        │   └── verify-fix.md             # 補丁驗證與防禦不變量確認合約
        ├── references/
        │   ├── discovery.md              # 9 大元件 × 10 大弱點家族矩陣
        │   ├── patching-jail.md          # 補丁監獄邊界規格
        │   ├── swarm-consensus.md        # 3-Lens 連取共識規範
        │   ├── threat-modeling.md        # 威脅建模與 11 維向量基準
        │   ├── verifier-protocol.md      # 檢驗協議與證據綁定不變量
        │   ├── finding-lineage.md        # 弱點血統追蹤與指紋架構
        │   └── safe-proof-policy.md      # 安全防禦證明政策與禁止指令
        └── scripts/
            ├── path-containment.mjs      # 權威 TCB 路徑包容與抗 TOCTOU 原子檔案讀取器
            ├── safe-git.mjs              # 強化安全 Git 執行隔離器
            ├── finalize-scan.mjs         # 權威確定性終審器與標準整合
            ├── standards-mapping.mjs     # 業界標準映射與依賴邊界檢測器
            ├── render-sarif.mjs          # SARIF 2.1.0 / Markdown 渲染與 114 項不變量測試
            ├── build-inventory.mjs       # 地面真值目錄會計清單生成器
            ├── build-threat-model.mjs    # 確定性威脅模型生成器
            ├── validate-attack-path.mjs  # 攻擊路徑 Schema 2.0 校驗與證明缺口偵測
            ├── validate-patch.mjs        # 補丁語法、Patch Jail、過期檢測與修復驗證
            ├── run-evals.mjs             # 50 題確定性安全不變量與對抗迴歸套件
            ├── run-semantic-eval.mjs     # L1.5 決策地面真值基準測試 (Disposition Ground-Truth)
            ├── run-discovery-eval.mjs    # 代理發現評測套件 (Simulated CI / Recorded Agent Run)
            ├── run-stability-eval.mjs    # 發現穩定度與多輪實證基準評測引擎
            ├── record-benchmark-run.mjs  # 真實模型實證基準封套記錄工具
            └── check-release-invariants.mjs # Section 24 發行不變量閘門 (55 項檔案，38 項安全不變量)
```

---

## 測試與發行驗證

在專案目錄內執行：
```bash
# 執行全域安全不變量自動化測試：
npm test

# 執行 50 題確定性安全不變量與對抗迴歸套件：
npm run test:evals

# 執行 L1.5 處置決策地面真值基準測試 (12 案例)：
npm run test:semantic

# 執行代理發現評測基準測試 (Simulated CI)：
npm run test:discovery

# 執行穩定度基準測試 (Synthetic Harness)：
npm run test:stability

# 執行 Section 24 發行閘門檢驗 (檢查必要規格、安全不變量與零外部依賴)：
npm run check:release
```

---

## 公開基準宣稱政策 (Public Benchmark Claims Policy - R2-P2-02)

本工具嚴格遵循誠實揭露原則，不進行誇大或誤導性宣稱：
- **不宣稱「100% 準確率」或「絕對無漏洞」**：Clean 審查結果僅代表在**宣告範圍內完成定義覆蓋**、未發現具備驗證證據之可報告問題，並非全域安全證明。
- **測試集與基準測量透明度揭露**：
  - **確定性安全不變量與對抗迴歸套件**：50 案例（覆蓋 8 種邊界威脅），驗證確定性規則與防禦邊界（Invariant Rate: 100%）。
  - **L1.5 處置決策地面真值基準**：12 案例（8 漏洞，4 安全防護），評測 Finalizer 確定性處置決策邏輯，不代表真實 LLM 隨機發現率。
  - **代理發現評測 Harness**：內建 8 個 vulnerable ground-truth cases，以 SIMULATED_CI 驗證評測管線；實際模型 discovery precision/recall 僅在提供 recorded agent candidates (`--candidates`) 後計算；本 release 未附 empirical model benchmark 時，公開結果標示為 NOT MEASURED。
  - **穩定度評測 Harness**：synthetic mode 驗證 lineage/Jaccard/convergence 計算管線；empirical stability 需至少 2 組 recorded model runs (`--runs-dir`)；若未提供 recorded runs，公開狀態為 NOT MEASURED。

| 基準測試項目 (Benchmark) | 語料規模 (Corpus) | 測量類型 (Measurement Type) | 公開狀態 (Status) |
| :--- | :--- | :--- | :--- |
| 確定性安全不變量 (Deterministic Invariants) | 50 案例 (8 類邊界威脅) | 確定性規則測量 (MEASURED) | 100% PASS |
| 處置決策地面真值 (Disposition Ground Truth) | 12 案例 (8 弱點 / 4 防護) | 確定性決策測量 (MEASURED) | 100% PASS |
| 代理發現評測 Harness (Discovery Harness) | 8 弱點真值案例 | 合成管線自檢 (SYNTHETIC PIPELINE TEST) | PASS (SIMULATED_CI) |
| 實證代理發現 (Empirical Discovery) | 需提供 `--candidates` | 實體模型觀測 (RECORDED MODEL RUN) | NOT MEASURED (未附錄) |
| 穩定度評測 Harness (Stability Harness) | 3 語料庫合成 pass | 合成管線自檢 (SYNTHETIC PIPELINE TEST) | PASS (SYNTHETIC_HARNESS) |
| 實證隨機穩定度 (Empirical Stability) | 需提供 `--runs-dir` | 實體模型多輪觀測 (RECORDED MULTI-RUN) | NOT MEASURED (未附錄) |

- **模型無關架構**：所有代理契約均採用資料架構與 JSON Schema 進行嚴格規格化，協調器與裁決核心不依賴任何特定 LLM 之專有隱藏行為。

---

## 授權與治理規範 (Governance & Defensive Use - R2-P2-07)

- 本專案採用 **MIT 授權條款**（詳見 [LICENSE](LICENSE)）。
- **專案範疇與防禦用途聲明**：本工具專為合法授權之防禦性安全審查、弱點驗證與防禦性研發設計並提供支援。非設計、不預期亦不支援用於未經授權之滲透測試、漏洞利用、破壞性指令執行、憑證重用或非經同意之外部系統探測。
