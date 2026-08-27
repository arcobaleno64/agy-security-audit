# Antigravity (AGY) Security Audit Plugin (`security-audit`) v1.0.0

Evidence-backed, multi-stage security review and vulnerability hunting plugin for **Google Antigravity (AGY)**, modeled after Anthropic's **Claude Security**, OpenAI Codex Security principles, and NIST SP 800-115 standards.

## 核心公理：以不通過為前提 (Presumption of Non-Pass / Default-Deny)
所有受審代碼與弱點候選項目預設為 **`UNVERIFIED / NON_PASS`**。候選項目無法自行宣告 `CONFIRMED` 或 `REPORTABLE`；在無驗證者共識、法定人數不足（< 2 票）或 0 票狀態下一律強制歸類為 `DEFERRED` (`NEEDS_MANUAL_REVIEW`)。任何聲稱代碼安全或偽陽性者負有積極舉證責任（Affirmative Mitigation Proof）。當目錄核算覆蓋率不完整時，系統嚴格禁止宣告代碼庫為乾淨（Clean Claim Fail-Closed）。

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
├── package.json                          # npm test, test:evals, test:semantic, check:release (1.0.0)
├── plugin.json                           # Antigravity 外掛清單 (含 schema，無 BOM)
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
│   └── semantic-benchmark/               # L1.5 語意安全推理基準 (8 漏洞 + 4 安全防護)
├── rules/
│   └── AGENTS.md                         # 全域零信任與資料審查邊界規則
└── skills/
    └── security-audit/
        ├── SKILL.md                      # 主技能入口與工作流調度
        ├── jobs/                         # 6 大標準工作合約規格
        │   ├── scan.md                   # 全庫會計審查合約
        │   ├── review.md                 # 差異與 pre-image 審查合約
        │   ├── validate.md               # 獨立弱點校驗合約
        │   ├── deep.md                   # 多輪隨機發現與聯集合約
        │   ├── remediate.md              # 最小手術補丁生成合約
        │   └── verify-fix.md             # 補丁驗證與防禦不變量確認合約
        ├── references/
        │   ├── discovery.md              # 9 大元件 × 10 大弱點家族矩陣
        │   ├── threat-modeling.md        # 目錄會計核算制度與 CVSS v4.0 11 維向量
        │   ├── swarm-consensus.md        # 彈性子代理滑動池、4 大角色雙盲投票
        │   ├── verifier-protocol.md      # 客觀數學嚴謹度、機密脫敏與防投毒 Nonce
        │   └── patching-jail.md          # 補丁拘束器與雙軌交付
        └── scripts/
            ├── safe-git.mjs              # 防禦型 Git Provenance 與 Pre-image 提取
            ├── finalize-scan.mjs         # 確定性 Security Authority 與 Canonical Finalizer
            ├── render-sarif.mjs          # SARIF 2.1.0 / Markdown 渲染與 66 項不變量測試
            ├── build-inventory.mjs       # 地面真值目錄會計清單生成器
            ├── build-threat-model.mjs    # 確定性威脅模型生成器
            ├── validate-attack-path.mjs  # 攻擊路徑 Schema 校驗與證明缺口 (Proof Gap) 偵測
            ├── validate-patch.mjs        # 補丁語法、Patch Jail、過期檢測與修復驗證
            ├── run-evals.mjs             # 50 題確定性安全不變量與對抗迴歸套件
            ├── run-semantic-eval.mjs     # L1.5 語意安全推理精確度基準測試
            └── check-release-invariants.mjs # Section 24 發行不變量閘門 (100% 規格無殘留驗證)
```

---

## 測試與發行驗證
在專案目錄內執行：
```bash
# 執行 66 項全域安全不變量自動化測試：
npm test

# 執行 50 題確定性安全不變量與對抗迴歸套件：
npm run test:evals

# 執行 L1.5 語意安全推理精確度基準測試 (12 案例)：
npm run test:semantic

# 執行 Section 24 發行閘門檢驗 (檢查 32 項規格、15 項安全不變量與零外部依賴)：
npm run check:release
```

