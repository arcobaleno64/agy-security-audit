# Antigravity (AGY) Security Audit Plugin (`security-audit`)

Evidence-backed, multi-stage security review and vulnerability hunting plugin for **Google Antigravity (AGY)**, modeled after Anthropic's **Claude Security**, OpenAI Codex Security principles, and NIST SP 800-115 standards.

## 核心公理：以不通過為前提 (Presumption of Non-Pass / Default-Deny)
所有受審代碼與弱點候選項目預設為 **`UNVERIFIED / NON_PASS`**。候選項目無法自行宣告 `CONFIRMED` 或 `REPORTABLE`；在無驗證者共識、法定人數不足（< 2 票）或 0 票狀態下一律強制歸類為 `DEFERRED` (`NEEDS_MANUAL_REVIEW`)。任何聲稱代碼安全或偽陽性者負有積極舉證責任（Affirmative Mitigation Proof）。當目錄核算覆蓋率不完整時，系統嚴格禁止宣告代碼庫為乾淨（Clean Claim Fail-Closed）。

---

## 5 大啟動自訂選項 (Customization Dimensions)
使用者在啟動時可透過命令列參數指定，或由互動式選單動態配置：

```text
/security-audit [--scope <codebase|changes|secrets|path>] [--workers <N>] [--strictness <paranoid|balanced|blocking>] [--patch] [--export]
```

1. **子代理規模 (`--workers <N>`)**：快速 (2) / 標準 (4, 預設) / 窮舉 (8) / 自訂 (1~16)。
2. **審查範疇 (`--scope`)**：Git 變更 (預設) / 全庫會計盤點 / 僅掃機密 / 指定目錄。
3. **嚴苛門檻 (`--strictness`)**：偏執零信任 (R >= 0.85, 預設) / 標準平衡 (R >= 0.70) / 僅高危阻斷。
4. **補丁建議 (`--patch`)**：僅產出報告 / 雙軌補丁試套 (受 Patch Jail 保護，並經 `git apply --check` 驗證)。
5. **導出目標 (`--export`)**：Brain 私有存儲 (預設) / 專案 reports 目錄。

---

## 目錄結構
```text
security-audit/
├── package.json                          # npm test 腳本配置 (0.9.1)
├── plugin.json                           # Antigravity 外掛清單 (含 schema，無 BOM)
├── SECURITY.md                           # 誠實信任模型與沙箱邊界說明
├── rules/
│   └── AGENTS.md                         # 全域零信任與資料審查邊界規則
└── skills/
    └── security-audit/
        ├── SKILL.md                      # 主技能入口與工作流調度
        ├── references/
        │   ├── threat-modeling.md        # 目錄會計核算制度與 CVSS v4.0 11 維向量
        │   ├── swarm-consensus.md        # 彈性子代理滑動池、4 大角色雙盲投票
        │   ├── verifier-protocol.md      # 客觀數學嚴謹度、機密脫敏與防投毒 Nonce
        │   └── patching-jail.md          # 補丁拘束器與雙軌交付
        └── scripts/
            ├── safe-git.mjs              # 防禦型 Git Provenance 提取模組
            ├── finalize-scan.mjs         # 確定性 Security Authority 與 Canonical Finalizer
            └── render-sarif.mjs          # SARIF 2.1.0 / Markdown 渲染與 17 項 P0 驗證測試
```

---

## 測試與驗證
在專案目錄內執行：
```bash
npm test
# 或直接執行腳本測試：
node skills/security-audit/scripts/render-sarif.mjs --test
```
