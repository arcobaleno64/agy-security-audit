# Three-Lens (3lens) 常見問題 (FAQ)

> **查核基準**：本 FAQ 以 Three-Lens 公開儲存庫指定發佈實作與測試證據為基礎，並參考 NIST SSDF (SP 800-218 v1.1) 與 OWASP ASVS 5.0.0 的相關安全原則；本文件不構成任何官方機構或外掛平台之官方認證或背書。

---

### Q1：原始碼、憑證與個資如何處理？資料會離開本機嗎？

**答**：  
外掛在執行期採取「最小權限」與「本機敏感資訊遮蔽與隔離」防禦機制：
1. **本機影子審查上下文隔離與符號連結防護**：
   在啟用審查流程時，生命週期鉤子 [`hooks/shadow-context-guard.mjs`](../hooks/shadow-context-guard.mjs) 透過 `PreToolUse` 攔截，以檔案描述符與路徑邊界檢查阻斷 CWE-59 符號連結逃逸（Symlink Escape）與路徑穿越。
2. **本機遮蔽與秘密替換**：
   標準審查流程會先在本機建立去敏副本，將符合偵測規則的金鑰、Token 等秘密替換成結構化遮蔽標記，再交由模型分析。
3. **資料處理邊界誠實揭露**：
   去敏規則無法保證辨識並過濾 100% 的所有非結構化個資或未定義的機敏資訊；若選用雲端模型服務（例如 Google Gemini 或 Anthropic Claude API），送交模型的內容包含去敏後的程式碼、檔案名稱與提示上下文，實際資料保留取決於宿主與模型供應商之資料保留政策（Data Retention Policy）。本機產出的結構化報告（SARIF/Markdown）、遮蔽記錄與稽核軌跡，亦應依專案機敏等級妥善保管。外掛本身不夾帶任何獨立第三方商業追蹤器或背景遙測回傳機制。

---

### Q2：哪些 Antigravity CLI (agy) 與系統環境適用？這是 Google 官方外掛嗎？

**答**：  
Three-Lens 是原生執行於 Antigravity CLI（agy）的**獨立開源社群外掛，沒有 Google LLC、Anthropic 或 OpenAI 官方背書、贊助或隸屬關係**。
- **核心環境需求**：
  - Antigravity CLI（`agy`）：`>= 1.2.0`（若使用 PreInvocation 終止鉤子與原生 ACP 傳輸則建議 `>= 1.5.1`）
  - Node.js：最低宣告版本為 `>= 20.0.0`，CI 相容性矩陣實測基準涵蓋至 `20.18.0+`（純 Node.js 原生標準庫實作）
  - Git：`>= 2.30.0`
  - GitHub CLI（`gh`）：選用（執行發行來源與證明驗證時需求 `>= 2.50.0`）
- **環境診斷**：
  安裝後可在外掛目錄執行 `npm run doctor`（或 `npm run doctor -- --json`）進行自動化環境與相容性檢查（詳見 [`docs/reproduction/platform-compatibility.md`](reproduction/platform-compatibility.md)）。

---

### Q3：「零外部依賴 (Zero External Dependencies)」是什麼意思？還需要其他工具嗎？

**答**：  
「零外部依賴」是指 Three-Lens 核心**完全使用 Node.js 原生內建模組**（`node:fs`、`node:path`、`node:crypto`、`node:child_process`），`package.json` 中的 `dependencies` 與 `devDependencies` 均為 0，旨在大幅降低第三方 npm 套件引入的供應鏈風險（Supply-Chain Risk）與套件劫持面。
- **系統層工具需求**：
  外掛執行仍依賴宿主作業系統具備 Node.js、AGY CLI 與 Git；選用之發行來源與 Sigstore 證明驗證另需 GitHub CLI（`gh`）。「零 npm 依賴」不代表整體環境無任何依賴或系統安全風險。
- **可信計算基 (TCB)**：
  透過 [`evals/evidence-matrix.json`](../evals/evidence-matrix.json) 追蹤 51 項實體產物 SHA-256 雜湊值與 40 項安全不變量，支援完整性比對與確定性行為驗證。

---

### Q4：與直接請單一 LLM（或 2 比 1 多數決投票）審查代碼相比，3lens 有何本質差異？

**答**：  
傳統單一 LLM 審查容易產生幻覺與高誤報率；而一般的多代理「民主投票（多數決）」則容易因語意模型的一致性偏見，覆蓋單一確定性的編譯或靜態事實。
- **合取式三視角驗證 (Conjunctive 3-Lens Verification)**：
  候選弱點必須由「可達性 (Reachability)」、「防禦控制 (Defenses)」與「實際影響 (Impact)」三種獨立專業角色分別檢驗，再由確定性 Finalizer 程式依據 Default-Deny 進行交集驗證與裁決。
- **決定性反證不可被票數推翻**：
  當任一審查視角提出具備可驗證程式碼位置與完整證據鏈的決定性反證（例如已確認阻斷攻擊路徑的參數化查詢或嚴格過濾），即使其他角色投票贊成，該弱點仍會被依 Default-Deny 規則壓制（Suppressed），有效遏止誤報。未充分證明的反證則進入人工複審（DEFERRED）。
- **客觀邊界與測試數據**：
  在公開的 L1.5 Ground-Truth 基準測試集中，確定性 Finalizer 對 10 個弱點案例與 10 個安全對照案例達成 100% 一致性裁決（20/20 PASS）；此數據反映指定測試集的決策邏輯表現，不代表真實專案中的普遍漏洞發現率。三個審查視角代表三種分工檢驗邏輯，預設不代表使用三個不同的外部模型供應商；`Clean` 僅代表在宣告的稽核範圍與規則下通過驗證，不能作為系統絕對無漏洞的商業擔保。

---

### Q5：外掛會自行修改、推送或部署程式碼嗎？

**答**：  
Three-Lens 在各階段均維持嚴格的「審查與修補權限隔離」：
1. **掃描階段唯讀**：
   審查角色僅獲取工作區唯讀與分析權限，僅寫入結構化稽核報告（SARIF 2.1.0 / Markdown）與本機去敏副本。
2. **修補隔離區 (Patch Jail)**：
   只有在明確執行 `/3lens [--patch]` 或修補流程時，系統才會在 `scratch/patches/` 隔離目錄產出候選 patch，並交由 `validate-patch.mjs` 與 `verify-fix` 進行語法及路徑邊界回歸驗證。
3. **推薦權限防護與最終裁決權**：
   專案提供推薦角色權限設定（[`recommended-security-audit-permissions.json`](../recommended-security-audit-permissions.json)），對遠端推送（`git push`）等高風險操作設定拒絕規則；實際強制效果取決於宿主（AGY）是否載入並落實該設定。修補驗證通過僅代表修復具備技術有效性，不構成自動合併、提交、推送或部署授權，最終裁決權永遠保留給開發者。
