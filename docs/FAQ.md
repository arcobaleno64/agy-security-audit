# Three-Lens (3lens) 常見問題 (FAQ)

> **查核基準**：依據專案最新發佈版本（commit 基準與靜態程式碼結構）、NIST SSDF (SP 800-218) 與 OWASP ASVS 5.0.0 規範整理。

---

### Q1：原始碼、憑證與個資如何處理？資料會離開本機嗎？

**答**：  
外掛在執行期採取「最小權限」與「本地去敏隔離」防禦機制：
1. **本地端影子上下文隔離與符號連結防護**：
   透過生命週期鉤子 [`hooks/shadow-context-guard.mjs`](../hooks/shadow-context-guard.mjs) 實作 `PreToolUse` 攔截，以原子級檔案描述符限制路徑邊界，阻斷 CWE-59 符號連結逃逸（Symlink Escape）與路徑穿越。
2. **本機去敏與秘密遮蔽**：
   標準審查流程會先在本機建立去敏副本，將符合偵測規則的金鑰、Token 等秘密替換成遮蔽標記，再交由模型分析。
3. **資料處理邊界誠實揭露**：
   去敏規則無法保證辨識並過濾 100% 的所有非結構化個資；若外掛選用雲端模型服務（例如 Google Gemini 或 Anthropic Claude API），去敏後的審查上下文將傳輸至該服務進行推理。使用前請確認專案代碼之機敏等級是否符合所選模型服務之資料保留政策（Data Retention Policy）。外掛本身不夾帶任何獨立第三方商業追蹤器或背景遙測回傳機制。

---

### Q2：哪些 Antigravity CLI (agy) 與系統環境適用？這是 Google 官方外掛嗎？

**答**：  
Three-Lens 是原生執行於 Antigravity CLI（agy）的**獨立開源社群外掛，沒有 Google LLC、Anthropic 或 OpenAI 官方背書或贊助關係**。
- **核心環境需求**：
  - Antigravity CLI（`agy`）：`>= 1.2.0`（若使用 PreInvocation 終止鉤子與原生 ACP 傳輸則建議 `>= 1.5.1`）
  - Node.js：`>= 20.0.0`（純 Node.js 原生標準庫，CI 實測至 20.18.0+）
  - Git：`>= 2.30.0`
- **環境診斷**：
  安裝後可在外掛目錄執行 `npm run doctor`（或 `npm run doctor -- --json`）進行自動化環境與相容性檢查（詳見 [`docs/reproduction/platform-compatibility.md`](reproduction/platform-compatibility.md)）。

---

### Q3：「零外部依賴 (Zero External Dependencies)」是什麼意思？還需要其他工具嗎？

**答**：  
「零外部依賴」是指 Three-Lens 核心**完全使用 Node.js 原生內建模組**（`node:fs`、`node:path`、`node:crypto`、`node:child_process`），`package.json` 中的 `dependencies` 與 `devDependencies` 均為 0，從根本消除第三方 npm 套件的供應鏈攻擊面（Supply-Chain Attack Surface）與套件劫持風險。
- **系統層工具需求**：
  核心執行仍需要宿主作業系統具備 Node.js、AGY CLI 與 Git；若需執行發行來源與 Sigstore 證明驗證，另需 GitHub CLI（`gh`）。
- **可信計算基 (TCB)**：
  透過 [`evals/evidence-matrix.json`](../evals/evidence-matrix.json) 追蹤 51 項實體產物 SHA-256 雜湊值與 40 項安全不變量，確保核心檔案皆具備確定性與可重現性。

---

### Q4：與直接請單一 LLM（或 2 比 1 多數決投票）審查代碼相比，3lens 有何本質差異？

**答**：  
傳統單一 LLM 審查容易產生幻覺與高偽陽性；而一般的多代理「民主投票（多數決）」則容易因語意模型的一致性偏見，覆蓋單一確定性的編譯或靜態事實。
- **連言三鏡頭共識 (Conjunctive 3-Lens Consensus)**：
  候選弱點必須由「可達性 (Reachability)」、「防禦控制 (Defenses)」與「實質衝擊 (Impact)」三種獨立專業角色分別檢驗，再由確定性 Finalizer 程式依據 Default-Deny 進行交集驗證與裁決。
- **硬性反證不可被票數推翻**：
  只要有具體證據證明防禦控制有效（如已參數化或存在硬編碼過濾器），即使其他角色投票贊成，該弱點仍會被強制壓制（Suppressed），有效遏止偽陽性。在公開基準測試中達成 20/20 成對案例（10 個漏洞／10 個安全對照組）100% 準確裁決。
- **客觀邊界說明**：
  三個審查視角代表三種分工檢驗邏輯，預設不代表使用三個不同的外部模型供應商；`Clean` 僅代表在宣告的稽核範圍與規則下通過驗證，不能作為系統絕對無漏洞的商業擔保。

---

### Q5：外掛會自行修改、推送或部署程式碼嗎？

**答**：  
Three-Lens 在各階段均維持嚴格的「審查與修補權限隔離」：
1. **掃描階段唯讀**：
   審查角色僅獲取工作區唯讀與分析權限，僅寫入結構化稽核報告（SARIF 2.1.0 / Markdown）與本機去敏副本。
2. **修補隔離牢籠 (Patch Jail)**：
   只有在明確執行 `/3lens patch` 或修補流程時，系統才會在 `scratch/patches/` 隔離目錄產出候選 patch，並交由 `verify-fix` 進行回歸驗證。
3. **禁止自動推送**：
   推薦角色權限設定（[`recommended-security-audit-permissions.json`](../recommended-security-audit-permissions.json)）嚴格禁止修補角色執行 `git push`、`git commit` 或發佈指令。修補驗證通過僅代表修復有效，不構成程式碼合併或部署的自動授權，最終合併裁決權永遠保留給開發者。
