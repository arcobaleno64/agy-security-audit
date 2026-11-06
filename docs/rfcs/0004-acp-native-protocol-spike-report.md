# ACP (Agent Client Protocol) 原生架構驗證技術報告 (Milestone 5.4 Phase 1 / M54-P1-F04)

- **文檔編號**：RFC-0004-ADDENDUM-ACP
- **測試日期**：2026-11-05
- **實體執行環境**：Antigravity CLI (AGY) 1.5.1 on Windows (x64)
- **相依審查條目**：[ChatGPT R1 審查回執 M54-P1-F04](file:///C:/Users/arcobaleno/.gemini/antigravity-cli/brain/4310e9d3-6383-494a-a2bd-39cb2b92671a/m54-phase-1-review-r1-receipt.md)

---

## 一、 測試目標與 Gate 0 依據

依據獨立第三方架構審查員在回執中之 High/Medium 裁定：
> **`M54-P1-F04` (Medium)**：
> 「優先驗證官方原生 `agy acp`；僅當已證明必須進行子代理路由或診斷轉換且原生能力無法滿足時，才新增最小橋接層；SARIF 是交換格式而非編輯器即時診斷協定。」

本報告透過實體 stdio JSON-RPC 2.0 雙向通訊探針，實測 `agy acp --stdio` 的原生握手、能力協商、模型切換與會話管理契約。

---

## 二、 實體協議探針觀測事實 (Empirical Findings)

### 1. 服務端身分與協定版本
- **Server Name**：`Antigravity ACP Server`
- **Server Version**：`1.5.1`
- **Protocol Version**：`1` (Agent Client Protocol v1)
- **Transport**：Stdio JSON-RPC 2.0 (支援每條訊息以換行符分隔)

### 2. 握手回應 (`initialize` Response)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": 1,
    "agentCapabilities": {
      "loadSession": true,
      "load_session": true,
      "promptCapabilities": {
        "image": true,
        "audio": false,
        "embeddedContext": true
      },
      "sessionCapabilities": {
        "resume": {},
        "close": {},
        "load": {},
        "list": {},
        "additionalDirectories": {}
      },
      "session_capabilities": {
        "resume": {},
        "close": {},
        "load": {},
        "list": {},
        "additionalDirectories": {}
      },
      "auth": { "logout": {} },
      "_meta": {
        "antigravity": {
          "tier": true,
          "systemPrompt": { "append": true }
        }
      }
    },
    "agentInfo": {
      "name": "Antigravity ACP Server",
      "version": "1.5.1"
    },
    "authMethods": [
      {"id": "oauth-personal", "name": "Log in with Google"},
      {"id": "oauth-business", "name": "Log in with Gemini Enterprise"},
      {"id": "gemini-api-key", "name": "Gemini API key"},
      {"id": "agent-platform", "name": "Gemini Enterprise Agent Platform"}
    ]
  }
}
```

### 3. 會話建立與模型清單 (`session/new` Response)
發送 `session/new` 請求後，`agy acp` 原生返回完整支援的模型與 Effort 矩陣：
1. **可用模型 (13 組原生組合)**：
   - `gemini-4-argon-low`, `gemini-4-argon-medium`, `gemini-4-argon-high`
   - `gemini-3.8-flash-low`, `gemini-3.8-flash-medium`, `gemini-3.8-flash-high`
   - `claude-opus-5-5-low`, `claude-opus-5-5-medium`, `claude-opus-5-5-high`
   - `claude-sonnet-5-5-low`, `claude-sonnet-5-5-medium`, `claude-sonnet-5-5-high`
   - `gpt-oss-120b-medium`
2. **動態配置選項 (`configOptions`)**：
   - `id: "model"`: 支援下拉選擇底層模型系列
   - `id: "thought_level"`: 支援動態指定思考深度 (`low`, `medium`, `high`)
   - `id: "mode"`: 支援切換 `default`, `accept-edits`, `plan`
3. **即時指令更新通知 (`session/update`)**：
   - 伺服器主動透過 `available_commands_update` 推送當前已安裝之 Skills 與 Slash Commands（包含 `agy-customizations`, `security-audit`, `companion-routing` 等）。

---

## 三、 架構裁定與結論

1. **無須外部橋接層**：
   官方 `agy acp` 已提供完整的原生 JSON-RPC 2.0 介面，支援會話生命週期、多模型切換、思考深度調整及 Skills 整合。外部 IDE / 編輯器（如 VSCode ACP 擴充或 Neovim）可直接透過 stdio 連結，不應自行撰寫自訂的轉換中間層。
2. **協議邊界確立**：
   - **即時通訊／編輯器介面**：使用原生 **ACP (Agent Client Protocol)**。
   - **靜態分析交換與合規稽核**：使用標準 **SARIF 2.1.0**。
   兩者職責分明，SARIF 絕不可被混充為即時編輯器通訊協定。
3. **M54-P1-F04 驗收閉環**：
   本技術報告之觀測實證已完全滿足審查員針對 `M54-P1-F04` 的驗證要求。
