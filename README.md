# GCB 政府組態基準 檢測與修復工具

> **English:** A zero-dependency Python tool that audits Linux hosts against Taiwan's Government Configuration Baseline (TWGCB) for RHEL 8/9 and Ubuntu 22.04, auto-remediates failed items with per-change backups, runs health checks before and after, rolls back automatically if critical checks regress, and produces Excel reports. Documentation is in Traditional Chinese.

> [!WARNING]
> **使用前請先閱讀**
> - 本工具會以 root 權限修改系統設定，包括 SSH、PAM、防火牆、核心參數、掛載選項與套件。設定錯誤可能導致無法登入或服務中斷。
> - 執行修復前**務必先建立 VM 快照**，並先在測試環境驗證，再套用到正式環境。
> - 本工具非官方工具，與數位發展部資通安全署、國家資通安全研究院無關。檢測結果僅供參考，不代表通過任何正式稽核。
> - 依 MIT 授權「按原樣」提供，不負任何擔保責任；使用造成的任何損失由使用者自行承擔。

自動檢測 Linux 主機是否符合 GCB 規範，產出不合格清單，並可自動修復、記錄 log、驗證系統正常，最後產出修復報告。

| 支援系統 | 依據文件 | 規則數 |
|---|---|---|
| RHEL 8（含 Rocky / Alma 8） | TWGCB-01-008 v1.3 | 290 |
| RHEL 9（含 Rocky / Alma 9） | TWGCB-01-012 v1.2（伺服器） | 314 |
| Ubuntu 22.04 LTS | TWGCB-01-014 v1.2 | 234 |

只需要系統內建的 Python 3（RHEL 8 會自動使用 `platform-python`），不用另外安裝任何套件。

## 文件

所有文件都在 `docs/`：

| 文件 | 給誰 | 內容 |
|---|---|---|
| [操作手冊.md](docs/操作手冊.md) | 操作人員 | 事前準備、流程、操作步驟、修復類型（A / B / C）、指令大全、回滾、異常處理、config.ini、快照與手動部署 |
| [規則清單.md](docs/規則清單.md) | 所有人 | 各平台每條規則的修復類型、是否需重開機、說明與無法自動修復的原因（由程式自動產生） |
| [決策紀錄.md](docs/決策紀錄.md) | 所有人 | GCB 規格模糊或與實務衝突時的判定原則與個別決定 |
| [開發指南.md](docs/開發指南.md) | 開發人員 | 專案架構、執行流程、輸出檔案、規則寫法、測試、新增作業系統、已知限制 |
| [gcb/README.md](docs/gcb/README.md) | 開發人員 | GCB 官方說明文件下載位置（本專案不附原檔） |

## 快速開始

在你的電腦（`gcb-checker` 資料夾內）：

```bash
./deploy.sh 帳號@VM的IP
```

完整步驟見 [操作手冊.md](docs/操作手冊.md)。

## 範例報告

`samples/` 內有各平台在容器中實際執行產生的不合格清單與修復報告。

## 授權

[MIT](LICENSE)。GCB 官方說明文件的智慧財產權屬數位發展部資通安全署，請至[國家資通安全研究院](https://www.nics.nat.gov.tw/core_business/cybersecurity_defense/GCB/GCB_Documentation/)下載。
