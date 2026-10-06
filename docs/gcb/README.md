# GCB 官方說明文件

GCB 官方說明文件的智慧財產權屬數位發展部資通安全署，本專案不附上 PDF 原檔與切分後的原文（`chunks.json`）。

## 下載

請到國家資通安全研究院的 [GCB 說明文件](https://www.nics.nat.gov.tw/core_business/cybersecurity_defense/GCB/GCB_Documentation/) 頁面下載以下文件：

| 平台目錄 | 文件 |
|---|---|
| `rhel8/` | TWGCB-01-008 Red Hat Enterprise Linux 8 政府組態基準說明文件 v1.3 |
| `rhel9/` | TWGCB-01-012 Red Hat Enterprise Linux 9 政府組態基準說明文件（伺服器）v1.2 |
| `ubuntu2204/` | TWGCB-01-014 Ubuntu 22.04 LTS 政府組態基準說明文件 v1.2 |

## 產生原文切塊（開發時才需要）

執行工具本身不需要這些檔案。開發或驗證規則時，把 PDF 放到對應的平台目錄，再切成 `chunks.json`：

```bash
pip3 install pypdf
python3 tools/gcb_pdf_split.py "docs/gcb/rhel8/<PDF 檔名>" docs/gcb/rhel8/chunks.json
```

有 `chunks.json` 時，`tests/test_platforms.py` 會比對程式中的規則編號與名稱是否和原文一致；沒有時會自動略過這項測試。

PDF 與 `chunks.json` 已列在 `.gitignore`，不會被提交。
