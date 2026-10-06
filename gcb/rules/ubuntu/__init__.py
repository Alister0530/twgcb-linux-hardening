# -*- coding: utf-8 -*-
"""Ubuntu 規則（目前支援 22.04：TWGCB-01-014 v1.2；新版本以多編號共用同一條規則），依 GCB 文件分類拆成多個檔案：

  disk.py      磁碟與檔案系統          0001–0028
  system.py    系統設定與維護          0029–0078
  network.py   系統服務、軟體、網路    0079–0111
  audit.py     日誌與稽核              0112–0154
  access.py    AppArmor、cron、帳號    0155–0193
  optional.py  校時、防火牆、GNOME     0194–0234（依系統實際使用的元件適用）

跨作業系統共用的 19 條在 ../common.py（0001、0011、0043–0046、0062、0079、0088–0091、
0113、0114、0150、0157、0173、0178、0184），各檔案不重複定義。
"""
import importlib

RULES = []
for _name in ("disk", "system", "network", "audit", "access", "optional"):
    RULES += importlib.import_module("." + _name, __name__).RULES  # 載入錯誤直接顯示，不可略過
