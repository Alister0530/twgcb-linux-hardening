# -*- coding: utf-8 -*-
"""RHEL 8 / 9（TWGCB-01-008 v1.3、TWGCB-01-012 v1.2）規則，兩版共用，依規格分組拆成多個檔案：

  disk.py        RHEL 8 0001–0047；RHEL 9 0001–0047、0285–0300
  system.py      RHEL 8 0048–0091；RHEL 9 0048–0091、0301–0307
  network.py     RHEL 8 0092–0131；RHEL 9 0092–0131
  logging.py     RHEL 8 0132–0182；RHEL 9 0132–0182、0308
  selinux.py     RHEL 8 0185–0207、0244–0261；RHEL 9 0183–0205、0242–0253（SELinux、cron、防火牆）
  accounts.py    RHEL 8 0208–0243；RHEL 9 0206–0241、0309–0314
  ssh.py         RHEL 8 0262–0292；RHEL 9 0254–0284、0315

編號對照見 docs/specs/rhel/編號對照.md；跨作業系統共用的規則在 ../common.py，各檔案不重複定義。
"""
import importlib

from ..base import TITLE_OVERRIDES

# RHEL 8 原文用字（「密碼」「的」「驗證」等）與 RHEL 9（「通行碼」「之」「鑑別」）不同的項目名稱；規則物件以 RHEL 9 用字為準
TITLE_OVERRIDES.update({
    "TWGCB-01-008-0072": "帳號不使用空白密碼",
    "TWGCB-01-008-0073": "root 帳號的路徑變數",
    "TWGCB-01-008-0074": "root 帳號的路徑變數不包含 world-writable 或 group-writable 目錄",
    "TWGCB-01-008-0075": "/etc/passwd 檔案行首的「+」符號",
    "TWGCB-01-008-0076": "/etc/shadow 檔案行首的「+」符號",
    "TWGCB-01-008-0077": "/etc/group 檔案行首的「+」符號",
    "TWGCB-01-008-0082": "使用者家目錄的「.」檔案權限",
    "TWGCB-01-008-0083": "使用者家目錄的「.forward」檔案",
    "TWGCB-01-008-0084": "使用者家目錄的「.netrc」檔案",
    "TWGCB-01-008-0085": "使用者家目錄的「.rhosts」檔案",
    "TWGCB-01-008-0086": "檢查 /etc/passwd 檔案設定的群組",
    "TWGCB-01-008-0087": "唯一的 UID",
    "TWGCB-01-008-0088": "唯一的 GID",
    "TWGCB-01-008-0089": "唯一的使用者帳號名稱",
    "TWGCB-01-008-0090": "唯一的群組名稱",
    "TWGCB-01-008-0109": "所有網路介面傳送 ICMP 重新導向封包",
    "TWGCB-01-008-0110": "預設網路介面傳送 ICMP 重新導向封包",
    "TWGCB-01-008-0208": "可設定密碼次數",
    "TWGCB-01-008-0209": "強制 root 密碼須符合密碼規則",
    "TWGCB-01-008-0210": "密碼最小長度",
    "TWGCB-01-008-0211": "密碼必須至少包含字元類別數量",
    "TWGCB-01-008-0212": "密碼必須至少包含數字個數",
    "TWGCB-01-008-0213": "密碼必須至少包含大寫字母個數",
    "TWGCB-01-008-0214": "密碼必須至少包含小寫字母個數",
    "TWGCB-01-008-0215": "密碼必須至少包含特殊字元個數",
    "TWGCB-01-008-0216": "新密碼與舊密碼最少相異字元數",
    "TWGCB-01-008-0219": "必須禁止使用字典檔單字做為密碼",
    "TWGCB-01-008-0222": "強制執行密碼歷程記錄",
    "TWGCB-01-008-0224": "密碼雜湊演算法",
    "TWGCB-01-008-0225": "密碼最短使用期限",
    "TWGCB-01-008-0226": "密碼到期前提醒使用者變更密碼",
    "TWGCB-01-008-0227": "密碼最長使用期限",
    "TWGCB-01-008-0228": "密碼到期後，帳號停用前的天數",
    "TWGCB-01-008-0231": "要求使用者必須經過身分驗證才能提升權限",
    "TWGCB-01-008-0241": "所有使用者帳號的預設 umask",
    "TWGCB-01-008-0242": "在 /etc/login.defs 設定所有使用者的預設 umask",
})

RULES = []
for _name in ("disk", "system", "network", "logging", "selinux", "accounts", "ssh"):
    RULES += importlib.import_module("." + _name, __name__).RULES  # 載入錯誤直接顯示，不可略過
