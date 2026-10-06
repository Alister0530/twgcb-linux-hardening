# -*- coding: utf-8 -*-
"""GCB 規則定義。

每條規則：
  ids       各 OS 對應的 TWGCB-ID（沒有該 OS 代表不適用）
  risk      A=自動修復  B=有風險，需 --include-risky  C=僅檢測，需人工
  check()   回傳 Check
  fix()     透過 Fx 執行修復（所有動作自動寫 log 與回滾紀錄）
"""
from ..fixer import ManualRequired

PASS, FAIL, NA, ERROR = "合格", "不合格", "不適用", "檢測失敗"


# 同一條規則在各版本 GCB 文件中的名稱用字不同時，以 TWGCB-ID 指定該版本的原文名稱
# （例：RHEL 8 用「密碼」、RHEL 9 用「通行碼」）。由各平台規則套件填入。
TITLE_OVERRIDES = {}


class Check(object):
    def __init__(self, status, current, detail=""):
        self.status = status
        self.current = current
        self.detail = detail


class Rule(object):
    title = ""
    category = ""
    risk = "A"
    ids = {}
    expected = ""
    needs_reboot = False
    manual_hint = ""
    # C 類（或修復時判定需人工）的「無法自動修復原因」；空字串時由 manual_reason_for() 依說明內容推斷
    manual_reason = ""
    # 規則清單的「說明」欄（非 C 類的特殊處理方式，例如 B 類會移動使用者檔案）
    doc_note = ""
    # True：在所有規則之後才修復（例：會影響套件下載的加密原則，避免讓同一次執行中其他安裝套件的修復失敗）
    run_last = False

    def rule_id(self, osi):
        return self.ids.get(osi.key)

    def title_for(self, osi):
        """依作業系統顯示 GCB 原文的項目名稱（同一條規則在不同版本文件用字可能不同）。"""
        return TITLE_OVERRIDES.get(self.rule_id(osi)) or self.title

    def expected_for(self, osi):
        if isinstance(self.expected, dict):
            return self.expected.get(osi.key) or self.expected.get(osi.family, "")
        return self.expected

    def check(self, ctx):
        raise NotImplementedError

    # 適用條件：when(ctx) 回傳不適用的原因字串，或 None 代表適用
    when = None

    def not_applicable(self, ctx):
        return self.when(ctx) if self.when else None

    def precondition(self, ctx):
        """回傳略過原因字串，或 None。"""
        return None

    def fix(self, ctx, fx):
        raise ManualRequired(self.manual_hint or "此項目需人工處理")


# 無法自動修復的原因分類：(關鍵字, 原因)；依序比對規則名稱與 manual_hint，取第一個符合的
MANUAL_REASONS = [
    (("重新規劃磁區", "分割磁區", "邏輯磁區"),
     "需要重新規劃磁碟分割並搬移資料，自動處理可能造成資料遺失或無法開機"),
    (("開機載入程式之通行碼", "grub-mkpasswd", "grub2-setpassword"),
     "需要由管理者設定並保管開機通行碼，且設定後每次開機都可能要求輸入，工具不代為設定"),
    (("屬使用者資料", ".forward", ".netrc", ".rhosts", ".shosts"),
     "涉及使用者自己的檔案，刪除前需先通知使用者並確認不再需要"),
    (("家目錄",),
     "涉及使用者家目錄，需先通知使用者並確認不是共用或系統目錄"),
    (("校時伺服器", "NTP", "允許／拒絕清單", "需由單位提供", "需由管理者提供"),
     "需要單位提供的環境資訊（例如校時伺服器位址、允許登入的帳號清單），工具無法自行決定"),
    (("authselect check", "PAM 是否曾被手動修改"),
     "PAM 設定曾被手動修改，自動覆寫可能讓所有人無法登入"),
    (("passwd root", "重設通行碼", "設定通行碼", "通行碼重設"),
     "需要由帳號持有人或管理者輸入通行碼，工具不代為設定"),
    (("路徑變數", "PATH 可能來自"),
     "root 的 PATH 可能來自多個登入設定檔，需找出實際來源再修改，改錯可能導致系統指令找不到"),
    (("混雜模式",),
     "混雜模式可能是橋接器、虛擬化、容器網路或監控工具的正常需求，需確認用途後再關閉"),
    (("帳號", "UID", "GID", "群組名稱", "sudoers", "vipw", "vigr"),
     "需要確認帳號或群組的用途，自動修改可能影響服務運作或使用者登入"),
    (("檔案用途", "目錄用途", "RPM 套件", "程序"),
     "需要確認檔案、目錄或程式的用途，應用程式可能依賴目前的設定"),
    (("照 GCB 字面", "依決策紀錄"),
     "依決策紀錄只檢測不修改（技術上已符合 GCB 目的或屬使用者資料，由人工判斷）"),
]


def manual_reason_for(rule):
    """回傳規則無法自動修復的原因（優先使用規則自己定義的 manual_reason）。"""
    if getattr(rule, "manual_reason", ""):
        return rule.manual_reason
    text = (rule.title or "") + " " + (rule.manual_hint or "")
    for keys, reason in MANUAL_REASONS:
        if any(k in text for k in keys):
            return reason
    return "自動修改可能影響系統運作或需要人工判斷，請依處理方式人工確認"
