# -*- coding: utf-8 -*-
"""常見錯誤訊息 → 中文原因與處理建議。

規則由上往下比對，較具體的放前面；同一段錯誤最多回傳 2 條說明；
通用說明（如「權限不足」）只在沒有更具體的說明時使用。
新增規則：在 HINTS 加入 (正規表示式, 原因, 建議)。
"""
import re

HINTS = [
    # ---- 環境 ----
    (r"System has not been booted with systemd|Failed to connect to bus",
     "系統不是以 systemd 啟動（通常是在容器內執行），無法管理服務",
     "請在實體機或 VM 上執行"),
    (r"sysctl: (permission denied|setting key .*Read-only file system)",
     "核心參數無法修改：在容器內執行，或核心參數被鎖定",
     "請在實體機或 VM 上以 root 執行；若為容器，需由宿主機設定"),
    (r"No space left on device",
     "磁碟空間不足",
     "清理空間後重新執行（可用 df -h 檢查）"),
    (r"Read-only file system",
     "檔案系統為唯讀狀態",
     "確認磁碟是否以唯讀掛載或發生錯誤（可用 mount、dmesg 檢查）"),

    # ---- 套件 ----
    (r"not registered with an entitlement|This system is not registered",
     "RHEL 尚未註冊訂閱，無法使用官方套件庫",
     "以 subscription-manager register 註冊，或設定內部鏡像站後重新執行"),
    (r"Could not get lock|dpkg was interrupted|is held by process|waiting for .*lock",
     "套件管理系統被其他程序佔用（例如自動更新）",
     "等待其他安裝程序完成後重新執行；若 dpkg 曾中斷，先執行 dpkg --configure -a"),
    (r"Could not resolve host|Temporary failure resolving|Failed to download|Cannot download|"
     r"Curl error|Network is unreachable|Unable to fetch some archives|Errors during downloading metadata|"
     r"Failed to fetch|Cannot find a valid baseurl|Connection timed out",
     "無法連線套件庫（網路、DNS 或 Proxy 問題）",
     "確認網路與套件庫設定（或內部鏡像站），也可手動安裝套件後重新執行"),
    (r"Unable to locate package|No match for argument|No package .* available|has no installation candidate",
     "套件庫中找不到此套件，可能沒有啟用對應的套件庫",
     "RHEL 確認已啟用 BaseOS / AppStream；Ubuntu 確認已啟用 main / universe"),
    (r"無法安裝套件",
     "套件安裝失敗",
     "請查看修復步驟紀錄中的安裝輸出，依錯誤訊息處理後重新執行"),

    (r"certificate key too weak|ee key too small|key too small|CA_MD_TOO_WEAK",
     "加密原則過嚴，對方伺服器的憑證金鑰長度或演算法不符（例如 FUTURE 原則拒絕 2048 位元 RSA 憑證）",
     "確認套件庫或連線對象的憑證符合加密原則，或改用 DEFAULT 原則後再處理"),

    # ---- 服務 ----
    (r"Unit \S+ (not found|does not exist)|No such file or directory.*\.service",
     "系統上沒有這個服務",
     "確認對應的套件是否已安裝"),
    (r"Job for \S+ failed|start request repeated too quickly|code=exited, status=",
     "服務啟動失敗",
     "以 journalctl -u <服務名稱> -n 50 查看失敗原因"),

    # ---- PAM / 帳號 ----
    (r"local modifications|pam-auth-update 失敗",
     "PAM 設定檔曾被手動修改，pam-auth-update 拒絕覆寫",
     "人工比對 /etc/pam.d/common-* 的修改內容，評估後再手動加入 pam_faillock"),
    (r"not managed by authselect|Unexpected changes to the configuration|authselect.*(check|--force)",
     "PAM 設定曾被手動修改，authselect 拒絕覆寫",
     "執行 authselect check 檢視差異，人工評估後再處理"),
    (r"未使用 authselect",
     "系統的 PAM 不是由 authselect 管理（可能使用自訂設定）",
     "依 GCB 文件手動在 system-auth / password-auth 加入 pam_faillock"),
    (r"立即過期",
     "套用通行碼期限後，該帳號的通行碼會立刻過期，可能造成自動化作業無法登入",
     "先請帳號擁有者變更通行碼，或確認影響後加 --include-risky"),

    # ---- SSH ----
    (r"sshd 設定語法錯誤|Bad configuration option|Unsupported option",
     "sshd 設定有語法錯誤或不支援的參數，已停止套用以免 SSH 中斷",
     "執行 sshd -t 查看錯誤行，修正後重新執行"),
    (r"Permission denied \(publickey",
     "SSH 金鑰登入被拒",
     "確認 sshd 的 PubkeyAuthentication、AllowUsers / AllowGroups 設定，以及測試帳號家目錄與 .ssh 權限"),
    (r"Connection refused",
     "SSH 連線被拒，服務可能沒有在監聽",
     "確認 sshd 是否運作中、連接埠與防火牆設定"),

    # ---- SELinux / 開機 ----
    (r"SELinux is disabled",
     "SELinux 目前為停用狀態，無法直接切換為 enforcing",
     "需重開機並重新標記檔案系統（程式會建立 /.autorelabel）"),
    (r"找不到 grubby|找不到 /etc/default/grub|找不到 /boot/grub|找不到 grub.cfg",
     "找不到開機載入程式設定，可能是容器環境或非標準開機方式",
     "請在實體機或 VM 上執行；若使用特殊開機方式，需人工設定"),
    (r"Module \S+ is in use|Device or resource busy",
     "核心模組使用中，無法立即卸載",
     "設定已寫入，重開機後生效"),

]

# 通用說明：只在沒有符合上面任何具體說明時使用
GENERIC_HINTS = [
    (r"Operation not permitted",
     "作業被拒絕，檔案可能設定了不可修改屬性",
     "以 lsattr <檔案> 檢查是否有 i 屬性，確認後以 chattr -i 移除"),
    (r"[Pp]ermission denied",
     "權限不足",
     "確認以 root 執行；若已是 root，可能被 SELinux 或檔案屬性阻擋"),
    (r"執行逾時|timed out",
     "指令執行逾時",
     "網路或系統過慢；可調高 config.ini 的 package_timeout 後重新執行"),
    (r"修復後檢測仍不合格",
     "指令執行成功但設定沒有生效",
     "可能被其他設定檔覆寫、需要重開機，或環境不允許修改（例如容器）；請比對修復步驟紀錄"),
]

_SPECIFIC = [(re.compile(p, re.I), c, t) for p, c, t in HINTS]
_GENERIC = [(re.compile(p, re.I), c, t) for p, c, t in GENERIC_HINTS]


def _match(rules, text, limit):
    out = []
    for rx, cause, tip in rules:
        if rx.search(text):
            out.append("原因：%s；建議：%s" % (cause, tip))
            if len(out) >= limit:
                break
    return out


def explain(text, limit=2):
    """回傳 ['原因：…；建議：…', …]，沒有符合的回傳空清單。"""
    text = text or ""
    return _match(_SPECIFIC, text, limit) or _match(_GENERIC, text, 1)
