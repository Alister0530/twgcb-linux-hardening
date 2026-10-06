# -*- coding: utf-8 -*-
"""RHEL 8 / 9 日誌與稽核（RHEL 8 0132–0182；RHEL 9 0132–0182（無 0180）、0308）。

寫法參考 ubuntu2204/audit.py，路徑、套件（audit、aide.conf）、開機參數（grubby）改為 RHEL 作法。
稽核規則寫入 /etc/audit/rules.d/gcb-NNNN.rules（每項一個檔案，回滾時只影響該項）。
"""
import glob
import os
import re
import stat
import time

from ... import auditrules
from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from ..generic import (AUDIT_RULES_DIR, AuditRules, FilePerm, KvSetting, PackagePresent,
                       audit_filter_syscalls, compare)
from .helpers import R

CAT = "日誌與稽核"
AUDITD_CONF = "/etc/audit/auditd.conf"
RELOAD_AUDITD = ["service", "auditd", "reload"]  # auditd 拒絕 systemctl restart/stop
AUDIT_PKG = "audit"  # RHEL 套件名稱為 audit（不是 auditd）


def audit_installed(ctx):
    return pkgsvc.pkg_installed(ctx.osi, AUDIT_PKG)


def audit_enabled():
    """auditctl -s 的 enabled 值（0/1/2）；無法取得回傳 None。"""
    m = re.search(r"^enabled\s+(\d)", run(["auditctl", "-s"], timeout=30).out, re.M)
    return m.group(1) if m else None


# ====================================================================
# 共用：未安裝 audit 時判定不合格（同一次執行中 0132 安裝後即可接著修復）
# ====================================================================

# [NeedsAudit] RHEL8 0137–0147 / RHEL9 0137–0147 未安裝 audit 時為不合格而非不適用
class NeedsAudit(Rule):
    def __init__(self, inner):
        self.inner = inner
        for a in ("title", "category", "ids", "risk", "expected", "needs_reboot", "manual_hint"):
            setattr(self, a, getattr(inner, a))

    def check(self, ctx):
        if not audit_installed(ctx):
            return Check(FAIL, "未安裝 audit 套件")
        return self.inner.check(ctx)

    def precondition(self, ctx):
        return self.inner.precondition(ctx)

    def fix(self, ctx, fx):
        if not audit_installed(ctx):
            raise ManualRequired("未安裝 audit 套件，請先完成「auditd 套件」項目（0132）")
        self.inner.fix(ctx, fx)


# ====================================================================
# 套件（0132）
# ====================================================================

# [AuditPackages] RHEL8 0132 / RHEL9 0132 auditd 套件（audit、audit-libs）
class AuditPackages(Rule):
    category = CAT
    title = "auditd 套件"
    expected = "安裝（audit、audit-libs）"
    PKGS = ("audit", "audit-libs")

    def __init__(self, ids):
        self.ids = ids

    def _missing(self, ctx):
        return [p for p in self.PKGS if not pkgsvc.pkg_installed(ctx.osi, p)]

    def check(self, ctx):
        miss = self._missing(ctx)
        return Check(FAIL if miss else PASS, "未安裝：%s" % "、".join(miss) if miss else "已安裝")

    def fix(self, ctx, fx):
        for p in self._missing(ctx):
            fx.pkg_install(p)


# ====================================================================
# 開機參數 audit_backlog_limit（0135，數值比較）
# ====================================================================

def cmdline_value(tokens, key):
    """參數最後一次出現的整數值（核心以最後出現者為準）；沒有或非數字回傳 None。"""
    val = None
    for t in tokens:
        if t.startswith(key + "="):
            try:
                val = int(t.split("=", 1)[1])
            except ValueError:
                val = None
    return val


def parse_grubby_info(text):
    """解析 grubby --info=ALL，回傳 [(kernel, args 字串)]。"""
    out, kernel = [], None
    for line in (text or "").splitlines():
        if line.startswith("kernel="):
            kernel = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("args=") and kernel:
            out.append((kernel, line.split("=", 1)[1].strip().strip('"')))
            kernel = None
    return out


def grub_env_files():
    """grubby 可能改寫的檔案（BLS 開機項目與 grubenv 的 kernelopts）。"""
    files = sorted(glob.glob("/boot/loader/entries/*.conf"))
    files += [f for f in ["/boot/grub2/grubenv"] + sorted(glob.glob("/boot/efi/EFI/*/grubenv"))
              if os.path.exists(f)]
    return files


# [AuditBacklogLimit] RHEL8 0135 / RHEL9 0135 稽核待辦事項數量限制
class AuditBacklogLimit(Rule):
    category = CAT
    title = "稽核待辦事項數量限制"
    expected = "audit_backlog_limit 8,192 以上"
    risk = "B"
    needs_reboot = True
    KEY = "audit_backlog_limit"
    MIN = 8192
    DEFAULT = "/etc/default/grub"

    def __init__(self, ids):
        self.ids = ids

    def _ok(self, v):
        return v is not None and v >= self.MIN

    def _entries(self):
        """回傳 ([(kernel, 目前值)], 錯誤訊息)。"""
        if not which("grubby"):
            return None, "找不到 grubby"
        r = run(["grubby", "--info=ALL"], timeout=60)
        if not r.ok:
            return None, "grubby 執行失敗"
        return [(k, cmdline_value(a.split(), self.KEY)) for k, a in parse_grubby_info(r.out)], ""

    def _default_value(self, text):
        return cmdline_value((te.grub_cmdline_get(text) or "").split(), self.KEY)

    def check(self, ctx):
        default = read_text(self.DEFAULT)
        if default is None:
            return Check(ERROR, "找不到 %s" % self.DEFAULT)
        entries, err = self._entries()
        if entries is None:
            return Check(ERROR, err)
        dv = self._default_value(default)
        bad = [k for k, v in entries if not self._ok(v)]
        rt = cmdline_value((read_text("/proc/cmdline") or "").split(), self.KEY)
        cur = "/etc/default/grub：%s、開機項目不足：%d/%d 個、目前核心：%s" % (
            dv if dv is not None else "未設定", len(bad), len(entries), rt if rt is not None else "未設定")
        ok = self._ok(dv) and not bad and entries
        if ok and not self._ok(rt):
            cur += "（需重開機生效）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if read_text(self.DEFAULT) is None:
            raise ManualRequired("找不到 %s，系統可能未使用 GRUB2，請人工設定開機參數 audit_backlog_limit=8192" % self.DEFAULT)
        entries, err = self._entries()
        if entries is None:
            raise ManualRequired("%s，無法更新開機項目，請人工以 grubby 設定" % err)
        for f in grub_env_files():
            fx.backup_only(f)
        if not self._ok(self._default_value(read_text(self.DEFAULT))):
            fx.edit_file(self.DEFAULT, lambda t: te.grub_cmdline_add(t, "%s=%d" % (self.KEY, self.MIN)))
        # 已設定 8192 以上的開機項目保留原值；只更新不足的項目
        for k, v in entries:
            if self._ok(v):
                continue
            if v is None:
                fx.add_undo(["grubby", "--update-kernel", k, "--remove-args", self.KEY],
                            "移除 %s 的 %s" % (k, self.KEY))
            else:
                fx.add_undo(["grubby", "--update-kernel", k, "--args", "%s=%d" % (self.KEY, v)],
                            "還原 %s 的 %s=%d" % (k, self.KEY, v))
                fx.run(["grubby", "--update-kernel", k, "--remove-args", self.KEY],
                       "移除舊的開機參數 %s → %s" % (self.KEY, k))
            fx.run(["grubby", "--update-kernel", k, "--args", "%s=%d" % (self.KEY, self.MIN)],
                   "加入開機參數 %s=%d → %s" % (self.KEY, self.MIN, k))


# ====================================================================
# /etc/aliases postmaster（0136）
# ====================================================================

_ALIAS_RX = re.compile(r"^\s*postmaster\s*:\s*(.*?)\s*$", re.I)


def alias_target(text, name="postmaster"):
    """回傳別名最後一次設定的目標（去除空白）；未設定回傳 None。"""
    val = None
    for line in (text or "").splitlines():
        if line.strip().startswith("#"):
            continue
        m = _ALIAS_RX.match(line)
        if m:
            val = re.sub(r"\s+", "", m.group(1))
    return val


def alias_set(text, value="root"):
    out, done = [], False
    for line in (text or "").splitlines():
        if not line.strip().startswith("#") and _ALIAS_RX.match(line):
            out.append(te.MARK + line if done else "postmaster:\t%s" % value)
            done = True
            continue
        out.append(line)
    if not done:
        out.append("postmaster:\t%s" % value)
    return "\n".join(out) + "\n"


# [PostmasterAlias] RHEL8 0136 / RHEL9 0136 稽核處理失敗時通知系統管理者
class PostmasterAlias(Rule):
    category = CAT
    title = "稽核處理失敗時通知系統管理者"
    expected = "啟用（/etc/aliases 設定 postmaster: root）"
    PATH = "/etc/aliases"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text(self.PATH)
        if text is None:
            return Check(FAIL, "找不到 %s" % self.PATH)
        v = alias_target(text)
        if v is None:
            return Check(FAIL, "未設定 postmaster 別名")
        return Check(PASS if v == "root" else FAIL, "postmaster: %s" % v)

    def fix(self, ctx, fx):
        if which("newaliases"):
            fx.add_undo(["newaliases"], "重新產生別名資料庫")
        fx.edit_file(self.PATH, alias_set)
        if which("newaliases"):
            fx.run(["newaliases"], "重新產生別名資料庫", check=False)
        else:
            fx.note("未安裝郵件服務（找不到 newaliases），別名已寫入；實際寄送通知需安裝 MTA（如 postfix）")


# ====================================================================
# 稽核日誌檔案與目錄（0137–0140）
# ====================================================================

def audit_log_file():
    return te.get_kv(read_text(AUDITD_CONF) or "", "log_file") or "/var/log/audit/audit.log"


def audit_log_group():
    return te.get_kv(read_text(AUDITD_CONF) or "", "log_group") or "root"


# [AuditLogPerm] RHEL8 0137–0140 / RHEL9 0137–0140 稽核日誌檔案／目錄之所有權與權限
class AuditLogPerm(FilePerm):
    """路徑依 auditd.conf 的 log_file 決定。auditd 會依 log_group 重設日誌檔群組與權限
    （非 root 時為 0640）；依規格不自動修改 log_group，只修正現有檔案並提示（部分修復）。"""

    def __init__(self, title, ids, target, **kw):
        FilePerm.__init__(self, title, CAT, ids, [], **kw)
        self.target = target  # file / dir

    def _targets(self):
        lf = audit_log_file()
        self.paths = [lf, lf + ".[0-9]*"] if self.target == "file" else [os.path.dirname(lf)]
        return FilePerm._targets(self)

    def check(self, ctx):
        c = FilePerm.check(self, ctx)
        if self.target != "file":
            return c
        g = audit_log_group()
        if g in ("root", "0"):
            if c.status == NA:  # 尚未產生日誌；log_group=root 時會以 root:root 0600 建立
                return Check(PASS, "尚未產生日誌檔；log_group=root")
            return c
        if c.status == NA:
            return Check(FAIL, "尚未產生日誌檔；auditd.conf log_group=%s（建立的日誌將為 root:%s 0640）" % (g, g))
        c.status = FAIL
        c.current += "；auditd.conf log_group=%s（auditd 會依此重設日誌群組與權限）" % g
        return c

    def fix(self, ctx, fx):
        FilePerm.fix(self, ctx, fx)
        g = audit_log_group()
        if self.target == "file" and g not in ("root", "0"):
            fx.partial = True
            fx.note("auditd.conf 的 log_group=%s，auditd 會把日誌改回 root:%s 0640；"
                    "此設定可能是為了讓該群組讀取日誌，未自動修改，請確認後將 log_group 改為 root 並執行 service auditd reload" % (g, g))


# ====================================================================
# AIDE 保護稽核工具（0145）
# ====================================================================

AIDE_ATTRS = "p+i+n+u+g+s+b+acl+xattrs+sha512"
AIDE_TOOLS = ["/usr/sbin/auditctl", "/usr/sbin/auditd", "/usr/sbin/ausearch", "/usr/sbin/aureport",
              "/usr/sbin/autrace", "/usr/sbin/audisp-remote", "/usr/sbin/audisp-syslog", "/usr/sbin/augenrules"]


def aide_rule_attrs(texts, path):
    """回傳 [屬性集合]：各設定中針對 path 的選取規則（排除 ! 否定規則）。"""
    out = []
    for text in texts:
        for line in (text or "").splitlines():
            tok = line.split("#", 1)[0].split()
            if len(tok) >= 2 and tok[0].lstrip("=").rstrip("$") == path:
                out.append(set(re.split(r"[+\s]+", " ".join(tok[1:]))))
    return out


def aide_includes(text):
    """@@include 的檔案（目錄則取其下所有檔案）。"""
    out = []
    for line in (text or "").splitlines():
        tok = line.split()
        if len(tok) >= 2 and tok[0] == "@@include":
            if os.path.isdir(tok[1]):
                out += sorted(f for f in glob.glob(tok[1] + "/*") if os.path.isfile(f))
            else:
                out.append(tok[1])
    return out


# [AideAuditTools] RHEL8 0145 / RHEL9 0145 保護稽核工具
class AideAuditTools(Rule):
    category = CAT
    title = "保護稽核工具"
    expected = "啟用（AIDE 監控 8 個稽核工具：%s）" % AIDE_ATTRS
    CONF = "/etc/aide.conf"

    def __init__(self, ids):
        self.ids = ids

    def _files(self):
        return [self.CONF] + aide_includes(read_text(self.CONF))

    def _missing(self):
        texts = [read_text(f) for f in self._files()]
        need = set(AIDE_ATTRS.split("+"))
        return [p for p in AIDE_TOOLS if not any(need <= a for a in aide_rule_attrs(texts, p))]

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "aide") or read_text(self.CONF) is None:
            return Check(FAIL, "未安裝 AIDE（見「AIDE 套件」項目 0036）")
        miss = self._missing()
        if not miss:
            return Check(PASS, "8 個稽核工具皆已設定監控")
        return Check(FAIL, "未設定監控：%s" % "、".join(os.path.basename(p) for p in miss))

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "aide") or read_text(self.CONF) is None:
            raise ManualRequired("未安裝 AIDE，請先完成「AIDE 套件」項目（0036）")
        need = set(AIDE_ATTRS.split("+"))

        def _drop_weak(text):
            # 註解掉同路徑但屬性不足的舊規則，避免重複定義
            out = []
            for line in text.splitlines():
                tok = line.split("#", 1)[0].split()
                if len(tok) >= 2 and tok[0].lstrip("=").rstrip("$") in AIDE_TOOLS \
                        and not need <= set(re.split(r"[+\s]+", " ".join(tok[1:]))):
                    line = te.MARK + line
                out.append(line)
            return "\n".join(out) + "\n" if out else ""

        before_ok = run(["aide", "--config-check", "-c", self.CONF], timeout=120).ok if which("aide") else False
        for f in self._files():
            if os.path.isfile(f):
                fx.edit_file(f, _drop_weak)
        block = "# Audit Tools（GCB %s，gcb-checker 產生）\n" % self.rule_id(ctx.osi) + \
            "".join("%s %s\n" % (p, AIDE_ATTRS) for p in AIDE_TOOLS)
        fx.edit_file(self.CONF, lambda t: t + ("" if not t or t.endswith("\n") else "\n") + block)
        if before_ok:
            r = fx.run(["aide", "--config-check", "-c", self.CONF], "檢查 AIDE 設定語法", check=False)
            if r is not None and not r.ok:
                raise FixError("AIDE 設定檢查失敗：%s" % r.text()[-200:])
        fx.note("請於方便時執行 aide --update（或 aide --init）更新 AIDE 資料庫，否則下次檢查會回報新增的監控項目")


# ====================================================================
# 稽核規則（0148–0172）
# ====================================================================

_SYSCALL_CACHE = {}


def syscall_exists(arch, name):
    key = (arch, name)
    if key not in _SYSCALL_CACHE:
        _SYSCALL_CACHE[key] = run(["ausyscall", arch, name], timeout=10).ok
    return _SYSCALL_CACHE[key]


def uid_min():
    """/etc/login.defs 的 UID_MIN（文件要求 auid>=1000 依此調整），預設 1000。"""
    v = te.get_kv(read_text("/etc/login.defs") or "", "UID_MIN")
    try:
        return int(v)
    except (TypeError, ValueError):
        return 1000


def is_x86():
    return os.uname()[4] in ("x86_64", "i686", "i386")


def audit_target(line):
    m = re.match(r"\s*-w\s+(\S+)", line) or re.search(r"-F\s+(?:path|dir)=(\S+)", line)
    return m.group(1) if m else None


def audit_loadable(line):
    """上層目錄不存在時核心拒絕載入，會讓 auditctl -R 整批中斷；檔案本身不存在則可正常監看。"""
    p = audit_target(line)
    if not p:
        return True
    return os.path.isdir(os.path.dirname(p.rstrip("/")) or "/")


def prepare_audit_lines(lines, uid=1000, x86=True, exists=syscall_exists):
    """回傳 (要載入的規則, 略過說明)：代入 UID_MIN、非 x86 略過 arch=b32、
    過濾本機不存在的系統呼叫、略過上層目錄不存在的監看。"""
    req, skipped = [], []
    for l in lines:
        l = l.replace("auid>=1000", "auid>=%d" % uid)
        if not x86 and "arch=b32" in l.split():
            skipped.append("b32 規則（非 x86_64 平台）")
            continue
        f = audit_filter_syscalls(l, exists=exists) if which("ausyscall") else l
        if not f:
            skipped.append("系統呼叫不存在：%s" % l)
            continue
        if not audit_loadable(f):
            skipped.append("上層目錄不存在：%s" % audit_target(f))
            continue
        req.append(f)
    return req, skipped


# [AuditRuleSet] RHEL8 0148–0172 / RHEL9 0148–0172 稽核規則（寫入 rules.d/gcb-NNNN.rules）
class AuditRuleSet(AuditRules):
    """generic.AuditRules 加上：兩版規則不同時以 {"rhel8": [...], "rhel9": [...]} 指定、
    UID_MIN 代入、非 x86 平台略過 b32、權限 0600（0141）、規則已鎖定（-e 2）時以設定檔判定。"""

    def __init__(self, title, ids, lines=None, risk="A"):
        AuditRules.__init__(self, title, ids, [], expected="啟用", risk=risk)
        self.spec = lines or []

    def _lines(self, ctx):
        if isinstance(self.spec, dict):
            return self.spec[ctx.osi.key]
        return self.spec

    def _split(self, ctx):
        return prepare_audit_lines(self._lines(ctx), uid_min(), is_x86())

    def _empty_text(self):
        return "無需設定的規則"

    def _extra_note(self, ctx):
        return ""

    def check(self, ctx):
        if not which("auditctl"):
            return Check(FAIL, "未安裝 audit 套件")
        req, skipped = self._split(ctx)
        note = "；略過 %d 條（%s）" % (len(skipped), "、".join(sorted(set(skipped))[:3])) if skipped else ""
        note += self._extra_note(ctx)
        if not req:
            return Check(PASS, self._empty_text() + note)
        loaded = run(["auditctl", "-l"], timeout=30).out
        disk = "\n".join(read_text(f) or "" for f in sorted(glob.glob(AUDIT_RULES_DIR + "/*.rules")))
        miss_disk = auditrules.missing(req, disk)
        miss_rt = auditrules.missing(req, loaded)
        if not miss_disk and not miss_rt:
            return Check(PASS, "%d 條規則皆已生效%s" % (len(req), note))
        if not miss_disk and audit_enabled() == "2":
            return Check(PASS, "%d 條規則已寫入設定檔；稽核規則已鎖定（-e 2），需重開機生效%s" % (len(req), note))
        return Check(FAIL, "未生效 %d 條、未寫入設定檔 %d 條（例：%s）%s" % (
            len(miss_rt), len(miss_disk), (miss_disk or miss_rt)[0], note))

    def fix(self, ctx, fx):
        if not which("augenrules"):
            raise ManualRequired("未安裝 audit 套件，請先完成「auditd 套件」項目（0132）")
        req, skipped = self._split(ctx)
        if not req:
            raise ManualRequired("沒有可載入的規則（%s）" % self._empty_text())
        path = self._file(ctx)
        fx.add_undo(["augenrules", "--load"], "重新載入稽核規則")
        fx.write_file(path, "## GCB %s %s（gcb-checker 產生）\n%s\n" % (
            self.rule_id(ctx.osi), self.title, "\n".join(req)), mode=0o600)
        if not fx.dry and os.path.exists(path) and os.stat(path).st_mode & 0o177:
            fx.chmod(path, 0o600)  # 0141 稽核規則檔案權限
        if skipped:
            fx.note("略過 %d 條規則：%s" % (len(skipped), "、".join(sorted(set(skipped)))))
        fx.run(["augenrules", "--load"], "載入稽核規則", check=False)
        if not fx.dry and audit_enabled() == "2":
            fx.note("稽核規則目前為不可變更狀態（-e 2），設定已寫入，需重開機後生效")


# 0158：掃描 setuid/setgid 程式的檔案系統（本機磁碟；網路與虛擬檔案系統不掃描）
LOCAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "jfs", "reiserfs", "f2fs")


def local_mounts(mountinfo_text):
    """回傳要掃描的掛載點；同一裝置與子目錄的重複掛載（bind mount）只取一個。"""
    seen = {}
    for line in (mountinfo_text or "").splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        f = left.split()
        fstype = right.split()[0] if right.split() else ""
        if len(f) < 5:
            continue
        mp = f[4].replace("\\040", " ")
        # 容器的根目錄可能是 overlay；主機上其他 overlay（容器映像）不掃描
        if fstype not in LOCAL_FS and not (fstype == "overlay" and mp == "/"):
            continue
        key = (f[2], f[3])
        if key not in seen or len(mp) < len(seen[key]):
            seen[key] = mp
    return sorted(set(seen.values()))


_PRIV_CACHE = {}
PRIV_TIMEOUT = 1200


def find_privileged(mount):
    """find <mount> -xdev \\( -perm -4000 -o -perm -2000 \\) -type f（逾時 20 分鐘，結果快取 2 分鐘）。

    同一次執行中檢測、修復、修復後檢測、後測都會用到，快取避免重複掃描整個檔案系統。
    """
    c = _PRIV_CACHE.get(mount)
    if c and time.time() - c[0] < 120:
        return c[1]
    if not os.path.isdir(mount):
        return []
    r = run(["find", mount, "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-type", "f", "-print0"],
            timeout=PRIV_TIMEOUT)
    if r.rc == 124:
        raise RuntimeError("掃描 %s 逾時（%d 秒），請於離峰時間人工執行" % (mount, PRIV_TIMEOUT))
    if r.rc not in (0, 1):  # rc=1 為部分目錄無法讀取，結果仍可用
        raise RuntimeError("find 執行失敗：%s" % r.text()[-200:])
    out = sorted(p for p in r.out.split("\0") if p)
    _PRIV_CACHE[mount] = (time.time(), out)
    return out


# [PrivilegedCommands] RHEL8 0158 / RHEL9 0158 記錄特權指令使用情形（動態清單）
class PrivilegedCommands(AuditRuleSet):
    TPL = "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"

    def _lines(self, ctx):
        paths = set()
        for mp in local_mounts(read_text("/proc/self/mountinfo")):
            paths.update(find_privileged(mp))
        # 路徑含空白或控制字元無法寫成稽核規則
        return [self.TPL % p for p in sorted(paths) if re.match(r"^[\x21-\x7e]+$", p)]

    def _empty_text(self):
        return "本機磁碟未找到 setuid/setgid 程式"


def sudo_logfiles():
    """/etc/sudoers 與 /etc/sudoers.d/ 中 Defaults logfile= 的路徑（sudo 會略過含點號或 ~ 結尾的檔名）。"""
    files = ["/etc/sudoers"] + sorted(f for f in glob.glob("/etc/sudoers.d/*")
                                      if "." not in os.path.basename(f) and not f.endswith("~"))
    found = []
    for f in files:
        for line in (read_text(f) or "").splitlines():
            if line.strip().startswith("#") or not line.strip().startswith("Defaults"):
                continue
            for m in re.finditer(r"\blogfile\s*=\s*\"?([^\",\s]+)", line):
                if m.group(1) not in found:
                    found.append(m.group(1))
    return found


# [SudoLogRule] RHEL8 0161 / RHEL9 0161 記錄系統管理者活動日誌變更（依 sudoers 的 logfile）
class SudoLogRule(AuditRuleSet):
    def _lines(self, ctx):
        return ["-w %s -p wa -k actions" % p for p in (sudo_logfiles() or ["/var/log/sudo.log"])]


# [FaillockLogRule] RHEL8 0171 / RHEL9 0171 記錄 Pam_Faillock 日誌檔案（提示實際紀錄目錄）
class FaillockLogRule(AuditRuleSet):
    def _extra_note(self, ctx):
        d = te.get_kv(read_text("/etc/security/faillock.conf") or "", "dir") or "/var/run/faillock"
        if d.rstrip("/") != "/var/log/faillock":
            return "；註：pam_faillock 實際紀錄目錄為 %s（0149 已監控 /var/run/faillock）" % d
        return ""


# ====================================================================
# auditd 設定不變模式（0173）
# ====================================================================

def last_e_setting(texts):
    """augenrules 以最後一個 -e 為準（並移到最後載入）；回傳該值或 None。"""
    val = None
    for text in texts:
        for line in (text or "").splitlines():
            m = re.match(r"^\s*-e\s+(\d)\s*(#.*)?$", line)
            if m:
                val = m.group(1)
    return val


def has_loginuid_immutable(texts):
    return any(re.match(r"^\s*--loginuid-immutable\s*(#.*)?$", l)
               for t in texts for l in (t or "").splitlines())


# [AuditImmutable] RHEL8 0173 / RHEL9 0173 auditd 設定不變模式（--loginuid-immutable 與 -e 2）
class AuditImmutable(Rule):
    """B 類。啟用後核心拒絕任何稽核規則變更（含本工具的回滾），只有重新開機才能解除；
    --loginuid-immutable 使 loginuid 設定後不可變更，部分容器（podman、systemd-nspawn）內登入可能異常。
    為避免鎖定後本次執行的其他稽核修復與回滾無法生效，修復只寫入設定檔、不立即載入，重開機後生效。"""
    category = CAT
    title = "auditd 設定不變模式"
    expected = "2（rules.d 最後加入 --loginuid-immutable 與 -e 2）"
    risk = "B"
    needs_reboot = True
    # 檔名排在 rules.d 最後（gcb-*.rules、audit.rules 之後），即「最後被執行的 .rules 檔」
    FILE = AUDIT_RULES_DIR + "/zz-gcb-0173-finalize.rules"

    def __init__(self, ids):
        self.ids = ids

    def _texts(self):
        return [read_text(f) for f in sorted(glob.glob(AUDIT_RULES_DIR + "/*.rules"))]

    def check(self, ctx):
        if not which("auditctl"):
            return Check(FAIL, "未安裝 audit 套件")
        texts = self._texts()
        val = last_e_setting(texts)
        imm = has_loginuid_immutable(texts)
        st = run(["auditctl", "-s"], timeout=30).out
        rt = audit_enabled()
        m = re.search(r"^loginuid_immutable\s+(\d)", st, re.M)
        cur = "rules.d 設定：%s、--loginuid-immutable：%s；目前 enabled=%s、loginuid_immutable=%s" % (
            "-e " + val if val else "未設定", "有" if imm else "無", rt or "無法取得",
            m.group(1) if m else "無法取得")
        ok = val == "2" and imm
        if ok and rt != "2":
            cur += "（需重開機生效）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if not which("augenrules"):
            raise ManualRequired("未安裝 audit 套件，請先完成「auditd 套件」項目（0132）")
        # -e 2 必須是最後一行：鎖定後的設定（含 --loginuid-immutable）都會被核心拒絕
        fx.write_file(self.FILE, "## GCB %s auditd 設定不變模式（gcb-checker 產生，-e 2 需為最後一行）\n"
                      "--loginuid-immutable\n-e 2\n" % self.rule_id(ctx.osi), mode=0o600)
        if not fx.dry and last_e_setting(self._texts()) != "2":
            raise FixError("%s 之後還有其他 .rules 檔設定 -e，請人工調整" % self.FILE)
        fx.note("已寫入稽核設定不變模式（--loginuid-immutable、-e 2），重開機後生效。生效後任何稽核規則的新增、"
                "修改或回滾都要重新開機才會生效；--loginuid-immutable 可能使部分容器內登入異常。"
                "回滾本項只會移除設定檔，若已重開機鎖定，需再重開機才能解除。注意：重開機前若再次執行本工具，"
                "其他稽核規則項目執行 augenrules --load 時會一併載入 -e 2 而立即鎖定")


# ====================================================================
# rsyslog（0176、0177、0308）
# ====================================================================

RSYSLOG_CONF = "/etc/rsyslog.conf"


def rsyslog_files():
    return [RSYSLOG_CONF] + sorted(glob.glob("/etc/rsyslog.d/*.conf"))


_LEGACY_MODE = re.compile(r"^(\s*\$FileCreateMode\s+)(\S+)(.*)$", re.I)
_RAINER_MODE = re.compile(r"(fileCreateMode\s*=\s*\")([^\"]*)(\")", re.I)


def mode_ok(v, limit=0o640):
    try:
        return int(v, 8) & ~limit == 0
    except ValueError:
        return False


def rsyslog_modes(text):
    """回傳設定中所有 $FileCreateMode 與 fileCreateMode= 的值。"""
    vals = []
    for line in (text or "").splitlines():
        if line.strip().startswith("#"):
            continue
        m = _LEGACY_MODE.match(line)
        if m:
            vals.append(m.group(2))
        vals += [x.group(2) for x in _RAINER_MODE.finditer(line.split("#", 1)[0])]
    return vals


def rsyslog_fix_text(text, has_any):
    """把過寬的值改為 0640；完全沒有設定時加在第一個 include 之前（只影響其後的動作）。"""
    out, inserted = [], has_any
    for line in (text or "").splitlines():
        if not line.strip().startswith("#"):
            if not inserted and re.match(r"^\s*(\$IncludeConfig\b|include\s*\()", line, re.I):
                out.append("$FileCreateMode 0640")
                inserted = True
            m = _LEGACY_MODE.match(line)
            if m and not mode_ok(m.group(2)):
                line = m.group(1) + "0640" + m.group(3)
            line = _RAINER_MODE.sub(lambda x: x.group(1) + (x.group(2) if mode_ok(x.group(2)) else "0640")
                                    + x.group(3), line)
        out.append(line)
    if not inserted:
        out.insert(0, "$FileCreateMode 0640")
    return "\n".join(out) + "\n"


def rsyslog_validate(fx):
    if which("rsyslogd"):
        r = fx.run(["rsyslogd", "-N1"], "檢查 rsyslog 設定語法", check=False)
        if r is not None and not r.ok:
            raise FixError("rsyslog 設定檢查失敗：%s" % r.text()[-200:])


# [RsyslogFileMode] RHEL8 0176 / RHEL9 0176 設定 rsyslog 日誌檔案預設權限
class RsyslogFileMode(Rule):
    category = CAT
    title = "設定 rsyslog 日誌檔案預設權限"
    expected = "$FileCreateMode 0640 或更低權限"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if read_text(RSYSLOG_CONF) is None:
            return Check(FAIL, "未安裝 rsyslog（找不到 %s）" % RSYSLOG_CONF)
        vals = [(f, v) for f in rsyslog_files() for v in rsyslog_modes(read_text(f))]
        if not vals:
            return Check(FAIL, "未設定 $FileCreateMode（rsyslog 預設 0644）")
        bad = [(f, v) for f, v in vals if not mode_ok(v)]
        if bad:
            return Check(FAIL, "權限過寬：" + "、".join("%s（%s）" % (v, f) for f, v in bad))
        return Check(PASS, "、".join("%s（%s）" % (v, f) for f, v in vals))

    def fix(self, ctx, fx):
        if read_text(RSYSLOG_CONF) is None:
            raise ManualRequired("未安裝 rsyslog，請先完成「rsyslog 套件」項目（0174）")
        has_any = any(rsyslog_modes(read_text(f)) for f in rsyslog_files())
        fx.add_undo(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog")
        for f in rsyslog_files():
            if f == RSYSLOG_CONF or any(not mode_ok(v) for v in rsyslog_modes(read_text(f))):
                fx.edit_file(f, lambda t, f=f: rsyslog_fix_text(t, has_any or f != RSYSLOG_CONF))
        rsyslog_validate(fx)
        fx.run(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog", check=False)
        fx.note("既有日誌檔權限不會改變，只影響之後新建的檔案")


SECURE_FACILITIES = ("auth", "authpriv", "daemon")
SECURE_LINE = "auth.*,authpriv.*,daemon.* /var/log/secure"


def rsyslog_secure_facilities(texts, target="/var/log/secure"):
    """解析傳統 selector 行，回傳全部等級（.* 或 .debug）都寫到 target 的 facility 集合。"""
    got = set()
    for text in texts:
        for line in (text or "").splitlines():
            s = line.strip()
            if not s or s.startswith(("#", "$")) or "(" in s.split(None, 1)[0]:
                continue
            parts = s.split(None, 1)
            if len(parts) < 2 or parts[1].split()[0].lstrip("-") != target:
                continue
            ok = set()
            for sel in parts[0].split(";"):
                if "." not in sel:
                    continue
                # 「auth,authpriv.*」與 GCB 寫法「auth.*,authpriv.*」都接受：未帶等級者沿用最後的等級
                last = sel.rsplit(".", 1)[1]
                for item in sel.split(","):
                    fac, prio = item.rsplit(".", 1) if "." in item else (item, last)
                    names = SECURE_FACILITIES if fac == "*" else (fac,)
                    if prio in ("*", "debug"):
                        ok.update(names)
                    elif prio == "none":
                        ok.difference_update(names)
            got |= ok
    return got


# [RsyslogSecure] RHEL8 0177 / RHEL9 0177 設定 rsyslog 日誌記錄規則
class RsyslogSecure(Rule):
    category = CAT
    title = "設定 rsyslog 日誌記錄規則"
    expected = "auth、authpriv 及 daemon（%s）" % SECURE_LINE
    DROPIN = "/etc/rsyslog.d/50-gcb-secure.conf"

    def __init__(self, ids):
        self.ids = ids

    def _missing(self):
        got = rsyslog_secure_facilities(read_text(f) for f in rsyslog_files())
        return [f for f in SECURE_FACILITIES if f not in got]

    def check(self, ctx):
        if read_text(RSYSLOG_CONF) is None:
            return Check(FAIL, "未安裝 rsyslog（找不到 %s）" % RSYSLOG_CONF)
        miss = self._missing()
        if miss:
            return Check(FAIL, "未記錄到 /var/log/secure：%s" % "、".join(miss))
        return Check(PASS, "auth、authpriv、daemon 皆記錄到 /var/log/secure")

    def fix(self, ctx, fx):
        if read_text(RSYSLOG_CONF) is None:
            raise ManualRequired("未安裝 rsyslog，請先完成「rsyslog 套件」項目（0174）")
        fx.add_undo(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog")
        fx.write_file(self.DROPIN, "# GCB %s（gcb-checker 產生）\n%s\n" % (self.rule_id(ctx.osi), SECURE_LINE))
        rsyslog_validate(fx)
        fx.run(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog", check=False)
        fx.note("daemon 訊息加入 /var/log/secure 後該檔案量會增加（同時仍寫入 /var/log/messages）")


# ---------- 0308 rsyslog logrotate ----------

LOGROTATE_DIR = "/var/log/rsyslog"
LOGROTATE_FILE = "/etc/logrotate.d/rsyslog"
LOGROTATE_PATTERN = "/var/log/rsyslog/*.log"
LOGROTATE_STANZA = """/var/log/rsyslog/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl reload rsyslog.service >/dev/null || true
    endscript
}
"""
LOGROTATE_DIRECTIVES = ("weekly", "rotate 4", "compress", "missingok", "notifempty")


def logrotate_blocks(text):
    """解析 logrotate 設定，回傳 [{"paths", "start", "end", "directives", "scripts"}]（行號從 0 起算）。"""
    blocks, pending, pend_start = [], [], None
    cur, script = None, None
    for i, line in enumerate((text or "").splitlines()):
        s = line.strip()
        if cur is None:
            if not s or s.startswith("#"):
                continue
            if "{" in s:
                before = s.split("{", 1)[0].split()
                cur = {"paths": pending + before, "start": pend_start if pending else i, "end": None,
                       "directives": [], "scripts": {}}
                pending, pend_start = [], None
                rest = s.split("{", 1)[1].strip()
                if rest == "}":
                    cur["end"] = i
                    blocks.append(cur)
                    cur = None
            elif s[0] in "/\"'":  # 路徑行；其他為全域設定（weekly、include…）
                if not pending:
                    pend_start = i
                pending += s.split()
            else:
                pending, pend_start = [], None
            continue
        if script is not None:
            if s == "endscript":
                script = None
            else:
                cur["scripts"][script].append(s)
            continue
        if s in ("postrotate", "prerotate", "firstaction", "lastaction", "preremove"):
            script = s
            cur["scripts"][s] = []
            continue
        if s == "}" or (s.endswith("}") and not s.startswith("#")):
            cur["end"] = i
            blocks.append(cur)
            cur = None
            continue
        if s and not s.startswith("#"):
            cur["directives"].append(re.sub(r"\s+", " ", s))
    return blocks


def logrotate_block_ok(block):
    """區塊含 weekly、rotate 4、compress、missingok、notifempty 與重新載入 rsyslog 的 postrotate。"""
    miss = [d for d in LOGROTATE_DIRECTIVES if d not in block["directives"]]
    post = " ".join(block["scripts"].get("postrotate", []))
    if not re.search(r"systemctl\s+reload\s+rsyslog", post):
        miss.append("postrotate（systemctl reload rsyslog）")
    return miss


def logrotate_files():
    return ["/etc/logrotate.conf"] + sorted(f for f in glob.glob("/etc/logrotate.d/*") if os.path.isfile(f))


# [RsyslogLogrotate] RHEL9 0308 rsyslog logrotate（不重複加入同一路徑的輪替區塊）
class RsyslogLogrotate(Rule):
    category = CAT
    title = "rsyslog logrotate"
    expected = "啟用（/var/log/rsyslog 750 以下；/etc/logrotate.d/rsyslog 設定 /var/log/rsyslog/*.log 每週輪替 4 份、壓縮）"

    def __init__(self, ids):
        self.ids = ids

    def _ours(self):
        """/etc/logrotate.d/rsyslog 中含 /var/log/rsyslog/*.log 的區塊。"""
        return [b for b in logrotate_blocks(read_text(LOGROTATE_FILE)) if LOGROTATE_PATTERN in b["paths"]]

    def _others(self):
        """其他設定檔中涵蓋 /var/log/rsyslog/ 的區塊（同一檔案出現在兩個區塊時 logrotate 會報錯）。"""
        out = []
        for f in logrotate_files():
            if f == LOGROTATE_FILE:
                continue
            for b in logrotate_blocks(read_text(f)):
                if any(p.startswith(LOGROTATE_DIR + "/") for p in b["paths"]):
                    out.append(f)
        return out

    def _dir_problem(self):
        if not os.path.isdir(LOGROTATE_DIR):
            return "%s 不存在" % LOGROTATE_DIR
        mode = os.stat(LOGROTATE_DIR).st_mode & 0o7777
        if mode & ~0o750:
            return "%s 權限 %03o" % (LOGROTATE_DIR, mode)
        return None

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "rsyslog"):
            return Check(FAIL, "未安裝 rsyslog（見 0174）")
        probs = []
        d = self._dir_problem()
        if d:
            probs.append(d)
        ours = self._ours()
        if not ours:
            probs.append("%s 沒有 %s 的輪替區塊" % (LOGROTATE_FILE, LOGROTATE_PATTERN))
        else:
            miss = logrotate_block_ok(ours[-1])
            if miss:
                probs.append("輪替區塊缺少：%s" % "、".join(miss))
            if len(ours) > 1:
                probs.append("%s 重複出現 %d 次" % (LOGROTATE_PATTERN, len(ours)))
        others = self._others()
        if others:
            probs.append("其他設定檔也輪替 %s：%s" % (LOGROTATE_DIR, "、".join(sorted(set(others)))))
        if probs:
            return Check(FAIL, "；".join(probs))
        return Check(PASS, "%s 750 以下；輪替區塊設定完整" % LOGROTATE_DIR)

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "rsyslog"):
            raise ManualRequired("未安裝 rsyslog，請先完成「rsyslog 套件」項目（0174）")
        others = self._others()
        if others:
            raise ManualRequired("%s 已在其他設定檔設定輪替（%s），再加入會造成 logrotate duplicate log entry 錯誤，"
                                 "請人工合併到 %s" % (LOGROTATE_DIR, "、".join(sorted(set(others))), LOGROTATE_FILE))
        ours = self._ours()
        if len(ours) > 1 or any(len(b["paths"]) > 1 for b in ours):
            raise ManualRequired("%s 中 %s 的輪替區塊重複或與其他路徑共用，請人工整理" % (LOGROTATE_FILE, LOGROTATE_PATTERN))
        # 目錄
        if not os.path.isdir(LOGROTATE_DIR):
            fx.add_undo(["rmdir", "--ignore-fail-on-non-empty", LOGROTATE_DIR], "刪除新建的 %s（空目錄）" % LOGROTATE_DIR)
            fx.run(["mkdir", "-m", "750", LOGROTATE_DIR], "建立 %s" % LOGROTATE_DIR)
        if not fx.dry:
            mode = os.stat(LOGROTATE_DIR).st_mode & 0o7777
            if mode & ~0o750:
                fx.chmod(LOGROTATE_DIR, mode & 0o750)
        # 輪替區塊：已有則整段取代（不重複加入），沒有則附加在檔尾；不動 RHEL 預設的其他區塊
        if not ours or logrotate_block_ok(ours[0]):
            before_ok = self._validate() if which("logrotate") and read_text(LOGROTATE_FILE) is not None else False

            def _edit(text):
                lines = (text or "").splitlines()
                if ours:
                    b = ours[0]
                    lines[b["start"]:b["end"] + 1] = LOGROTATE_STANZA.rstrip("\n").splitlines()
                    return "\n".join(lines) + "\n"
                return (text or "") + ("" if not text or text.endswith("\n") else "\n") + LOGROTATE_STANZA
            fx.edit_file(LOGROTATE_FILE, _edit)
            if before_ok and not fx.dry and not self._validate():
                raise FixError("logrotate 設定檢查失敗（logrotate -d %s）" % LOGROTATE_FILE)

    @staticmethod
    def _validate():
        return run(["logrotate", "-d", LOGROTATE_FILE], timeout=60).ok


# ====================================================================
# journald（0180–0182）
# ====================================================================

JOURNALD_CONF = "/etc/systemd/journald.conf"
JOURNALD_DIRS = ["/usr/lib/systemd/journald.conf.d", "/usr/local/lib/systemd/journald.conf.d",
                 "/run/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"]  # 優先順序由低到高
JOURNALD_OWN = "/etc/systemd/journald.conf.d/60-gcb-journald.conf"
_TRUE = ("yes", "true", "1", "on")


def journald_files():
    """systemd 的讀取順序：journald.conf，再依檔名讀 drop-in（同檔名以 /etc 優先）。"""
    chosen = {}
    for d in JOURNALD_DIRS:
        for f in glob.glob(d + "/*.conf"):
            chosen[os.path.basename(f)] = f
    return [JOURNALD_CONF] + [chosen[b] for b in sorted(chosen)]


# [JournaldSetting] RHEL8 0180–0182 / RHEL9 0181–0182 journald 參數（寫入 drop-in，重啟 systemd-journald）
class JournaldSetting(Rule):
    category = CAT

    def __init__(self, title, ids, key, value, default=None):
        self.title = title
        self.ids = ids
        self.key = key
        self.value = value
        self.default = default
        self.expected = value

    def _values(self):
        out = []
        for f in journald_files():
            v = te.get_kv(read_text(f) or "", self.key)
            if v is not None:
                out.append((f, v))
        return out

    def check(self, ctx):
        vals = self._values()
        if not vals:
            return Check(FAIL, "%s 未設定%s" % (self.key, "（systemd 預設 %s，GCB 要求明確設定）" % self.default
                                                 if self.default else ""))
        f, v = vals[-1]
        cur = "%s=%s（%s）" % (self.key, v, f)
        ok = compare(v, "eq", self.value)
        if not ok and self.value == "yes" and v.lower() in _TRUE:
            cur += "；與 yes 等價，但 GCB 要求設定為 yes"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        own = os.path.basename(JOURNALD_OWN)
        later = [(f, v) for f, v in self._values()
                 if f != JOURNALD_CONF and os.path.basename(f) > own and not compare(v, "eq", self.value)]
        for f, v in later:
            if not f.startswith("/etc/"):
                raise ManualRequired("%s 設定 %s=%s 會覆寫本工具設定，請人工調整" % (f, self.key, v))
        fx.add_undo(["systemctl", "restart", "systemd-journald"], "重新啟動 systemd-journald")
        for f, v in later:
            fx.edit_file(f, lambda t: te.comment_kv(t, self.key))
        fx.edit_file(JOURNALD_OWN, lambda t: te.set_kv(t or "[Journal]\n", self.key, self.value, sep="="))
        fx.run(["systemctl", "restart", "systemd-journald"], "重新啟動 systemd-journald", check=False)


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

def _perm(title, ids, paths, expected, **kw):
    return NeedsAudit(FilePerm(title, CAT, ids, paths, expected=expected, **kw))


def _auditd_conf(title, ids, key, value, cmp="eq", target=None, expected=None, risk="A"):
    # generic.auditd_conf 的適用條件是 Debian 套件名 auditd，RHEL 改以 NeedsAudit 判斷 audit 套件
    return NeedsAudit(KvSetting(title, CAT, ids, AUDITD_CONF, key, value, cmp, target, sep=" = ",
                                apply=RELOAD_AUDITD, risk=risk, expected=expected))


AUDIT_TOOLS = ["/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd",
               "/sbin/audisp-remote", "/sbin/audisp-syslog", "/sbin/augenrules", "/sbin/rsyslogd"]

RULES = [
    # RHEL8 0132 / RHEL9 0132 auditd 套件
    AuditPackages(R(r8=132, r9=132)),
    # RHEL8 0133 / RHEL9 0133 auditd 服務 → common.py
    # RHEL8 0134 / RHEL9 0134 稽核 auditd 服務啟動前之程序 → common.py
    # RHEL8 0135 / RHEL9 0135 稽核待辦事項數量限制
    AuditBacklogLimit(R(r8=135, r9=135)),
    # RHEL8 0136 / RHEL9 0136 稽核處理失敗時通知系統管理者
    PostmasterAlias(R(r8=136, r9=136)),
    # RHEL8 0137 / RHEL9 0137 稽核日誌檔案所有權
    NeedsAudit(AuditLogPerm("稽核日誌檔案所有權", R(r8=137, r9=137), "file", owner="root", groups=["root"],
                            expected="root:root")),
    # RHEL8 0138 / RHEL9 0138 稽核日誌檔案權限
    NeedsAudit(AuditLogPerm("稽核日誌檔案權限", R(r8=138, r9=138), "file", max_mode=0o600,
                            expected="600 或更低權限")),
    # RHEL8 0139 / RHEL9 0139 稽核日誌目錄所有權
    NeedsAudit(AuditLogPerm("稽核日誌目錄所有權", R(r8=139, r9=139), "dir", owner="root", groups=["root"],
                            expected="root:root")),
    # RHEL8 0140 / RHEL9 0140 稽核日誌目錄權限
    NeedsAudit(AuditLogPerm("稽核日誌目錄權限", R(r8=140, r9=140), "dir", max_mode=0o700,
                            expected="700 或更低權限")),
    # RHEL8 0141 / RHEL9 0141 稽核規則檔案權限（文件列 audit.rules，本工具新增的 rules.d/*.rules 一併檢查）
    _perm("稽核規則檔案權限", R(r8=141, r9=141), AUDIT_RULES_DIR + "/*.rules", "600 或更低權限",
          max_mode=0o600, missing="pass"),
    # RHEL8 0142 / RHEL9 0142 稽核設定檔案權限
    _perm("稽核設定檔案權限", R(r8=142, r9=142), AUDITD_CONF, "640 或更低權限", max_mode=0o640),
    # RHEL8 0143 / RHEL9 0143 稽核工具權限（不存在者略過；套件更新會還原為 0755，需定期重新檢測）
    _perm("稽核工具權限", R(r8=143, r9=143), AUDIT_TOOLS, "750 或更低權限", max_mode=0o750),
    # RHEL8 0144 / RHEL9 0144 稽核工具所有權
    _perm("稽核工具所有權", R(r8=144, r9=144), AUDIT_TOOLS, "root:root", owner="root", groups=["root"]),
    # RHEL8 0145 / RHEL9 0145 保護稽核工具
    AideAuditTools(R(r8=145, r9=145)),
    # RHEL8 0146 / RHEL9 0146 稽核日誌檔案大小上限
    _auditd_conf("稽核日誌檔案大小上限", R(r8=146, r9=146), "max_log_file", 32, "ge", 32, expected="32 以上"),
    # RHEL8 0147 / RHEL9 0147 稽核日誌達到其檔案大小上限之行為（B 類：keep_logs 不刪舊檔，需規劃空間與備份清理）
    _auditd_conf("稽核日誌達到其檔案大小上限之行為", R(r8=147, r9=147), "max_log_file_action", "keep_logs",
                 expected="keep_logs", risk="B"),
    # RHEL8 0148 / RHEL9 0148 記錄系統管理者活動
    AuditRuleSet("記錄系統管理者活動", R(r8=148, r9=148), [
        "-w /etc/sudoers -p wa -k scope",
        "-w /etc/sudoers.d/ -p wa -k scope",
    ]),
    # RHEL8 0149 / RHEL9 0149 記錄變更登入與登出資訊事件
    AuditRuleSet("記錄變更登入與登出資訊事件", R(r8=149, r9=149), [
        "-w /var/run/faillock/ -p wa -k logins",
        "-w /var/log/lastlog -p wa -k logins",
    ]),
    # RHEL8 0150 / RHEL9 0150 記錄會談啟始資訊（wtmp、btmp 依原文標記為 logins）
    AuditRuleSet("記錄會談啟始資訊", R(r8=150, r9=150), [
        "-w /var/run/utmp -p wa -k session",
        "-w /var/log/wtmp -p wa -k logins",
        "-w /var/log/btmp -p wa -k logins",
    ]),
    # RHEL8 0151 / RHEL9 0151 記錄變更日期與時間事件
    AuditRuleSet("記錄變更日期與時間事件", R(r8=151, r9=151), [
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change",
        "-a always,exit -F arch=b64 -S clock_settime -k time-change",
        "-a always,exit -F arch=b32 -S clock_settime -k time-change",
        "-w /etc/localtime -p wa -k time-change",
    ]),
    # RHEL8 0152 / RHEL9 0152 記錄變更系統強制存取控制事件
    AuditRuleSet("記錄變更系統強制存取控制事件", R(r8=152, r9=152), [
        "-w /etc/selinux/ -p wa -k MAC-policy",
        "-w /usr/share/selinux/ -p wa -k MAC-policy",
    ]),
    # RHEL8 0153 / RHEL9 0153 記錄變更系統網路環境事件（RHEL 9 另有 NetworkManager、network、hostname）
    AuditRuleSet("記錄變更系統網路環境事件", R(r8=153, r9=153), {
        "rhel8": [
            "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale",
            "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale",
            "-w /etc/issue -p wa -k system-locale",
            "-w /etc/issue.net -p wa -k system-locale",
            "-w /etc/hosts -p wa -k system-locale",
            "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale",
        ],
        "rhel9": [
            "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale",
            "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale",
            "-w /etc/issue -p wa -k system-locale",
            "-w /etc/issue.net -p wa -k system-locale",
            "-w /etc/hosts -p wa -k system-locale",
            "-w /etc/sysconfig/network-scripts -p wa -k system-locale",
            "-w /etc/NetworkManager -p wa -k system-locale",
            "-w /etc/sysconfig/network -p wa -k system-locale",
            "-w /etc/hostname -p wa -k system-locale",
        ],
    }),
    # RHEL8 0154 / RHEL9 0154 記錄變更自主存取控制權限事件
    AuditRuleSet("記錄變更自主存取控制權限事件", R(r8=154, r9=154), [
        "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 "
        "-k perm_mod",
        "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 "
        "-k perm_mod",
        "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr "
        "-S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr "
        "-S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod",
    ]),
    # RHEL8 0155 / RHEL9 0155 記錄不成功之未經授權檔案存取
    AuditRuleSet("記錄不成功之未經授權檔案存取", R(r8=155, r9=155), [
        "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES "
        "-F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES "
        "-F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM "
        "-F auid>=1000 -F auid!=4294967295 -k access",
        "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM "
        "-F auid>=1000 -F auid!=4294967295 -k access",
    ]),
    # RHEL8 0156 / RHEL9 0156 記錄變更使用者或群組資訊事件（RHEL 9 另有 nsswitch.conf、pam.conf、pam.d）
    AuditRuleSet("記錄變更使用者或群組資訊事件", R(r8=156, r9=156), {
        "rhel8": [
            "-w /etc/group -p wa -k identity",
            "-w /etc/passwd -p wa -k identity",
            "-w /etc/gshadow -p wa -k identity",
            "-w /etc/shadow -p wa -k identity",
            "-w /etc/security/opasswd -p wa -k identity",
        ],
        "rhel9": [
            "-w /etc/group -p wa -k identity",
            "-w /etc/passwd -p wa -k identity",
            "-w /etc/gshadow -p wa -k identity",
            "-w /etc/shadow -p wa -k identity",
            "-w /etc/security/opasswd -p wa -k identity",
            "-w /etc/nsswitch.conf -p wa -k identity",
            "-w /etc/pam.conf -p wa -k identity",
            "-w /etc/pam.d -p wa -k identity",
        ],
    }),
    # RHEL8 0157 / RHEL9 0157 記錄變更檔案系統掛載事件
    AuditRuleSet("記錄變更檔案系統掛載事件", R(r8=157, r9=157), [
        "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
        "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
    ]),
    # RHEL8 0158 / RHEL9 0158 記錄特權指令使用情形（掃描本機磁碟的 setuid/setgid 程式）
    PrivilegedCommands("記錄特權指令使用情形", R(r8=158, r9=158)),
    # RHEL8 0159 / RHEL9 0159 記錄檔案刪除事件（RHEL 9 原文「renameat-S」斷行黏字已修正）
    AuditRuleSet("記錄檔案刪除事件", R(r8=159, r9=159), [
        "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -S rmdir -F auid>=1000 "
        "-F auid!=4294967295 -k delete",
        "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -S rmdir -F auid>=1000 "
        "-F auid!=4294967295 -k delete",
    ]),
    # RHEL8 0160 / RHEL9 0160 記錄核心模組掛載與卸載事件
    AuditRuleSet("記錄核心模組掛載與卸載事件", R(r8=160, r9=160), [
        "-w /sbin/insmod -p x -k modules",
        "-w /sbin/rmmod -p x -k modules",
        "-w /sbin/modprobe -p x -k modules",
        "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules",
        "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules",
    ]),
    # RHEL8 0161 / RHEL9 0161 記錄系統管理者活動日誌變更（sudoers 的 logfile，未設定時 /var/log/sudo.log）
    SudoLogRule("記錄系統管理者活動日誌變更", R(r8=161, r9=161)),
    # RHEL8 0162 / RHEL9 0162 記錄 chcon 指令使用情形
    AuditRuleSet("記錄 chcon 指令使用情形", R(r8=162, r9=162), [
        "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng",
    ]),
    # RHEL8 0163 / RHEL9 0163 記錄 ssh-agent 程序使用情形
    AuditRuleSet("記錄 ssh-agent 程序使用情形", R(r8=163, r9=163), [
        "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh",
    ]),
    # RHEL8 0164 / RHEL9 0164 記錄 unix_update 程序使用情形
    AuditRuleSet("記錄 unix_update 程序使用情形", R(r8=164, r9=164), [
        "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 "
        "-k privileged-unix-update",
    ]),
    # RHEL8 0165 / RHEL9 0165 記錄 setfacl 指令使用情形
    AuditRuleSet("記錄 setfacl 指令使用情形", R(r8=165, r9=165), [
        "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng",
    ]),
    # RHEL8 0166 / RHEL9 0166 記錄 finit_module 指令使用情形
    AuditRuleSet("記錄 finit_module 指令使用情形", R(r8=166, r9=166), [
        "-a always,exit -F arch=b32 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng",
        "-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng",
    ]),
    # RHEL8 0167 / RHEL9 0167 記錄 open_by_handle_at 系統呼叫使用情形
    AuditRuleSet("記錄 open_by_handle_at 系統呼叫使用情形", R(r8=167, r9=167), [
        "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 "
        "-k perm_access",
        "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 "
        "-k perm_access",
        "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 "
        "-k perm_access",
        "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 "
        "-k perm_access",
    ]),
    # RHEL8 0168 / RHEL9 0168 記錄 usermod 指令使用情形
    AuditRuleSet("記錄 usermod 指令使用情形", R(r8=168, r9=168), [
        "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 "
        "-k privileged-usermod",
    ]),
    # RHEL8 0169 / RHEL9 0169 記錄 chacl 指令使用情形
    AuditRuleSet("記錄 chacl 指令使用情形", R(r8=169, r9=169), [
        "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng",
    ]),
    # RHEL8 0170 / RHEL9 0170 記錄 kmod 指令使用情形
    AuditRuleSet("記錄 kmod 指令使用情形", R(r8=170, r9=170), [
        "-w /bin/kmod -p x -k modules",
    ]),
    # RHEL8 0171 / RHEL9 0171 記錄 Pam_Faillock 日誌檔案
    FaillockLogRule("記錄 Pam_Faillock 日誌檔案", R(r8=171, r9=171), [
        "-w /var/log/faillock -p wa -k logins",
    ]),
    # RHEL8 0172 / RHEL9 0172 記錄 execve 系統呼叫使用情形
    AuditRuleSet("記錄 execve 系統呼叫使用情形", R(r8=172, r9=172), [
        "-a always,exit -F arch=b32 -F auid!=unset -S execve -C uid!=euid -F key=execpriv",
        "-a always,exit -F arch=b64 -F auid!=unset -S execve -C uid!=euid -F key=execpriv",
        "-a always,exit -F arch=b32 -F auid!=unset -S execve -C gid!=egid -F key=execpriv",
        "-a always,exit -F arch=b64 -F auid!=unset -S execve -C gid!=egid -F key=execpriv",
    ]),
    # RHEL8 0173 / RHEL9 0173 auditd 設定不變模式（B 類；--loginuid-immutable 在前、-e 2 為最後一行）
    AuditImmutable(R(r8=173, r9=173)),
    # RHEL8 0174 / RHEL9 0174 rsyslog 套件
    PackagePresent("rsyslog 套件", "rsyslog", R(r8=174, r9=174), CAT),
    # RHEL8 0175 / RHEL9 0175 rsyslog 服務 → common.py
    # RHEL8 0176 / RHEL9 0176 設定 rsyslog 日誌檔案預設權限
    RsyslogFileMode(R(r8=176, r9=176)),
    # RHEL8 0177 / RHEL9 0177 設定 rsyslog 日誌記錄規則（RHEL 9 原文「authpriv.* ,daemon.*」多餘空白已修正）
    RsyslogSecure(R(r8=177, r9=177)),
    # RHEL8 0178 / RHEL9 0178 /var/log/messages 檔案所有權
    FilePerm("/var/log/messages 檔案所有權", CAT, R(r8=178, r9=178), "/var/log/messages",
             owner="root", groups=["root"], expected="root:root"),
    # RHEL8 0179 / RHEL9 0179 /var/log 目錄所有權
    FilePerm("/var/log 目錄所有權", CAT, R(r8=179, r9=179), "/var/log",
             owner="root", groups=["root"], missing="fail", expected="root:root"),
    # RHEL8 0180 設定 journald 將日誌發送到 rsyslog（RHEL 9 無此項）
    JournaldSetting("設定 journald 將日誌發送到 rsyslog", R(r8=180), "ForwardToSyslog", "yes"),
    # RHEL8 0181 / RHEL9 0181 設定 journald 壓縮日誌檔案
    JournaldSetting("設定 journald 壓縮日誌檔案", R(r8=181, r9=181), "Compress", "yes", default="yes"),
    # RHEL8 0182 / RHEL9 0182 設定 journald 將日誌檔案永久保存於磁碟
    JournaldSetting("設定 journald 將日誌檔案永久保存於磁碟", R(r8=182, r9=182), "Storage", "persistent",
                    default="auto"),
    # RHEL9 0308 rsyslog logrotate
    RsyslogLogrotate(R(r9=308)),
]
