# -*- coding: utf-8 -*-
"""Ubuntu 22.04 日誌與稽核（TWGCB-01-014-0112 ～ 0154）。"""
import glob
import os
import re
import stat

from ... import auditrules
from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from ..generic import (AUDIT_RULES_DIR, AuditRules, FilePerm, PackagePresent,
                       auditd_conf, compare)
from .helpers import U

CAT = "日誌與稽核"
AUDITD_CONF = "/etc/audit/auditd.conf"
RELOAD_AUDITD = ["service", "auditd", "reload"]  # auditd 不接受 systemctl restart/stop


def auditd_installed(ctx):
    return pkgsvc.pkg_installed(ctx.osi, "auditd")


def audit_enabled():
    """auditctl -s 的 enabled 值（0/1/2）；無法取得回傳 None。"""
    m = re.search(r"^enabled\s+(\d)", run(["auditctl", "-s"], timeout=30).out, re.M)
    return m.group(1) if m else None


# ====================================================================
# 共用：未安裝 auditd 時判定不合格（同一次執行中 0112 安裝後即可接著修復）
# ====================================================================

# [NeedsAuditd] 包裝 0116–0125、0127、0128：未安裝 auditd 時為不合格而非不適用
class NeedsAuditd(Rule):
    def __init__(self, inner):
        self.inner = inner
        for a in ("title", "category", "ids", "risk", "expected", "needs_reboot", "manual_hint"):
            setattr(self, a, getattr(inner, a))

    def check(self, ctx):
        if not auditd_installed(ctx):
            return Check(FAIL, "未安裝 auditd")
        return self.inner.check(ctx)

    def precondition(self, ctx):
        return self.inner.precondition(ctx)

    def fix(self, ctx, fx):
        if not auditd_installed(ctx):
            raise ManualRequired("未安裝 auditd，請先完成「auditd 套件」項目（0112）")
        self.inner.fix(ctx, fx)


# ====================================================================
# 套件
# ====================================================================

# [AuditPackages] TWGCB-01-014-0112 auditd 套件（auditd、audispd-plugins）
class AuditPackages(Rule):
    category = CAT
    title = "auditd 套件"
    expected = "安裝（auditd、audispd-plugins）"
    PKGS = ("auditd", "audispd-plugins")

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
# GRUB 開機參數 audit_backlog_limit（數值比較）
# ====================================================================

_GRUB_LINE = re.compile(r'^\s*GRUB_CMDLINE_LINUX=(["\']?)(.*?)\1\s*$')


def grub_effective_cmdline(texts):
    """依 grub-mkconfig 載入順序（/etc/default/grub、grub.d/*.cfg）求 GRUB_CMDLINE_LINUX。"""
    val = ""
    for text in texts:
        for line in (text or "").splitlines():
            m = _GRUB_LINE.match(line)
            if m and not line.strip().startswith("#"):
                v = m.group(2)
                val = v.replace("${GRUB_CMDLINE_LINUX}", val).replace("$GRUB_CMDLINE_LINUX", val)
    return val


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


# [AuditBacklogLimit] TWGCB-01-014-0115 稽核待辦事項數量限制
class AuditBacklogLimit(Rule):
    category = CAT
    title = "稽核待辦事項數量限制"
    expected = "audit_backlog_limit 8,192 以上"
    risk = "B"
    needs_reboot = True
    KEY = "audit_backlog_limit"
    MIN = 8192
    DEFAULT = "/etc/default/grub"
    DROPIN = "/etc/default/grub.d/99-gcb-audit-backlog.cfg"
    GRUB_CFG = "/boot/grub/grub.cfg"

    def __init__(self, ids):
        self.ids = ids

    def _ok(self, v):
        return v is not None and v >= self.MIN

    def _persistent(self, default_text=None, extra=None):
        texts = [read_text(self.DEFAULT) if default_text is None else default_text]
        texts += [read_text(f) for f in sorted(glob.glob("/etc/default/grub.d/*.cfg")) if f != self.DROPIN]
        dropin = read_text(self.DROPIN) if extra is None else extra
        if dropin:
            texts.append(dropin)
        return cmdline_value(grub_effective_cmdline(texts).split(), self.KEY)

    def _grub_cfg_bad(self):
        text = read_text(self.GRUB_CFG)
        if text is None:
            return None
        return [l for l in text.splitlines()
                if re.match(r"^\s*linux\s", l) and not self._ok(cmdline_value(l.split(), self.KEY))]

    def check(self, ctx):
        if read_text(self.DEFAULT) is None:
            return Check(ERROR, "找不到 %s" % self.DEFAULT)
        bad = self._grub_cfg_bad()
        if bad is None:
            return Check(ERROR, "找不到 %s" % self.GRUB_CFG)
        pv = self._persistent()
        rt = cmdline_value((read_text("/proc/cmdline") or "").split(), self.KEY)
        ok = self._ok(pv) and not bad
        cur = "GRUB 設定：%s、開機項目不足：%d 個、目前核心：%s" % (
            pv if pv is not None else "未設定", len(bad), rt if rt is not None else "未設定")
        if ok and not self._ok(rt):
            cur += "（需重開機生效）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        old = read_text(self.DEFAULT)
        if old is None:
            raise ManualRequired("找不到 %s，系統可能未使用 GRUB，請人工設定開機參數" % self.DEFAULT)
        fx.add_undo(["update-grub"], "重新產生 grub.cfg")
        new = old
        if not self._ok(cmdline_value((te.grub_cmdline_get(old) or "").split(), self.KEY)):
            new = te.grub_cmdline_add(old, "%s=%d" % (self.KEY, self.MIN))
            fx.write_file(self.DEFAULT, new)
        # grub.d 若整個覆寫 GRUB_CMDLINE_LINUX，改以 drop-in 附加
        if not self._ok(self._persistent(default_text=new)):
            text = 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX %s=%d"\n' % (self.KEY, self.MIN)
            fx.write_file(self.DROPIN, text)
        fx.run(["update-grub"], "更新 GRUB 設定", timeout=300)


# ====================================================================
# 稽核日誌檔案與目錄（0116–0119）
# ====================================================================

def audit_log_file():
    return te.get_kv(read_text(AUDITD_CONF) or "", "log_file") or "/var/log/audit/audit.log"


def audit_log_group():
    return te.get_kv(read_text(AUDITD_CONF) or "", "log_group") or "root"


# [AuditLogPerm] TWGCB-01-014-0116～0119 稽核日誌檔案／目錄之所有權與權限
class AuditLogPerm(FilePerm):
    """路徑依 auditd.conf 的 log_file 決定。auditd 會依 log_group 重設日誌檔群組與權限
    （非 root 時為 0640），因此日誌檔項目一併要求 log_group = root。"""

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
            if c.status == NA:  # auditd 尚未產生日誌，log_group=root 時會以 root:root 0600 建立
                return Check(PASS, "尚未產生日誌檔；log_group=root")
            return c
        if c.status == NA:
            return Check(FAIL, "尚未產生日誌檔；auditd.conf log_group=%s（建立的日誌將為 root:%s 0640）" % (g, g))
        c.status = FAIL
        c.current += "；auditd.conf log_group=%s（auditd 會依此重設日誌群組與權限）" % g
        return c

    def fix(self, ctx, fx):
        if self.target == "file" and audit_log_group() not in ("root", "0"):
            fx.add_undo(RELOAD_AUDITD, "重新載入 auditd 設定")
            fx.edit_file(AUDITD_CONF, lambda t: te.set_kv(t, "log_group", "root"))
            fx.run(RELOAD_AUDITD, "重新載入 auditd 設定", check=False)
        FilePerm.fix(self, ctx, fx)


# ====================================================================
# AIDE 保護稽核工具（0126）
# ====================================================================

AIDE_ATTRS = "p+i+n+u+g+s+b+acl+xattrs+sha512"
AUDIT_TOOLS = ["/usr/sbin/auditctl", "/usr/sbin/auditd", "/usr/sbin/ausearch",
               "/usr/sbin/aureport", "/usr/sbin/autrace", "/usr/sbin/augenrules"]


def aide_rule_attrs(texts, path):
    """回傳 [屬性集合]：各設定中針對 path 的選取規則（排除 ! 否定規則）。"""
    out = []
    for text in texts:
        for line in (text or "").splitlines():
            tok = line.split("#", 1)[0].split()
            if len(tok) >= 2 and tok[0].lstrip("=").rstrip("$") == path:
                out.append(set(re.split(r"[+\s]+", " ".join(tok[1:]))))
    return out


# [AideAuditTools] TWGCB-01-014-0126 保護稽核工具
class AideAuditTools(Rule):
    category = CAT
    title = "保護稽核工具"
    expected = "啟用（AIDE 監控稽核工具：%s）" % AIDE_ATTRS
    CONF = "/etc/aide/aide.conf"
    DIR = "/etc/aide/aide.conf.d"
    DROPIN = DIR + "/99_gcb_audit_tools"  # aide.conf 以 ^[a-zA-Z0-9_-]+$ 載入，檔名不可有點號

    def __init__(self, ids):
        self.ids = ids

    def _files(self):
        return [self.CONF] + sorted(f for f in glob.glob(self.DIR + "/*")
                                    if re.match(r"^[A-Za-z0-9_-]+$", os.path.basename(f)))

    def _missing(self):
        texts = [read_text(f) for f in self._files()]
        need = set(AIDE_ATTRS.split("+"))
        return [p for p in AUDIT_TOOLS if not any(need <= a for a in aide_rule_attrs(texts, p))]

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "aide") or read_text(self.CONF) is None:
            return Check(FAIL, "未安裝 AIDE（見 0033 AIDE 套件）")
        miss = self._missing()
        if not miss:
            return Check(PASS, "6 個稽核工具皆已設定監控")
        return Check(FAIL, "未設定監控：%s" % "、".join(os.path.basename(p) for p in miss))

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "aide") or read_text(self.CONF) is None:
            raise ManualRequired("未安裝 AIDE，請先完成「AIDE 套件」項目（0033）")
        need = set(AIDE_ATTRS.split("+"))

        def _drop_weak(text):
            # 註解掉同路徑但屬性不足的舊規則，避免重複定義
            out = []
            for line in text.splitlines():
                tok = line.split("#", 1)[0].split()
                if len(tok) >= 2 and tok[0].lstrip("=").rstrip("$") in AUDIT_TOOLS \
                        and not need <= set(re.split(r"[+\s]+", " ".join(tok[1:]))):
                    line = te.MARK + line
                out.append(line)
            return "\n".join(out) + "\n" if out else ""

        for f in self._files():
            if f != self.DROPIN:
                fx.edit_file(f, _drop_weak)
        block = "# Audit Tools（GCB TWGCB-01-014-0126，gcb-checker 產生）\n" + \
            "".join("%s %s\n" % (p, AIDE_ATTRS) for p in AUDIT_TOOLS)
        before_ok = run(["aide", "--config-check", "-c", self.CONF], timeout=120).ok if which("aide") else False
        if re.search(r"^\s*@@x_include\s+%s" % re.escape(self.DIR), read_text(self.CONF) or "", re.M):
            fx.write_file(self.DROPIN, block)
        else:
            fx.edit_file(self.CONF, lambda t: t + ("" if not t or t.endswith("\n") else "\n") + block)
        if before_ok:
            r = fx.run(["aide", "--config-check", "-c", self.CONF], "檢查 AIDE 設定語法", check=False)
            if r is not None and not r.ok:
                raise FixError("AIDE 設定檢查失敗：%s" % r.text()[-200:])
        fx.note("請於方便時執行 aideinit 更新 AIDE 資料庫，否則下次檢查會回報新增的監控項目")


# ====================================================================
# 稽核規則（0129–0147）
# ====================================================================

def normalize_audit_text(text):
    """配合 auditctl -l 的顯示：目錄監看去掉結尾的 /，path 規則的「-S all」移除。"""
    out = []
    for l in (text or "").splitlines():
        l = re.sub(r"(-w\s+\S+?)/+(?=\s|$)", r"\1", l)
        l = re.sub(r"\s-S\s+all(?=\s|$)", "", l)
        out.append(l)
    return "\n".join(out)


_SYSCALL_CACHE = {}


def syscall_exists(arch, name):
    key = (arch, name)
    if key not in _SYSCALL_CACHE:
        _SYSCALL_CACHE[key] = run(["ausyscall", arch, name], timeout=10).ok
    return _SYSCALL_CACHE[key]


def filter_syscalls(line, exists=syscall_exists):
    """移除本機架構不存在的系統呼叫（例如 ARM 沒有 b32、rename、create_module），
    否則 auditctl 會整批載入失敗；全部不存在時回傳 None。"""
    m = re.search(r"arch=(b32|b64)", line)
    if not m or "-S" not in line.split() or not which("ausyscall"):
        return line
    out, any_left = [], False
    tok = line.split()
    i = 0
    while i < len(tok):
        if tok[i] == "-S" and i + 1 < len(tok):
            names = [n for n in tok[i + 1].split(",") if exists(m.group(1), n)]
            if names:
                out += ["-S", ",".join(names)]
                any_left = True
            i += 2
            continue
        out.append(tok[i])
        i += 1
    return " ".join(out) if any_left else None


def audit_target(line):
    m = re.match(r"\s*-w\s+(\S+)", line) or re.search(r"-F\s+(?:path|dir)=(\S+)", line)
    return m.group(1) if m else None


def audit_loadable(line):
    """上層目錄不存在時核心拒絕載入，會讓 auditctl -R 整批中斷；檔案本身不存在則可正常監看。"""
    p = audit_target(line)
    if not p:
        return True
    return os.path.isdir(os.path.dirname(p.rstrip("/")) or "/")


# [AuditRuleSet] TWGCB-01-014-0129～0147 稽核規則（寫入 rules.d/gcb-NNNN.rules）
class AuditRuleSet(AuditRules):
    """generic.AuditRules 加上：上層目錄不存在的規則略過、檔案權限 0600（0121）、
    auditctl -l 顯示差異的正規化，以及規則已鎖定（-e 2）時以設定檔判定。"""

    def __init__(self, title, ids, lines=None, risk="A"):
        AuditRules.__init__(self, title, ids, lines or [], expected="啟用", risk=risk)

    def _lines(self, ctx):
        return self.lines

    def _split(self, ctx):
        lines = [l for l in (filter_syscalls(x) for x in self._lines(ctx)) if l]
        return [l for l in lines if audit_loadable(l)], [l for l in lines if not audit_loadable(l)]

    def _empty_text(self):
        return "無需設定的規則"

    def check(self, ctx):
        if not which("auditctl"):
            return Check(FAIL, "未安裝 auditd")
        req, skipped = self._split(ctx)
        note = "；略過 %d 條（上層目錄不存在：%s）" % (
            len(skipped), "、".join(audit_target(l) for l in skipped)) if skipped else ""
        if not req:
            return Check(PASS, self._empty_text() + note)
        loaded = normalize_audit_text(run(["auditctl", "-l"], timeout=30).out)
        disk = "\n".join(read_text(f) or "" for f in sorted(glob.glob(AUDIT_RULES_DIR + "/*.rules")))
        miss_disk = auditrules.missing(req, disk)
        miss_rt = [l for l in req if auditrules.missing([normalize_audit_text(l)], loaded)]
        if not miss_disk and not miss_rt:
            return Check(PASS, "%d 條規則皆已生效%s" % (len(req), note))
        if not miss_disk and audit_enabled() == "2":
            return Check(PASS, "%d 條規則已寫入設定檔；稽核規則已鎖定（-e 2），需重開機生效%s" % (len(req), note))
        return Check(FAIL, "未生效 %d 條、未寫入設定檔 %d 條（例：%s）%s" % (
            len(miss_rt), len(miss_disk), (miss_disk or miss_rt)[0], note))

    def fix(self, ctx, fx):
        if not which("augenrules"):
            raise ManualRequired("未安裝 auditd，請先完成「auditd 套件」項目（0112）")
        req, skipped = self._split(ctx)
        if not req:
            raise ManualRequired("沒有可載入的規則（%s）" % self._empty_text())
        path = self._file(ctx)
        fx.add_undo(["augenrules", "--load"], "重新載入稽核規則")
        fx.write_file(path, "## GCB %s %s（gcb-checker 產生）\n%s\n" % (
            self.rule_id(ctx.osi), self.title, "\n".join(req)), mode=0o600)
        if not fx.dry and os.stat(path).st_mode & 0o177:
            fx.chmod(path, 0o600)  # 0121 稽核規則檔案權限
        if skipped:
            fx.note("略過 %d 條規則（上層目錄不存在）：%s" % (len(skipped), "、".join(audit_target(l) for l in skipped)))
        fx.run(["augenrules", "--load"], "載入稽核規則", check=False)
        if not fx.dry and audit_enabled() == "2":
            fx.note("稽核規則目前為不可變更狀態（-e 2），設定已寫入，需重開機後生效")


# 0139：掃描 setuid/setgid 程式的檔案系統（本機磁碟；squashfs、網路檔案系統、虛擬檔案系統不掃描）
LOCAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "jfs", "reiserfs", "f2fs", "bcachefs")


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
        # 容器的根目錄可能是 overlay，主機上的 overlay（容器映像）則不掃描
        if fstype not in LOCAL_FS and not (fstype == "overlay" and mp == "/"):
            continue
        key = (f[2], f[3])
        if key not in seen or len(mp) < len(seen[key]):
            seen[key] = mp
    return sorted(set(seen.values()))


def find_privileged(mount):
    """等同 find <mount> -xdev \\( -perm -4000 -o -perm -2000 \\) -type f。"""
    out = []
    try:
        dev = os.lstat(mount).st_dev
    except OSError:
        return out
    if not os.path.isdir(mount):
        return out
    for root, dirs, files in os.walk(mount):
        keep = []
        for d in dirs:
            try:
                st = os.lstat(os.path.join(root, d))
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode) and st.st_dev == dev:
                keep.append(d)
        dirs[:] = keep
        for n in files:
            p = os.path.join(root, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & 0o6000 and st.st_dev == dev:
                out.append(p)
    return out


# [PrivilegedCommands] TWGCB-01-014-0139 記錄特權指令使用情形（動態清單）
class PrivilegedCommands(AuditRuleSet):
    TPL = "-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=unset -k privileged"

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


# [SudoLogRule] TWGCB-01-014-0142 記錄系統管理者活動日誌變更（依 sudoers 的 logfile）
class SudoLogRule(AuditRuleSet):
    def _lines(self, ctx):
        return ["-w %s -p wa -k sudo_log_file" % p for p in (sudo_logfiles() or ["/var/log/sudo.log"])]


# ====================================================================
# auditd 設定不變模式（0148）
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


# [AuditImmutable] TWGCB-01-014-0148 auditd 設定不變模式（-e 2）
class AuditImmutable(Rule):
    category = CAT
    title = "auditd 設定不變模式"
    expected = "2"
    risk = "B"
    # 檔名排在 rules.d 最後（gcb-*.rules、audit.rules 之後），即「最後被執行的 .rules 檔」
    FILE = AUDIT_RULES_DIR + "/zz-gcb-0148-finalize.rules"

    def __init__(self, ids):
        self.ids = ids

    def _disk(self):
        files = sorted(glob.glob(AUDIT_RULES_DIR + "/*.rules"))
        return last_e_setting(read_text(f) for f in files), (files[-1] if files else "")

    def check(self, ctx):
        if not which("auditctl"):
            return Check(FAIL, "未安裝 auditd")
        val, last = self._disk()
        rt = audit_enabled()
        cur = "rules.d 設定：%s；目前 enabled=%s" % ("-e " + val if val else "未設定", rt or "無法取得")
        ok = val == "2"
        if ok and rt != "2":
            cur += "（重新載入規則或重新開機後生效）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if not which("augenrules"):
            raise ManualRequired("未安裝 auditd，請先完成「auditd 套件」項目（0112）")
        # 回滾只能移除設定檔並重新產生 audit.rules，鎖定要重新開機才會解除
        fx.add_undo(["augenrules"], "重新產生 audit.rules")
        fx.write_file(self.FILE, "## GCB TWGCB-01-014-0148 auditd 設定不變模式（gcb-checker 產生，需為最後一行）\n-e 2\n",
                      mode=0o600)
        if not fx.dry and self._disk()[0] != "2":
            raise FixError("%s 之後還有其他 .rules 檔設定 -e，請人工調整" % self.FILE)
        fx.run(["augenrules", "--load"], "載入稽核規則（啟用不變模式）", check=False)
        fx.note("已啟用稽核設定不變模式（-e 2）：之後任何稽核規則的新增、修改或回滾都要重新開機才會生效；"
                "回滾本項只會移除設定檔，需重新開機才能解除鎖定；"
                "重開機前若再次執行本工具修復其他稽核項目，會一併載入 -e 2 而立即鎖定")


# ====================================================================
# rsyslog（0151）
# ====================================================================

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


# [RsyslogFileMode] TWGCB-01-014-0151 設定 rsyslog 日誌檔案預設權限
class RsyslogFileMode(Rule):
    category = CAT
    title = "設定 rsyslog 日誌檔案預設權限"
    expected = "$FileCreateMode 0640 或更低權限"
    MAIN = "/etc/rsyslog.conf"

    def __init__(self, ids):
        self.ids = ids

    def _files(self):
        return [self.MAIN] + sorted(glob.glob("/etc/rsyslog.d/*.conf"))

    def check(self, ctx):
        if read_text(self.MAIN) is None:
            return Check(FAIL, "未安裝 rsyslog（找不到 %s）" % self.MAIN)
        vals = [(f, v) for f in self._files() for v in rsyslog_modes(read_text(f))]
        if not vals:
            return Check(FAIL, "未設定 $FileCreateMode（rsyslog 預設 0644）")
        bad = [(f, v) for f, v in vals if not mode_ok(v)]
        if bad:
            return Check(FAIL, "權限過寬：" + "、".join("%s（%s）" % (v, f) for f, v in bad))
        return Check(PASS, "、".join("%s（%s）" % (v, f) for f, v in vals))

    def fix(self, ctx, fx):
        if read_text(self.MAIN) is None:
            raise ManualRequired("未安裝 rsyslog，請先完成「rsyslog 套件」項目（0149）")
        has_any = any(rsyslog_modes(read_text(f)) for f in self._files())
        fx.add_undo(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog")
        for f in self._files():
            if f == self.MAIN or any(not mode_ok(v) for v in rsyslog_modes(read_text(f))):
                fx.edit_file(f, lambda t, f=f: rsyslog_fix_text(t, has_any or f != self.MAIN))
        if which("rsyslogd"):
            r = fx.run(["rsyslogd", "-N1"], "檢查 rsyslog 設定語法", check=False)
            if r is not None and not r.ok:
                raise FixError("rsyslog 設定檢查失敗：%s" % r.text()[-200:])
        fx.run(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog", check=False)


# ====================================================================
# journald（0152–0154）
# ====================================================================

JOURNALD_CONF = "/etc/systemd/journald.conf"
JOURNALD_DIRS = ["/usr/lib/systemd/journald.conf.d", "/usr/local/lib/systemd/journald.conf.d",
                 "/run/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"]  # 優先順序由低到高
JOURNALD_OWN = "/etc/systemd/journald.conf.d/60-gcb-journald.conf"


def journald_files():
    """systemd 的讀取順序：journald.conf，再依檔名讀 drop-in（同檔名以 /etc 優先）。"""
    chosen = {}
    for d in JOURNALD_DIRS:
        for f in glob.glob(d + "/*.conf"):
            chosen[os.path.basename(f)] = f
    return [JOURNALD_CONF] + [chosen[b] for b in sorted(chosen)]


# [JournaldSetting] TWGCB-01-014-0152～0154 journald 參數（寫入 drop-in，重啟 systemd-journald）
class JournaldSetting(Rule):
    category = CAT

    def __init__(self, title, ids, key, value):
        self.title = title
        self.ids = ids
        self.key = key
        self.value = value
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
            return Check(FAIL, "%s 未設定" % self.key)
        f, v = vals[-1]
        return Check(PASS if compare(v, "eq", self.value) else FAIL, "%s=%s（%s）" % (self.key, v, f))

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

def _perm(title, n, paths, expected, **kw):
    return NeedsAuditd(FilePerm(title, CAT, U(n), paths, expected=expected, **kw))


TOOLS = ["/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules"]

RULES = [
    # 0112 auditd 套件
    AuditPackages(U(112)),
    # 0113 auditd 服務 → common.py
    # 0114 稽核 auditd 服務啟動前之程序 → common.py
    # 0115 稽核待辦事項數量限制
    AuditBacklogLimit(U(115)),
    # 0116 稽核日誌檔案所有權
    NeedsAuditd(AuditLogPerm("稽核日誌檔案所有權", U(116), "file", owner="root", groups=["root"],
                             expected="root:root")),
    # 0117 稽核日誌檔案權限
    NeedsAuditd(AuditLogPerm("稽核日誌檔案權限", U(117), "file", max_mode=0o600, expected="600 或更低權限")),
    # 0118 稽核日誌目錄所有權
    NeedsAuditd(AuditLogPerm("稽核日誌目錄所有權", U(118), "dir", owner="root", groups=["root"],
                             expected="root:root")),
    # 0119 稽核日誌目錄權限
    NeedsAuditd(AuditLogPerm("稽核日誌目錄權限", U(119), "dir", max_mode=0o700, expected="700 或更低權限")),
    # 0120 稽核規則檔案所有權
    _perm("稽核規則檔案所有權", 120, AUDIT_RULES_DIR + "/*.rules", "root:root",
          owner="root", groups=["root"], missing="pass"),
    # 0121 稽核規則檔案權限
    _perm("稽核規則檔案權限", 121, AUDIT_RULES_DIR + "/*.rules", "600 或更低權限",
          max_mode=0o600, missing="pass"),
    # 0122 稽核設定檔案所有權
    _perm("稽核設定檔案所有權", 122, AUDITD_CONF, "root:root", owner="root", groups=["root"]),
    # 0123 稽核設定檔案權限
    _perm("稽核設定檔案權限", 123, AUDITD_CONF, "640 或更低權限", max_mode=0o640),
    # 0124 稽核工具權限
    _perm("稽核工具權限", 124, TOOLS, "750 或更低權限", max_mode=0o750),
    # 0125 稽核工具所有權
    _perm("稽核工具所有權", 125, TOOLS, "root:root", owner="root", groups=["root"]),
    # 0126 保護稽核工具
    AideAuditTools(U(126)),
    # 0127 稽核日誌檔案大小上限
    NeedsAuditd(auditd_conf("稽核日誌檔案大小上限", U(127), "max_log_file", 32, "ge", 32, expected="32 以上")),
    # 0128 稽核日誌達到其檔案大小上限之行為（keep_logs 不刪舊檔，需定期備份清理）
    NeedsAuditd(auditd_conf("稽核日誌達到其檔案大小上限之行為", U(128), "max_log_file_action", "keep_logs",
                            expected="keep_logs")),
    # 0129 記錄系統管理者活動
    AuditRuleSet("記錄系統管理者活動", U(129), [
        "-w /etc/sudoers -p wa -k scope",
        "-w /etc/sudoers.d/ -p wa -k scope",
    ]),
    # 0130 記錄變更登入與登出資訊事件
    AuditRuleSet("記錄變更登入與登出資訊事件", U(130), [
        "-w /var/run/faillock/ -p wa -k logins",
        "-w /var/log/lastlog -p wa -k logins",
    ]),
    # 0131 記錄會談啟始資訊
    AuditRuleSet("記錄會談啟始資訊", U(131), [
        "-w /var/run/utmp -p wa -k session",
        "-w /var/log/wtmp -p wa -k session",
        "-w /var/log/btmp -p wa -k session",
    ]),
    # 0132 記錄變更日期與時間事件
    AuditRuleSet("記錄變更日期與時間事件", U(132), [
        "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change",
        "-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change",
        "-w /etc/localtime -p wa -k time-change",
    ]),
    # 0133 記錄變更系統強制存取控制事件
    AuditRuleSet("記錄變更系統強制存取控制事件", U(133), [
        "-w /etc/apparmor/ -p wa -k MAC-policy",
        "-w /etc/apparmor.d/ -p wa -k MAC-policy",
    ]),
    # 0134 記錄變更系統網路環境事件
    AuditRuleSet("記錄變更系統網路環境事件", U(134), [
        "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale",
        "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale",
        "-w /etc/issue -p wa -k system-locale",
        "-w /etc/issue.net -p wa -k system-locale",
        "-w /etc/hosts -p wa -k system-locale",
        "-w /etc/networks -p wa -k system-locale",
        "-w /etc/network/ -p wa -k system-locale",
    ]),
    # 0135 記錄變更自主存取控制權限事件
    AuditRuleSet("記錄變更自主存取控制權限事件", U(135), [
        "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
        "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
        "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
        "-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
        "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr "
        "-F auid>=1000 -F auid!=unset -k perm_mod",
        "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr "
        "-F auid>=1000 -F auid!=unset -k perm_mod",
    ]),
    # 0136 記錄不成功之未經授權檔案存取
    AuditRuleSet("記錄不成功之未經授權檔案存取", U(136), [
        "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES "
        "-F auid>=1000 -F auid!=unset -k access",
        "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES "
        "-F auid>=1000 -F auid!=unset -k access",
        "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM "
        "-F auid>=1000 -F auid!=unset -k access",
        "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM "
        "-F auid>=1000 -F auid!=unset -k access",
    ]),
    # 0137 記錄變更使用者或群組資訊事件
    AuditRuleSet("記錄變更使用者或群組資訊事件", U(137), [
        "-w /etc/group -p wa -k identity",
        "-w /etc/passwd -p wa -k identity",
        "-w /etc/gshadow -p wa -k identity",
        "-w /etc/shadow -p wa -k identity",
        "-w /etc/security/opasswd -p wa -k identity",
    ]),
    # 0138 記錄變更檔案系統掛載事件
    AuditRuleSet("記錄變更檔案系統掛載事件", U(138), [
        "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
        "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts",
    ]),
    # 0139 記錄特權指令使用情形（掃描本機磁碟的 setuid/setgid 程式）
    PrivilegedCommands("記錄特權指令使用情形", U(139)),
    # 0140 記錄檔案刪除事件
    AuditRuleSet("記錄檔案刪除事件", U(140), [
        "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete",
        "-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete",
    ]),
    # 0141 記錄核心模組掛載、卸載及修改事件
    AuditRuleSet("記錄核心模組掛載、卸載及修改事件", U(141), [
        "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module "
        "-F auid>=1000 -F auid!=unset -k kernel_modules",
        "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module,create_module,query_module "
        "-F auid>=1000 -F auid!=unset -k kernel_modules",
    ]),
    # 0142 記錄系統管理者活動日誌變更（sudoers 的 logfile，未設定時 /var/log/sudo.log）
    SudoLogRule("記錄系統管理者活動日誌變更", U(142)),
    # 0143 記錄 setfacl 指令使用情形
    AuditRuleSet("記錄 setfacl 指令使用情形", U(143), [
        "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng",
    ]),
    # 0144 記錄 usermod 指令使用情形
    AuditRuleSet("記錄 usermod 指令使用情形", U(144), [
        "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod",
    ]),
    # 0145 記錄 chacl 指令使用情形
    AuditRuleSet("記錄 chacl 指令使用情形", U(145), [
        "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng",
    ]),
    # 0146 記錄 kmod 指令使用情形
    AuditRuleSet("記錄 kmod 指令使用情形", U(146), [
        "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules",
    ]),
    # 0147 記錄 execve 系統呼叫使用情形
    AuditRuleSet("記錄 execve 系統呼叫使用情形", U(147), [
        "-a always,exit -F arch=b32 -F auid!=unset -S execve -C uid!=euid -k user_emulation",
        "-a always,exit -F arch=b64 -F auid!=unset -S execve -C uid!=euid -k user_emulation",
        "-a always,exit -F arch=b32 -F auid!=unset -S execve -C gid!=egid -k user_emulation",
        "-a always,exit -F arch=b64 -F auid!=unset -S execve -C gid!=egid -k user_emulation",
    ]),
    # 0148 auditd 設定不變模式（B 類，須為最後套用的稽核設定）
    AuditImmutable(U(148)),
    # 0149 rsyslog 套件
    PackagePresent("rsyslog 套件", "rsyslog", U(149), CAT),
    # 0150 rsyslog 服務 → common.py
    # 0151 設定 rsyslog 日誌檔案預設權限
    RsyslogFileMode(U(151)),
    # 0152 設定 journald 將日誌發送到 rsyslog
    JournaldSetting("設定 journald 將日誌發送到 rsyslog", U(152), "ForwardToSyslog", "yes"),
    # 0153 設定 journald 壓縮日誌檔案
    JournaldSetting("設定 journald 壓縮日誌檔案", U(153), "Compress", "yes"),
    # 0154 設定 journald 將日誌檔案永久保存於磁碟
    JournaldSetting("設定 journald 將日誌檔案永久保存於磁碟", U(154), "Storage", "persistent"),
]
