# -*- coding: utf-8 -*-
"""通用規則類型：在 ubuntu/、rhel/ 的規則清單中以參數組合成各條 GCB 規則。

每個類型上方註明適用的規則範圍；個別規則編號標示在規則清單中。
"""
import glob
import grp
import os
import pwd
import re

from .. import auditrules
from .. import pkgsvc
from .. import textedit as te
from ..fixer import FixError, ManualRequired
from ..util import read_text, run, which
from .base import ERROR, FAIL, NA, PASS, Check, Rule
from .common import ModuleDisabled


def _ids(osi_key, num, prefix):
    return {osi_key: "%s-%04d" % (prefix, num)}


# ====================================================================
# 適用條件（when）
# ====================================================================

def installed(pkg):
    """套件已安裝才適用。pkg 可為字串或 {"rhel": ..., "debian": ...}（各系列套件名不同時）。"""
    def _when(ctx):
        name = pkg[ctx.osi.family] if isinstance(pkg, dict) else pkg
        return None if pkgsvc.pkg_installed(ctx.osi, name) else "未安裝 %s，沒有需要檢查的設定" % name
    return _when


AUDIT_PKG = {"rhel": "audit", "debian": "auditd"}


def not_separate(mount):
    """掛載點不是獨立分割時的說明（GCB 掛載選項條目未設前提條件，依字面判定不合格、需人工建立分割）。"""
    return ("%s 不是獨立的磁碟分割，無法設定掛載選項；需先完成「設定 %s 目錄之檔案系統」（建立獨立分割）"
            % (mount, mount))


def all_of(*conds):
    def _when(ctx):
        for c in conds:
            r = c(ctx)
            if r:
                return r
        return None
    return _when


# ====================================================================
# 核心模組（磁碟與檔案系統 0001–0003 等）
# ====================================================================

def module_builtin(module):
    """模組編入核心時，modprobe.d 設定無效。"""
    rel = os.uname().release
    text = read_text("/lib/modules/%s/modules.builtin" % rel) or ""
    return any(l.endswith("/%s.ko" % module) for l in text.splitlines())


class Module(ModuleDisabled):
    """ModuleDisabled 加上風險等級、類別，以及「編入核心」與「使用中」的判斷。

    in_use(ctx) 回傳使用中說明（例如 squashfs 被 snap 掛載）或 None；使用中時略過修復。
    """

    def __init__(self, module, ids, risk="A", category="磁碟與檔案系統", title=None, in_use=None):
        ModuleDisabled.__init__(self, module, ids)
        self.risk = risk
        self.category = category
        self.in_use = in_use
        if title:
            self.title = title

    def check(self, ctx):
        c = ModuleDisabled.check(self, ctx)
        if module_builtin(self.module):
            c.current += "；模組已編入核心，無法以 modprobe.d 停用"
        return c

    def precondition(self, ctx):
        if self.in_use:
            why = self.in_use(ctx)
            if why and not ctx.include_risky:
                return why + "，停用會影響現有功能；確認後可加 --include-risky"
        return None

    def fix(self, ctx, fx):
        if module_builtin(self.module):
            raise ManualRequired("%s 已編入核心，無法以 modprobe.d 停用，需更換核心或接受此項" % self.module)
        ModuleDisabled.fix(self, ctx, fx)


# ====================================================================
# 掛載選項（/tmp、/dev/shm、/var、/var/tmp、/var/log、/var/log/audit、/home 的 nodev/nosuid/noexec）
# ====================================================================

INVERSE = {"nodev": "dev", "nosuid": "suid", "noexec": "exec"}


def mount_options(mount):
    """回傳目前掛載選項清單；未獨立掛載回傳 None。"""
    opts = None
    for line in (read_text("/proc/self/mounts") or "").splitlines():
        p = line.split()
        if len(p) > 3 and p[1] == mount:
            opts = p[3].split(",")  # 同一掛載點多次掛載時取最後一個
    return opts


class MountOption(Rule):
    category = "磁碟與檔案系統"
    risk = "B"
    FSTAB = "/etc/fstab"

    def __init__(self, mount, option, ids):
        self.mount = mount
        self.option = option
        self.ids = ids
        self.title = "設定 %s 目錄之 %s 選項" % (mount, option)
        self.expected = "啟用 %s" % option

    def _persistent(self):
        """回傳 (來源說明, 選項清單或 None)。"""
        opts = te.fstab_options(read_text(self.FSTAB) or "", self.mount)
        if opts is not None:
            return "fstab", opts
        if self.mount == "/tmp":
            unit = te.get_kv(read_text("/etc/systemd/system/tmp.mount.d/60-gcb.conf") or "", "Options") \
                or te.get_kv(read_text("/etc/systemd/system/tmp.mount") or "", "Options") \
                or te.get_kv(read_text("/usr/share/systemd/tmp.mount") or "", "Options") \
                or te.get_kv(read_text("/usr/lib/systemd/system/tmp.mount") or "", "Options")
            if unit:
                return "tmp.mount", unit.split(",")
        return "未設定", None

    def check(self, ctx):
        rt = mount_options(self.mount)
        src, opts = self._persistent()
        if rt is None:
            if opts is not None and self.option in opts:  # 已寫入開機設定（例如 /tmp 改為 tmpfs），重開機後掛載
                return Check(PASS, "目前未掛載；開機設定（%s）已含 %s，重開機後生效" % (src, self.option))
            if self.mount == "/dev/shm" or opts is not None:
                return Check(FAIL, "目前未掛載；開機設定（%s）%s" % (src, "無 %s" % self.option if opts else "未設定"))
            return Check(FAIL, not_separate(self.mount))
        ok = self.option in rt and opts is not None and self.option in opts
        return Check(PASS if ok else FAIL, "目前：%s；開機設定（%s）：%s" % (
            "有" if self.option in rt else "無", src, "有" if opts and self.option in opts else "無"))

    def fix(self, ctx, fx):
        src, opts = self._persistent()
        mounted_now = mount_options(self.mount) is not None
        if not mounted_now and opts is None and self.mount != "/dev/shm":
            raise ManualRequired(not_separate(self.mount))
        if src == "tmp.mount":
            new = sorted(set(opts) | {self.option})
            # 先登記：回滾為反向執行，才會在刪除 drop-in 之後才 reload
            fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")
            fx.write_file("/etc/systemd/system/tmp.mount.d/60-gcb.conf",
                          "[Mount]\nOptions=%s\n" % ",".join(new))
            fx.run(["systemctl", "daemon-reload"], "重新載入 systemd")
        else:
            if self.mount != "/dev/shm" and te.fstab_options(read_text(self.FSTAB) or "", self.mount) is None:
                raise ManualRequired("%s 沒有寫在 /etc/fstab（可能由 autofs 或其他方式掛載），請人工設定掛載選項 %s"
                                     % (self.mount, self.option))
            fx.edit_file(self.FSTAB, lambda t: te.fstab_add_option(t, self.mount, self.option))
            r = fx.run(["findmnt", "--verify"], "檢查 fstab 語法", check=False)
            if r is not None and not r.ok and "error" in r.text().lower():
                raise FixError("fstab 檢查失敗，不套用：%s" % r.text()[-200:])
        if not mounted_now:
            fx.note("%s 目前未掛載，已寫入開機設定，重開機後生效" % self.mount)
            return
        fx.add_undo(["mount", "-o", "remount,%s" % INVERSE.get(self.option, self.option), self.mount],
                    "恢復 %s 掛載選項" % self.mount)
        fx.run(["mount", "-o", "remount,%s" % self.option, self.mount], "重新掛載 %s" % self.mount)


# ====================================================================
# 套件
# ====================================================================

class PackagePresent(Rule):
    """安裝套件。"""

    def __init__(self, title, pkg, ids, category, risk="A"):
        self.title = title
        self.pkg = pkg
        self.ids = ids
        self.category = category
        self.risk = risk
        self.expected = "安裝 %s" % pkg

    def check(self, ctx):
        inst = pkgsvc.pkg_installed(ctx.osi, self.pkg)
        return Check(PASS if inst else FAIL, "已安裝" if inst else "未安裝")

    def fix(self, ctx, fx):
        fx.pkg_install(self.pkg)


# ====================================================================
# 設定檔參數（login.defs、pwquality、faillock、auditd.conf、journald.conf…）
# ====================================================================

def _num(v):
    try:
        return int(str(v).strip().split()[0])
    except (ValueError, IndexError):
        return None


def compare(value, cmp, target):
    """cmp：eq（不分大小寫）/ ge / le / range（target=(lo, hi)）/ in（target=清單）。"""
    if value is None:
        return False
    if cmp == "eq":
        return str(value).strip().lower() == str(target).strip().lower()
    if cmp == "in":
        return str(value).strip().lower() in [str(t).lower() for t in target]
    n = _num(value)
    if n is None:
        return False
    if cmp == "ge":
        return n >= target
    if cmp == "le":
        return n <= target
    if cmp == "range":
        return target[0] <= n <= target[1]
    raise ValueError(cmp)


class KvSetting(Rule):
    """單一檔案的 key/value 參數；可指定 drop-in 目錄一併檢查。

    path      主要設定檔（修復時寫入這裡，除非指定 write_to）
    dropins   會覆寫主設定的 drop-in 樣式（例：/etc/systemd/journald.conf.d/*.conf）
    write_to  修復時改寫入的獨立檔案（例：journald drop-in），搭配 section 產生標頭
    value     修復時寫入的值；cmp/target 決定怎樣算合格
    apply     修復後要執行的指令（例：重新載入服務），回滾時也會再執行一次
    """

    def __init__(self, title, category, ids, path, key, value, cmp="eq", target=None, sep=" = ",
                 dropins=None, write_to=None, section=None, apply=None, risk="A", expected=None,
                 when=None, missing_ok=False):
        self.title = title
        self.category = category
        self.ids = ids
        self.path = path
        self.key = key
        self.value = value
        self.cmp = cmp
        self.target = value if target is None else target
        self.sep = sep
        self.dropins = dropins
        self.write_to = write_to
        self.section = section
        self.apply = apply
        self.risk = risk
        self.expected = expected or "%s %s" % (key, value)
        self.when = when
        self.missing_ok = missing_ok

    def _files(self):
        files = [self.path]
        if self.dropins:
            files += sorted(glob.glob(self.dropins))
        return files

    def _values(self):
        out = []
        for f in self._files():
            v = te.get_kv(read_text(f) or "", self.key)
            if v is not None:
                out.append((f, v))
        return out

    def check(self, ctx):
        vals = self._values()
        if not vals:
            if self.missing_ok:
                return Check(PASS, "%s 未設定（使用預設值，符合規範）" % self.key)
            return Check(FAIL, "%s 未設定" % self.key)
        eff_file, eff = vals[-1]
        bad = [(f, v) for f, v in vals if not compare(v, self.cmp, self.target)]
        ok = compare(eff, self.cmp, self.target) and not bad
        cur = "%s=%s（%s）" % (self.key, eff, eff_file)
        if bad and ok is False and len(vals) > 1:
            cur += "；不符合：" + "、".join("%s=%s（%s）" % (self.key, v, f) for f, v in bad)
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if self.apply:
            fx.add_undo(self.apply, "重新套用設定")
        target = self.write_to or self.path
        for f, v in self._values():
            if f != target and not compare(v, self.cmp, self.target):
                fx.edit_file(f, lambda t: te.comment_kv(t, self.key))

        def _set(t):
            if not t and self.section:
                t = "[%s]\n" % self.section
            return te.set_kv(t, self.key, str(self.value), sep=self.sep)
        fx.edit_file(target, _set)
        if self.apply:
            fx.run(self.apply, "套用設定", check=False)


def login_defs(title, ids, key, value, cmp, target=None, expected=None, risk="A"):
    """/etc/login.defs 參數（帳號與存取控制）。"""
    return KvSetting(title, "帳號與存取控制", ids, "/etc/login.defs", key, value, cmp, target,
                     sep="\t", risk=risk, expected=expected)


def auditd_conf(title, ids, key, value, cmp="eq", target=None, expected=None, risk="A"):
    """/etc/audit/auditd.conf 參數（日誌與稽核）。修改後以 HUP 重新讀取設定。"""
    return KvSetting(title, "日誌與稽核", ids, "/etc/audit/auditd.conf", key, value, cmp, target,
                     sep=" = ", apply=["service", "auditd", "reload"], risk=risk, expected=expected,
                     when=installed(AUDIT_PKG))


# ====================================================================
# 檔案與目錄權限（可用萬用字元、可遞迴）
# ====================================================================

def _owner_names(st):
    try:
        u = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        u = str(st.st_uid)
    try:
        g = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        g = str(st.st_gid)
    return u, g


class FilePerm(Rule):
    """檔案擁有者／群組／權限上限。

    paths     路徑或萬用字元清單
    owner     擁有者（None 不檢查）
    groups    允許的群組清單（None 不檢查）
    max_mode  權限上限（例：0o600；None 不檢查）
    recursive 目錄時是否檢查底下所有檔案
    missing   檔案都不存在時：na / pass / fail
    """

    def __init__(self, title, category, ids, paths, owner=None, groups=None, max_mode=None,
                 recursive=False, missing="na", expected=None, risk="A", when=None, files_only=False):
        self.title = title
        self.category = category
        self.ids = ids
        self.paths = [paths] if isinstance(paths, str) else paths
        self.owner = owner
        self.groups = groups
        self.max_mode = max_mode
        self.recursive = recursive
        self.missing = missing
        self.risk = risk
        self.when = when
        self.files_only = files_only
        parts = []
        if owner or groups:
            parts.append("%s:%s" % (owner or "*", "或".join(groups) if groups else "*"))
        if max_mode is not None:
            parts.append("%03o 或更低權限" % max_mode)
        self.expected = expected or "、".join(parts)

    def _targets(self):
        out = []
        for pat in self.paths:
            for p in sorted(glob.glob(pat)):
                if self.recursive and os.path.isdir(p):
                    for root, dirs, files in os.walk(p):
                        if not self.files_only:
                            out.append(root)
                        out += [os.path.join(root, f) for f in files]
                elif not (self.files_only and os.path.isdir(p)):
                    out.append(p)
        return [p for p in out if os.path.exists(p) and not os.path.islink(p)]

    def _bad(self, path):
        st = os.stat(path)
        u, g = _owner_names(st)
        mode = st.st_mode & 0o7777
        why = []
        if self.owner and u != self.owner:
            why.append("擁有者 %s" % u)
        if self.groups and g not in self.groups:
            why.append("群組 %s" % g)
        if self.max_mode is not None and mode & ~self.max_mode:
            why.append("權限 %03o" % mode)
        return why

    def check(self, ctx):
        targets = self._targets()
        if not targets:
            st = {"na": NA, "pass": PASS, "fail": FAIL}[self.missing]
            return Check(st, "檔案不存在：%s%s" % ("、".join(self.paths), "，沒有需要設定權限的對象" if st == NA else ""))
        bad = [(p, self._bad(p)) for p in targets]
        bad = [(p, w) for p, w in bad if w]
        if not bad:
            if len(targets) == 1:
                st = os.stat(targets[0])
                return Check(PASS, "%s:%s %03o" % (_owner_names(st) + (st.st_mode & 0o7777,)))
            return Check(PASS, "共 %d 個檔案皆符合" % len(targets))
        show = "；".join("%s（%s）" % (p, "、".join(w)) for p, w in bad[:5])
        if len(bad) > 5:
            show += "；…另 %d 個" % (len(bad) - 5)
        return Check(FAIL, show)

    def fix(self, ctx, fx):
        for p in self._targets():
            why = self._bad(p)
            if not why:
                continue
            st = os.stat(p)
            if (self.owner or self.groups) and any(w.startswith(("擁有者", "群組")) for w in why):
                uid = pwd.getpwnam(self.owner).pw_uid if self.owner else st.st_uid
                _, g = _owner_names(st)
                gname = g if not self.groups or g in self.groups else self.groups[0]
                fx.chown(p, uid, grp.getgrnam(gname).gr_gid, "%s:%s" % (self.owner or st.st_uid, gname))
            if self.max_mode is not None:
                mode = os.stat(p).st_mode & 0o7777
                if mode & ~self.max_mode:
                    fx.chmod(p, mode & self.max_mode)


# ====================================================================
# 稽核規則（日誌與稽核：auditd 規則類）
# ====================================================================

AUDIT_RULES_DIR = "/etc/audit/rules.d"


def audit_filter_syscalls(line, exists=None):
    """移除本機架構不存在的系統呼叫（例如 ARM 沒有 create_module）；全部都不存在時回傳 None。

    auditctl 遇到不存在的系統呼叫會讓整批規則載入失敗，所以先過濾。
    exists(arch, name) 可替換以便測試；預設呼叫 ausyscall。
    """
    m = re.search(r"arch=(b32|b64)", line)
    if not m or "-S" not in line:
        return line
    if exists is None:
        if not which("ausyscall"):
            return line
        exists = lambda arch, n: run(["ausyscall", arch, n], timeout=10).ok
    arch = m.group(1)
    tokens = line.split()
    out, kept_any = [], False
    i = 0
    while i < len(tokens):
        if tokens[i] == "-S" and i + 1 < len(tokens):
            keep = [n for n in tokens[i + 1].split(",") if exists(arch, n)]
            if keep:
                out += ["-S", ",".join(keep)]
                kept_any = True
            i += 2
            continue
        out.append(tokens[i])
        i += 1
    return " ".join(out) if kept_any else None


class AuditRules(Rule):
    """一組 auditd 規則；寫入 /etc/audit/rules.d/gcb-<編號>.rules 並以 augenrules 載入。"""
    category = "日誌與稽核"

    def __init__(self, title, ids, lines, expected=None, risk="A"):
        self.title = title
        self.ids = ids
        self.lines = lines
        self.risk = risk
        self.expected = expected or "設定稽核規則（%d 條）" % len(lines)

    def _required(self):
        out = []
        for l in self.lines:
            f = audit_filter_syscalls(l)
            if f:
                out.append(f)
        return out

    def _file(self, ctx):
        return os.path.join(AUDIT_RULES_DIR, "gcb-%s.rules" % self.rule_id(ctx.osi)[-4:])

    def check(self, ctx):
        if not which("auditctl"):
            return Check(FAIL, "未安裝 auditd")
        req = self._required()
        loaded = run(["auditctl", "-l"], timeout=30).out
        disk = "\n".join(read_text(f) or "" for f in sorted(glob.glob(AUDIT_RULES_DIR + "/*.rules")))
        miss_rt = auditrules.missing(req, loaded)
        miss_disk = auditrules.missing(req, disk)
        if not miss_rt and not miss_disk:
            return Check(PASS, "%d 條規則皆已生效" % len(req))
        return Check(FAIL, "未生效 %d 條、未寫入設定檔 %d 條（例：%s）" % (
            len(miss_rt), len(miss_disk), (miss_disk or miss_rt)[0]))

    def fix(self, ctx, fx):
        if not which("augenrules"):
            raise ManualRequired("未安裝 auditd，請先完成「auditd 服務」項目（安裝並啟用 auditd）")
        path = self._file(ctx)
        fx.add_undo(["augenrules", "--load"], "重新載入稽核規則")
        fx.write_file(path, "## GCB %s %s（gcb-checker 產生）\n%s\n" % (
            self.rule_id(ctx.osi), self.title, "\n".join(self._required())), mode=0o600)
        r = fx.run(["augenrules", "--load"], "載入稽核規則", check=False)
        if r is not None and ("immutable" in r.text().lower() or "enabled 2" in r.text()):
            fx.note("稽核規則目前為不可變更狀態（-e 2），設定已寫入，需重開機後生效")
