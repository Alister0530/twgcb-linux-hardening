# -*- coding: utf-8 -*-
"""Ubuntu 22.04 系統設定與維護（TWGCB-01-014-0029 ～ 0078）。"""
import glob
import grp
import os
import pwd
import re
import stat
import tempfile
import time

from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from ..common import PackageAbsent, ServiceDisabled
from ..generic import FilePerm, PackagePresent, installed
from .helpers import U

CAT = "系統設定與維護"
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")


# ====================================================================
# 共用：sudoers 解析（0030–0032）
# ====================================================================

SUDOERS = "/etc/sudoers"
SUDOERS_D = "/etc/sudoers.d"


def _sudoers_dir_files(d, extra=None):
    """sudoers.d 中會被讀取的檔案（檔名不含「.」且不以「~」結尾），依字典序。"""
    names = set(os.listdir(d)) if os.path.isdir(d) else set()
    for p in (extra or {}):
        if os.path.dirname(p) == d:
            names.add(os.path.basename(p))
    names = [n for n in names if "." not in n and not n.endswith("~")]
    return [os.path.join(d, n) for n in sorted(names)]


def _strip_comment(line):
    """去掉行尾註解（引號內的 # 不算）。"""
    q = False
    for i, ch in enumerate(line):
        if ch == '"':
            q = not q
        elif ch == "#" and not q:
            return line[:i]
    return line


def _split_params(s):
    out, cur, q = [], "", False
    for ch in s:
        if ch == '"':
            q = not q
        if ch == "," and not q:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


_PARAM_RX = re.compile(r"^(!*)\s*([A-Za-z_]+)\s*(?:([+-]?=)\s*(.*))?$")
_INCLUDE_RX = re.compile(r"^[#@](include|includedir)\s+(\S+)")
_DEFAULTS_RX = re.compile(r"^Defaults([:@!>]\S+)?\s+(.+)$")


def sudoers_defaults(extra=None, path=SUDOERS, depth=0):
    """依 sudo 讀取順序回傳 [(檔案, 綁定對象或 None, 參數名, 是否否定, 值)]。

    extra：{路徑: 內容} 模擬尚未寫入的檔案（修復前預判結果）。
    """
    extra = extra or {}
    text = extra[path] if path in extra else read_text(path)
    out = []
    if text is None or depth > 8:
        return out
    text = re.sub(r"\\\n", " ", text)
    for raw in text.splitlines():
        s = raw.strip()
        m = _INCLUDE_RX.match(s)
        if m:
            target = m.group(2)
            if not target.startswith("/"):
                target = os.path.join(os.path.dirname(path), target)
            if m.group(1) == "includedir":
                for f in _sudoers_dir_files(target, extra):
                    out += sudoers_defaults(extra, f, depth + 1)
            else:
                out += sudoers_defaults(extra, target, depth + 1)
            continue
        s = _strip_comment(s).strip()
        m = _DEFAULTS_RX.match(s)
        if not m:
            continue
        binding = m.group(1)
        for p in _split_params(m.group(2)):
            pm = _PARAM_RX.match(p)
            if not pm:
                continue
            val = pm.group(4)
            if val is not None:
                val = val.strip().strip('"')
            out.append((path, binding, pm.group(2), len(pm.group(1)) % 2 == 1, val))
    return out


def sudoers_includes_dir(text):
    for line in (text or "").splitlines():
        m = _INCLUDE_RX.match(line.strip())
        if m and m.group(1) == "includedir" and m.group(2).rstrip("/") == SUDOERS_D:
            return True
    return False


def visudo_problems(r):
    """visudo -c 輸出中的錯誤或警告行（排除「parsed OK」）。"""
    if r.ok:
        return []
    lines = [l.strip() for l in r.text().splitlines() if l.strip() and not l.strip().endswith("parsed OK")]
    return lines or ["visudo -c 失敗（rc=%s）" % r.rc]


def _to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# [SudoDefault] TWGCB-01-014-0030 設定 sudo 指令使用 pty、0031 sudo 自定義日誌檔案、0032 sudo 身分鑑別逾時時間
class SudoDefault(Rule):
    """kind：flag（布林旗標）/ logfile（有設定路徑即可）/ timeout（0 < 值 <= 5）。

    修復時寫入獨立檔案 /etc/sudoers.d/99-gcb-NNNN，寫入前以 visudo -cf 驗證語法，
    寫入後再以 visudo -c 驗證整體設定，失敗則由框架回滾（刪除該檔）。
    """
    category = CAT

    def __init__(self, title, ids, kind, name, line, expected):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.name = name
        self.line = line
        self.expected = expected
        self.when = installed("sudo")

    def _file(self, ctx):
        return os.path.join(SUDOERS_D, "99-gcb-%s" % self.rule_id(ctx.osi)[-4:])

    def evaluate(self, entries):
        """回傳 (合格, 目前狀態說明)。"""
        mine = [e for e in entries if e[2] == self.name]
        glob_ = [e for e in mine if e[1] is None]
        scoped = [e for e in mine if e[1] is not None]
        if self.kind == "flag":
            eff = None
            for f, b, n, neg, v in glob_:
                eff = (not neg, f)
            ok = bool(eff and eff[0])
            cur = "未設定" if eff is None else ("%s%s（%s）" % ("" if eff[0] else "!", self.name, eff[1]))
            return ok, cur
        if self.kind == "logfile":
            eff = None
            for f, b, n, neg, v in glob_:
                eff = (None if neg or not v else v, f)
            ok = bool(eff and eff[0])
            cur = "未設定" if eff is None else ("logfile=%s（%s）" % (eff[0], eff[1]) if eff[0] else "已停用（%s）" % eff[1])
            return ok, cur
        # timeout
        eff = None
        for f, b, n, neg, v in glob_:
            eff = (0.0 if neg else _to_float(v), v, f)
        ok = bool(eff and eff[0] is not None and 0 < eff[0] <= 5)
        cur = "未設定（預設 15 分鐘）" if eff is None else "%s=%s（%s）" % (self.name, eff[1], eff[2])
        bad = [e for e in scoped if e[3] or not (_to_float(e[4]) is not None and 0 < _to_float(e[4]) <= 5)]
        if bad:
            ok = False
            cur += "；個別設定不符合：" + "、".join("Defaults%s %s=%s（%s）" % (b, n, v, f) for f, b, n, neg, v in bad)
        return ok, cur

    def check(self, ctx):
        if not os.path.exists(SUDOERS):
            return Check(ERROR, "找不到 %s" % SUDOERS)
        ok, cur = self.evaluate(sudoers_defaults())
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        visudo = which("visudo")
        if not visudo:
            raise ManualRequired("找不到 visudo，無法安全驗證 sudoers 語法，請人工設定：%s" % self.line)
        if not sudoers_includes_dir(read_text(SUDOERS)):
            raise ManualRequired("/etc/sudoers 未引入 /etc/sudoers.d（@includedir），請以 visudo 人工新增：%s" % self.line)
        r = run([visudo, "-c"], timeout=30)
        before = visudo_problems(r)
        if any("error" in l.lower() for l in before):
            raise ManualRequired("現有 sudoers 設定有語法錯誤，請先以 visudo 修正：%s" % "；".join(before)[-300:])
        if before:
            fx.note("現有 sudoers 設定有警告（不影響本項）：%s" % "；".join(before)[-300:])
        path = self._file(ctx)
        content = "# %s (gcb-checker)\n%s\n" % (self.rule_id(ctx.osi), self.line)
        ok, cur = self.evaluate(sudoers_defaults({path: content}))
        if not ok:
            if self.kind == "timeout" and "個別設定" in cur:
                fx.partial = True
                fx.note("Defaults:使用者 等個別設定的逾時時間不符合，請以 visudo 人工修改：" + cur)
            else:
                raise ManualRequired("排序在 %s 之後的 sudoers 設定會覆蓋本項，請以 visudo 人工修改：%s" % (path, cur))
        # 先以暫存檔驗證語法，通過才寫入（sudoers 寫壞會讓所有人無法 sudo）
        fd, tmp = tempfile.mkstemp(prefix="gcb-sudoers-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(content.encode("utf-8"))
            r = run([visudo, "-cf", tmp], timeout=30)
        finally:
            os.unlink(tmp)
        if not r.ok:
            raise FixError("sudoers 內容語法驗證失敗，未寫入：%s" % r.text()[-200:])
        fx.write_file(path, content, mode=0o440)
        r = fx.run([visudo, "-c"], "驗證整體 sudoers 語法", check=False)
        new = [l for l in visudo_problems(r) if l not in before] if r is not None else []
        if new:
            raise FixError("寫入後 visudo -c 驗證失敗，將還原：%s" % "；".join(new)[-300:])


# ====================================================================
# AIDE（0033、0034）
# ====================================================================

AIDE_DB = "/var/lib/aide/aide.db"


# [AidePackage] TWGCB-01-014-0033 AIDE 套件
class AidePackage(Rule):
    category = CAT
    title = "AIDE 套件"
    expected = "安裝（aide、aide-common，並完成 aideinit 初始化）"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        miss = [p for p in ("aide", "aide-common") if not pkgsvc.pkg_installed(ctx.osi, p)]
        if miss:
            return Check(FAIL, "未安裝 %s" % "、".join(miss))
        if not os.path.exists(AIDE_DB):
            return Check(FAIL, "已安裝，但尚未初始化（%s 不存在）" % AIDE_DB)
        return Check(PASS, "已安裝並已初始化")

    # 相依套件建立的系統帳號、群組與檔案，套件移除（purge）後不會自動刪除：(類型, 名稱, 所屬套件)
    LEFTOVERS = [("user", "postfix", "postfix"), ("group", "postfix", "postfix"), ("group", "postdrop", "postfix"),
                 ("group", "crontab", "cron"), ("group", "ssl-cert", "ssl-cert"),
                 ("file", "/etc/aliases", "postfix"), ("file", "/etc/aliases.db", "postfix")]

    def _register_cleanup(self, fx):
        """回滾時（套件移除之後）清除本次安裝才出現的帳號、群組與檔案；套件仍安裝時不動。"""
        cmds = []
        for kind, name, pkg in self.LEFTOVERS:
            try:
                if kind == "user":
                    pwd.getpwnam(name)
                elif kind == "group":
                    grp.getgrnam(name)
                elif os.path.exists(name):
                    continue
                else:
                    raise KeyError(name)
                continue  # 安裝前已存在，回滾時保留
            except KeyError:
                pass
            act = {"user": "userdel %s" % name, "group": "groupdel %s" % name, "file": "rm -f %s" % name}[kind]
            cmds.append("dpkg -s %s >/dev/null 2>&1 || %s >/dev/null 2>&1" % (pkg, act))
        if cmds:
            fx.add_undo(["sh", "-c", "; ".join(cmds) + "; true"], "清除安裝 AIDE 時連帶建立的帳號、群組與檔案")

    def fix(self, ctx, fx):
        if not all(pkgsvc.pkg_installed(ctx.osi, p) for p in ("aide", "aide-common")):
            if not os.path.exists("/usr/sbin/sendmail"):
                # aide-common 相依 bsd-mailx → 會連帶安裝 postfix，預設為只在本機收送
                fx.run("echo 'postfix postfix/main_mailer_type select Local only' | debconf-set-selections",
                       "預設 postfix 為 Local only（僅本機）", check=False)
                fx.note("aide-common 相依郵件程式，會連帶安裝 postfix（已設定為 Local only，只監聽本機）")
            self._register_cleanup(fx)
            fx.pkg_install("aide-common")
            if not ctx.dry_run and not pkgsvc.pkg_installed(ctx.osi, "aide"):
                fx.pkg_install("aide")
        if os.path.exists(AIDE_DB):
            return
        fx.add_undo(["rm", "-f", AIDE_DB, AIDE_DB + ".new"], "刪除 AIDE 資料庫")
        fx.run(["aideinit", "-y", "-f"], "初始化 AIDE 資料庫（掃描整個檔案系統）", timeout=7200)
        if not ctx.dry_run and not os.path.exists(AIDE_DB) and os.path.exists(AIDE_DB + ".new"):
            fx.run(["cp", "-p", AIDE_DB + ".new", AIDE_DB], "複製 aide.db.new 為 aide.db")
        fx.note("AIDE 資料庫記錄的是目前狀態；之後的系統修改會在檢查報告中列為變更，必要時以 aideinit 重新初始化")


def _cron_fields(line, has_user):
    """回傳 (是否至少每天執行, 指令)；非排程行回傳 None。"""
    s = line.strip()
    if not s or s.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
        return None
    if s.startswith("@"):
        p = s.split(None, 2 if has_user else 1)
        cmd = p[-1] if len(p) > (2 if has_user else 1) else ""
        return p[0] in ("@daily", "@midnight", "@hourly"), cmd
    p = s.split(None, 6 if has_user else 5)
    if len(p) < (7 if has_user else 6):
        return None
    return p[2] == "*" and p[3] == "*" and p[4] == "*", p[-1]


def _is_aide_check(cmd):
    return bool(re.search(r"(^|[\s/])aide(\.wrapper)?(\s|$)", cmd)) and bool(re.search(r"(--check|\s-C(\s|$))", cmd))


def aide_schedules():
    """回傳 [說明] 已設定的每日 AIDE 檢查。"""
    found = []
    for line in (read_text("/var/spool/cron/crontabs/root") or "").splitlines():
        r = _cron_fields(line, False)
        if r and r[0] and _is_aide_check(r[1]):
            found.append("root crontab")
    for f in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
        if "." in os.path.basename(f):
            continue  # Debian cron 不讀取含「.」的檔名
        for line in (read_text(f) or "").splitlines():
            r = _cron_fields(line, True)
            if r and r[0] and _is_aide_check(r[1]):
                found.append(f)
    daily = "/etc/cron.daily/aide"
    if os.path.isfile(daily) and os.access(daily, os.X_OK):
        dflt = read_text("/etc/default/aide") or ""
        run_ = (te.get_kv(dflt, "CRON_DAILY_RUN") or "yes").strip('"\'')
        cmd = (te.get_kv(dflt, "COMMAND") or "check").strip('"\'')
        if run_ == "yes" and cmd in ("check", "update"):
            found.append("%s（aide-common 內附，COMMAND=%s）" % (daily, cmd))
    if which("systemctl"):
        if run(["systemctl", "is-enabled", "dailyaidecheck.timer"], timeout=15).out.strip() == "enabled":
            found.append("dailyaidecheck.timer")
    return found


# [AideSchedule] TWGCB-01-014-0034 定期檢查檔案系統完整性
class AideSchedule(Rule):
    category = CAT
    title = "定期檢查檔案系統完整性"
    expected = "每天（例：0 5 * * * /usr/bin/aide --config /etc/aide/aide.conf --check）"
    CRON = "/etc/cron.d/gcb-aide"
    LINE = "0 5 * * * root /usr/bin/aide --config /etc/aide/aide.conf --check"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if not which("aide"):
            return Check(FAIL, "未安裝 AIDE")
        found = aide_schedules()
        if not found:
            return Check(FAIL, "未設定每日 AIDE 檢查排程")
        if not (which("cron") or which("crond")) and found != ["dailyaidecheck.timer"]:
            return Check(FAIL, "已設定排程（%s），但未安裝 cron，排程不會執行" % "、".join(found))
        return Check(PASS, "已設定：" + "、".join(found))

    def fix(self, ctx, fx):
        if not which("aide"):
            raise ManualRequired("尚未安裝 AIDE，請先完成「AIDE 套件」項目（0033，需 --include-risky）")
        if not (which("cron") or which("crond")):
            fx.pkg_install("cron")
        if aide_schedules():
            return
        fx.write_file(self.CRON, "# %s (gcb-checker)\n%s\n" % (self.rule_id(ctx.osi), self.LINE), mode=0o644)


# ====================================================================
# 開機載入程式（0035–0037）
# ====================================================================

GRUB_FILES = ["/boot/grub/grub.cfg", "/boot/grub/grubenv"]
NO_GRUB = "未使用 GRUB 開機載入程式（%s 不存在），本項目是 GRUB 設定，不需設定"
GRUB_NOTE = "update-grub 會保留既有 grub.cfg 的權限；但 grub.cfg 被刪除後重新產生時權限為 444，屆時需重新檢測修復"


def _unoct(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def proc_mounts():
    """回傳 [(裝置, 掛載點, 類型, 選項清單)]。"""
    out = []
    for line in (read_text("/proc/self/mounts") or "").splitlines():
        p = line.split()
        if len(p) >= 4:
            out.append((_unoct(p[0]), _unoct(p[1]), p[2], p[3].split(",")))
    return out


def _opts_dict(opts):
    d = {}
    for o in opts:
        k, _, v = o.partition("=")
        d[k] = v
    return d


def fstab_set_opts(text, mount, kv):
    """把 fstab 中掛載點的 key=value 選項設為指定值（已有同名選項則取代）。"""
    out = []
    for line in (text or "").splitlines():
        p = line.split()
        if line.strip() and not line.strip().startswith("#") and len(p) >= 4 and p[1] == mount:
            opts = [o for o in p[3].split(",") if o.split("=", 1)[0] not in kv and o != "defaults"]
            opts += ["%s=%s" % (k, v) for k, v in sorted(kv.items())]
            p[3] = ",".join(opts)
            line = "\t".join(p)
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


def efi_status(kind):
    """UEFI /boot/efi（vfat）是否符合。kind：owner（uid/gid=0）或 mode（fmask 遮蔽 0177）。

    回傳 None（非 UEFI 或未掛載）或 (開機設定合格, 目前合格, 說明)。
    """
    if not os.path.isdir("/sys/firmware/efi"):
        return None
    mnt = [m for m in proc_mounts() if m[1] == "/boot/efi"]
    if not mnt or mnt[-1][2] not in ("vfat", "msdos"):
        return None
    rt = _opts_dict(mnt[-1][3])
    fst = te.fstab_options(read_text("/etc/fstab") or "", "/boot/efi")
    fs = _opts_dict(fst) if fst is not None else None

    def ok(d, runtime):
        if kind == "owner":
            return d.get("uid", "0") == "0" and d.get("gid", "0") == "0"
        mask = d.get("fmask", d.get("umask"))
        if mask is None:
            return runtime  # fstab 未指定時以實際掛載結果為準
        try:
            return int(mask, 8) & 0o177 == 0o177
        except ValueError:
            return False
    rt_ok = ok(rt, False)
    fs_ok = ok(fs, rt_ok) if fs is not None else rt_ok
    keys = ("uid", "gid") if kind == "owner" else ("fmask", "umask")
    desc = "/boot/efi 掛載選項：%s" % (",".join("%s=%s" % (k, rt[k]) for k in keys if k in rt) or "預設")
    return fs_ok, rt_ok, desc


# [GrubCfgPerm] TWGCB-01-014-0035 開機載入程式設定檔之所有權、0036 開機載入程式設定檔之權限
class GrubCfgPerm(Rule):
    category = CAT

    def __init__(self, title, ids, kind):
        self.title = title
        self.ids = ids
        self.kind = kind
        if kind == "owner":
            self.perm = FilePerm(title, CAT, ids, GRUB_FILES, owner="root", groups=["root"])
            self.expected = "root:root"
        else:
            self.perm = FilePerm(title, CAT, ids, GRUB_FILES, max_mode=0o600)
            self.expected = "600 或更低權限"

    def when(self, ctx):
        return None if os.path.exists(GRUB_FILES[0]) else NO_GRUB % GRUB_FILES[0]

    def check(self, ctx):
        c = self.perm.check(ctx)
        efi = efi_status(self.kind)
        if efi is None:
            if c.status == FAIL and self.kind == "mode":
                c.current += "（%s）" % GRUB_NOTE
            if any(m[1] == "/boot/efi" for m in proc_mounts()):
                # GCB 的 /boot/efi fmask 規定只適用 UEFI 開機；BIOS 開機時說明未檢查的原因
                c.current += "；本機為 BIOS 開機，/boot/efi 的 UEFI 規定（fmask=0177）不適用，改為 UEFI 開機後需重新檢測"
            return c
        fs_ok, rt_ok, desc = efi
        ok = c.status == PASS and fs_ok
        cur = "%s；%s%s" % (c.current, desc, "" if rt_ok or not fs_ok else "（fstab 已設定，需重開機生效）")
        if not fs_ok:
            cur += "（fstab 不符合）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        self.perm.fix(ctx, fx)
        if self.kind == "mode":
            fx.note(GRUB_NOTE)
        efi = efi_status(self.kind)
        if efi is None or efi[0]:
            return
        if not ctx.include_risky:
            fx.partial = True
            fx.note("UEFI /boot/efi 掛載選項需修改 /etc/fstab（需重開機生效），屬風險項目；確認後可加 --include-risky")
            return
        kv = {"uid": "0", "gid": "0"} if self.kind == "owner" else {"fmask": "0177"}
        fx.edit_file("/etc/fstab", lambda t: fstab_set_opts(t, "/boot/efi", kv))
        r = fx.run(["findmnt", "--verify"], "檢查 fstab 語法", check=False)
        if r is not None and not r.ok and "error" in r.text().lower():
            raise FixError("fstab 檢查失敗，不套用：%s" % r.text()[-200:])
        fx.note("已修改 /etc/fstab 的 /boot/efi 掛載選項，重開機後生效")


# [GrubPassword] TWGCB-01-014-0037 開機載入程式之通行碼（C 類）
class GrubPassword(Rule):
    category = CAT
    title = "開機載入程式之通行碼"
    expected = "設定通行碼（grub.cfg 含 set superusers 與 password_pbkdf2）"
    risk = "C"
    manual_hint = ("執行 grub-mkpasswd-pbkdf2 產生雜湊，在 /etc/grub.d/40_custom 加入 set superusers=\"帳號\" 與 "
                   "password_pbkdf2 帳號 雜湊，再執行 update-grub。注意：設定後預設每次開機都要輸入通行碼，"
                   "無人值守伺服器需在 /etc/grub.d/10_linux 的 CLASS 加上 --unrestricted")

    def __init__(self, ids):
        self.ids = ids

    def when(self, ctx):
        return None if os.path.exists(GRUB_FILES[0]) else NO_GRUB % GRUB_FILES[0]

    def check(self, ctx):
        text = read_text(GRUB_FILES[0])
        if text is None:
            return Check(ERROR, "無法讀取 %s" % GRUB_FILES[0])
        supers, pw = set(), []
        for line in text.splitlines():
            m = re.match(r'^\s*set\s+superusers=["\']?([^"\']*)["\']?\s*$', line)
            if m:
                supers = set(re.split(r"[\s,;|&]+", m.group(1).strip())) - {""}
            m = re.match(r"^\s*password_pbkdf2\s+(\S+)\s+grub\.pbkdf2\.sha512\.\S+", line)
            if m:
                pw.append(m.group(1))
        ok = bool(supers) and any(u in supers for u in pw)
        return Check(PASS if ok else FAIL, "superusers=%s、password_pbkdf2 帳號=%s" % (
            ",".join(sorted(supers)) or "未設定", ",".join(pw) or "未設定"))


# ====================================================================
# 單一使用者模式、核心傾印、ASLR（0038–0040）
# ====================================================================

def shadow_entry(user):
    for u in te.parse_shadow(read_text("/etc/shadow") or ""):
        if u["name"] == user:
            return u
    return None


# [SingleUserAuth] TWGCB-01-014-0038 單一使用者模式身分鑑別（C 類）
class SingleUserAuth(Rule):
    category = CAT
    title = "單一使用者模式身分鑑別"
    expected = "啟用（root 帳號設定通行碼）"
    risk = "C"
    manual_hint = "請以 passwd root 設定 root 通行碼（需人工輸入通行碼），並配合 SSH 禁止 root 登入等規則"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if read_text("/etc/shadow") is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        u = shadow_entry("root")
        if u is None:
            return Check(FAIL, "/etc/shadow 無 root 帳號")
        force = []
        for unit in ("rescue", "emergency"):
            for f in ["/etc/systemd/system/%s.service" % unit] + \
                    sorted(glob.glob("/etc/systemd/system/%s.service.d/*.conf" % unit)):
                if "SYSTEMD_SULOGIN_FORCE" in (read_text(f) or ""):
                    force.append(f)
        if u["pw"] == "":
            return Check(FAIL, "root 未設定通行碼（空白），單一使用者模式無需鑑別")
        if force:
            return Check(FAIL, "救援模式設定了 SYSTEMD_SULOGIN_FORCE（%s），會略過鑑別" % "、".join(force))
        if u["pw"].startswith(("!", "*")):
            return Check(FAIL, "root 帳號為鎖定狀態、未設定通行碼（sulogin 會拒絕進入救援模式，但 GCB 要求設定 root 通行碼）")
        return Check(PASS, "root 已設定通行碼")


SYSCTL_OWN = "/etc/sysctl.d/60-gcb-system.conf"


def sysctl_state(key, want):
    """回傳 (合格, 說明)；系統無此參數回傳 (None, 說明)。"""
    rt = pkgsvc.sysctl_runtime(key)
    if rt is None:
        return None, "核心沒有參數 %s（相關功能未編入或未載入），無法也不需設定" % key
    pv, src, _ = pkgsvc.sysctl_persistent(key)
    ok = rt == want and pv == want
    return ok, "%s 目前=%s 開機=%s%s" % (key, rt, pv if pv is not None else "未設定", "（%s）" % src if src else "")


def sysctl_fix(fx, key, want):
    """註解其他設定檔中的衝突值（非 /etc 的套件檔以同名檔覆蓋），寫入本檔並立即套用。"""
    for f, v in pkgsvc.sysctl_persistent(key)[2]:
        if v == want or f == SYSCTL_OWN:
            continue
        real = os.path.realpath(f)
        if real.startswith("/etc/"):
            fx.edit_file(real, lambda t: te.comment_sysctl(t, key, want))
        else:
            # /usr/lib/sysctl.d 等套件檔不直接修改，以 /etc/sysctl.d 同名檔覆蓋
            fx.write_file(os.path.join("/etc/sysctl.d", os.path.basename(f)),
                          te.comment_sysctl(read_text(f) or "", key, want))
    fx.edit_file(SYSCTL_OWN, lambda t: te.set_kv(t, key, want))
    if pkgsvc.sysctl_runtime(key) != want:
        fx.sysctl_set(key, want)


def limits_files():
    return ["/etc/security/limits.conf"] + sorted(glob.glob("/etc/security/limits.d/*.conf"))


LIMITS_OWN = "/etc/security/limits.d/60-gcb-coredump.conf"
COREDUMP_OWN = "/etc/systemd/coredump.conf.d/60-gcb.conf"


def limits_core(texts):
    """回傳 (有 * hard core 0, [不符合的行])。texts：[(檔案, 內容)]。"""
    good, bad = False, []
    for f, text in texts:
        for line in (text or "").splitlines():
            p = line.split("#", 1)[0].split()
            if len(p) >= 4 and p[0] == "*" and p[1] in ("hard", "-") and p[2] == "core":
                if p[3] == "0":
                    good = True
                else:
                    bad.append("%s: %s" % (f, line.strip()))
    return good, bad


def _limits_comment(text):
    out = []
    for line in (text or "").splitlines():
        p = line.split("#", 1)[0].split()
        if len(p) >= 4 and p[0] == "*" and p[1] in ("hard", "-") and p[2] == "core" and p[3] != "0":
            line = te.MARK + line
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


def coredump_values():
    """依 systemd 讀取順序合併 coredump.conf 與 drop-in，回傳 {Storage, ProcessSizeMax}。"""
    files = ["/etc/systemd/coredump.conf"]
    chosen = {}
    for d in ("/usr/lib/systemd/coredump.conf.d", "/run/systemd/coredump.conf.d", "/etc/systemd/coredump.conf.d"):
        for f in glob.glob(d + "/*.conf"):
            chosen[os.path.basename(f)] = f  # 同名檔以 /etc 優先
    files += [chosen[b] for b in sorted(chosen)]
    vals = {}
    for f in files:
        text = read_text(f) or ""
        for k in ("Storage", "ProcessSizeMax"):
            v = te.get_kv(text, k)
            if v is not None:
                vals[k] = v
    return vals


# [CoreDump] TWGCB-01-014-0039 核心傾印功能
class CoreDump(Rule):
    category = CAT
    title = "核心傾印功能"
    expected = "停用（* hard core 0、fs.suid_dumpable=0；已安裝 systemd-coredump 時 Storage=none、ProcessSizeMax=0 並遮蔽 systemd-coredump.socket）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        cur, ok = [], True
        good, bad = limits_core([(f, read_text(f)) for f in limits_files()])
        ok = ok and good and not bad
        cur.append("limits * hard core 0：%s%s" % ("有" if good else "無", "；衝突：" + "、".join(bad) if bad else ""))
        s_ok, s_cur = sysctl_state("fs.suid_dumpable", "0")
        ok = ok and s_ok is not False
        cur.append(s_cur)
        if s_ok is False and pkgsvc.svc_state("apport.service")[1] == "active":
            cur.append("apport 執行中會把 fs.suid_dumpable 改為 2（見 0042）")
        if pkgsvc.pkg_installed(ctx.osi, "systemd-coredump"):
            v = coredump_values()
            en = pkgsvc.svc_state("systemd-coredump.socket")[0]
            c_ok = v.get("Storage", "").lower() == "none" and v.get("ProcessSizeMax") == "0" and en == "masked"
            ok = ok and c_ok
            cur.append("coredump Storage=%s ProcessSizeMax=%s socket=%s" % (
                v.get("Storage", "未設定"), v.get("ProcessSizeMax", "未設定"), en))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        coredump = pkgsvc.pkg_installed(ctx.osi, "systemd-coredump")
        if coredump:
            fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")  # 先登記：回滾時在還原檔案之後才 reload
        for f in limits_files():
            if f != LIMITS_OWN and limits_core([(f, read_text(f))])[1]:
                fx.edit_file(f, _limits_comment)
        fx.write_file(LIMITS_OWN, "# %s (gcb-checker)\n* hard core 0\n" % self.rule_id(ctx.osi))
        if coredump:
            fx.write_file(COREDUMP_OWN, "[Coredump]\nStorage=none\nProcessSizeMax=0\n")
            fx.run(["systemctl", "daemon-reload"], "重新載入 systemd", check=False)
            if pkgsvc.svc_state("systemd-coredump.socket")[0] != "masked":
                fx.service_mask("systemd-coredump.socket")
        sysctl_fix(fx, "fs.suid_dumpable", "0")
        fx.note("limits 設定對新登入的工作階段生效")


# [SysctlValue] TWGCB-01-014-0040 記憶體位址空間配置隨機載入
class SysctlValue(Rule):
    category = CAT

    def __init__(self, title, ids, key, want):
        self.title = title
        self.ids = ids
        self.key = key
        self.want = want
        self.expected = want

    def check(self, ctx):
        ok, cur = sysctl_state(self.key, self.want)
        if ok is None:
            return Check(NA, cur)
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        sysctl_fix(fx, self.key, self.want)


# [Prelink] TWGCB-01-014-0041 prelink 套件
class Prelink(PackageAbsent):
    def fix(self, ctx, fx):
        if which("prelink"):
            fx.run(["prelink", "-ua"], "還原已預連結的執行檔", timeout=1800, check=False)
        PackageAbsent.fix(self, ctx, fx)


# ====================================================================
# 檔案系統掃描（0059–0061）
# ====================================================================

LOCAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "exfat", "f2fs", "jfs", "reiserfs",
            "ntfs", "ntfs3", "tmpfs")
SKIP_PREFIX = ("/proc", "/sys", "/dev", "/run")
SCAN_TIMEOUT = 1200
_scan_cache = {}


def scan_roots():
    """本機檔案系統掛載點（排除虛擬、網路、唯讀映像與 /proc /sys /dev /run），同一裝置只掃一次。"""
    roots, devs = [], set()
    for dev, mp, fstype, opts in sorted(proc_mounts(), key=lambda m: len(m[1])):
        if mp != "/" and any(mp == p or mp.startswith(p + "/") for p in SKIP_PREFIX):
            continue
        if not (fstype in LOCAL_FS or (fstype == "overlay" and mp == "/")):
            continue
        if not os.path.isdir(mp):
            continue
        try:
            d = os.stat(mp).st_dev
        except OSError:
            continue
        if d in devs:
            continue
        devs.add(d)
        roots.append(mp)
    return roots


def fs_scan():
    """一次掃描找出全域可寫一般檔案、無擁有者、無群組的檔案與目錄（結果快取 2 分鐘）。

    回傳 dict(ww=[路徑], nouser=[(uid, 路徑)], nogroup=[(gid, 路徑)], roots=[...]) 或 錯誤字串。
    """
    c = _scan_cache.get("r")
    if c and time.time() - c[0] < 120:
        return c[1]
    roots = scan_roots()
    if not roots:
        return "找不到可掃描的本機檔案系統"
    prune = []
    for p in SKIP_PREFIX:
        prune += ["-path", p, "-o"]
    cmd = ["find"] + roots + ["-xdev", "("] + prune[:-1] + [")", "-prune", "-o", "(",
                                                           "(", "-type", "f", "-perm", "-0002", "-printf", "W\t%p\\0", ")", ",",
                                                           "(", "-nouser", "-printf", "U\t%U\t%p\\0", ")", ",",
                                                           "(", "-nogroup", "-printf", "G\t%G\t%p\\0", ")", ")"]
    r = run(cmd, timeout=SCAN_TIMEOUT)
    if r.rc == 124:
        return "檔案系統掃描逾時（%d 秒），請於離峰時間人工執行 find (掛載點) -xdev 檢查" % SCAN_TIMEOUT
    if r.rc == 127:
        return "找不到 find 指令"
    res = {"ww": [], "nouser": [], "nogroup": [], "roots": roots}
    for rec in r.out.split("\0"):
        p = rec.split("\t", 2)
        if p[0] == "W" and len(p) == 2:
            res["ww"].append(p[1])
        elif p[0] == "U" and len(p) == 3:
            res["nouser"].append((p[1], p[2]))
        elif p[0] == "G" and len(p) == 3:
            res["nogroup"].append((p[1], p[2]))
    _scan_cache["r"] = (time.time(), res)
    return res


def _show(items, n=10):
    s = "、".join(items[:n])
    return s + ("…等共 %d 個" % len(items) if len(items) > n else "")


# [FsScan] TWGCB-01-014-0059 全域寫入權限之檔案、0060 檔案與目錄之擁有者、0061 檔案與目錄之擁有群組（C 類）
class FsScan(Rule):
    category = CAT
    risk = "C"

    def __init__(self, title, ids, kind, expected, manual_hint):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.expected = expected
        self.manual_hint = manual_hint

    def check(self, ctx):
        res = fs_scan()
        if not isinstance(res, dict):
            return Check(ERROR, res)
        items = res[self.kind]
        scope = "掃描範圍：%s" % "、".join(res["roots"])
        if not items:
            return Check(PASS, "未發現；" + scope)
        if self.kind == "ww":
            shown = items
        else:
            shown = ["%s（%s=%s）" % (p, "uid" if self.kind == "nouser" else "gid", i) for i, p in items]
        return Check(FAIL, "%d 個：%s；%s" % (len(items), _show(shown), scope))


# ====================================================================
# 帳號資料庫（0063、0064、0072–0078）
# ====================================================================

def parse_passwd(text=None):
    """回傳 [dict(name, pw, uid, gid, home, shell)]（欄位不足的行略過）。"""
    out = []
    for line in (read_text("/etc/passwd") if text is None else text or "").splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[0] or f[0].startswith(("+", "-")):
            continue
        out.append({"name": f[0], "pw": f[1], "uid": f[2], "gid": f[3], "home": f[5], "shell": f[6]})
    return out


def parse_group(text=None):
    """回傳 [dict(name, gid, members)]。"""
    out = []
    for line in (read_text("/etc/group") if text is None else text or "").splitlines():
        f = line.split(":")
        if len(f) < 4 or not f[0] or f[0].startswith(("+", "-")):
            continue
        out.append({"name": f[0], "gid": f[2], "members": [m for m in f[3].split(",") if m.strip()]})
    return out


def path_problems(path):
    """回傳 PATH 中不合格的元素說明。"""
    bad = []
    for i, e in enumerate(path.split(":")):
        if e == "":
            bad.append("第 %d 個為空元素" % (i + 1))
        elif e in (".", ".."):
            bad.append("「%s」" % e)
        elif not e.startswith("/"):
            bad.append("「%s」開頭不是 /" % e)
    return bad


def root_login_path():
    """取得 root 登入環境的 PATH（經 PAM 與登入 shell 設定檔），回傳 (PATH, 來源) 或 (None, 錯誤)。"""
    mark = "__GCB_PATH__"
    r = run(["su", "-", "root", "-c", "printf '%s%%s%s' \"$PATH\"" % (mark, mark)], timeout=30)
    m = re.search(re.escape(mark) + "(.*?)" + re.escape(mark), r.out, re.S)
    if m:
        return m.group(1), "su - root"
    return None, "無法取得 root 登入環境的 PATH：%s" % r.text()[-200:]


# [RootPath] TWGCB-01-014-0063 root 帳號之路徑變數（C 類）
class RootPath(Rule):
    category = CAT
    title = "root 帳號之路徑變數"
    expected = "不允許「.」、「..」、路徑開頭不是「/」及空元素"
    risk = "C"
    manual_hint = ("PATH 可能來自 /etc/environment、/etc/profile、/etc/profile.d/*.sh、/root/.profile、/root/.bashrc，"
                   "請找出來源並移除「.」、「..」、相對路徑與空元素（例如結尾的「:」）")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        path, src = root_login_path()
        if path is None:
            return Check(ERROR, src)
        bad = path_problems(path)
        if bad:
            return Check(FAIL, "PATH=%s；不合格：%s" % (path, "、".join(bad)))
        return Check(PASS, "PATH=%s" % path)


# [AccountDb] TWGCB-01-014-0064 UID=0 之帳號、0072–0077 帳號與群組資料庫檢查（C 類）
class AccountDb(Rule):
    """func(passwd, group) 回傳不合格說明清單。"""
    category = CAT
    risk = "C"

    def __init__(self, title, ids, expected, func, manual_hint, ok_text):
        self.title = title
        self.ids = ids
        self.expected = expected
        self.func = func
        self.manual_hint = manual_hint
        self.ok_text = ok_text

    def check(self, ctx):
        if read_text("/etc/passwd") is None or read_text("/etc/group") is None:
            return Check(ERROR, "無法讀取 /etc/passwd 或 /etc/group")
        bad = self.func(parse_passwd(), parse_group())
        if bad:
            return Check(FAIL, _show(bad))
        return Check(PASS, self.ok_text)


def _dups(names):
    seen, out = {}, []
    for n in names:
        seen[n] = seen.get(n, 0) + 1
    return [n for n in sorted(seen) if seen[n] > 1]


def bad_uid0(pw, gr):
    return ["%s（UID 0）" % u["name"] for u in pw if u["uid"] == "0" and u["name"] != "root"]


def bad_passwd_field(pw, gr):
    return ["%s（通行碼欄位非 x）" % u["name"] for u in pw if u["pw"] != "x"]


def bad_passwd_gid(pw, gr):
    gids = set(g["gid"] for g in gr)
    return ["%s（GID %s 不存在於 /etc/group）" % (u["name"], u["gid"]) for u in pw if u["gid"] not in gids]


def bad_dup_uid(pw, gr):
    out = []
    for uid in _dups([u["uid"] for u in pw]):
        out.append("UID %s：%s" % (uid, ",".join(u["name"] for u in pw if u["uid"] == uid)))
    return out


def bad_dup_gid(pw, gr):
    out = []
    for gid in _dups([g["gid"] for g in gr]):
        out.append("GID %s：%s" % (gid, ",".join(g["name"] for g in gr if g["gid"] == gid)))
    return out


def bad_dup_user(pw, gr):
    return ["帳號名稱重複：%s" % n for n in _dups([u["name"] for u in pw])]


def bad_dup_group(pw, gr):
    return ["群組名稱重複：%s" % n for n in _dups([g["name"] for g in gr])]


def shadow_group_problems(pw, gr):
    """回傳 (次要成員清單, 主要群組為 shadow 的帳號清單)；無 shadow 群組回傳 ([], [])。"""
    sg = [g for g in gr if g["name"] == "shadow"]
    if not sg:
        return [], []
    return sg[0]["members"], [u["name"] for u in pw if u["gid"] == sg[0]["gid"]]


# [ShadowGroup] TWGCB-01-014-0078 shadow 群組成員
class ShadowGroup(Rule):
    category = CAT
    title = "shadow 群組成員"
    expected = "shadow 群組不包含任何使用者"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        mem, prim = shadow_group_problems(parse_passwd(), parse_group())
        if not mem and not prim:
            return Check(PASS, "shadow 群組無成員")
        cur = []
        if mem:
            cur.append("成員：%s" % ",".join(mem))
        if prim:
            cur.append("主要群組為 shadow 的帳號：%s" % ",".join(prim))
        return Check(FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        mem, prim = shadow_group_problems(parse_passwd(), parse_group())
        if mem:
            files = ["/etc/group", "/etc/gshadow"]
            for f in files:
                fx.backup_only(f)
            for u in mem:
                fx.run_tracked(["gpasswd", "-d", u, "shadow"], "將 %s 移出 shadow 群組" % u, files)
        if prim:
            fx.partial = True
            fx.note("帳號 %s 的主要群組為 shadow，請確認用途後以 usermod -g (群組) (帳號) 人工修改" % ",".join(prim))


# ====================================================================
# 使用者家目錄（0065–0071）
# ====================================================================

SHARED_PREFIX = ("/bin", "/sbin", "/usr", "/lib", "/etc", "/dev", "/proc", "/sys", "/run", "/boot", "/var",
                 "/tmp", "/srv", "/opt", "/snap", "/nonexistent")


def _uid_range():
    ld = read_text("/etc/login.defs") or ""
    try:
        lo = int(te.get_kv(ld, "UID_MIN") or 1000)
    except ValueError:
        lo = 1000
    try:
        hi = int(te.get_kv(ld, "UID_MAX") or 60000)
    except ValueError:
        hi = 60000
    return lo, hi


def login_users(include_root=True, regular_only=True, passwd_text=None):
    """依 GCB 腳本篩選具登入 shell 的帳號（排除 halt、sync、shutdown 與 nologin/false）。

    regular_only：只取 root 與一般使用者（UID_MIN–UID_MAX），並略過共用或系統目錄（/、/var/lib…）
    及多個帳號共用的家目錄。回傳 (帳號清單, 略過說明清單)。
    """
    users = [u for u in parse_passwd(passwd_text)
             if u["name"] not in ("halt", "sync", "shutdown") and u["shell"] not in NOLOGIN]
    if not include_root:
        users = [u for u in users if u["name"] != "root"]
    if not regular_only:
        return users, []
    lo, hi = _uid_range()
    homes = {}
    for u in parse_passwd(passwd_text):
        homes.setdefault(os.path.normpath(u["home"] or "/"), []).append(u["name"])
    keep, skipped = [], []
    for u in users:
        try:
            uid = int(u["uid"])
        except ValueError:
            continue
        if uid != 0 and not lo <= uid <= hi:
            continue  # 系統帳號
        h = os.path.normpath(u["home"] or "/")
        if h == "/" or any(h == p or h.startswith(p + "/") for p in SHARED_PREFIX):
            skipped.append("%s（%s 為系統或共用目錄）" % (u["name"], h))
        elif len(homes.get(h, [])) > 1:
            skipped.append("%s（%s 與 %s 共用）" % (u["name"], h, ",".join(n for n in homes[h] if n != u["name"])))
        else:
            keep.append(u)
    return keep, skipped


# [HomeDirs] TWGCB-01-014-0065 使用者家目錄權限、0066 擁有者、0067 擁有群組、0068「.」檔案權限
class HomeDirs(Rule):
    """kind：mode（700）/ owner / group / dotfiles（go-w）。

    只處理 root 與一般使用者；系統帳號、共用目錄（/、/var/lib…）與多帳號共用的家目錄略過。
    """
    category = CAT

    def __init__(self, title, ids, kind, expected, risk, manual_hint=""):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.expected = expected
        self.risk = risk
        self.manual_hint = manual_hint

    def _problems(self):
        """回傳 ([(路徑, 說明, 可修復)], 略過說明清單)。"""
        users, skipped = login_users()
        out = []
        for u in users:
            d = u["home"]
            if not os.path.isdir(d):
                out.append((d, "帳號 %s 的家目錄不存在" % u["name"], False))
                continue
            st = os.stat(d)
            if self.kind == "mode" and st.st_mode & 0o077:
                out.append((d, "%s 權限 %03o" % (d, st.st_mode & 0o777), True))
            elif self.kind == "owner" and str(st.st_uid) != u["uid"]:
                out.append((d, "%s 擁有者 uid=%s（應為 %s %s）" % (d, st.st_uid, u["name"], u["uid"]), False))
            elif self.kind == "group" and str(st.st_gid) != u["gid"]:
                out.append((d, "%s 群組 gid=%s（應為 %s）" % (d, st.st_gid, u["gid"]), False))
            elif self.kind == "dotfiles":
                try:
                    names = sorted(os.listdir(d))
                except OSError:
                    names = []
                for n in names:
                    if not re.match(r"^\.[A-Za-z0-9]", n):
                        continue
                    p = os.path.join(d, n)
                    lst = os.lstat(p)
                    if stat.S_ISREG(lst.st_mode) and lst.st_mode & 0o022:
                        out.append((p, "%s 權限 %03o" % (p, lst.st_mode & 0o777), True))
        return out, skipped

    def check(self, ctx):
        bad, skipped = self._problems()
        cur = _show([b[1] for b in bad]) if bad else "皆符合"
        if skipped:
            cur += "；略過：" + _show(skipped, 5)
        return Check(FAIL if bad else PASS, cur)

    def fix(self, ctx, fx):
        bad, _ = self._problems()
        for path, desc, fixable in bad:
            if not fixable:
                fx.partial = True
                fx.note("無法自動處理：" + desc)
                continue
            mode = os.lstat(path).st_mode & 0o7777
            fx.chmod(path, mode & (0o7700 if self.kind == "mode" else ~0o022 & 0o7777))
        fx.note("已變更使用者家目錄相關權限，請通知使用者")


# [HomeFile] TWGCB-01-014-0069「.forward」、0070「.netrc」檔案（C 類）；0071 見 HomeRhosts
class HomeFile(Rule):
    category = CAT
    risk = "C"

    def __init__(self, name, ids):
        self.name = name
        self.ids = ids
        self.title = "使用者家目錄之「%s」檔案" % name
        self.expected = "移除"
        self.manual_hint = ("屬使用者資料，請先通知使用者，確認不再需要後移除（建議先備份）：rm (家目錄)/%s" % name)

    def check(self, ctx):
        found = self.found()
        return Check(FAIL if found else PASS, ("存在：" + _show(found)) if found else "未發現")

    def found(self):
        users, _ = login_users(include_root=False, regular_only=False)
        out = []
        for u in users:
            p = os.path.join(u["home"], self.name)
            try:
                if stat.S_ISREG(os.lstat(p).st_mode):
                    out.append(p)
            except OSError:
                pass
        return out


RSH_PKGS = ("rsh-server", "rsh-redone-server", "inetutils-rshd", "inetutils-rlogind")


# [HomeRhosts] TWGCB-01-014-0071「.rhosts」檔案（B 類：移到備份目錄，可回滾）
class HomeRhosts(HomeFile):
    """.rhosts 只給 rsh／rlogin 使用，Ubuntu 22.04 預設未安裝；修復時備份後移除，回滾放回原位。"""
    risk = "B"
    doc_note = ("會移動使用者檔案：備份到報告的 backup 目錄後移除，回滾可放回原位；"
                "已安裝 rsh／rlogin 服務時不處理")

    def __init__(self, ids):
        HomeFile.__init__(self, ".rhosts", ids)
        self.manual_hint = ""

    def precondition(self, ctx):
        used = [p for p in RSH_PKGS if pkgsvc.pkg_installed(ctx.osi, p)]
        if used:
            return ("已安裝 %s，.rhosts 可能仍在使用；請確認不再使用 rsh／rlogin 後人工移除"
                    % "、".join(used))
        return None

    def fix(self, ctx, fx):
        for path in self.found():
            fx.backup_only(path)  # 回滾時依備份放回原位（含權限與擁有者）
            if fx.dry:
                fx.step("移除檔案", "[預覽] " + path, "預覽")
                continue
            os.unlink(path)
            fx.step("移除檔案", "%s（已備份，回滾可放回）" % path, "成功")
        fx.note("已將使用者的 .rhosts 移到報告的 backup 目錄；如使用者仍需要，執行回滾即可放回")


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

def _perm(title, n, path, groups=None, mode=None, expected=None, missing="na"):
    if groups:
        return FilePerm(title, CAT, U(n), path, owner="root", groups=groups, missing=missing, expected=expected)
    return FilePerm(title, CAT, U(n), path, max_mode=mode, missing=missing, expected=expected)


ROOT_ROOT = "root:root"
ROOT_SHADOW = "root:root 或 root:shadow"
MODE_644 = "644 或更低權限"
MODE_000 = "000"

_prelink = Prelink("prelink 套件", "prelink", U(41))
_prelink.category = CAT
_apport = ServiceDisabled("自動錯誤回報服務", ["apport.service"], U(42))
_apport.category = CAT
_apport.expected = "停用（systemctl --now mask apport.service）"

RULES = [
    # 0029 sudo 套件
    PackagePresent("sudo 套件", "sudo", U(29), CAT),
    # 0030 設定 sudo 指令使用 pty
    SudoDefault("設定 sudo 指令使用 pty", U(30), "flag", "use_pty", "Defaults use_pty", "Defaults use_pty"),
    # 0031 sudo 自定義日誌檔案
    SudoDefault("sudo 自定義日誌檔案", U(31), "logfile", "logfile", 'Defaults logfile="/var/log/sudo.log"',
                '啟用（例：Defaults logfile="/var/log/sudo.log"）'),
    # 0032 sudo 身分鑑別逾時時間
    SudoDefault("sudo 身分鑑別逾時時間", U(32), "timeout", "timestamp_timeout",
                "Defaults env_reset,timestamp_timeout=5", "5 分鐘(含)以下，但須大於 0"),
    # 0033 AIDE 套件
    AidePackage(U(33)),
    # 0034 定期檢查檔案系統完整性
    AideSchedule(U(34)),
    # 0035 開機載入程式設定檔之所有權
    GrubCfgPerm("開機載入程式設定檔之所有權", U(35), "owner"),
    # 0036 開機載入程式設定檔之權限
    GrubCfgPerm("開機載入程式設定檔之權限", U(36), "mode"),
    # 0037 開機載入程式之通行碼
    GrubPassword(U(37)),
    # 0038 單一使用者模式身分鑑別
    SingleUserAuth(U(38)),
    # 0039 核心傾印功能
    CoreDump(U(39)),
    # 0040 記憶體位址空間配置隨機載入
    SysctlValue("記憶體位址空間配置隨機載入", U(40), "kernel.randomize_va_space", "2"),
    # 0041 prelink 套件
    _prelink,
    # 0042 自動錯誤回報服務
    _apport,
    # 0043 /etc/passwd 檔案所有權 → common.py
    # 0044 /etc/passwd 檔案權限 → common.py
    # 0045 /etc/shadow 檔案所有權 → common.py
    # 0046 /etc/shadow 檔案權限 → common.py
    # 0047 /etc/group 檔案所有權
    _perm("/etc/group 檔案所有權", 47, "/etc/group", groups=["root"], expected=ROOT_ROOT, missing="fail"),
    # 0048 /etc/group 檔案權限
    _perm("/etc/group 檔案權限", 48, "/etc/group", mode=0o644, expected=MODE_644, missing="fail"),
    # 0049 /etc/gshadow 檔案所有權
    _perm("/etc/gshadow 檔案所有權", 49, "/etc/gshadow", groups=["shadow", "root"], expected=ROOT_SHADOW,
          missing="fail"),
    # 0050 /etc/gshadow 檔案權限
    _perm("/etc/gshadow 檔案權限", 50, "/etc/gshadow", mode=0o000, expected=MODE_000, missing="fail"),
    # 0051 /etc/passwd- 檔案所有權
    _perm("/etc/passwd- 檔案所有權", 51, "/etc/passwd-", groups=["root"], expected=ROOT_ROOT),
    # 0052 /etc/passwd- 檔案權限
    _perm("/etc/passwd- 檔案權限", 52, "/etc/passwd-", mode=0o644, expected=MODE_644),
    # 0053 /etc/shadow- 檔案所有權
    _perm("/etc/shadow- 檔案所有權", 53, "/etc/shadow-", groups=["shadow", "root"], expected=ROOT_SHADOW),
    # 0054 /etc/shadow- 檔案權限
    _perm("/etc/shadow- 檔案權限", 54, "/etc/shadow-", mode=0o000, expected=MODE_000),
    # 0055 /etc/group- 檔案所有權
    _perm("/etc/group- 檔案所有權", 55, "/etc/group-", groups=["root"], expected=ROOT_ROOT),
    # 0056 /etc/group- 檔案權限
    _perm("/etc/group- 檔案權限", 56, "/etc/group-", mode=0o644, expected=MODE_644),
    # 0057 /etc/gshadow- 檔案所有權
    _perm("/etc/gshadow- 檔案所有權", 57, "/etc/gshadow-", groups=["shadow", "root"], expected=ROOT_SHADOW),
    # 0058 /etc/gshadow- 檔案權限
    _perm("/etc/gshadow- 檔案權限", 58, "/etc/gshadow-", mode=0o000, expected=MODE_000),
    # 0059 其他使用者寫入具有全域寫入權限之檔案
    FsScan("其他使用者寫入具有全域寫入權限之檔案", U(59), "ww", "禁止寫入",
           "請確認檔案用途後以 chmod o-w (檔案名稱) 移除其他使用者寫入權限（應用程式可能依賴，需人工判斷）"),
    # 0060 檢查所有檔案與目錄之擁有者
    FsScan("檢查所有檔案與目錄之擁有者", U(60), "nouser", "所有檔案與目錄擁有者皆為合法使用者",
           "請確認檔案用途後以 chown (使用者) (檔案) 指定擁有者，或確認不需要後刪除"),
    # 0061 檢查所有檔案與目錄之擁有群組
    FsScan("檢查所有檔案與目錄之擁有群組", U(61), "nogroup", "所有檔案與目錄擁有群組皆為合法群組",
           "請確認檔案用途後以 chgrp (群組) (檔案) 指定群組，或確認不需要後刪除"),
    # 0062 帳號不使用空白通行碼 → common.py
    # 0063 root 帳號之路徑變數
    RootPath(U(63)),
    # 0064 UID=0 之帳號
    AccountDb("UID=0 之帳號", U(64), "僅 root 帳號之 UID 為 0", bad_uid0,
              "請確認帳號用途後以 userdel (帳號) 刪除或 usermod -u (UID) (帳號) 變更 UID", "僅 root 之 UID 為 0"),
    # 0065 使用者家目錄權限
    HomeDirs("使用者家目錄權限", U(65), "mode", "700 或更低權限", "B"),
    # 0066 使用者家目錄擁有者
    HomeDirs("使用者家目錄擁有者", U(66), "owner", "使用者擁有", "C",
             "請先通知使用者，確認後以 chown (使用者) (家目錄) 修改"),
    # 0067 使用者家目錄擁有群組
    HomeDirs("使用者家目錄擁有群組", U(67), "group", "使用者群組擁有", "C",
             "請先通知使用者，確認後以 chgrp (使用者主要群組) (家目錄) 修改"),
    # 0068 使用者家目錄之「.」檔案權限
    HomeDirs("使用者家目錄之「.」檔案權限", U(68), "dotfiles", "go-w 或更低權限", "B"),
    # 0069 使用者家目錄之「.forward」檔案
    HomeFile(".forward", U(69)),
    # 0070 使用者家目錄之「.netrc」檔案
    HomeFile(".netrc", U(70)),
    # 0071 使用者家目錄之「.rhosts」檔案
    HomeRhosts(U(71)),
    # 0072 檢查 /etc/passwd 檔案設定之通行碼
    AccountDb("檢查/etc/passwd 檔案設定之通行碼", U(72), "/etc/passwd 檔案中之通行碼欄位皆須設為「x」",
              bad_passwd_field, "請先備份 /etc/passwd 與 /etc/shadow，執行 pwconv 將通行碼移入 /etc/shadow，"
              "或依文件改為 x 後以 passwd (帳號) 重設通行碼", "通行碼欄位皆為 x"),
    # 0073 檢查 /etc/passwd 檔案設定之群組
    AccountDb("檢查/etc/passwd 檔案設定之群組", U(73), "/etc/passwd 檔案中帳號之群組皆須存在於 /etc/group 檔案中",
              bad_passwd_gid, "請以 groupadd -g (GID) (群組) 建立群組，或以 usermod -g (群組) (帳號) 修改主要群組",
              "所有帳號的群組皆存在"),
    # 0074 唯一之 UID
    AccountDb("唯一之 UID", U(74), "為每個帳號設定唯一之 UID", bad_dup_uid,
              "請以 usermod -u (UID) (帳號) 指定唯一 UID，並修正該帳號檔案的擁有者", "無重複 UID"),
    # 0075 唯一之 GID
    AccountDb("唯一之 GID", U(75), "為每個群組設定唯一之 GID", bad_dup_gid,
              "請以 groupmod -g (GID) (群組) 指定唯一 GID，並修正相關檔案的群組", "無重複 GID"),
    # 0076 唯一之使用者帳號名稱
    AccountDb("唯一之使用者帳號名稱", U(76), "為每個使用者帳號設定唯一之名稱", bad_dup_user,
              "請以 vipw 人工編輯 /etc/passwd（及 vipw -s 編輯 /etc/shadow），為帳號設定唯一名稱", "無重複帳號名稱"),
    # 0077 唯一之群組名稱
    AccountDb("唯一之群組名稱", U(77), "為每個群組設定唯一之群組名稱", bad_dup_group,
              "請以 vigr 人工編輯 /etc/group（及 vigr -s 編輯 /etc/gshadow），為群組設定唯一名稱", "無重複群組名稱"),
    # 0078 shadow 群組成員
    ShadowGroup(U(78)),
]
