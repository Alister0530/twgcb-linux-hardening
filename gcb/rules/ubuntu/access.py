# -*- coding: utf-8 -*-
"""Ubuntu 22.04 AppArmor、cron 設定、帳號與存取控制（TWGCB-01-014-0155 ～ 0193）。"""
import glob
import grp
import os
import pwd
import re
import time

from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, which
from ..base import ERROR, FAIL, PASS, Check, Rule
from ..common import UBUNTU_FAILLOCK_PROFILES, Faillock, GrubArg, ServiceEnabled, grub_effective_cmdline
from ..generic import FilePerm, KvSetting, PackagePresent
from .helpers import U

ACC = "帳號與存取控制"
CRON = "cron 設定"

PAM_COMMON = ["/etc/pam.d/common-auth", "/etc/pam.d/common-account", "/etc/pam.d/common-password",
              "/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive"]
COMMON_PASSWORD = "/etc/pam.d/common-password"
PROFILE_D = "/etc/profile.d"
BASHRC = "/etc/bash.bashrc"
SHELL_FILES = ["/etc/profile", BASHRC]


def _today():
    return int(time.time() // 86400)


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _shell_files():
    """全域 shell 設定檔：/etc/profile、/etc/bash.bashrc、/etc/profile.d/*.sh。"""
    return SHELL_FILES + sorted(glob.glob(PROFILE_D + "/*.sh"))


def _code(line):
    """去除 shell 註解（簡化：# 前需為行首或空白）。"""
    return re.split(r"(?:^|\s)#", line, maxsplit=1)[0]


# ====================================================================
# PAM 共用工具
# ====================================================================

def pam_args(text, ptype, module):
    """回傳 PAM 設定中 ptype 類型、使用 module 的有效行參數清單 [[arg, ...], ...]。"""
    out = []
    rx = re.compile(r"(?:^|[\s/])" + re.escape(module) + r"(?:\s|$)")
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.split()[0].lstrip("-") != ptype:
            continue
        m = rx.search(s)
        if m:
            out.append(s[m.end():].split())
    return out


def arg_value(args, name):
    """取參數 name=value 的最後一個值（PAM 模組以最後出現者為準）。"""
    val = None
    for a in args:
        if a.startswith(name + "="):
            val = a.split("=", 1)[1]
    return val


GCB_UNIX = "/usr/share/pam-configs/gcb_unix"
STOCK_UNIX = "/usr/share/pam-configs/unix"
GCB_UNIX_NAME = "GCB Unix authentication (gcb-checker)"
HASH_ARGS = ("md5", "bigcrypt", "sha256", "sha512", "blowfish", "gost_yescrypt", "yescrypt")


def unix_profile(text, transform):
    """由 pam-configs/unix 產生 gcb_unix profile：改名、宣告與 unix 互斥，
    並以 transform(args) 修改 Password / Password-Initial 的 pam_unix.so 參數。"""
    out, field, has_conflicts = [], None, False
    for line in (text or "").splitlines():
        m = re.match(r"^(\S+):\s*(.*)$", line)
        if m and not line[:1].isspace():
            field = m.group(1)
            if field == "Name":
                line = "Name: " + GCB_UNIX_NAME
            elif field == "Conflicts":
                has_conflicts = True
                items = [x.strip() for x in m.group(2).split(",") if x.strip()]
                if "unix" not in items:
                    line = "Conflicts: " + ", ".join(items + ["unix"])
            out.append(line)
            continue
        if field in ("Password", "Password-Initial") and "pam_unix.so" in line:
            pre, post = line.split("pam_unix.so", 1)
            line = pre + "pam_unix.so " + " ".join(transform(post.split()))
        out.append(line)
    if not has_conflicts:
        idx = next((i + 1 for i, l in enumerate(out) if l.startswith("Priority:")), 1)
        out.insert(idx, "Conflicts: unix")
    return "\n".join(out) + "\n"


def with_remember(n):
    def _t(args):
        return [a for a in args if not a.startswith("remember=")] + ["remember=%d" % n]
    return _t


def with_yescrypt(args):
    keep = [a for a in args if a not in HASH_ARGS]
    return keep + ["yescrypt"]


def _pam_backup(fx):
    for f in PAM_COMMON + sorted(glob.glob("/var/lib/pam/*")):
        fx.backup_only(f)


def _pam_auth_update(fx, cmd, desc):
    """執行 pam-auth-update 並確認沒有因本機修改而拒絕更新。"""
    r = fx.run_tracked(cmd, desc, PAM_COMMON, env=pkgsvc.APT_ENV, check=False)
    if r is not None and (not r.ok or "local modifications" in r.text().lower()):
        raise FixError("pam-auth-update 未套用（/etc/pam.d/common-* 可能曾被手動修改），請人工處理")
    return r


def _verify_unix_stack():
    """pam-auth-update 後確認基本堆疊完整：auth/account/password 各有一行 pam_unix.so。"""
    for path, ptype in (("/etc/pam.d/common-auth", "auth"), ("/etc/pam.d/common-account", "account"),
                        (COMMON_PASSWORD, "password")):
        n = len(pam_args(read_text(path) or "", ptype, "pam_unix.so"))
        if n != 1:
            raise FixError("PAM 堆疊驗證失敗：%s 的 pam_unix.so 有 %d 行（應為 1 行），已還原" % (path, n))


def apply_gcb_unix(fx, transform, desc):
    """以 pam-auth-update 啟用 gcb_unix profile（取代 Ubuntu 內建 unix profile），不直接手改 common-*。"""
    if not which("pam-auth-update"):
        raise ManualRequired("找不到 pam-auth-update，請人工修改 /etc/pam.d/common-password 的 pam_unix.so 參數")
    base = read_text(GCB_UNIX) or read_text(STOCK_UNIX)
    if not base or "pam_unix.so" not in base:
        raise ManualRequired("找不到 %s，無法以 pam-auth-update 管理，請人工處理" % STOCK_UNIX)
    # 最先登記、最後執行：檔案全部還原後，重新同步 pam-auth-update 的 debconf 狀態
    fx.add_undo(["pam-auth-update", "--package"], "重新同步 pam-auth-update 狀態")
    _pam_backup(fx)
    fx.write_file(GCB_UNIX, unix_profile(base, transform))
    _pam_auth_update(fx, ["pam-auth-update", "--enable", "gcb_unix"], desc)
    if not fx.dry:
        _verify_unix_stack()
    fx.note("已以 %s（複製自 Ubuntu 內建 unix profile，宣告與 unix 互斥）產生 common-* 設定；"
            "libpam-runtime 更新 unix profile 時不會同步到此檔，升級後請確認" % GCB_UNIX)


# ====================================================================
# AppArmor
# ====================================================================

# [GrubArgs] TWGCB-01-014-0156 開機載入程式啟用 AppArmor（多個 GRUB 參數）
class GrubArgs(Rule):
    category = "AppArmor"
    risk = "B"
    needs_reboot = True

    def __init__(self, title, args, ids):
        self.title = title
        self.args = args
        self.ids = ids
        self.expected = "GRUB_CMDLINE_LINUX 加入 %s（啟用）" % " ".join(args)
        self.subs = [GrubArg(title, a, ids) for a in args]

    def when(self, ctx):
        return None if os.path.exists("/etc/default/grub") else "未使用 GRUB 開機載入程式（找不到 /etc/default/grub），本項目是 GRUB 設定，不需設定"

    def check(self, ctx):
        res = [(s.arg, s.check(ctx)) for s in self.subs]
        if any(c.status == ERROR for a, c in res):
            st = ERROR
        else:
            st = PASS if all(c.status == PASS for a, c in res) else FAIL
        return Check(st, "；".join("%s：%s" % (a, c.current) for a, c in res))

    def fix(self, ctx, fx):
        fx.add_undo(["update-grub"], "重新產生 grub.cfg")
        for a in self.args:
            fx.edit_file("/etc/default/grub", lambda t, a=a: te.grub_cmdline_add(t, a))
        missing = [a for a in self.args if a not in grub_effective_cmdline().split()] if not fx.dry else []
        if missing:  # grub.d 覆寫了 GRUB_CMDLINE_LINUX：以排序最後的 drop-in 附加參數
            fx.write_file("/etc/default/grub.d/99-gcb-apparmor.cfg",
                          'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX %s"\n' % " ".join(missing))
        fx.run(["update-grub"], "更新 GRUB 設定", timeout=300)
        fx.note("已更新 GRUB 開機參數，重開機後生效")


# ====================================================================
# cron 設定
# ====================================================================

def cron_perm(title, ids, path, owner=False, max_mode=None):
    """cron 檔案／目錄的擁有者或權限（不存在時不適用）。"""
    return FilePerm(title, CRON, ids, path, owner="root" if owner else None,
                    groups=["root"] if owner else None, max_mode=max_mode)


# [CronAllow] TWGCB-01-014-0171 at.allow 與 cron.allow 檔案所有權、TWGCB-01-014-0172 檔案權限
class CronAllow(Rule):
    category = CRON
    risk = "B"
    NOTE = ("已移除 deny 檔並建立 allow 檔：未列在 allow 檔中的非 root 使用者將無法使用 crontab/at。"
            "另 Ubuntu 的 crontab 以 crontab 群組（setgid）讀取 cron.allow，at 以 daemon 身分讀取 at.allow，"
            "依 GCB 設為 root:root 600 後，即使列在 allow 檔中的一般使用者也可能被拒；"
            "若需開放一般使用者排程，請人工評估改為 root:crontab 640 / root:daemon 640")

    def __init__(self, title, ids, mode):
        self.title = title
        self.ids = ids
        self.mode = mode  # "owner" 或 "perm"
        self.expected = "root:root" if mode == "owner" else "600 或更低權限"
        self.expected += "（移除 cron.deny/at.deny，建立 cron.allow/at.allow）"

    PAIRS = (("/etc/cron.allow", "/etc/cron.deny"), ("/etc/at.allow", "/etc/at.deny"))

    def _pairs(self, ctx):
        """GCB 要求兩組檔案都設定（不論是否安裝 at）；cron 與 at 都未安裝時才不適用。"""
        if any(pkgsvc.pkg_installed(ctx.osi, p) for p in ("cron", "at")):
            return list(self.PAIRS)
        return []

    def when(self, ctx):
        return None if self._pairs(ctx) else "未安裝 cron 與 at，沒有排程設定需要限制"

    def _bad_attr(self, path):
        st = os.stat(path)
        if self.mode == "owner":
            return None if st.st_uid == 0 and st.st_gid == 0 else "uid=%d gid=%d" % (st.st_uid, st.st_gid)
        mode = st.st_mode & 0o7777
        return None if not mode & ~0o600 else "權限 %03o" % mode

    def check(self, ctx):
        bad, ok = [], []
        for allow, deny in self._pairs(ctx):
            if os.path.exists(deny):
                bad.append("%s 存在" % deny)
            if not os.path.exists(allow):
                bad.append("%s 不存在" % allow)
                continue
            why = self._bad_attr(allow)
            (bad if why else ok).append("%s %s" % (allow, why or "符合"))
        return Check(FAIL if bad else PASS, "；".join(bad + ok))

    def fix(self, ctx, fx):
        for allow, deny in self._pairs(ctx):
            if os.path.exists(deny):
                fx.backup_only(deny)
                fx.run(["rm", "-f", deny], "刪除 %s" % deny)
            if not os.path.exists(allow):
                fx.write_file(allow, "", mode=0o600)
            if not os.path.exists(allow):  # 預覽模式
                continue
            if self._bad_attr(allow):
                if self.mode == "owner":
                    fx.chown(allow, 0, 0, "root:root")
                else:
                    fx.chmod(allow, os.stat(allow).st_mode & 0o600)
        fx.note(self.NOTE)


# ====================================================================
# 帳號與存取控制：pwquality
# ====================================================================

PWQ = "/etc/security/pwquality.conf"
PWQ_D = "/etc/security/pwquality.conf.d/*.conf"


# [Pwquality] TWGCB-01-014-0174 ～ 0177 通行碼必須至少包含數字／大寫／小寫／特殊字元個數
class Pwquality(KvSetting):
    def __init__(self, title, ids, key):
        KvSetting.__init__(self, title, ACC, ids, PWQ, key, "-1", cmp="le", target=-1, sep="=",
                           dropins=PWQ_D, expected="%s=-1（1 個以上）" % key)

    def _pam_override(self):
        bad = []
        for args in pam_args(read_text(COMMON_PASSWORD) or "", "password", "pam_pwquality.so"):
            v = arg_value(args, self.key)
            if v is not None and not ((_int(v) or 0) <= -1):
                bad.append("%s=%s" % (self.key, v))
        return bad

    def check(self, ctx):
        c = KvSetting.check(self, ctx)
        extra = []
        if not pkgsvc.pkg_installed(ctx.osi, "libpam-pwquality"):
            extra.append("未安裝 libpam-pwquality（設定不會生效）")
        elif not pam_args(read_text(COMMON_PASSWORD) or "", "password", "pam_pwquality.so"):
            extra.append("common-password 未啟用 pam_pwquality（設定不會生效）")
        over = self._pam_override()
        if over:
            extra.append("PAM 參數覆寫：" + "、".join(over))
        if extra:
            return Check(FAIL, "；".join([c.current] + extra))
        return c

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "libpam-pwquality"):
            # 安裝時 pam-auth-update 會改寫 common-password，先備份
            fx.backup_only(COMMON_PASSWORD)
            for f in sorted(glob.glob("/var/lib/pam/*")):
                fx.backup_only(f)
            fx.pkg_install("libpam-pwquality", track=[COMMON_PASSWORD])
        KvSetting.fix(self, ctx, fx)
        if not fx.dry and not pam_args(read_text(COMMON_PASSWORD) or "", "password", "pam_pwquality.so"):
            fx.partial = True
            fx.note("common-password 未啟用 pam_pwquality，請人工執行 pam-auth-update --enable pwquality")
        if self._pam_override():
            fx.partial = True
            fx.note("common-password 的 pam_pwquality.so 參數會覆寫設定檔，請人工修改：" + "、".join(self._pam_override()))


# ====================================================================
# 帳號與存取控制：faillock
# ====================================================================

FAILLOCK_CONF = "/etc/security/faillock.conf"


def enable_ubuntu_faillock(fx):
    """與 common.Faillock 相同：以 pam-auth-update 啟用 pam_faillock（不改 deny 值）。"""
    _pam_backup(fx)
    for path, content in UBUNTU_FAILLOCK_PROFILES.items():
        fx.write_file(path, content)
    _pam_auth_update(fx, ["pam-auth-update", "--enable", "gcb_faillock", "gcb_faillock_notify"],
                     "以 pam-auth-update 啟用 pam_faillock")


# [FaillockTime] TWGCB-01-014-0179 帳戶鎖定時間
class FaillockTime(Rule):
    category = ACC
    risk = "B"
    title = "帳戶鎖定時間"
    expected = "fail_interval 設定 900 秒以下但須大於 0，unlock_time 設定 900 秒以上"

    def __init__(self, ids):
        self.ids = ids
        self._fl = Faillock(ids)

    @staticmethod
    def _ok(key, v):
        n = _int(v)
        if key == "fail_interval":
            return n is not None and 0 < n <= 900
        # unlock_time=0 / never 為永久鎖定：依 GCB 字面「900 秒以上」判定不符
        return n is not None and n >= 900

    def _pam_override(self):
        bad = []
        for f in ("/etc/pam.d/common-auth", "/etc/pam.d/common-account"):
            text = read_text(f) or ""
            for t in ("auth", "account"):
                for args in pam_args(text, t, "pam_faillock.so"):
                    for k in ("fail_interval", "unlock_time"):
                        v = arg_value(args, k)
                        if v is not None and not self._ok(k, v):
                            bad.append("%s %s=%s" % (os.path.basename(f), k, v))
        return bad

    def check(self, ctx):
        text = read_text(FAILLOCK_CONF) or ""
        cur, ok = [], True
        for k in ("fail_interval", "unlock_time"):
            v = te.get_kv(text, k)
            good = self._ok(k, v)
            ok = ok and good
            note = "（永久鎖定，依 GCB 字面「900 秒以上」不符）" if k == "unlock_time" and v in ("0", "never") else ""
            cur.append("%s=%s%s" % (k, v if v is not None else "未設定", note))
        active = self._fl._pam_active(ctx.osi)
        cur.append("pam_faillock:%s" % ("已啟用" if active else "未啟用"))
        over = self._pam_override()
        if over:
            cur.append("PAM 參數覆寫：" + "、".join(over))
        return Check(PASS if ok and active and not over else FAIL, "、".join(cur))

    def fix(self, ctx, fx):
        text = read_text(FAILLOCK_CONF) or ""
        if not self._ok("fail_interval", te.get_kv(text, "fail_interval")):
            fx.edit_file(FAILLOCK_CONF, lambda t: te.set_kv(t, "fail_interval", "900"))
        ut = te.get_kv(text, "unlock_time")
        if ut in ("0", "never"):
            fx.partial = True
            fx.note("unlock_time 目前為永久鎖定（需管理者解鎖），安全性高於 GCB 但不符字面「900 秒以上」；"
                    "為避免降低安全性未自動修改，請人工決定是否改為 unlock_time = 900")
        elif not self._ok("unlock_time", ut):
            fx.edit_file(FAILLOCK_CONF, lambda t: te.set_kv(t, "unlock_time", "900"))
        if not self._fl._pam_active(ctx.osi):
            enable_ubuntu_faillock(fx)
        if self._pam_override():
            fx.partial = True
            fx.note("PAM 設定中 pam_faillock.so 的參數會覆寫 faillock.conf，請人工修改：" + "、".join(self._pam_override()))


# ====================================================================
# 帳號與存取控制：通行碼歷程、雜湊演算法
# ====================================================================

def _unix_password_args():
    return pam_args(read_text(COMMON_PASSWORD) or "", "password", "pam_unix.so")


# [PassRemember] TWGCB-01-014-0180 強制執行通行碼歷程記錄
class PassRemember(Rule):
    category = ACC
    risk = "B"
    title = "強制執行通行碼歷程記錄"
    expected = "3 以上（common-password 的 pam_unix.so remember=3）"
    OPASSWD = "/etc/security/opasswd"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        lines = _unix_password_args()
        if not lines:
            return Check(FAIL, "common-password 未找到 pam_unix.so")
        vals = [arg_value(a, "remember") for a in lines]
        if all((_int(v) or 0) >= 3 for v in vals):
            return Check(PASS, "pam_unix.so remember=%s" % ",".join(vals))
        # 可接受的替代：pam_pwhistory（未指定 remember 時預設 10）
        hist = pam_args(read_text(COMMON_PASSWORD) or "", "password", "pam_pwhistory.so")
        if hist and all((_int(arg_value(a, "remember") or "10") or 0) >= 3 for a in hist):
            return Check(PASS, "pam_pwhistory.so remember=%s" % ",".join(arg_value(a, "remember") or "10（預設）"
                                                                         for a in hist))
        return Check(FAIL, "pam_unix.so remember=%s" % ",".join(v or "未設定" for v in vals))

    def fix(self, ctx, fx):
        apply_gcb_unix(fx, with_remember(3), "以 pam-auth-update 設定 pam_unix.so remember=3")
        if not os.path.exists(self.OPASSWD):
            fx.write_file(self.OPASSWD, "", mode=0o600)


# [HashAlgorithm] TWGCB-01-014-0181 系統通行碼雜湊演算法
class HashAlgorithm(Rule):
    category = ACC
    risk = "B"
    title = "系統通行碼雜湊演算法"
    expected = "yescrypt（common-password 的 pam_unix.so 與 login.defs ENCRYPT_METHOD）"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _pam_ok(lines):
        return bool(lines) and all("yescrypt" in a and not [x for x in a if x in HASH_ARGS and x != "yescrypt"]
                                   for a in lines)

    def check(self, ctx):
        lines = _unix_password_args()
        algs = [" ".join(x for x in a if x in HASH_ARGS) or "未指定" for a in lines]
        em = te.get_kv(read_text("/etc/login.defs") or "", "ENCRYPT_METHOD")
        ok = self._pam_ok(lines) and (em or "").lower() == "yescrypt"
        return Check(PASS if ok else FAIL, "pam_unix.so：%s；ENCRYPT_METHOD=%s" % (
            ",".join(algs) or "未找到", em or "未設定"))

    def fix(self, ctx, fx):
        if not self._pam_ok(_unix_password_args()):
            apply_gcb_unix(fx, with_yescrypt, "以 pam-auth-update 設定 pam_unix.so yescrypt")
        fx.edit_file("/etc/login.defs", lambda t: te.set_kv(t, "ENCRYPT_METHOD", "yescrypt", sep=" "))
        fx.note("Ubuntu 22.04 的 shadow 工具（4.8.1）不支援 ENCRYPT_METHOD yescrypt：使用者通行碼經 PAM 已是 yescrypt 不受影響，"
                "但不經 PAM 的 gpasswd/chgpasswd（群組通行碼）會顯示 Invalid ENCRYPT_METHOD 並改用 DES")


HASH_IDS = {"y": "yescrypt", "gy": "gost_yescrypt", "1": "md5", "2a": "blowfish", "2b": "blowfish",
            "2y": "blowfish", "5": "sha256", "6": "sha512", "7": "scrypt"}


# [UserHashAlgorithm] TWGCB-01-014-0182 使用者通行碼雜湊演算法（C 類）
class UserHashAlgorithm(Rule):
    category = ACC
    risk = "C"
    title = "使用者通行碼雜湊演算法"
    expected = "使用者所採用之通行碼雜湊演算法與系統採用之通行碼雜湊演算法一致"
    manual_hint = ("請先完成 0181（ENCRYPT_METHOD yescrypt），再通知不一致的帳號以 passwd 重設通行碼；"
                   "需由帳號持有人設定新通行碼，無法自動修復")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text("/etc/shadow")
        if text is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        em = (te.get_kv(read_text("/etc/login.defs") or "", "ENCRYPT_METHOD") or "DES").lower()
        bad = []
        for u in te.parse_shadow(text):
            if not u["pw"].startswith("$"):
                continue  # 與 GCB 腳本相同，只比對未鎖定的雜湊
            hid = u["pw"].split("$")[1]
            alg = HASH_IDS.get(hid, "未知($%s$)" % hid)
            if alg != em:
                bad.append("%s(%s)" % (u["name"], alg))
        if bad:
            return Check(FAIL, "ENCRYPT_METHOD=%s；不一致帳號：%s" % (em, ", ".join(bad)))
        return Check(PASS, "ENCRYPT_METHOD=%s，所有帳號一致" % em)


# ====================================================================
# 帳號與存取控制：通行碼期限（login.defs / useradd + 既有帳號 chage）
# ====================================================================

def read_shadow():
    """回傳 [dict(name, pw, lastchg, min, max, warn, inact)]（欄位為字串）。"""
    out = []
    for line in (read_text("/etc/shadow") or "").splitlines():
        f = line.split(":")
        if len(f) < 7:
            continue
        out.append({"name": f[0], "pw": f[1], "lastchg": f[2], "min": f[3], "max": f[4],
                    "warn": f[5], "inact": f[6]})
    return out


def would_disable_now(u, inactive):
    """套用 inactive 天數後，帳號是否會立即停用（通行碼已過期超過該天數）。"""
    last, mx = _int(u["lastchg"]), _int(u["max"])
    if not last or mx is None or mx < 0:
        return False
    return _today() >= last + mx + inactive


# [ShadowAging] TWGCB-01-014-0183 通行碼最短使用期限、0185 到期前提醒、0186 帳號停用前之天數
class ShadowAging(Rule):
    category = ACC

    def __init__(self, title, ids, path, key, sep, value, ok, field, opt, expected, risk="A", guard=False):
        self.title = title
        self.ids = ids
        self.path = path
        self.key = key
        self.sep = sep
        self.value = value
        self.ok = ok
        self.field = field
        self.opt = opt
        self.expected = expected
        self.risk = risk
        self.guard = guard  # True：略過套用後會立即停用的帳號

    def _bad_users(self):
        return [u for u in read_shadow() if te.has_usable_password(u["pw"]) and not self.ok(_int(u[self.field]))]

    def check(self, ctx):
        if read_text("/etc/shadow") is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        v = te.get_kv(read_text(self.path) or "", self.key)
        good = self.ok(_int(v))
        bad = self._bad_users()
        cur = "%s=%s" % (self.key, v if v is not None else "未設定")
        if bad:
            cur += "；不符合之帳號：" + ", ".join("%s(%s)" % (u["name"], u[self.field] or "未設定") for u in bad[:20])
            if len(bad) > 20:
                cur += "…共 %d 個" % len(bad)
        return Check(PASS if good and not bad else FAIL, cur)

    def fix(self, ctx, fx):
        fx.edit_file(self.path, lambda t: te.set_kv(t, self.key, str(self.value), sep=self.sep))
        for u in self._bad_users():
            if self.guard and would_disable_now(u, self.value):
                fx.partial = True
                fx.note("帳號 %s 通行碼已過期超過 %d 天，套用後會立即停用而無法登入，已略過；請人工處理"
                        % (u["name"], self.value))
                continue
            old = u[self.field] or "-1"
            fx.add_undo(["chage", self.opt, old, u["name"]], "還原帳號 %s 的 %s（原值 %s）" % (u["name"], self.opt, old))
            fx.run(["chage", self.opt, str(self.value), u["name"]],
                   "設定帳號 %s %s %s（原值 %s）" % (u["name"], self.opt, self.value, u[self.field] or "未設定"))


# ====================================================================
# 帳號與存取控制：sudo、通行碼變更日期、系統帳號（C 類）
# ====================================================================

# [SudoAuth] TWGCB-01-014-0187 要求使用者必須經過身分鑑別才能提升權限（C 類）
class SudoAuth(Rule):
    category = ACC
    risk = "C"
    title = "要求使用者必須經過身分鑑別才能提升權限"
    expected = "要求身分鑑別（sudoers 不得有 NOPASSWD 或 !authenticate）"
    manual_hint = ("請確認列出的 sudoers 設定用途（雲端映像檔預設帳號、自動化帳號常使用 NOPASSWD），"
                   "確認該帳號有通行碼後，以 visudo -f <檔案> 將該行註解")

    def __init__(self, ids):
        self.ids = ids

    def when(self, ctx):
        return None if os.path.exists("/etc/sudoers") else "未安裝 sudo，沒有 sudo 設定需要檢查"

    def check(self, ctx):
        hits = []
        for f in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
            if not os.path.isfile(f):
                continue
            text = read_text(f)
            if text is None:
                return Check(ERROR, "無法讀取 %s" % f)
            ignored = f != "/etc/sudoers" and ("." in os.path.basename(f) or f.endswith("~"))
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if s.startswith("#") or not re.search(r"nopasswd|!\s*authenticate", s, re.I):
                    continue
                hits.append("%s:%d%s" % (f, i, "（sudo 不讀取此檔）" if ignored else ""))
        if hits:
            return Check(FAIL, "發現 NOPASSWD/!authenticate：" + "、".join(hits[:10]))
        return Check(PASS, "未發現 NOPASSWD 或 !authenticate")


# [PassLastChange] TWGCB-01-014-0188 通行碼最後變更日期（C 類）
class PassLastChange(Rule):
    category = ACC
    risk = "C"
    title = "通行碼最後變更日期"
    expected = "通行碼最後變更日期皆為過去之日期"
    manual_hint = "請確認系統時間正確後，通知列出的帳號以 passwd 重設通行碼（或由管理者以 chage -d 修正日期）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if read_text("/etc/shadow") is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        today = _today()
        bad = [u for u in read_shadow() if te.has_usable_password(u["pw"]) and (_int(u["lastchg"]) or 0) > today]
        if bad:
            return Check(FAIL, "最後變更日期在未來的帳號：" + ", ".join(u["name"] for u in bad))
        return Check(PASS, "所有帳號之最後變更日期皆為過去日期")


NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")


# [SystemAccounts] TWGCB-01-014-0189 系統帳號登入方式（C 類）
class SystemAccounts(Rule):
    category = ACC
    risk = "C"
    title = "系統帳號登入方式"
    expected = "nologin（系統帳號不可使用殼層登入且已鎖定）"
    manual_hint = ("請確認列出的系統帳號用途後，執行 usermod -s /usr/sbin/nologin <帳號> 與 usermod -L <帳號>；"
                   "部分服務帳號（如資料庫）可能需要 shell 供維運使用")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        shadow = read_text("/etc/shadow")
        if shadow is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        uid_min = _int(te.get_kv(read_text("/etc/login.defs") or "", "UID_MIN")) or 1000
        pwmap = {u["name"]: u["pw"] for u in te.parse_shadow(shadow)}
        shell_bad, lock_bad = [], []
        for line in (read_text("/etc/passwd") or "").splitlines():
            f = line.split(":")
            if len(f) < 7 or f[0].startswith("+") or f[0] == "root" or (_int(f[2]) is None) or _int(f[2]) >= uid_min:
                continue
            if f[0] not in ("sync", "shutdown", "halt") and f[6] not in NOLOGIN:
                shell_bad.append("%s(%s)" % (f[0], f[6]))
            if not pwmap.get(f[0], "!").startswith(("!", "*")):
                lock_bad.append(f[0])
        cur = []
        if shell_bad:
            cur.append("可登入殼層：" + ", ".join(shell_bad))
        if lock_bad:
            cur.append("未鎖定：" + ", ".join(lock_bad))
        return Check(FAIL if cur else PASS, "；".join(cur) or "系統帳號皆為 nologin 且已鎖定")


# ====================================================================
# 帳號與存取控制：TMOUT、root 群組、umask、su
# ====================================================================

TMOUT_FILE = PROFILE_D + "/99-gcb-tmout.sh"
TMOUT_SCRIPT = ("# GCB TWGCB-01-014-0190 Bash shell 閒置時登出時間（gcb-checker 產生）\n"
                "# 已設為唯讀時不重複設定，避免 readonly variable 錯誤\n"
                "case \"$(readonly -p 2>/dev/null)\" in\n"
                "  *\" TMOUT=\"*) ;;\n"
                "  *) readonly TMOUT=900 ; export TMOUT ;;\n"
                "esac\n")


def tmout_scan(texts):
    """texts：[(file, text)]。回傳 (values=[(file, n)], readonly, export)。"""
    vals, ro, ex = [], False, False
    for f, text in texts:
        for line in (text or "").splitlines():
            code = _code(line)
            for m in re.finditer(r"\bTMOUT=['\"]?(\d+)", code):
                vals.append((f, int(m.group(1))))
            if re.search(r"\breadonly\b[^;&|]*\bTMOUT\b|\b(declare|typeset)\s+-\w*r\w*\s[^;&|]*\bTMOUT\b", code):
                ro = True
            if re.search(r"\bexport\b[^;&|]*\bTMOUT\b|\b(declare|typeset)\s+-\w*x\w*\s[^;&|]*\bTMOUT\b", code):
                ex = True
    return vals, ro, ex


# [Tmout] TWGCB-01-014-0190 Bash shell 閒置時登出時間
class Tmout(Rule):
    category = ACC
    title = "Bash shell 閒置時登出時間"
    expected = "900 秒以下，但須大於 0（readonly TMOUT=900 ; export TMOUT）"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _texts():
        return [(f, read_text(f)) for f in _shell_files()]

    def check(self, ctx):
        vals, ro, ex = tmout_scan(self._texts())
        if not vals:
            return Check(FAIL, "未設定 TMOUT")
        bad = [(f, n) for f, n in vals if not 0 < n <= 900]
        cur = "、".join("TMOUT=%d（%s）" % (n, f) for f, n in vals)
        cur += "；readonly:%s、export:%s" % ("有" if ro else "無", "有" if ex else "無")
        return Check(PASS if not bad and ro and ex else FAIL, cur)

    def fix(self, ctx, fx):
        for f, text in self._texts():
            if f == TMOUT_FILE or not text:
                continue
            vals, _, _ = tmout_scan([(f, text)])
            if any(not 0 < n <= 900 for _, n in vals):
                fx.edit_file(f, lambda t: re.sub(r"\bTMOUT=(['\"]?)\d+\1", "TMOUT=900", t))
        fx.write_file(TMOUT_FILE, TMOUT_SCRIPT)


# [RootGid] TWGCB-01-014-0191 root 帳號所屬群組
class RootGid(Rule):
    category = ACC
    title = "root 帳號所屬群組"
    expected = "GID 0"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _gid():
        for line in (read_text("/etc/passwd") or "").splitlines():
            f = line.split(":")
            if len(f) > 3 and f[0] == "root":
                return f[3]
        return None

    def check(self, ctx):
        g = self._gid()
        if g is None:
            return Check(ERROR, "/etc/passwd 找不到 root")
        return Check(PASS if g == "0" else FAIL, "GID %s" % g)

    def fix(self, ctx, fx):
        old = self._gid()
        fx.add_undo(["usermod", "-g", old, "root"], "還原 root 主要群組 GID %s" % old)
        fx.run(["usermod", "-g", "0", "root"], "設定 root 主要群組為 GID 0（原 %s）" % old)


UMASK_FILE = PROFILE_D + "/99-gcb-umask.sh"
_UMASK_RX = re.compile(r"(^|[;&|({\s])umask\s+(-S\s+)?([0-7]{1,4}|[ugoa=rwx,]+)(?=\s|;|$)")


def umask_value(arg):
    """umask 參數轉為八進位遮罩；無法判讀回傳 None。支援 027、0027、u=rwx,g=rx,o=。"""
    if re.match(r"^[0-7]{1,4}$", arg):
        return int(arg, 8)
    perm = {"u": 0, "g": 0, "o": 0}
    for part in arg.split(","):
        m = re.match(r"^([ugo]+)=([rwx]*)$", part)
        if not m:
            return None
        bits = sum({"r": 4, "w": 2, "x": 1}[c] for c in set(m.group(2)))
        for who in m.group(1):
            perm[who] = bits
    return 0o777 & ~(perm["u"] << 6 | perm["g"] << 3 | perm["o"])


def umask_scan(texts):
    """回傳 [(file, 原字串, 遮罩或 None)]。"""
    out = []
    for f, text in texts:
        for line in (text or "").splitlines():
            for m in _UMASK_RX.finditer(_code(line)):
                out.append((f, m.group(3), umask_value(m.group(3))))
    return out


def umask_ok(v):
    return v is not None and v & 0o027 == 0o027


# [Umask] TWGCB-01-014-0192 所有使用者帳號之預設 umask
class Umask(Rule):
    category = ACC
    title = "所有使用者帳號之預設 umask"
    expected = "027 或更低權限（/etc/profile、/etc/profile.d/*.sh、/etc/bash.bashrc 設定 umask 027）"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _texts():
        return [(f, read_text(f)) for f in _shell_files()]

    def check(self, ctx):
        found = umask_scan(self._texts())
        defs = te.get_kv(read_text("/etc/login.defs") or "", "UMASK") or "未設定"
        info = "；login.defs UMASK=%s（pam_umask，僅供參考）" % defs
        if not found:
            return Check(FAIL, "shell 設定檔未設定 umask" + info)
        bad = [x for x in found if not umask_ok(x[2])]
        cur = "、".join("umask %s（%s）" % (a, f) for f, a, v in found)
        # GCB 要求 /etc/bash.bashrc 也設定：非登入的互動式 shell 只讀 bash.bashrc，不讀 profile.d
        if not any(f == BASHRC for f, _, _ in found):
            bad.append(BASHRC)
            cur += "；%s 未設定 umask（非登入的互動式 shell 不會套用）" % BASHRC
        return Check(FAIL if bad else PASS, cur + info)

    def fix(self, ctx, fx):
        for f, text in self._texts():
            if f == UMASK_FILE or not text:
                continue
            if any(not umask_ok(v) for _, _, v in umask_scan([(f, text)])):
                fx.edit_file(f, lambda t: "\n".join(_fix_umask_line(l) for l in t.split("\n")))
        fx.write_file(UMASK_FILE, "# GCB TWGCB-01-014-0192 預設 umask（gcb-checker 產生）\numask 027\n")
        bashrc = read_text(BASHRC)
        if bashrc is not None and not umask_scan([(BASHRC, bashrc)]):
            fx.edit_file(BASHRC, lambda t: t + ("" if t.endswith("\n") or not t else "\n")
                         + "# GCB TWGCB-01-014-0192 預設 umask（gcb-checker 加入）\numask 027\n")
        defs = te.get_kv(read_text("/etc/login.defs") or "", "UMASK")
        if not umask_ok(umask_value(defs or "022")):
            fx.note("login.defs UMASK=%s 未修改：它由 pam_umask 套用到所有 PAM 工作階段（含 cron 排程、sftp），"
                    "改為 027 可能影響服務產生的檔案權限；若需要請人工評估" % (defs or "未設定"))


def _fix_umask_line(line):
    code = _code(line)
    for m in _UMASK_RX.finditer(code):
        if not umask_ok(umask_value(m.group(3))):
            line = line[:m.start(3)] + "027" + line[m.end(3):]
            break
    return line


SU_PAM = "/etc/pam.d/su"
SU_LINE = "auth       required   pam_wheel.so use_uid group=sugroup"
_WHEEL_RX = re.compile(r"^\s*auth\s+(required|requisite)\s+pam_wheel\.so\b(.*)$")


def su_wheel_status(text):
    """回傳 (是否已正確設定, 說明)。"""
    lines = [l for l in (text or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    rootok = next((i for i, l in enumerate(lines) if "pam_rootok.so" in l), -1)
    other = next((i for i, l in enumerate(lines)
                  if i > rootok and (re.match(r"^\s*@include\s+common-auth", l) or
                                     (re.match(r"^\s*auth\s", l) and "pam_wheel.so" not in l))), len(lines))
    for i, l in enumerate(lines):
        m = _WHEEL_RX.match(l)
        if m:
            args = m.group(2).split()
            if "use_uid" in args and "group=sugroup" in args and "deny" not in args and rootok < i < other:
                return True, "已設定：%s" % l.strip()
    return False, "未設定 auth required pam_wheel.so use_uid group=sugroup"


def su_wheel_apply(text):
    """註解既有的 pam_wheel 限制行，並在 pam_rootok.so 之後插入 GCB 設定行。"""
    out = []
    for l in (text or "").splitlines():
        m = _WHEEL_RX.match(l)
        if m and "deny" not in m.group(2).split() and "trust" not in m.group(2).split():
            out.append(te.MARK + l)
        else:
            out.append(l)
    idx = next((i + 1 for i, l in enumerate(out) if not l.strip().startswith("#") and "pam_rootok.so" in l), None)
    if idx is None:
        idx = next((i for i, l in enumerate(out) if not l.strip().startswith("#") and
                    re.match(r"^\s*(auth\s|@include\s+common-auth)", l)), len(out))
    out.insert(idx, SU_LINE)
    return "\n".join(out) + "\n"


def sugroup_admins():
    """回傳 sugroup 中屬於管理者（sudo/admin 群組）的非 root 帳號；群組不存在回傳 None。"""
    try:
        g = grp.getgrnam("sugroup")
    except KeyError:
        return None
    members = set(g.gr_mem) | set(p.pw_name for p in pwd.getpwall() if p.pw_gid == g.gr_gid)
    admins = set()
    for name in ("sudo", "admin"):
        try:
            ag = grp.getgrnam(name)
        except KeyError:
            continue
        admins |= set(ag.gr_mem) | set(p.pw_name for p in pwd.getpwall() if p.pw_gid == ag.gr_gid)
    return sorted((members & admins) - {"root"})


# [SuGroup] TWGCB-01-014-0193 可使用 su 指令之群組
class SuGroup(Rule):
    category = ACC
    risk = "B"
    title = "可使用 su 指令之群組"
    expected = "僅限 sugroup 群組才能使用 su 指令（auth required pam_wheel.so use_uid group=sugroup）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text(SU_PAM)
        if text is None:
            return Check(ERROR, "找不到 %s" % SU_PAM)
        ok, why = su_wheel_status(text)
        adm = sugroup_admins()
        gdesc = "sugroup 不存在" if adm is None else "sugroup 管理帳號：%s" % (", ".join(adm) or "無")
        return Check(PASS if ok and adm is not None else FAIL, "%s；%s" % (why, gdesc))

    def precondition(self, ctx):
        if not sugroup_admins():
            return ("sugroup 群組不存在或沒有非 root 的管理帳號（sudo 群組成員），啟用後可能無人能使用 su；"
                    "請先執行 groupadd sugroup 與 usermod -aG sugroup <管理帳號> 後再修復")
        return None

    def fix(self, ctx, fx):
        # /etc/pam.d/su 不由 pam-auth-update 管理，備份後直接修改
        fx.edit_file(SU_PAM, su_wheel_apply)
        fx.note("僅 sugroup 成員（%s）可使用 su；root 與 sudo 執行的 su 不受影響" % ", ".join(sugroup_admins() or []))


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

RULES = [
    # 0155 AppArmor 套件
    PackagePresent("AppArmor 套件", "apparmor", U(155), "AppArmor"),
    # 0156 開機載入程式啟用 AppArmor
    GrubArgs("開機載入程式啟用 AppArmor", ["apparmor=1", "security=apparmor"], U(156)),
    # 0157 AppArmor 啟用狀態 → common.py
    # 0158 cron 守護程序
    ServiceEnabled("cron 守護程序", CRON, "cron", {"debian": "cron"}, U(158)),
    # 0159 /etc/crontab 檔案所有權
    cron_perm("/etc/crontab 檔案所有權", U(159), "/etc/crontab", owner=True),
    # 0160 /etc/crontab 檔案權限
    cron_perm("/etc/crontab 檔案權限", U(160), "/etc/crontab", max_mode=0o600),
    # 0161 /etc/cron.hourly 目錄所有權
    cron_perm("/etc/cron.hourly 目錄所有權", U(161), "/etc/cron.hourly", owner=True),
    # 0162 /etc/cron.hourly 目錄權限
    cron_perm("/etc/cron.hourly 目錄權限", U(162), "/etc/cron.hourly", max_mode=0o700),
    # 0163 /etc/cron.daily 目錄所有權
    cron_perm("/etc/cron.daily 目錄所有權", U(163), "/etc/cron.daily", owner=True),
    # 0164 /etc/cron.daily 目錄權限
    cron_perm("/etc/cron.daily 目錄權限", U(164), "/etc/cron.daily", max_mode=0o700),
    # 0165 /etc/cron.weekly 目錄所有權
    cron_perm("/etc/cron.weekly 目錄所有權", U(165), "/etc/cron.weekly", owner=True),
    # 0166 /etc/cron.weekly 目錄權限
    cron_perm("/etc/cron.weekly 目錄權限", U(166), "/etc/cron.weekly", max_mode=0o700),
    # 0167 /etc/cron.monthly 目錄所有權
    cron_perm("/etc/cron.monthly 目錄所有權", U(167), "/etc/cron.monthly", owner=True),
    # 0168 /etc/cron.monthly 目錄權限
    cron_perm("/etc/cron.monthly 目錄權限", U(168), "/etc/cron.monthly", max_mode=0o700),
    # 0169 /etc/cron.d 目錄所有權
    cron_perm("/etc/cron.d 目錄所有權", U(169), "/etc/cron.d", owner=True),
    # 0170 /etc/cron.d 目錄權限
    cron_perm("/etc/cron.d 目錄權限", U(170), "/etc/cron.d", max_mode=0o700),
    # 0171 at.allow 與 cron.allow 檔案所有權
    CronAllow("at.allow 與 cron.allow 檔案所有權", U(171), "owner"),
    # 0172 at.allow 與 cron.allow 檔案權限
    CronAllow("at.allow 與 cron.allow 檔案權限", U(172), "perm"),
    # 0173 通行碼最小長度 → common.py
    # 0174 通行碼必須至少包含數字個數
    Pwquality("通行碼必須至少包含數字個數", U(174), "dcredit"),
    # 0175 通行碼必須至少包含大寫字母個數
    Pwquality("通行碼必須至少包含大寫字母個數", U(175), "ucredit"),
    # 0176 通行碼必須至少包含小寫字母個數
    Pwquality("通行碼必須至少包含小寫字母個數", U(176), "lcredit"),
    # 0177 通行碼必須至少包含特殊字元個數
    Pwquality("通行碼必須至少包含特殊字元個數", U(177), "ocredit"),
    # 0178 帳戶鎖定閾值 → common.py
    # 0179 帳戶鎖定時間
    FaillockTime(U(179)),
    # 0180 強制執行通行碼歷程記錄
    PassRemember(U(180)),
    # 0181 系統通行碼雜湊演算法
    HashAlgorithm(U(181)),
    # 0182 使用者通行碼雜湊演算法
    UserHashAlgorithm(U(182)),
    # 0183 通行碼最短使用期限
    ShadowAging("通行碼最短使用期限", U(183), "/etc/login.defs", "PASS_MIN_DAYS", "\t", 1,
                lambda n: n is not None and n >= 1, "min", "--mindays", "1 天以上（login.defs 與既有帳號）"),
    # 0184 通行碼最長使用期限 → common.py
    # 0185 通行碼到期前提醒使用者變更通行碼
    ShadowAging("通行碼到期前提醒使用者變更通行碼", U(185), "/etc/login.defs", "PASS_WARN_AGE", "\t", 14,
                lambda n: n is not None and n >= 14, "warn", "--warndays", "14 天以上（login.defs 與既有帳號）"),
    # 0186 通行碼到期後，帳號停用前之天數
    ShadowAging("通行碼到期後，帳號停用前之天數", U(186), "/etc/default/useradd", "INACTIVE", "=", 30,
                lambda n: n is not None and 0 < n <= 30, "inact", "--inactive",
                "30 天以下，但須大於 0（useradd 預設值與既有帳號）", risk="B", guard=True),
    # 0187 要求使用者必須經過身分鑑別才能提升權限
    SudoAuth(U(187)),
    # 0188 通行碼最後變更日期
    PassLastChange(U(188)),
    # 0189 系統帳號登入方式
    SystemAccounts(U(189)),
    # 0190 Bash shell 閒置時登出時間
    Tmout(U(190)),
    # 0191 root 帳號所屬群組
    RootGid(U(191)),
    # 0192 所有使用者帳號之預設 umask
    Umask(U(192)),
    # 0193 可使用 su 指令之群組
    SuGroup(U(193)),
]
