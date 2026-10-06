# -*- coding: utf-8 -*-
"""RHEL 8 / 9 帳號與存取控制（RHEL 8 0208–0243；RHEL 9 0206–0241、0309–0314）。

PAM 一律透過 authselect（enable-feature）修改，不直接改 /etc/pam.d/system-auth、password-auth；
/etc/pam.d/su、/etc/security/*.conf、login.defs、shell 設定檔則備份後直接修改。
"""
import glob
import grp
import os
import pwd
import re
import time

from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, PASS, Check, Rule
from ..common import Faillock
from ..generic import PackagePresent, login_defs
from .helpers import R

ACC = "帳號與存取控制"

SYSTEM_AUTH = "/etc/pam.d/system-auth"
PASSWORD_AUTH = "/etc/pam.d/password-auth"
PAM_FILES = [SYSTEM_AUTH, PASSWORD_AUTH]
POSTLOGIN = "/etc/pam.d/postlogin"
SU_PAM = "/etc/pam.d/su"

PWQ = "/etc/security/pwquality.conf"
PWQ_D = "/etc/security/pwquality.conf.d/*.conf"
FAILLOCK_CONF = "/etc/security/faillock.conf"
PWHISTORY_CONF = "/etc/security/pwhistory.conf"
LOGIN_DEFS = "/etc/login.defs"
USERADD_DEFAULTS = "/etc/default/useradd"
LIBUSER_CONF = "/etc/libuser.conf"

PROFILE = "/etc/profile"
BASHRC = "/etc/bashrc"
PROFILE_D = "/etc/profile.d"


# ====================================================================
# 共用小工具
# ====================================================================

def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _today():
    return int(time.time() // 86400)


def _is_rhel8_before(osi, ver):
    """RHEL 8 且小版本早於 ver（例：(8, 4)）。"""
    return osi.key == "rhel8" and osi.version_tuple() < ver


def _code(line):
    """去除 shell 註解（# 前需為行首或空白）。"""
    return re.split(r"(?:^|\s)#", line, maxsplit=1)[0]


def _active(line):
    s = line.strip()
    return bool(s) and not s.startswith("#")


# ---- name = value 設定檔（pwquality.conf、faillock.conf、pwhistory.conf；鍵名不分大小寫） ----

def _ci_rx(key):
    return re.compile(r"^\s*" + re.escape(key) + r"\s*=\s*(.*?)\s*$", re.I)


def conf_get(text, key):
    """取最後一個有效值（鍵名不分大小寫）；未設定回傳 None。"""
    rx, val = _ci_rx(key), None
    for line in (text or "").splitlines():
        if _active(line):
            m = rx.match(line.split("#", 1)[0])
            if m:
                val = m.group(1).strip()
    return val


def conf_set(text, key, value, sep=" = "):
    """以小寫鍵名寫入：取代第一個有效行，其餘重複行註解；沒有則附加在檔尾。"""
    rx, out, done = _ci_rx(key), [], False
    for line in (text or "").splitlines():
        if _active(line) and rx.match(line.split("#", 1)[0]):
            out.append(te.MARK + line if done else key + sep + value)
            done = True
        else:
            out.append(line)
    if not done:
        out.append(key + sep + value)
    return "\n".join(out) + "\n"


def conf_comment(text, key):
    rx = _ci_rx(key)
    out = [te.MARK + l if _active(l) and rx.match(l.split("#", 1)[0]) else l for l in (text or "").splitlines()]
    return "\n".join(out) + "\n" if out else ""


def flag_present(text, flag):
    """無值旗標（例：enforce_for_root、even_deny_root）是否單獨成行啟用。"""
    return any(_active(l) and l.split("#", 1)[0].strip().lower() == flag for l in (text or "").splitlines())


def flag_set(text, flag):
    if flag_present(text, flag):
        return text
    lines = (text or "").splitlines() + [flag]
    return "\n".join(lines) + "\n"


# ---- PAM ----

def pam_args(text, ptype, module):
    """回傳 ptype 類型、使用 module 的有效行參數清單 [[arg, ...], ...]。"""
    out = []
    rx = re.compile(r"(?:^|[\s/])" + re.escape(module) + r"(?:\s|$)")
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.split()[0].lstrip("-") != ptype:
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


def pam_text(path):
    return read_text(path) or ""


# ---- authselect ----

def authselect_current():
    """回傳 (profile, [features])；未使用 authselect 回傳 None。"""
    if not which("authselect"):
        return None
    r = run(["authselect", "current", "--raw"], timeout=30)
    if r.ok and r.out.split():
        parts = r.out.split()
        return parts[0], parts[1:]
    r = run(["authselect", "current"], timeout=30)
    if not r.ok:
        return None
    prof, feats = None, []
    for line in r.out.splitlines():
        if line.startswith("Profile ID:"):
            prof = line.split(":", 1)[1].strip()
        elif line.strip().startswith("- "):
            feats.append(line.strip()[2:].strip())
    return (prof, feats) if prof else None


def authselect_features(profile):
    r = run(["authselect", "list-features", profile], timeout=30)
    return r.out.split() if r.ok else []


def authselect_enable(fx, feature):
    """以 authselect enable-feature 啟用功能：先確認 authselect check 通過、備份 /etc/authselect/ 與 /var/lib/authselect/，
    登記回滾（disable-feature 後還原備份），啟用後再以 authselect check 驗證。"""
    cur = authselect_current()
    if cur is None:
        raise ManualRequired("系統未使用 authselect 管理 PAM，請人工於 /etc/pam.d/system-auth、password-auth 設定 %s"
                             % feature)
    if feature in cur[1]:
        return
    if feature not in authselect_features(cur[0]):
        raise ManualRequired("目前 authselect profile（%s）沒有 %s 功能，需依 GCB 文件建立自訂 profile，請人工處理"
                             % (cur[0], feature))
    chk = run(["authselect", "check"], timeout=30)
    if not chk.ok:
        raise ManualRequired("authselect check 未通過（PAM 設定曾被手動修改），為避免覆寫不使用 --force，"
                             "請人工確認後再啟用 %s：%s" % (feature, chk.text()[-200:]))
    # 回滾順序（反向）：先 disable-feature，再以備份還原原始檔案。
    # /var/lib/authselect/ 存有 authselect check 比對用的副本（含產生時間），需一併備份，否則還原後 check 不通過
    for f in sorted(glob.glob("/etc/authselect/*") + glob.glob("/var/lib/authselect/*")):
        if os.path.isfile(f):
            fx.backup_only(f)
    fx.add_undo(["authselect", "disable-feature", feature], "停用 authselect %s" % feature)
    fx.run_tracked(["authselect", "enable-feature", feature], "啟用 authselect %s" % feature,
                   PAM_FILES + [POSTLOGIN])
    r = fx.run(["authselect", "check"], "確認 authselect check 通過", check=False)
    if r is not None and not r.ok:
        raise FixError("啟用 %s 後 authselect check 未通過，已還原：%s" % (feature, r.text()[-200:]))


_FAILLOCK = Faillock({})


def faillock_active(osi):
    """與 common.Faillock 相同：system-auth、password-auth 都有 pam_faillock 行。"""
    return _FAILLOCK._pam_active(osi)


# ---- INI（libuser.conf、dconf keyfile、gdm custom.conf） ----

_SECT_RX = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def ini_get(text, section, key, icase=False):
    sect, val = None, None
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        m = _SECT_RX.match(s)
        if m:
            sect = m.group(1).strip()
            continue
        if sect == section and "=" in s:
            k, v = s.split("=", 1)
            if k.strip() == key or (icase and k.strip().lower() == key.lower()):
                val = v.strip()
    return val


def ini_set(text, section, key, value, sep="=", icase=False):
    """在段落內設定 key：取代第一個有效行並註解其餘重複行；沒有則加在段落末端；段落不存在則新增。"""
    lines = (text or "").splitlines()
    out, sect, done, sect_seen, last_in_sect = [], None, False, False, None
    for line in lines:
        s = line.strip()
        m = _SECT_RX.match(s) if s else None
        if m:
            sect = m.group(1).strip()
            out.append(line)
            if sect == section:
                sect_seen = True
                last_in_sect = len(out)
            continue
        if sect == section and s and s[0] not in "#;" and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k == key or (icase and k.lower() == key.lower()):
                out.append(te.MARK + line if done else key + sep + value)
                done = True
                last_in_sect = len(out)
                continue
        out.append(line)
        if sect == section and s:
            last_in_sect = len(out)
    if not done:
        if sect_seen:
            out.insert(last_in_sect, key + sep + value)
        else:
            if out and out[-1].strip():
                out.append("")
            out += ["[%s]" % section, key + sep + value]
    return "\n".join(out) + "\n"


# ====================================================================
# pwquality（0208、0211–0219 / 0206、0209–0217、0311）
# ====================================================================

def pwq_files():
    return [PWQ] + sorted(glob.glob(PWQ_D))


def pwq_values(key):
    """[(file, value)]：主檔與 conf.d 中 key 的有效值（每檔取最後一個）。"""
    out = []
    for f in pwq_files():
        v = conf_get(read_text(f) or "", key)
        if v is not None:
            out.append((f, v))
    return out


def ge(n):
    return lambda v: _int(v) is not None and _int(v) >= n


def le(n):
    return lambda v: _int(v) is not None and _int(v) <= n


def rng(lo, hi):
    return lambda v: _int(v) is not None and lo <= _int(v) <= hi


def eq(n):
    return lambda v: _int(v) == n


PWQ_MISSING = "未啟用 pam_pwquality（設定不會生效）"


# [Pwquality] RHEL8 0208、0211–0219 / RHEL9 0206、0209–0217、0311 pwquality 通行碼原則參數
class Pwquality(Rule):
    """pwquality.conf（含 conf.d）參數；PAM 行上的同名參數會覆寫設定檔，一併檢查。

    legacy：RHEL 8 小於此版本時 pwquality.conf 不支援此參數（retry 需 8.4），只看 PAM 行、修復轉人工。
    missing_ok：未設定時模組預設值即符合（dictcheck 預設 1）。
    """
    category = ACC

    def __init__(self, title, ids, key, value, ok, expected, missing_ok=False, legacy=None):
        self.title = title
        self.ids = ids
        self.key = key
        self.value = value
        self.ok = ok
        self.expected = expected
        self.missing_ok = missing_ok
        self.legacy = legacy

    def _legacy(self, osi):
        return bool(self.legacy) and _is_rhel8_before(osi, self.legacy)

    def _status(self, osi):
        """回傳 (合格, 說明清單, 不合格的 PAM 覆寫, 未啟用模組的檔案)。"""
        legacy = self._legacy(osi)
        vals = [] if legacy else pwq_values(self.key)
        conf_eff = vals[-1][1] if vals else None
        cur, ok = [], True
        if legacy:
            cur.append("RHEL 8.%d 以前 pwquality.conf 不支援 %s，以 PAM 參數判定" % (self.legacy[1] - 1, self.key))
        else:
            cur.append("%s：%s" % (os.path.basename(PWQ), "、".join(
                "%s=%s（%s）" % (self.key, v, os.path.basename(f)) for f, v in vals) or "未設定"))
            bad_conf = [(f, v) for f, v in vals if not self.ok(v)]
            if bad_conf:
                ok = False
        over_bad, missing = [], []
        for f in PAM_FILES:
            lines = pam_args(pam_text(f), "password", "pam_pwquality.so")
            if not lines:
                missing.append(f)
                continue
            pv = None
            for a in lines:
                pv = arg_value(a, self.key) if arg_value(a, self.key) is not None else pv
            if pv is not None:
                cur.append("%s PAM 參數 %s=%s" % (os.path.basename(f), self.key, pv))
                if not self.ok(pv):
                    over_bad.append("%s %s=%s" % (os.path.basename(f), self.key, pv))
                    ok = False
                continue
            eff = conf_eff
            if eff is None and not self.missing_ok:
                ok = False
        if missing:
            ok = False
            cur.append("%s %s" % ("、".join(os.path.basename(f) for f in missing), PWQ_MISSING))
        if conf_eff is None and not legacy and self.missing_ok and ok:
            cur[0] = "%s 未設定（模組預設值符合規範）" % self.key
        return ok, cur, over_bad, missing

    def check(self, ctx):
        ok, cur, _, _ = self._status(ctx.osi)
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        if self._legacy(ctx.osi):
            raise ManualRequired("RHEL 8.%d 以前 pwquality.conf 不支援 %s，需依 GCB 文件建立自訂 authselect profile "
                                 "並在 pam_pwquality.so 行加入 %s=%s，請人工處理"
                                 % (self.legacy[1] - 1, self.key, self.key, self.value))
        vals = pwq_values(self.key)
        for f, v in vals:
            if f != PWQ and not self.ok(v):
                fx.edit_file(f, lambda t: conf_comment(t, self.key))
        main = [v for f, v in vals if f == PWQ]
        if not main or not self.ok(main[-1]):
            fx.edit_file(PWQ, lambda t: conf_set(t, self.key, str(self.value)))
        _, _, over_bad, missing = self._status(ctx.osi)
        if over_bad:
            fx.partial = True
            fx.note("PAM 的 pam_pwquality.so 參數會覆寫設定檔（屬 authselect 管理範圍），請人工修改：" + "、".join(over_bad))
        if missing:
            fx.partial = True
            fx.note("%s 未啟用 pam_pwquality，設定不會生效；請人工以 authselect 修正（見「啟用 pam_pwquality」項目）"
                    % "、".join(missing))


# [EnforceForRoot] RHEL8 0209 / RHEL9 0207 強制 root 通行碼須符合通行碼規則
class EnforceForRoot(Rule):
    """GCB 文件以自訂 authselect profile 在 PAM 行加入 enforce_for_root；RHEL 8.4+ / 9 的 libpwquality
    支援在 pwquality.conf 設定同名旗標，效果相同且不需改 PAM，故修復採設定檔做法（A 類）。"""
    category = ACC
    title = "強制 root 通行碼須符合通行碼規則"
    expected = "啟用（enforce_for_root）"
    LEGACY = (8, 4)

    def __init__(self, ids):
        self.ids = ids

    def _status(self, osi):
        legacy = _is_rhel8_before(osi, self.LEGACY)
        lines = {f: pam_args(pam_text(f), "password", "pam_pwquality.so") for f in PAM_FILES}
        missing = [f for f in PAM_FILES if not lines[f]]
        pam_ok = not missing and all(any("enforce_for_root" in a for a in lines[f]) for f in PAM_FILES)
        conf = [] if legacy else [f for f in pwq_files() if flag_present(read_text(f) or "", "enforce_for_root")]
        return legacy, missing, pam_ok, conf

    def check(self, ctx):
        legacy, missing, pam_ok, conf = self._status(ctx.osi)
        if missing:
            return Check(FAIL, "%s %s" % ("、".join(os.path.basename(f) for f in missing), PWQ_MISSING))
        if pam_ok:
            return Check(PASS, "PAM pam_pwquality.so 已帶 enforce_for_root")
        if conf:
            return Check(PASS, "%s 已設定 enforce_for_root（與 PAM 參數效果相同）" % os.path.basename(conf[0]))
        return Check(FAIL, "未設定 enforce_for_root" + ("（RHEL 8.3 以前需設定於 PAM 行）" if legacy else ""))

    def fix(self, ctx, fx):
        legacy, missing, _, _ = self._status(ctx.osi)
        if legacy:
            raise ManualRequired("RHEL 8.3 以前 pwquality.conf 不支援 enforce_for_root，需依 GCB 文件建立自訂 "
                                 "authselect profile 並在 pam_pwquality.so 行加入 enforce_for_root，請人工處理")
        fx.edit_file(PWQ, lambda t: flag_set(t, "enforce_for_root"))
        if missing:
            fx.partial = True
            fx.note("%s 未啟用 pam_pwquality，設定不會生效；請人工以 authselect 修正" % "、".join(missing))


# ====================================================================
# faillock（0221 / 0219、RHEL 9 0310）
# ====================================================================

def faillock_pam_values(key):
    """PAM 檔 pam_faillock.so 行上的 key=value：[(file, value)]。"""
    out = []
    for f in PAM_FILES:
        text = pam_text(f)
        for t in ("auth", "account"):
            for a in pam_args(text, t, "pam_faillock.so"):
                v = arg_value(a, key)
                if v is not None:
                    out.append((f, v))
    return out


def unlock_ok(v):
    # unlock_time=0 / never 為永久鎖定：依決策紀錄照 GCB 字面「900 秒以上」判不合格
    n = _int(v)
    return n is not None and n >= 900


# [FaillockUnlock] RHEL8 0221 / RHEL9 0219 帳戶鎖定時間
class FaillockUnlock(Rule):
    category = ACC
    risk = "B"
    title = "帳戶鎖定時間"
    expected = "900 秒以上（unlock_time = 900），且 pam_faillock 已啟用"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        osi = ctx.osi
        legacy = _is_rhel8_before(osi, (8, 2))
        cur, ok = [], True
        pam = faillock_pam_values("unlock_time")
        if legacy:
            cur.append("RHEL 8.1 以前無 faillock.conf，以 PAM 參數判定")
            if not pam:
                ok = False
                cur.append("PAM 未設定 unlock_time")
        else:
            v = conf_get(read_text(FAILLOCK_CONF) or "", "unlock_time")
            good = unlock_ok(v)
            ok = good
            note = "（永久鎖定，依 GCB 字面「900 秒以上」不符）" if (v or "").lower() in ("0", "never") else ""
            if v is None:
                note = "（預設 600）"
            cur.append("unlock_time=%s%s" % (v if v is not None else "未設定", note))
        bad = ["%s unlock_time=%s" % (os.path.basename(f), v) for f, v in pam if not unlock_ok(v)]
        if bad:
            ok = False
            cur.append("PAM 參數覆寫：" + "、".join(bad))
        active = faillock_active(osi)
        cur.append("pam_faillock:%s" % ("已啟用" if active else "未啟用"))
        return Check(PASS if ok and active else FAIL, "、".join(cur))

    def fix(self, ctx, fx):
        if _is_rhel8_before(ctx.osi, (8, 2)):
            raise ManualRequired("RHEL 8.1 以前沒有 faillock.conf，需依 GCB 文件建立自訂 authselect profile，請人工處理")
        v = conf_get(read_text(FAILLOCK_CONF) or "", "unlock_time")
        if v is not None and v.lower() in ("0", "never"):
            fx.partial = True
            fx.note("unlock_time 目前為永久鎖定（需管理者解鎖），安全性高於 GCB 但不符字面「900 秒以上」；"
                    "依決策紀錄不自動修改，請人工決定是否改為 unlock_time = 900")
        elif not unlock_ok(v):
            fx.edit_file(FAILLOCK_CONF, lambda t: conf_set(t, "unlock_time", "900"))
        if not faillock_active(ctx.osi):
            authselect_enable(fx, "with-faillock")
        bad = [(f, x) for f, x in faillock_pam_values("unlock_time") if not unlock_ok(x)]
        if bad:
            fx.partial = True
            fx.note("PAM 的 pam_faillock.so 參數會覆寫 faillock.conf，請人工修改：" +
                    "、".join("%s unlock_time=%s" % (os.path.basename(f), x) for f, x in bad))


def _admin_login_ok(ctx):
    pre = ctx.pre_health_status
    if pre.get("H04") != "通過" or pre.get("H05") != "通過":
        return "前測未確認一般帳號可 SSH 登入並使用 sudo，為避免 root 遭鎖定後無法管理而略過"
    return None


# [FaillockRoot] RHEL9 0310 root 帳戶鎖定時間
class FaillockRoot(Rule):
    category = ACC
    risk = "B"
    title = "root 帳戶鎖定時間"
    expected = "60 秒以上（even_deny_root、root_unlock_time = 60），且 pam_faillock 已啟用"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _combined(text):
        """文件寫法「even_deny_root root_unlock_time=60」寫在同一行，faillock.conf 無法解析，視為無效。"""
        return [l for l in (text or "").splitlines()
                if _active(l) and re.match(r"^\s*even_deny_root\s+\S", l.split("#", 1)[0])]

    def check(self, ctx):
        text = read_text(FAILLOCK_CONF) or ""
        flag = flag_present(text, "even_deny_root")
        v = conf_get(text, "root_unlock_time")
        pam = faillock_pam_values("root_unlock_time")
        cur = ["even_deny_root:%s" % ("有" if flag else "無"),
               "root_unlock_time=%s" % (v if v is not None else "未設定")]
        ok = flag and _int(v) is not None and _int(v) >= 60
        bad = ["%s root_unlock_time=%s" % (os.path.basename(f), x) for f, x in pam if not (_int(x) or 0) >= 60]
        if bad:
            ok = False
            cur.append("PAM 參數覆寫：" + "、".join(bad))
        if self._combined(text):
            cur.append("faillock.conf 有兩個參數寫在同一行（無效）")
        active = faillock_active(ctx.osi)
        cur.append("pam_faillock:%s" % ("已啟用" if active else "未啟用"))
        return Check(PASS if ok and active else FAIL, "、".join(cur))

    def precondition(self, ctx):
        return _admin_login_ok(ctx)

    def fix(self, ctx, fx):
        def _apply(t):
            out = [te.MARK + l if l in self._combined(t) else l for l in (t or "").splitlines()]
            t = "\n".join(out) + "\n" if out else ""
            t = flag_set(t, "even_deny_root")
            if (_int(conf_get(t, "root_unlock_time")) or 0) < 60:
                t = conf_set(t, "root_unlock_time", "60")
            return t
        fx.edit_file(FAILLOCK_CONF, _apply)
        if not faillock_active(ctx.osi):
            authselect_enable(fx, "with-faillock")
        fx.note("root 連續登入失敗達 deny 次數後會被鎖定 root_unlock_time 秒（含主控台）；"
                "必要時以 faillock --user root --reset 解除")


# ====================================================================
# 通行碼歷程、登入失敗顯示、雜湊演算法（0222–0224 / 0220–0222）
# ====================================================================

# [PwHistory] RHEL8 0222 / RHEL9 0220 強制執行通行碼歷程記錄
class PwHistory(Rule):
    category = ACC
    risk = "B"
    title = "強制執行通行碼歷程記錄"
    expected = "3 以上（remember=3）"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _file_status(path):
        """回傳 (合格, 說明)：pam_pwhistory.so 或 pam_unix.so 的 remember。"""
        text = pam_text(path)
        name = os.path.basename(path)
        hist = pam_args(text, "password", "pam_pwhistory.so")
        if hist:
            v = None
            for a in hist:
                v = arg_value(a, "remember") if arg_value(a, "remember") is not None else v
            src = "PAM 參數"
            if v is None and os.path.exists(PWHISTORY_CONF):
                v, src = conf_get(read_text(PWHISTORY_CONF) or "", "remember"), os.path.basename(PWHISTORY_CONF)
            if v is None:
                v, src = "10", "模組預設"
            return (_int(v) or 0) >= 3, "%s pam_pwhistory remember=%s（%s）" % (name, v, src)
        unix = [arg_value(a, "remember") for a in pam_args(text, "password", "pam_unix.so")]
        unix = [v for v in unix if v is not None]
        if unix:
            return (_int(unix[-1]) or 0) >= 3, "%s pam_unix remember=%s" % (name, unix[-1])
        return False, "%s 未設定 remember" % name

    def check(self, ctx):
        ok, cur = self._file_status(SYSTEM_AUTH)
        ok2, cur2 = self._file_status(PASSWORD_AUTH)
        # GCB 文件只要求 system-auth；password-auth（遠端登入改密碼）列出供參考
        return Check(PASS if ok else FAIL, "%s；%s（參考）" % (cur, cur2))

    def fix(self, ctx, fx):
        hist = pam_args(pam_text(SYSTEM_AUTH), "password", "pam_pwhistory.so")
        def _too_low(a):  # PAM 行上的 remember 參數會覆寫 pwhistory.conf（含 remember=0）
            v = arg_value(a, "remember")
            return v is not None and (_int(v) is None or _int(v) < 3)
        if hist and any(_too_low(a) for a in hist):
            raise ManualRequired("system-auth 的 pam_pwhistory.so 帶有 remember 參數（自訂 profile），請人工修改為 remember=3")
        if os.path.exists(PWHISTORY_CONF):
            v = conf_get(read_text(PWHISTORY_CONF) or "", "remember")
            if (_int(v) or 0) < 3:
                fx.edit_file(PWHISTORY_CONF, lambda t: conf_set(t, "remember", "3"))
        if not hist:
            authselect_enable(fx, "with-pwhistory")
        elif not os.path.exists(PWHISTORY_CONF):
            fx.note("此版本無 pwhistory.conf，pam_pwhistory 使用預設 remember=10")


def lastlog_lines(text):
    """postlogin 中帶 showfailed 的 session pam_lastlog.so 行（[(控制旗標, 參數)]）。"""
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not _active(s):
            continue
        m = re.match(r"^-?session\s+(\[[^\]]*\]|\S+)\s+\S*pam_lastlog\.so\b(.*)$", s)
        if m and "showfailed" in m.group(2).split():
            out.append((m.group(1), m.group(2).split()))
    return out


# [LastlogShowfailed] RHEL8 0223 / RHEL9 0221 顯示登入失敗次數與日期
class LastlogShowfailed(Rule):
    """GCB 設定值為「啟用」；authselect 內建 postlogin 已以 optional / [default=1] 方式帶 showfailed，
    功能相同，以參數判定並在結果註明（文件做法為在檔案最上方加 required 行）。"""
    category = ACC
    risk = "B"
    title = "顯示登入失敗次數與日期"
    expected = "啟用（session required pam_lastlog.so showfailed）"
    LINE = "session     required    pam_lastlog.so showfailed"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text(POSTLOGIN)
        if text is None:
            return Check(FAIL, "找不到 %s" % POSTLOGIN)
        lines = lastlog_lines(text)
        if not lines:
            return Check(FAIL, "postlogin 未設定 pam_lastlog.so showfailed")
        flags = "、".join(c for c, _ in lines)
        note = "" if any(c == "required" for c, _ in lines) else "（控制旗標為 %s，與文件 required 功能相同）" % flags
        return Check(PASS, "postlogin 已啟用 pam_lastlog.so showfailed" + note)

    def fix(self, ctx, fx):
        if authselect_current() is not None:
            raise ManualRequired("postlogin 由 authselect 管理，直接修改會被覆寫並使 authselect check 失敗；"
                                 "請依 GCB 文件建立自訂 profile（authselect create-profile）並在 postlogin "
                                 "加入 session required pam_lastlog.so showfailed")

        def _top(t):
            lines = (t or "").splitlines()
            idx = next((i for i, l in enumerate(lines) if _active(l)), len(lines))
            lines.insert(idx, self.LINE)
            return "\n".join(lines) + "\n"
        fx.edit_file(POSTLOGIN, _top)


HASH_ARGS = ("md5", "bigcrypt", "sha256", "sha512", "blowfish", "gost_yescrypt", "yescrypt")


# [HashSha512] RHEL8 0224 / RHEL9 0222 通行碼雜湊演算法
class HashSha512(Rule):
    """libuser.conf、login.defs 備份後直接修改；PAM 的 pam_unix.so 參數不自動修改（authselect 內建
    profile 已帶 sha512，不符代表 PAM 曾被手改或使用自訂 profile），不符時標部分修復。"""
    category = ACC
    title = "通行碼雜湊演算法"
    expected = "SHA512（libuser.conf crypt_style、login.defs ENCRYPT_METHOD、pam_unix.so sha512）"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _pam_bad():
        bad = []
        for f in PAM_FILES:
            lines = pam_args(pam_text(f), "password", "pam_unix.so")
            if not lines:
                bad.append("%s 無 pam_unix.so" % os.path.basename(f))
            for a in lines:
                algs = [x for x in a if x in HASH_ARGS]
                if algs != ["sha512"]:
                    bad.append("%s pam_unix.so %s" % (os.path.basename(f), " ".join(algs) or "未指定"))
        return bad

    def check(self, ctx):
        cur, ok = [], True
        lib = read_text(LIBUSER_CONF)
        if lib is None:
            cur.append("未安裝 libuser（不適用）")
        else:
            cs = ini_get(lib, "defaults", "crypt_style")
            ok = (cs or "").lower() == "sha512"
            cur.append("crypt_style=%s" % (cs or "未設定"))
        em = te.get_kv(read_text(LOGIN_DEFS) or "", "ENCRYPT_METHOD")
        ok = ok and (em or "").upper() == "SHA512"
        cur.append("ENCRYPT_METHOD=%s" % (em or "未設定"))
        bad = self._pam_bad()
        cur.append("PAM：" + ("、".join(bad) if bad else "pam_unix.so sha512"))
        return Check(PASS if ok and not bad else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        lib = read_text(LIBUSER_CONF)
        if lib is not None and (ini_get(lib, "defaults", "crypt_style") or "").lower() != "sha512":
            fx.edit_file(LIBUSER_CONF, lambda t: ini_set(t, "defaults", "crypt_style", "sha512", sep=" = "))
        if (te.get_kv(read_text(LOGIN_DEFS) or "", "ENCRYPT_METHOD") or "").upper() != "SHA512":
            fx.edit_file(LOGIN_DEFS, lambda t: te.set_kv(t, "ENCRYPT_METHOD", "SHA512", sep=" "))
        bad = self._pam_bad()
        if bad:
            fx.partial = True
            fx.note("PAM 的 pam_unix.so 雜湊參數不符（%s），屬 authselect 管理範圍，未自動修改；"
                    "請執行 authselect check 並依目前 profile 修正" % "、".join(bad))


# ====================================================================
# 通行碼期限（0225、0226、0228 / 0223、0224、0226）
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


def would_disable_now(u, inactive, today=None):
    """套用 inactive 後帳號是否會立即停用。最長期限無效或大於 90 時以 90 計
    （0227/0225 會改成 90）；lastchg 為 0（強制下次變更）視為已過期。"""
    today = _today() if today is None else today
    last, mx = _int(u["lastchg"]), _int(u["max"])
    if last is None:
        return False
    if last == 0:
        return True
    if mx is None or mx <= 0 or mx > 90:
        mx = 90
    return today >= last + mx + inactive


# [ShadowAging] RHEL8 0225、0226、0228 / RHEL9 0223、0224、0226 通行碼期限（預設值與既有帳號）
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
        if not self.ok(_int(te.get_kv(read_text(self.path) or "", self.key))):
            fx.edit_file(self.path, lambda t: te.set_kv(t, self.key, str(self.value), sep=self.sep))
        for u in self._bad_users():
            if self.guard and would_disable_now(u, self.value):
                fx.partial = True
                fx.note("帳號 %s 通行碼已過期（或套用 90 天期限後已過期）超過 %d 天，套用後會立即停用而無法登入，"
                        "已略過；請人工處理" % (u["name"], self.value))
                continue
            fx.chage(u["name"], self.opt, u[self.field], self.value)


# ====================================================================
# sudo、同時登入數、系統帳號（0231、0232、0237 / 0229、0230、0235）
# ====================================================================

def sudoers_files():
    """/etc/sudoers 與其 includedir / include 指向的檔案（sudo 會略過含 . 或結尾 ~ 的檔名）。"""
    files, dirs = ["/etc/sudoers"], ["/etc/sudoers.d"]
    for line in (read_text("/etc/sudoers") or "").splitlines():
        m = re.match(r"^\s*[#@]include(dir)?\s+(\S+)", line)
        if not m:
            continue
        (dirs if m.group(1) else files).append(m.group(2))
    out = []
    for f in files:
        if f not in out and os.path.isfile(f):
            out.append(f)
    for d in dirs:
        for f in sorted(glob.glob(os.path.join(d, "*"))):
            if f not in out and os.path.isfile(f):
                out.append(f)
    return out


# [SudoAuth] RHEL8 0231 / RHEL9 0229 要求使用者必須經過身分鑑別才能提升權限（C 類）
class SudoAuth(Rule):
    category = ACC
    risk = "C"
    title = "要求使用者必須經過身分鑑別才能提升權限"
    expected = "要求身分鑑別（sudoers 不得有 NOPASSWD 或 !authenticate）"
    manual_hint = ("請確認列出的 sudoers 設定用途（雲端映像檔預設帳號、自動化帳號常使用 NOPASSWD），"
                   "確認該帳號有通行碼後，以 visudo -f <檔案> 將該行註解，並以 visudo -c 檢查語法")

    def __init__(self, ids):
        self.ids = ids

    def when(self, ctx):
        return None if os.path.exists("/etc/sudoers") else "未安裝 sudo，沒有 sudo 設定需要檢查"

    def check(self, ctx):
        hits = []
        for f in sudoers_files():
            text = read_text(f)
            if text is None:
                return Check(ERROR, "無法讀取 %s" % f)
            base = os.path.basename(f)
            ignored = f != "/etc/sudoers" and ("." in base or base.endswith("~"))
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if s.startswith("#") or not re.search(r"nopasswd|!\s*authenticate", s, re.I):
                    continue
                hits.append("%s:%d%s" % (f, i, "（sudo 不讀取此檔）" if ignored else ""))
        if hits:
            return Check(FAIL, "發現 NOPASSWD/!authenticate：" + "、".join(hits[:10]))
        return Check(PASS, "未發現 NOPASSWD 或 !authenticate")


LIMITS = "/etc/security/limits.conf"
LIMITS_D = "/etc/security/limits.d/*.conf"
LIMITS_GCB = "/etc/security/limits.d/99-gcb.conf"


def maxlogins_entries(texts):
    """texts：[(file, text)]。回傳 domain 為 *、type 為 hard 或 - 的 maxlogins：[(file, value)]。"""
    out = []
    for f, text in texts:
        for line in (text or "").splitlines():
            p = line.split("#", 1)[0].split()
            if len(p) >= 4 and p[0] == "*" and p[1] in ("hard", "-") and p[2] == "maxlogins":
                out.append((f, p[3]))
    return out


def maxlogins_comment(text, ok):
    out = []
    for line in (text or "").splitlines():
        p = line.split("#", 1)[0].split()
        if len(p) >= 4 and p[0] == "*" and p[1] in ("hard", "-") and p[2] == "maxlogins" and not ok(p[3]):
            out.append(te.MARK + line)
        else:
            out.append(line)
    return "\n".join(out) + "\n" if out else ""


# [MaxLogins] RHEL8 0232 / RHEL9 0230 限制每個帳號可同時登入之數量
class MaxLogins(Rule):
    category = ACC
    risk = "B"
    title = "限制每個帳號可同時登入之數量"
    expected = "10 以下，但須大於 0（* hard maxlogins 10）"
    OK = staticmethod(rng(1, 10))

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _texts():
        return [(f, read_text(f)) for f in [LIMITS] + sorted(glob.glob(LIMITS_D))]

    @staticmethod
    def _pam_limits_missing():
        return [os.path.basename(f) for f in PAM_FILES if not pam_args(pam_text(f), "session", "pam_limits.so")]

    def check(self, ctx):
        vals = maxlogins_entries(self._texts())
        cur, ok = [], bool(vals)
        if vals:
            cur.append("、".join("maxlogins=%s（%s）" % (v, os.path.basename(f)) for f, v in vals))
            ok = all(self.OK(v) for _, v in vals)
        else:
            cur.append("未設定 * hard maxlogins")
        miss = self._pam_limits_missing()
        if miss:
            ok = False
            cur.append("%s 未啟用 pam_limits（設定不會生效）" % "、".join(miss))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        for f, text in self._texts():
            if f != LIMITS_GCB and any(not self.OK(v) for _, v in maxlogins_entries([(f, text)])):
                fx.edit_file(f, lambda t: maxlogins_comment(t, self.OK))
        fx.write_file(LIMITS_GCB, "# GCB 限制每個帳號可同時登入之數量（gcb-checker 產生）\n* hard maxlogins 10\n")
        fx.note("每個帳號（root 除外）最多同時 10 個登入工作階段，請確認各系統服務正常運作")
        if self._pam_limits_missing():
            fx.partial = True
            fx.note("system-auth/password-auth 未啟用 pam_limits，設定不會生效；請人工以 authselect 修正")


NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")


# [SystemAccounts] RHEL8 0237 / RHEL9 0235 系統帳號登入方式（C 類）
class SystemAccounts(Rule):
    category = ACC
    risk = "C"
    title = "系統帳號登入方式"
    expected = "nologin（系統帳號不可使用殼層登入且已鎖定）"
    manual_hint = ("請確認列出的系統帳號用途後，執行 usermod -s /sbin/nologin <帳號> 與 usermod -L <帳號>；"
                   "部分服務帳號（如資料庫）可能需要 shell 供維運使用")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        shadow = read_text("/etc/shadow")
        if shadow is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        uid_min = _int(te.get_kv(read_text(LOGIN_DEFS) or "", "UID_MIN")) or 1000
        pwmap = {u["name"]: u["pw"] for u in te.parse_shadow(shadow)}
        shell_bad, lock_bad = [], []
        for line in (read_text("/etc/passwd") or "").splitlines():
            f = line.split(":")
            if len(f) < 7 or f[0].startswith("+") or f[0] == "root" or _int(f[2]) is None or _int(f[2]) >= uid_min:
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
# GNOME（0234–0236、0239 / 0232–0234、0237）：未安裝 GNOME 時不適用
# ====================================================================

DCONF_DB = "/etc/dconf/db/local"
DCONF_DIR = "/etc/dconf/db/local.d"
DCONF_LOCKS = DCONF_DIR + "/locks"
DCONF_PROFILE = "/etc/dconf/profile/user"
DCONF_SCREENSAVER = DCONF_DIR + "/00-screensaver"
GDM_CUSTOM = "/etc/gdm/custom.conf"


def gnome_when(ctx):
    if pkgsvc.pkg_installed(ctx.osi, "gdm") or os.path.exists("/usr/bin/gnome-shell"):
        return None
    return "未安裝 GNOME 圖形介面（gdm、gnome-shell），本項目是桌面設定，不需設定"


def dconf_keyfiles():
    return [f for f in sorted(glob.glob(DCONF_DIR + "/*")) if os.path.isfile(f)]


def dconf_lockfiles():
    return [f for f in sorted(glob.glob(DCONF_LOCKS + "/*")) if os.path.isfile(f)]


def dconf_issues():
    """dconf 設定生效條件：profile 含 system-db:local，且已執行 dconf update。"""
    out = []
    prof = read_text(DCONF_PROFILE)
    if prof is None or "system-db:local" not in [l.strip() for l in prof.splitlines()]:
        out.append("%s 未設定 system-db:local（本機資料庫不生效）" % DCONF_PROFILE)
    srcs = dconf_keyfiles() + dconf_lockfiles()
    if srcs:
        if not os.path.exists(DCONF_DB):
            out.append("尚未執行 dconf update")
        elif max(os.path.getmtime(f) for f in srcs) > os.path.getmtime(DCONF_DB):
            out.append("設定檔較 dconf 資料庫新，尚未執行 dconf update")
    return out


def dconf_ensure_profile(fx):
    prof = read_text(DCONF_PROFILE)
    if prof is None:
        fx.write_file(DCONF_PROFILE, "user-db:user\nsystem-db:local\n")
    elif "system-db:local" not in [l.strip() for l in prof.splitlines()]:
        fx.edit_file(DCONF_PROFILE, lambda t: t.rstrip("\n") + "\nsystem-db:local\n")


def dconf_update(fx):
    if not which("dconf"):
        raise ManualRequired("找不到 dconf 指令，設定已寫入但無法更新資料庫，請安裝 dconf 後執行 dconf update")
    fx.add_undo(["dconf", "update"], "重新產生 dconf 資料庫")
    fx.run(["dconf", "update"], "更新 dconf 資料庫")


# [DconfKey] RHEL8 0234、0235 / RHEL9 0232、0233 GNOME 螢幕鎖定、閒置逾時
class DconfKey(Rule):
    category = ACC
    when = staticmethod(gnome_when)

    def __init__(self, title, ids, section, key, value, ok, expected):
        self.title = title
        self.ids = ids
        self.section = section
        self.key = key
        self.value = value
        self.ok = ok
        self.expected = expected

    def _values(self):
        out = []
        for f in dconf_keyfiles():
            v = ini_get(read_text(f) or "", self.section, self.key)
            if v is not None:
                out.append((f, v))
        return out

    def check(self, ctx):
        vals = self._values()
        if not vals:
            cur, ok = ["[%s] %s 未設定" % (self.section, self.key)], False
        else:
            cur = ["%s=%s（%s）" % (self.key, v, os.path.basename(f)) for f, v in vals]
            ok = all(self.ok(v) for _, v in vals)
        issues = dconf_issues()
        return Check(PASS if ok and not issues else FAIL, "；".join(cur + issues))

    def fix(self, ctx, fx):
        dconf_ensure_profile(fx)
        vals = self._values()
        for f, v in vals:
            if not self.ok(v):
                fx.edit_file(f, lambda t: ini_set(t, self.section, self.key, self.value))
        if not vals:
            fx.edit_file(DCONF_SCREENSAVER, lambda t: ini_set(t, self.section, self.key, self.value))
        dconf_update(fx)


def idle_ok(v):
    n = _int(re.sub(r"^\s*uint32\s+", "", v or ""))
    return n is not None and 0 < n <= 900


LOCK_PATHS = ["/org/gnome/desktop/session/idle-delay", "/org/gnome/desktop/screensaver/lock-enabled",
              "/org/gnome/desktop/screensaver/lock-delay", "/org/gnome/desktop/lockdown/disable-lock-screen"]


# [DconfLocks] RHEL8 0239 / RHEL9 0237 防止修改圖形使用者介面(GUI)設定
class DconfLocks(Rule):
    category = ACC
    title = "防止修改圖形使用者介面(GUI)設定"
    expected = "啟用（/etc/dconf/db/local.d/locks/session 鎖定 idle-delay、lock-enabled、lock-delay、disable-lock-screen）"
    when = staticmethod(gnome_when)
    FILE = DCONF_LOCKS + "/session"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _missing():
        have = set()
        for f in dconf_lockfiles():
            have |= set(l.strip() for l in (read_text(f) or "").splitlines() if _active(l))
        return [p for p in LOCK_PATHS if p not in have]

    def check(self, ctx):
        miss = self._missing()
        cur = ["未鎖定：" + "、".join(miss)] if miss else ["4 個設定皆已鎖定"]
        issues = dconf_issues()
        return Check(PASS if not miss and not issues else FAIL, "；".join(cur + issues))

    def fix(self, ctx, fx):
        dconf_ensure_profile(fx)
        miss = self._missing()
        if miss:
            fx.edit_file(self.FILE, lambda t: "\n".join([l for l in (t or "").splitlines()] + miss) + "\n")
        dconf_update(fx)


# [GdmAutoLogin] RHEL8 0236 / RHEL9 0234 禁止 GNOME 使用者自動登入
class GdmAutoLogin(Rule):
    category = ACC
    title = "禁止 GNOME 使用者自動登入"
    expected = "false（[daemon] AutomaticLoginEnable=false）"

    def __init__(self, ids):
        self.ids = ids

    def when(self, ctx):
        if os.path.exists(GDM_CUSTOM) or pkgsvc.pkg_installed(ctx.osi, "gdm"):
            return None
        return "未安裝 gdm 圖形登入畫面，本項目是登入畫面設定，不需設定"

    def check(self, ctx):
        v = ini_get(read_text(GDM_CUSTOM) or "", "daemon", "AutomaticLoginEnable")
        return Check(PASS if (v or "").lower() == "false" else FAIL,
                     "AutomaticLoginEnable=%s" % (v if v is not None else "未設定"))

    def fix(self, ctx, fx):
        # GCB 文件段落名稱誤植為「daemon]」，正確為 [daemon]
        fx.edit_file(GDM_CUSTOM, lambda t: ini_set(t, "daemon", "AutomaticLoginEnable", "false"))
        fx.note("重新啟動 gdm（或重開機）後生效；為避免中斷桌面工作階段未自動重啟")


# ====================================================================
# TMOUT、root 群組、umask、su（0238、0240–0243 / 0236、0238–0241、0309）
# ====================================================================

def shell_files():
    return [PROFILE, BASHRC] + sorted(glob.glob(PROFILE_D + "/*.sh"))


TMOUT_FILE = PROFILE_D + "/99-gcb-tmout.sh"
# 登入 shell 會先後讀取 profile.d 與 /etc/bashrc（非登入 shell 的 /etc/bashrc 也會讀 profile.d），
# 已設為唯讀時不重複設定，避免「TMOUT: readonly variable」錯誤
TMOUT_BODY = ("case \"$(readonly -p 2>/dev/null)\" in\n"
              "  *\" TMOUT=\"*) ;;\n"
              "  *) readonly TMOUT=900 ; export TMOUT ;;\n"
              "esac\n")
TMOUT_SCRIPT = "# GCB Bash shell 閒置時登出時間（gcb-checker 產生）\n" + TMOUT_BODY
BASHRC_BEGIN = "# >>> gcb-checker: Bash shell 閒置時登出時間 >>>"
BASHRC_END = "# <<< gcb-checker <<<"


def bashrc_tmout_block(text):
    """在 /etc/bashrc 末端加入（或更新）以標記包住的 TMOUT 區塊。"""
    lines, out, skip = (text or "").splitlines(), [], False
    for l in lines:
        if l.strip() == BASHRC_BEGIN:
            skip = True
            continue
        if skip:
            if l.strip() == BASHRC_END:
                skip = False
            continue
        out.append(l)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out + ["", BASHRC_BEGIN] + TMOUT_BODY.rstrip("\n").split("\n") + [BASHRC_END]) + "\n"


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


# [Tmout] RHEL8 0238 / RHEL9 0236 Bash shell 閒置時登出時間
class Tmout(Rule):
    category = ACC
    title = "Bash shell 閒置時登出時間"
    expected = "900 秒以下，但須大於 0（/etc/bashrc 與 /etc/profile(.d) 設定 readonly TMOUT=900 ; export TMOUT）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        texts = [(f, read_text(f)) for f in shell_files()]
        cur, ok = [], True
        for label, group in (("/etc/bashrc", [x for x in texts if x[0] == BASHRC]),
                             ("/etc/profile(.d)", [x for x in texts if x[0] != BASHRC])):
            vals, ro, ex = tmout_scan(group)
            if not vals:
                ok = False
                cur.append("%s 未設定 TMOUT" % label)
                continue
            good = all(0 < n <= 900 for _, n in vals) and ro and ex
            ok = ok and good
            cur.append("%s：%s、readonly:%s、export:%s" % (
                label, "、".join("TMOUT=%d（%s）" % (n, os.path.basename(f)) for f, n in vals),
                "有" if ro else "無", "有" if ex else "無"))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        for f in shell_files():
            text = read_text(f)
            if f == TMOUT_FILE or not text:
                continue
            vals, _, _ = tmout_scan([(f, text)])
            if any(not 0 < n <= 900 for _, n in vals):
                fx.edit_file(f, lambda t: re.sub(r"\bTMOUT=(['\"]?)\d+\1", "TMOUT=900", t))
        fx.write_file(TMOUT_FILE, TMOUT_SCRIPT)
        fx.edit_file(BASHRC, bashrc_tmout_block)
        fx.note("互動式 shell 閒置 900 秒會自動登出（以 shell 長時間監看工作者需注意）")


# [RootGid] RHEL8 0240 / RHEL9 0238 root 帳號所屬群組
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
    if arg is None:
        return None
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


def umask_ok(v):
    return v is not None and v & 0o027 == 0o027


def umask_scan(texts):
    """回傳 [(file, 原字串, 遮罩或 None)]。"""
    out = []
    for f, text in texts:
        for line in (text or "").splitlines():
            for m in _UMASK_RX.finditer(_code(line)):
                out.append((f, m.group(3), umask_value(m.group(3))))
    return out


def fix_umask_text(text):
    """把較寬鬆的 umask 值改為 027（保留 if 等結構）。"""
    out = []
    for line in (text or "").split("\n"):
        code = _code(line)
        for m in reversed(list(_UMASK_RX.finditer(code))):
            if not umask_ok(umask_value(m.group(3))):
                line = line[:m.start(3)] + "027" + line[m.end(3):]
        out.append(line)
    return "\n".join(out)


def append_umask(text):
    t = (text or "").rstrip("\n")
    return (t + "\n" if t else "") + "# GCB 預設 umask（gcb-checker 新增）\numask 027\n"


# [Umask] RHEL8 0241 / RHEL9 0239 所有使用者帳號之預設 umask
class Umask(Rule):
    category = ACC
    title = "所有使用者帳號之預設 umask"
    expected = "027 或更低權限（/etc/profile、/etc/profile.d/*.sh、/etc/bashrc 設定 umask 027）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        found = umask_scan([(f, read_text(f)) for f in shell_files()])
        cur, ok = [], True
        for need in (PROFILE, BASHRC):
            if not any(f == need and umask_ok(v) for f, _, v in found):
                ok = False
                cur.append("%s 未設定 umask 027" % need)
        bad = [x for x in found if not umask_ok(x[2])]
        if bad:
            ok = False
        if found:
            cur.append("、".join("umask %s（%s）" % (a, f) for f, a, v in found))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        for f in shell_files():
            text = read_text(f)
            if f == UMASK_FILE or text is None:
                continue
            found = umask_scan([(f, text)])
            if any(not umask_ok(v) for _, _, v in found):
                fx.edit_file(f, fix_umask_text)
            if f in (PROFILE, BASHRC) and not found:
                fx.edit_file(f, append_umask)
        fx.write_file(UMASK_FILE, "# GCB 所有使用者帳號之預設 umask（gcb-checker 產生）\numask 027\n")
        fx.note("之後新建檔案的預設權限改為 027，依賴群組寫入或其他人可讀的應用（如網站內容目錄）需注意")


# [LoginDefsUmask] RHEL8 0242 / RHEL9 0240 在 /etc/login.defs 設定所有使用者之預設 umask
class LoginDefsUmask(Rule):
    category = ACC
    title = "在 /etc/login.defs 設定所有使用者之預設 umask"
    expected = "027 或更低權限（UMASK 027）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        v = te.get_kv(read_text(LOGIN_DEFS) or "", "UMASK")
        return Check(PASS if umask_ok(umask_value(v)) else FAIL, "UMASK=%s" % (v or "未設定"))

    def fix(self, ctx, fx):
        fx.edit_file(LOGIN_DEFS, lambda t: te.set_kv(t, "UMASK", "027", sep="\t\t"))
        fx.note("RHEL 9 的 postlogin 以 pam_umask 套用 login.defs UMASK，會影響所有 PAM 工作階段（含 cron、sftp）產生的檔案權限")


ROOT_SHELL_FILES = ["/root/.bash_profile", "/root/.bashrc"]


# [RootUmask] RHEL9 0309 root 之預設 umask
class RootUmask(Rule):
    category = ACC
    title = "root 之預設 umask"
    expected = "027 或更低權限（/root/.bash_profile 與 /root/.bashrc 設定 umask 027）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        cur, ok = [], True
        for f in ROOT_SHELL_FILES:
            found = umask_scan([(f, read_text(f))])
            if not found:
                ok = False
                cur.append("%s 未設定 umask" % f)
                continue
            good = all(umask_ok(v) for _, _, v in found)
            ok = ok and good
            cur.append("%s：%s" % (f, "、".join("umask %s" % a for _, a, _ in found)))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        for f in ROOT_SHELL_FILES:
            text = read_text(f)
            found = umask_scan([(f, text)])
            if any(not umask_ok(v) for _, _, v in found):
                fx.edit_file(f, fix_umask_text, mode=0o644)
            if not found:
                # 附加在檔尾：/root/.bashrc 會先 source /etc/bashrc，放在其後才不會被覆蓋
                fx.edit_file(f, append_umask, mode=0o644)


_WHEEL_RX = re.compile(r"^\s*auth\s+(required|requisite)\s+pam_wheel\.so\b(.*)$")
_WHEEL_COMMENTED_RX = re.compile(r"^\s*#\s*auth\s+required\s+pam_wheel\.so\s+use_uid\s*$")
SU_LINE = "auth\t\trequired\tpam_wheel.so use_uid"


def su_wheel_status(text):
    """回傳 (是否已正確設定, 說明)。"""
    for l in (text or "").splitlines():
        m = _WHEEL_RX.match(l)
        if not m:
            continue
        args = m.group(2).split()
        group = arg_value(args, "group")
        if "use_uid" in args and "deny" not in args and group in (None, "wheel"):
            return True, "已設定：%s" % " ".join(l.split())
    return False, "未設定 auth required pam_wheel.so use_uid"


def su_wheel_apply(text):
    """取消註解 RHEL 預設的「#auth required pam_wheel.so use_uid」；沒有則插在 pam_rootok.so 之後。"""
    lines = (text or "").splitlines()
    for i, l in enumerate(lines):
        if _WHEEL_COMMENTED_RX.match(l):
            lines[i] = SU_LINE
            return "\n".join(lines) + "\n"
    idx = next((i + 1 for i, l in enumerate(lines) if _active(l) and "pam_rootok.so" in l), None)
    if idx is None:
        idx = next((i for i, l in enumerate(lines) if _active(l) and re.match(r"^\s*auth\s", l)), len(lines))
    lines.insert(idx, SU_LINE)
    return "\n".join(lines) + "\n"


def wheel_members():
    """wheel 群組的非 root 成員（含主要群組為 wheel 者）；群組不存在回傳 None。"""
    try:
        g = grp.getgrnam("wheel")
    except KeyError:
        return None
    members = set(g.gr_mem) | set(p.pw_name for p in pwd.getpwall() if p.pw_gid == g.gr_gid)
    return sorted(members - {"root"})


# [SuWheel] RHEL8 0243 / RHEL9 0241 可使用 su 指令之群組
class SuWheel(Rule):
    category = ACC
    risk = "B"
    title = "可使用 su 指令之群組"
    expected = "僅限 wheel 群組才能使用 su 指令（auth required pam_wheel.so use_uid）"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text(SU_PAM)
        if text is None:
            return Check(ERROR, "找不到 %s" % SU_PAM)
        ok, why = su_wheel_status(text)
        mem = wheel_members()
        gdesc = "wheel 群組不存在" if mem is None else "wheel 成員：%s" % (", ".join(mem) or "無（僅 root）")
        return Check(PASS if ok else FAIL, "%s；%s" % (why, gdesc))

    def precondition(self, ctx):
        mem = wheel_members()
        if not mem:
            return ("wheel 群組沒有非 root 的成員，啟用後除 root 外無人能使用 su；"
                    "請先以 usermod -aG wheel <管理帳號> 加入成員後再修復")
        # 執行本工具的維運帳號與 test_user 若會用 su 切換，也需在 wheel 內
        missing = [u for u in (os.environ.get("SUDO_USER"), ctx.cfg.test_user)
                   if u and u != "root" and u not in mem]
        if missing:
            return ("帳號 %s 不在 wheel 群組，啟用後將無法使用 su；請先以 usermod -aG wheel <帳號> 加入，"
                    "或確認這些帳號不需要 su 後人工修復" % "、".join(sorted(set(missing))))
        return None

    def fix(self, ctx, fx):
        # /etc/pam.d/su 不由 authselect 管理，備份後直接修改
        fx.edit_file(SU_PAM, su_wheel_apply)
        fx.note("僅 wheel 成員（%s）可使用 su；root 與經 sudo 執行的 su 不受影響。"
                "未自動調整 wheel 成員，請人工確認" % ", ".join(wheel_members() or []))


# ====================================================================
# RHEL 9 新增：without-nullok、pam_pwquality、pam_unix（0312–0314）
# ====================================================================

# [WithoutNullok] RHEL9 0312 啟用 without-nullok
class WithoutNullok(Rule):
    category = ACC
    risk = "B"
    title = "啟用 without-nullok"
    expected = "啟用（authselect enable-feature without-nullok）"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _nullok_lines():
        out = []
        for f in PAM_FILES:
            for t in ("auth", "account", "password", "session"):
                for a in pam_args(pam_text(f), t, "pam_unix.so"):
                    if "nullok" in a:
                        out.append("%s %s" % (os.path.basename(f), t))
        return out

    def check(self, ctx):
        cur, ok = [], True
        a = authselect_current()
        if a is not None:
            on = "without-nullok" in a[1]
            ok = on
            cur.append("authselect %s：without-nullok %s" % (a[0], "已啟用" if on else "未啟用"))
        else:
            cur.append("未使用 authselect")
        nl = self._nullok_lines()
        if nl:
            ok = False
            cur.append("pam_unix.so 帶 nullok：" + "、".join(nl))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def precondition(self, ctx):
        empty = [u["name"] for u in te.parse_shadow(read_text("/etc/shadow") or "") if u["pw"] == ""]
        if empty:
            return "有空白通行碼帳號（%s），啟用後將無法登入；請先處理「帳號不使用空白通行碼」項目" % ", ".join(empty)
        return None

    def fix(self, ctx, fx):
        authselect_enable(fx, "without-nullok")


# [PamModuleEnabled] RHEL9 0313 啟用 pam_pwquality、0314 啟用 pam_unix（C 類）
class PamModuleEnabled(Rule):
    """authselect 內建 profile 都已包含這些模組；不合格代表 PAM 被手改或使用自訂 profile，
    直接修改 /etc/pam.d 會被 authselect 覆寫、寫錯會鎖死登入，故只檢測，由人工修正。"""
    category = ACC
    risk = "C"
    manual_hint = ("請執行 authselect check 確認 PAM 是否曾被手動修改，並依目前 profile 修正"
                   "（authselect select <profile> <features> --force 會覆寫手動修改，需人工評估）")

    def __init__(self, title, ids, module, types):
        self.title = title
        self.ids = ids
        self.module = module
        self.types = types
        self.expected = "啟用（system-auth、password-auth 的 %s 皆有 %s）" % ("、".join(types), module)

    def check(self, ctx):
        miss = []
        for f in PAM_FILES:
            text = pam_text(f)
            for t in self.types:
                if not pam_args(text, t, self.module):
                    miss.append("%s %s" % (os.path.basename(f), t))
        if miss:
            return Check(FAIL, "缺少 %s：%s" % (self.module, "、".join(miss)))
        return Check(PASS, "system-auth、password-auth 皆已啟用 %s" % self.module)


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

RULES = [
    # RHEL8 0208 / RHEL9 0206 可設定通行碼次數（RHEL 8.3 以前只能設定於 PAM 行）
    Pwquality("可設定通行碼次數", R(208, 206), "retry", 3, rng(1, 3),
              "3 以下，但須大於 0（retry = 3）", legacy=(8, 4)),
    # RHEL8 0209 / RHEL9 0207 強制 root 通行碼須符合通行碼規則
    EnforceForRoot(R(209, 207)),
    # RHEL8 0210 / RHEL9 0208 通行碼最小長度 → common.py
    # RHEL8 0211 / RHEL9 0209 通行碼必須至少包含字元類別數量
    Pwquality("通行碼必須至少包含字元類別數量", R(211, 209), "minclass", 4, ge(4), "4（minclass = 4）"),
    # RHEL8 0212 / RHEL9 0210 通行碼必須至少包含數字個數
    Pwquality("通行碼必須至少包含數字個數", R(212, 210), "dcredit", -1, le(-1), "1 個以上（dcredit = -1）"),
    # RHEL8 0213 / RHEL9 0211 通行碼必須至少包含大寫字母個數
    Pwquality("通行碼必須至少包含大寫字母個數", R(213, 211), "ucredit", -1, le(-1), "1 個以上（ucredit = -1）"),
    # RHEL8 0214 / RHEL9 0212 通行碼必須至少包含小寫字母個數
    Pwquality("通行碼必須至少包含小寫字母個數", R(214, 212), "lcredit", -1, le(-1), "1 個以上（lcredit = -1）"),
    # RHEL8 0215 / RHEL9 0213 通行碼必須至少包含特殊字元個數
    Pwquality("通行碼必須至少包含特殊字元個數", R(215, 213), "ocredit", -1, le(-1), "1 個以上（ocredit = -1）"),
    # RHEL8 0216 / RHEL9 0214 新通行碼與舊通行碼最少相異字元數
    Pwquality("新通行碼與舊通行碼最少相異字元數", R(216, 214), "difok", 3, ge(3), "3 以上（difok = 3）"),
    # RHEL8 0217 / RHEL9 0215 同一類別字元可連續使用個數
    Pwquality("同一類別字元可連續使用個數", R(217, 215), "maxclassrepeat", 4, rng(1, 4),
              "4 以下，但須大於 0（maxclassrepeat = 4）"),
    # RHEL8 0218 / RHEL9 0216 相同字元可連續使用個數
    Pwquality("相同字元可連續使用個數", R(218, 216), "maxrepeat", 3, rng(1, 3), "3 以下，但須大於 0（maxrepeat = 3）"),
    # RHEL8 0219 / RHEL9 0217 必須禁止使用字典檔單字做為通行碼（libpwquality 預設 dictcheck=1）
    Pwquality("必須禁止使用字典檔單字做為通行碼", R(219, 217), "dictcheck", 1, eq(1), "1（dictcheck=1）",
              missing_ok=True),
    # RHEL8 0220 / RHEL9 0218 帳戶鎖定閾值 → common.py
    # RHEL8 0221 / RHEL9 0219 帳戶鎖定時間
    FaillockUnlock(R(221, 219)),
    # RHEL8 0222 / RHEL9 0220 強制執行通行碼歷程記錄
    PwHistory(R(222, 220)),
    # RHEL8 0223 / RHEL9 0221 顯示登入失敗次數與日期
    LastlogShowfailed(R(223, 221)),
    # RHEL8 0224 / RHEL9 0222 通行碼雜湊演算法
    HashSha512(R(224, 222)),
    # RHEL8 0225 / RHEL9 0223 通行碼最短使用期限
    ShadowAging("通行碼最短使用期限", R(225, 223), LOGIN_DEFS, "PASS_MIN_DAYS", "\t", 1,
                lambda n: n is not None and n >= 1, "min", "-m", "1 天以上（PASS_MIN_DAYS 1，含既有帳號）"),
    # RHEL8 0226 / RHEL9 0224 通行碼到期前提醒使用者變更通行碼
    ShadowAging("通行碼到期前提醒使用者變更通行碼", R(226, 224), LOGIN_DEFS, "PASS_WARN_AGE", "\t", 14,
                lambda n: n is not None and n >= 14, "warn", "-W", "14 天以上（PASS_WARN_AGE 14，含既有帳號）"),
    # RHEL8 0227 / RHEL9 0225 通行碼最長使用期限 → common.py
    # RHEL8 0228 / RHEL9 0226 通行碼到期後，帳號停用前之天數
    ShadowAging("通行碼到期後，帳號停用前之天數", R(228, 226), USERADD_DEFAULTS, "INACTIVE", "=", 30,
                lambda n: n is not None and 0 < n <= 30, "inact", "-I",
                "30 天以下，但須大於 0（useradd -D -f 30，含既有帳號）", risk="B", guard=True),
    # RHEL8 0229 / RHEL9 0227 登入嘗試失敗之延遲時間
    login_defs("登入嘗試失敗之延遲時間", R(229, 227), "FAIL_DELAY", "4", "ge", 4, expected="4 秒以上（FAIL_DELAY 4）"),
    # RHEL8 0230 / RHEL9 0228 新使用者帳號預設建立使用者家目錄
    login_defs("新使用者帳號預設建立使用者家目錄", R(230, 228), "CREATE_HOME", "yes", "eq", "yes",
               expected="yes（CREATE_HOME yes）"),
    # RHEL8 0231 / RHEL9 0229 要求使用者必須經過身分鑑別才能提升權限
    SudoAuth(R(231, 229)),
    # RHEL8 0232 / RHEL9 0230 限制每個帳號可同時登入之數量
    MaxLogins(R(232, 230)),
    # RHEL8 0233 / RHEL9 0231 kbd 套件（文件指定 kbd.x86_64，為相容其他架構不指定架構）
    PackagePresent("kbd 套件", "kbd", R(233, 231), ACC),
    # RHEL8 0234 / RHEL9 0232 使用者會談鎖定
    DconfKey("使用者會談鎖定", R(234, 232), "org/gnome/desktop/screensaver", "lock-enabled", "true",
             lambda v: (v or "").lower() == "true", "啟用（lock-enabled=true）"),
    # RHEL8 0235 / RHEL9 0233 GNOME 使用者會談逾時時間
    DconfKey("GNOME 使用者會談逾時時間", R(235, 233), "org/gnome/desktop/session", "idle-delay", "uint32 900",
             idle_ok, "900 秒以下，但須大於 0（idle-delay=uint32 900）"),
    # RHEL8 0236 / RHEL9 0234 禁止 GNOME 使用者自動登入
    GdmAutoLogin(R(236, 234)),
    # RHEL8 0237 / RHEL9 0235 系統帳號登入方式
    SystemAccounts(R(237, 235)),
    # RHEL8 0238 / RHEL9 0236 Bash shell 閒置時登出時間
    Tmout(R(238, 236)),
    # RHEL8 0239 / RHEL9 0237 防止修改圖形使用者介面(GUI)設定
    DconfLocks(R(239, 237)),
    # RHEL8 0240 / RHEL9 0238 root 帳號所屬群組
    RootGid(R(240, 238)),
    # RHEL8 0241 / RHEL9 0239 所有使用者帳號之預設 umask
    Umask(R(241, 239)),
    # RHEL8 0242 / RHEL9 0240 在 /etc/login.defs 設定所有使用者之預設 umask
    LoginDefsUmask(R(242, 240)),
    # RHEL8 0243 / RHEL9 0241 可使用 su 指令之群組
    SuWheel(R(243, 241)),
    # RHEL9 0309 root 之預設 umask
    RootUmask(R(r9=309)),
    # RHEL9 0310 root 帳戶鎖定時間
    FaillockRoot(R(r9=310)),
    # RHEL9 0311 連續字元序列可使用個數
    Pwquality("連續字元序列可使用個數", R(r9=311), "maxsequence", 3, rng(1, 3), "3 以下，但須大於 0（maxsequence=3）"),
    # RHEL9 0312 啟用 without-nullok
    WithoutNullok(R(r9=312)),
    # RHEL9 0313 啟用 pam_pwquality
    PamModuleEnabled("啟用 pam_pwquality", R(r9=313), "pam_pwquality.so", ["password"]),
    # RHEL9 0314 啟用 pam_unix
    PamModuleEnabled("啟用 pam_unix", R(r9=314), "pam_unix.so", ["auth", "account", "password", "session"]),
]
