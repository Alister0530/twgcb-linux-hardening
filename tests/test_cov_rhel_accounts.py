# -*- coding: utf-8 -*-
"""RHEL 8 / 9 帳號與存取控制（rhel/accounts.py）規則 check／fix 的模擬測試（不碰真實系統）。"""
import fnmatch
import os
import sys
import unittest
from contextlib import ExitStack

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402  (fakes 會把專案根目錄加入 sys.path)
from fakes import FakeCtx, FakeFx, FakeRunner, mock, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules import common  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS  # noqa: E402
from gcb.rules.rhel import accounts as a  # noqa: E402


# ---- 模擬環境 ----

class FakePath(object):
    """os.path 替身：fs 中的鍵視為存在的檔案。"""

    def __init__(self, fs, mtimes=None):
        self.fs = fs
        self.mtimes = mtimes or {}
        self.basename = os.path.basename
        self.join = os.path.join
        self.dirname = os.path.dirname

    def isfile(self, p):
        return p in self.fs

    def exists(self, p):
        return p in self.fs or any(k.startswith(p.rstrip("/") + "/") for k in self.fs)

    def getmtime(self, p):
        return self.mtimes.get(p, 0)


class FakeOs(object):
    def __init__(self, fs, environ=None, mtimes=None):
        self.path = FakePath(fs, mtimes)
        self.environ = environ or {}


class FakeGlob(object):
    """依路徑層級逐段比對 fs 的鍵（* 不跨越 /）。"""

    def __init__(self, fs):
        self.fs = fs

    def glob(self, pat):
        pp = pat.split("/")
        return sorted(k for k in self.fs if len(k.split("/")) == len(pp)
                      and all(fnmatch.fnmatchcase(x, y) for x, y in zip(k.split("/"), pp)))


def env(fs, runner=None, which=True, environ=None, mtimes=None, pkg=False):
    """patch accounts 模組讀檔、指令、glob、os；回傳 ExitStack。"""
    st = ExitStack()
    reader = fakes.fs_reader(fs)
    st.enter_context(mock.patch.object(a, "read_text", reader))
    st.enter_context(mock.patch.object(common, "read_text", reader))  # faillock_active 走 common
    st.enter_context(mock.patch.object(a, "run", runner or FakeRunner()))
    st.enter_context(mock.patch.object(a, "which", (lambda n: "/usr/bin/" + n) if which else (lambda n: None)))
    st.enter_context(mock.patch.object(a, "glob", FakeGlob(fs)))
    st.enter_context(mock.patch.object(a, "os", FakeOs(fs, environ, mtimes)))
    st.enter_context(mock.patch.object(a.pkgsvc, "pkg_installed", lambda osi, p: pkg))
    return st


def rule(cls, key=None):
    for r in a.RULES:
        if isinstance(r, cls) and (key is None or getattr(r, "key", None) == key):
            return r
    raise LookupError(cls)


def idx(fx, ev):
    return fx.events.index(ev)


PWQ_LINE = "password    requisite     pam_pwquality.so local_users_only %s\n"
UNIX_LINE = "password    sufficient    pam_unix.so sha512 shadow use_authtok\n"
FAILLOCK = ("auth        required      pam_faillock.so preauth silent\n"
            "account     required      pam_faillock.so\n")
LIMITS_LINE = "session     required      pam_limits.so\n"


def pam(extra_pwq="", faillock=True, unix=UNIX_LINE, limits=True):
    return ((FAILLOCK if faillock else "") + PWQ_LINE % extra_pwq + unix + (LIMITS_LINE if limits else ""))


def pam_fs(text=None, pa=None):
    t = pam() if text is None else text
    return {a.SYSTEM_AUTH: t, a.PASSWORD_AUTH: t if pa is None else pa}


# ---- authselect ----

# authselect 共用流程（PAM 修改一律經由 authselect enable-feature）
class TestAuthselect(unittest.TestCase):
    def test_current_without_authselect(self):
        with env({}, which=False):
            self.assertIsNone(a.authselect_current())

    def test_current_raw(self):
        runner = FakeRunner({"current --raw": res(0, "sssd with-faillock with-mkhomedir\n")})
        with env({}, runner):
            self.assertEqual(a.authselect_current(), ("sssd", ["with-faillock", "with-mkhomedir"]))

    def test_current_fallback_parse(self):
        out = "Profile ID: minimal\nEnabled features:\n- with-faillock\n- with-pwhistory\n"
        runner = FakeRunner({"current --raw": res(1), "authselect current": res(0, out)})
        with env({}, runner):
            self.assertEqual(a.authselect_current(), ("minimal", ["with-faillock", "with-pwhistory"]))

    def test_current_fallback_fail_or_no_profile(self):
        with env({}, FakeRunner({"current": res(2, err="No existing configuration")})):
            self.assertIsNone(a.authselect_current())
        with env({}, FakeRunner({"current --raw": res(0, ""), "authselect current": res(0, "garbage\n")})):
            self.assertIsNone(a.authselect_current())

    def _runner(self, check_rc=0):
        return FakeRunner({"current --raw": res(0, "sssd with-mkhomedir\n"),
                           "list-features": res(0, "with-faillock\nwith-pwhistory\nwithout-nullok\n"),
                           "authselect check": res(check_rc, err="File /etc/pam.d/system-auth was modified")})

    def test_enable_requires_authselect(self):
        fx = FakeFx(FakeCtx())
        with env({}, which=False):
            with self.assertRaises(ManualRequired):
                a.authselect_enable(fx, "with-faillock")
        self.assertEqual(fx.events, [])

    def test_enable_already_enabled_is_noop(self):
        fx = FakeFx(FakeCtx())
        with env({}, self._runner()):
            a.authselect_enable(fx, "with-mkhomedir")
        self.assertEqual(fx.events, [])

    def test_enable_feature_not_in_profile(self):
        fx = FakeFx(FakeCtx())
        with env({}, self._runner()):
            with self.assertRaises(ManualRequired) as cm:
                a.authselect_enable(fx, "with-foo")
        self.assertIn("自訂 profile", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_enable_refuses_when_check_fails(self):
        # authselect check 未通過（PAM 曾被手改）：不使用 --force，不做任何修改
        fx = FakeFx(FakeCtx())
        with env({}, self._runner(check_rc=1)):
            with self.assertRaises(ManualRequired) as cm:
                a.authselect_enable(fx, "with-faillock")
        self.assertIn("authselect check 未通過", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_enable_backs_up_and_registers_undo_first(self):
        fs = {"/etc/authselect/authselect.conf": "sssd\n", "/etc/authselect/system-auth": "x",
              "/var/lib/authselect/system-auth": "x"}
        fx = FakeFx(FakeCtx(), fs=dict(fs))
        with env(fs, self._runner()):
            a.authselect_enable(fx, "with-faillock")
        self.assertEqual(sorted(fx.kinds("backup")), sorted(fs))
        undo = ("undo", "authselect disable-feature with-faillock")
        enable = ("run", "authselect enable-feature with-faillock")
        self.assertLess(max(idx(fx, ("backup", p)) for p in fs), idx(fx, undo))
        self.assertLess(idx(fx, undo), idx(fx, enable))
        self.assertLess(idx(fx, enable), idx(fx, ("run", "authselect check")))

    def test_enable_post_check_failure_raises(self):
        fx = FakeFx(FakeCtx(), runner=FakeRunner({"authselect check": res(1, err="bad")}))
        with env({}, self._runner()):
            with self.assertRaises(FixError):
                a.authselect_enable(fx, "with-faillock")
        self.assertIn(("undo", "authselect disable-feature with-faillock"), fx.events)

    def test_enable_dry_run(self):
        fx = FakeFx(FakeCtx(dry_run=True), runner=FakeRunner({"authselect check": res(1)}))
        with env({}, self._runner()):
            a.authselect_enable(fx, "with-faillock")
        self.assertEqual(fx.kinds("undo"), [])
        self.assertEqual(fx.runner.calls, [])  # 預覽不執行指令


# ---- pwquality ----

# RHEL8 0208、0211–0219 / RHEL9 0206、0209–0217、0311 pwquality 通行碼原則參數
class TestPwquality(unittest.TestCase):
    def test_legacy_rhel8_retry(self):
        ctx = FakeCtx("rhel8", version="8.3")
        r = rule(a.Pwquality, "retry")
        fs = pam_fs(pam("retry=5"))
        with env(fs):
            c = r.check(ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("RHEL 8.3 以前", c.current)
            with self.assertRaises(ManualRequired):
                r.fix(ctx, FakeFx(ctx, fs=fs))

    def test_fix_conf_and_dropin(self):
        r = rule(a.Pwquality, "retry")
        fs = pam_fs()
        fs.update({a.PWQ: "# retry = 1\nretry = 5\n", "/etc/security/pwquality.conf.d/50-x.conf": "retry = 9\n"})
        ctx = FakeCtx()
        with env(fs):
            self.assertEqual(r.check(ctx).status, FAIL)
            fx = FakeFx(ctx, fs=fs)
            r.fix(ctx, fx)
            self.assertEqual(r.check(ctx).status, PASS)
        self.assertIn(a.te.MARK + "retry = 9", fs["/etc/security/pwquality.conf.d/50-x.conf"])
        self.assertEqual(a.conf_get(fs[a.PWQ], "retry"), "3")
        self.assertFalse(fx.partial)

    def test_pam_override_and_missing_module(self):
        r = rule(a.Pwquality, "minclass")
        fs = pam_fs(pam("minclass=2"), pa=FAILLOCK + UNIX_LINE)
        fs[a.PWQ] = "minclass = 4\n"
        ctx = FakeCtx()
        with env(fs):
            c = r.check(ctx)
            fx = FakeFx(ctx, fs=fs)
            r.fix(ctx, fx)
        self.assertEqual(c.status, FAIL)
        self.assertIn("system-auth PAM 參數 minclass=2", c.current)
        self.assertIn(a.PWQ_MISSING, c.current)
        self.assertTrue(fx.partial)
        self.assertTrue(any("覆寫設定檔" in n for n in fx.notes))
        self.assertTrue(any("未啟用 pam_pwquality" in n for n in fx.notes))
        self.assertEqual(fx.kinds("write"), [])  # 設定檔已合格不改

    def test_unset_value(self):
        ctx = FakeCtx()
        with env(pam_fs()):
            self.assertEqual(rule(a.Pwquality, "minclass").check(ctx).status, FAIL)
            c = rule(a.Pwquality, "dictcheck").check(ctx)
        self.assertEqual(c.status, PASS)
        self.assertIn("模組預設值符合規範", c.current)


# RHEL8 0209 / RHEL9 0207 強制 root 通行碼須符合通行碼規則
class TestEnforceForRoot(unittest.TestCase):
    r = rule(a.EnforceForRoot)

    def test_check(self):
        ctx = FakeCtx()
        with env(pam_fs(pa=UNIX_LINE)):
            self.assertIn(a.PWQ_MISSING, self.r.check(ctx).current)
        with env(pam_fs(pam("enforce_for_root"))):
            self.assertEqual(self.r.check(ctx).status, PASS)
        with env(pam_fs()):
            c = self.r.check(FakeCtx("rhel8", version="8.3"))
        self.assertEqual(c.status, FAIL)
        self.assertIn("RHEL 8.3 以前", c.current)

    def test_fix(self):
        ctx8 = FakeCtx("rhel8", version="8.2")
        with env(pam_fs()):
            with self.assertRaises(ManualRequired):
                self.r.fix(ctx8, FakeFx(ctx8))
        fs = pam_fs(pa=UNIX_LINE)
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            self.r.fix(ctx, fx)
        self.assertTrue(a.flag_present(fs[a.PWQ], "enforce_for_root"))
        self.assertTrue(fx.partial)


# ---- faillock ----

# RHEL8 0221 / RHEL9 0219 帳戶鎖定時間
class TestFaillockUnlock(unittest.TestCase):
    r = rule(a.FaillockUnlock)

    def test_legacy(self):
        ctx = FakeCtx("rhel8", version="8.1")
        with env(pam_fs()):
            c = self.r.check(ctx)
            with self.assertRaises(ManualRequired):
                self.r.fix(ctx, FakeFx(ctx))
        self.assertEqual(c.status, FAIL)
        self.assertIn("PAM 未設定 unlock_time", c.current)

    def test_pam_override(self):
        text = FAILLOCK.replace("silent", "silent unlock_time=60") + PWQ_LINE % ""
        fs = pam_fs(text)
        fs[a.FAILLOCK_CONF] = "unlock_time = 900\n"
        ctx = FakeCtx()
        with env(fs):
            c = self.r.check(ctx)
            fx = FakeFx(ctx, fs=fs)
            self.r.fix(ctx, fx)
        self.assertEqual(c.status, FAIL)
        self.assertIn("PAM 參數覆寫", c.current)
        self.assertTrue(fx.partial)
        self.assertEqual(fx.kinds("write"), [])

    def test_permanent_lock_not_changed(self):
        fs = pam_fs()
        fs[a.FAILLOCK_CONF] = "unlock_time = never\n"
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            self.r.fix(ctx, fx)
        self.assertEqual(fs[a.FAILLOCK_CONF], "unlock_time = never\n")
        self.assertTrue(fx.partial)

    def test_permanent_lock_note_case_insensitive(self):
        fs = pam_fs()
        fs[a.FAILLOCK_CONF] = "unlock_time = Never\n"
        with env(fs):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("永久鎖定", c.current)

    def test_fix_sets_value_and_enables_faillock(self):
        fs = pam_fs(pam(faillock=False))
        fs[a.FAILLOCK_CONF] = "unlock_time = 600\n"
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs), mock.patch.object(a, "authselect_enable") as en:
            self.r.fix(ctx, fx)
        self.assertEqual(a.conf_get(fs[a.FAILLOCK_CONF], "unlock_time"), "900")
        en.assert_called_once_with(fx, "with-faillock")


# RHEL9 0310 root 帳戶鎖定時間
class TestFaillockRoot(unittest.TestCase):
    r = rule(a.FaillockRoot)

    def test_precondition_pre_health(self):
        ctx = FakeCtx()
        self.assertIsNone(self.r.precondition(ctx))
        ctx.pre_health_status["H05"] = "失敗"
        self.assertIn("前測", self.r.precondition(ctx))

    def test_check_and_fix(self):
        text = FAILLOCK.replace("silent", "silent root_unlock_time=10") + PWQ_LINE % ""
        fs = pam_fs(text, pa=pam(faillock=False))
        fs[a.FAILLOCK_CONF] = "even_deny_root root_unlock_time=60\n"
        ctx = FakeCtx()
        with env(fs):
            c = self.r.check(ctx)
            fx = FakeFx(ctx, fs=fs)
            with mock.patch.object(a, "authselect_enable") as en:
                self.r.fix(ctx, fx)
        self.assertEqual(c.status, FAIL)
        self.assertIn("PAM 參數覆寫", c.current)
        self.assertIn("同一行", c.current)
        out = fs[a.FAILLOCK_CONF]
        self.assertIn(a.te.MARK + "even_deny_root root_unlock_time=60", out)
        self.assertTrue(a.flag_present(out, "even_deny_root"))
        self.assertEqual(a.conf_get(out, "root_unlock_time"), "60")
        en.assert_called_once_with(fx, "with-faillock")


# ---- 通行碼歷程、lastlog、雜湊 ----

# RHEL8 0222 / RHEL9 0220 強制執行通行碼歷程記錄
class TestPwHistory(unittest.TestCase):
    r = rule(a.PwHistory)
    HIST = "password    requisite     pam_pwhistory.so use_authtok %s\n"

    def test_file_status(self):
        with env(pam_fs(self.HIST % "")):
            self.assertEqual(a.PwHistory._file_status(a.SYSTEM_AUTH),
                             (True, "system-auth pam_pwhistory remember=10（模組預設）"))
        with env(pam_fs(UNIX_LINE.replace("use_authtok", "remember=5"))):
            ok, cur = a.PwHistory._file_status(a.SYSTEM_AUTH)
        self.assertTrue(ok)
        self.assertIn("pam_unix remember=5", cur)

    def test_fix_pam_remember_too_low(self):
        ctx = FakeCtx()
        with env(pam_fs(self.HIST % "remember=1")):
            with self.assertRaises(ManualRequired):
                self.r.fix(ctx, FakeFx(ctx))

    def test_fix_hist_without_conf(self):
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        with env(pam_fs(self.HIST % "")):
            self.r.fix(ctx, fx)
        self.assertTrue(any("remember=10" in n for n in fx.notes))
        self.assertEqual(fx.events, [])

    def test_fix_conf_and_enable(self):
        fs = pam_fs()
        fs[a.PWHISTORY_CONF] = "remember = 1\n"
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs), mock.patch.object(a, "authselect_enable") as en:
            self.r.fix(ctx, fx)
        self.assertEqual(a.conf_get(fs[a.PWHISTORY_CONF], "remember"), "3")
        en.assert_called_once_with(fx, "with-pwhistory")


# RHEL8 0223 / RHEL9 0221 顯示登入失敗次數與日期
class TestLastlog(unittest.TestCase):
    r = rule(a.LastlogShowfailed)

    def test_check(self):
        ctx = FakeCtx()
        with env({}):
            self.assertIn("找不到", self.r.check(ctx).current)
        with env({a.POSTLOGIN: "session optional pam_umask.so\n"}):
            self.assertEqual(self.r.check(ctx).status, FAIL)

    def test_fix_refuses_under_authselect(self):
        ctx = FakeCtx()
        with env({}, FakeRunner({"current --raw": res(0, "sssd\n")})):
            with self.assertRaises(ManualRequired):
                self.r.fix(ctx, FakeFx(ctx))

    def test_fix_without_authselect(self):
        fs = {a.POSTLOGIN: "#%PAM-1.0\n# comment\nsession optional pam_umask.so silent\n"}
        ctx = FakeCtx()
        with env(fs, which=False):
            self.r.fix(ctx, FakeFx(ctx, fs=fs))
            self.assertEqual(self.r.check(ctx).status, PASS)
        self.assertEqual(fs[a.POSTLOGIN].splitlines()[2], self.r.LINE)


# RHEL8 0224 / RHEL9 0222 通行碼雜湊演算法
class TestHashSha512(unittest.TestCase):
    r = rule(a.HashSha512)

    def test_check_pam_bad_no_libuser(self):
        fs = pam_fs(UNIX_LINE.replace("sha512", "md5"), pa=PWQ_LINE % "")
        fs[a.LOGIN_DEFS] = "ENCRYPT_METHOD SHA512\n"
        with env(fs):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("未安裝 libuser", c.current)
        self.assertIn("system-auth pam_unix.so md5", c.current)
        self.assertIn("password-auth 無 pam_unix.so", c.current)

    def test_fix(self):
        fs = pam_fs(UNIX_LINE.replace("sha512", "md5"))
        fs[a.LIBUSER_CONF] = "[defaults]\ncrypt_style = md5\n"
        fs[a.LOGIN_DEFS] = "ENCRYPT_METHOD MD5\n"
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            self.r.fix(ctx, fx)
        self.assertEqual(a.ini_get(fs[a.LIBUSER_CONF], "defaults", "crypt_style"), "sha512")
        self.assertEqual(a.te.get_kv(fs[a.LOGIN_DEFS], "ENCRYPT_METHOD"), "SHA512")
        self.assertTrue(fx.partial)  # PAM 不自動改
        self.assertNotIn(a.SYSTEM_AUTH, fx.kinds("write"))


# ---- 通行碼期限 ----

# RHEL8 0225、0226、0228 / RHEL9 0223、0224、0226 通行碼期限（預設值與既有帳號）
class TestShadowAging(unittest.TestCase):
    def _rule(self, key):
        return [r for r in a.RULES if isinstance(r, a.ShadowAging) and r.key == key][0]

    def test_check_no_shadow(self):
        with env({}):
            self.assertEqual(self._rule("PASS_MIN_DAYS").check(FakeCtx()).status, ERROR)

    def test_check_many_bad(self):
        shadow = "".join("u%d:$6$x:19000:0:90:7::\n" % i for i in range(25))
        fs = {"/etc/shadow": shadow, a.LOGIN_DEFS: "PASS_MIN_DAYS 1\n"}
        with env(fs):
            c = self._rule("PASS_MIN_DAYS").check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("…共 25 個", c.current)

    def test_inactive_guard_skips_expiring(self):
        # 套用 INACTIVE 後會立即停用的帳號略過（避免鎖死），其餘以 chage -I 設定
        today = a._today()
        shadow = ("broken:line\n"
                  "old:$6$x:0:0:90:7::\n"
                  "bob:$6$x:%d:0:90:7::\n"
                  "locked:!!:%d:0:90:7::\n"
                  "ok:$6$x:%d:0:90:7:30:\n" % (today - 10, today - 10, today - 10))
        fs = {"/etc/shadow": shadow, a.USERADD_DEFAULTS: "GROUP=100\nINACTIVE=-1\n"}
        r = self._rule("INACTIVE")
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            r.fix(ctx, fx)
        self.assertEqual(a.te.get_kv(fs[a.USERADD_DEFAULTS], "INACTIVE"), "30")
        self.assertEqual([e for e in fx.events if e[0] == "chage"], [("chage", "bob", "-I", "30")])
        self.assertTrue(fx.partial)
        self.assertTrue(any("old" in n for n in fx.notes))


# ---- sudo、maxlogins、系統帳號 ----

# RHEL8 0231 / RHEL9 0229 要求使用者必須經過身分鑑別才能提升權限
class TestSudoAuth(unittest.TestCase):
    def test_unreadable(self):
        fs = {"/etc/sudoers": None}
        with env(fs):
            c = rule(a.SudoAuth).check(FakeCtx())
        self.assertEqual(c.status, ERROR)


# RHEL8 0232 / RHEL9 0230 限制每個帳號可同時登入之數量
class TestMaxLogins(unittest.TestCase):
    r = rule(a.MaxLogins)

    def test_check_and_fix(self):
        fs = pam_fs(pam(limits=False))
        fs[a.LIMITS] = "* hard maxlogins 20\n"
        fs["/etc/security/limits.d/10-x.conf"] = "* - maxlogins 5\n"
        ctx = FakeCtx()
        with env(fs):
            c = self.r.check(ctx)
            fx = FakeFx(ctx, fs=fs)
            self.r.fix(ctx, fx)
        self.assertEqual(c.status, FAIL)
        self.assertIn("未啟用 pam_limits", c.current)
        self.assertIn(a.te.MARK + "* hard maxlogins 20", fs[a.LIMITS])
        self.assertNotIn("/etc/security/limits.d/10-x.conf", fx.kinds("write"))
        self.assertIn("* hard maxlogins 10", fs[a.LIMITS_GCB])
        self.assertTrue(fx.partial)


# RHEL8 0237 / RHEL9 0235 系統帳號登入方式
class TestSystemAccounts(unittest.TestCase):
    r = rule(a.SystemAccounts)

    def test_check(self):
        with env({}):
            self.assertEqual(self.r.check(FakeCtx()).status, ERROR)
        fs = {"/etc/shadow": "daemon:$6$abc:1::::::\nbin:*:1::::::\n",
              "/etc/passwd": ("root:x:0:0::/root:/bin/bash\ndaemon:x:2:2::/sbin:/bin/bash\n"
                              "bin:x:1:1::/bin:/sbin/nologin\nsync:x:5:0::/sbin:/bin/sync\n"
                              "alice:x:1000:1000::/home/alice:/bin/bash\n")}
        with env(fs):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "可登入殼層：daemon(/bin/bash)；未鎖定：daemon")


# ---- GNOME ----

# RHEL8 0234、0235、0239 / RHEL9 0232、0233、0237 GNOME dconf 設定共用流程
class TestDconf(unittest.TestCase):
    def test_gnome_when(self):
        with env({}, pkg=True):
            self.assertIsNone(a.gnome_when(FakeCtx()))
        with env({"/usr/bin/gnome-shell": ""}):
            self.assertIsNone(a.gnome_when(FakeCtx()))
        with env({}):
            self.assertIn("未安裝 GNOME", a.gnome_when(FakeCtx()))

    def test_issues(self):
        kf = a.DCONF_DIR + "/00-x"
        with env({kf: "[a]\nb=1\n"}):
            self.assertEqual(len(a.dconf_issues()), 2)  # profile 未設定、未 dconf update
        fs = {a.DCONF_PROFILE: "user-db:user\nsystem-db:local\n", kf: "", a.DCONF_DB: ""}
        with env(fs, mtimes={kf: 200, a.DCONF_DB: 100}):
            self.assertEqual(a.dconf_issues(), ["設定檔較 dconf 資料庫新，尚未執行 dconf update"])
        with env(fs, mtimes={kf: 100, a.DCONF_DB: 200}):
            self.assertEqual(a.dconf_issues(), [])

    def test_ensure_profile(self):
        fx = FakeFx(FakeCtx())
        with env(fx.fs):
            a.dconf_ensure_profile(fx)
        self.assertEqual(fx.fs[a.DCONF_PROFILE], "user-db:user\nsystem-db:local\n")
        fs = {a.DCONF_PROFILE: "user-db:user\n"}
        fx = FakeFx(FakeCtx(), fs=fs)
        with env(fs):
            a.dconf_ensure_profile(fx)
        self.assertEqual(fs[a.DCONF_PROFILE], "user-db:user\nsystem-db:local\n")

    def test_update_requires_dconf(self):
        fx = FakeFx(FakeCtx())
        with env({}, which=False):
            with self.assertRaises(ManualRequired):
                a.dconf_update(fx)
        self.assertEqual(fx.events, [])


# RHEL8 0234、0235 / RHEL9 0232、0233 使用者會談鎖定、GNOME 使用者會談逾時時間
class TestDconfKey(unittest.TestCase):
    def _rule(self, key):
        return [r for r in a.RULES if isinstance(r, a.DconfKey) and r.key == key][0]

    def test_check(self):
        r = self._rule("idle-delay")
        with env({}):
            self.assertIn("未設定", r.check(FakeCtx()).current)
        kf = a.DCONF_DIR + "/00-screensaver"
        fs = {a.DCONF_PROFILE: "system-db:local\n", kf: "[org/gnome/desktop/session]\nidle-delay=uint32 600\n",
              a.DCONF_DB: ""}
        with env(fs, mtimes={kf: 1, a.DCONF_DB: 2}):
            self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_fix_existing_bad_value(self):
        r = self._rule("lock-enabled")
        kf = a.DCONF_DIR + "/10-custom"
        fs = {a.DCONF_PROFILE: "system-db:local\n", kf: "[org/gnome/desktop/screensaver]\nlock-enabled=false\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            r.fix(ctx, fx)
        self.assertEqual(a.ini_get(fs[kf], "org/gnome/desktop/screensaver", "lock-enabled"), "true")
        self.assertNotIn(a.DCONF_SCREENSAVER, fs)
        self.assertLess(idx(fx, ("undo", "dconf update")), idx(fx, ("run", "dconf update")))

    def test_fix_new_value(self):
        r = self._rule("idle-delay")
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        with env(fx.fs):
            r.fix(ctx, fx)
        self.assertEqual(a.ini_get(fx.fs[a.DCONF_SCREENSAVER], "org/gnome/desktop/session", "idle-delay"),
                         "uint32 900")
        self.assertIn(a.DCONF_PROFILE, fx.fs)
        self.assertIn(("run", "dconf update"), fx.events)


# RHEL8 0239 / RHEL9 0237 防止修改圖形使用者介面(GUI)設定
class TestDconfLocks(unittest.TestCase):
    r = rule(a.DconfLocks)

    def test_fix_then_check(self):
        fs = {a.DCONF_PROFILE: "system-db:local\n",
              a.DCONF_LOCKS + "/session": "/org/gnome/desktop/session/idle-delay\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            self.assertIn("未鎖定", self.r.check(ctx).current)
            self.r.fix(ctx, fx)
        lines = fs[self.r.FILE].splitlines()
        self.assertEqual(sorted(lines), sorted(a.LOCK_PATHS))
        fs[a.DCONF_DB] = ""
        with env(fs, mtimes={a.DCONF_DB: 9}):
            self.assertEqual(self.r.check(ctx).status, PASS)


# RHEL8 0236 / RHEL9 0234 禁止 GNOME 使用者自動登入
class TestGdmAutoLogin(unittest.TestCase):
    r = rule(a.GdmAutoLogin)

    def test_when(self):
        with env({a.GDM_CUSTOM: ""}):
            self.assertIsNone(self.r.when(FakeCtx()))
        with env({}):
            self.assertEqual(self.r.when(FakeCtx()), "未安裝 gdm 圖形登入畫面，本項目是登入畫面設定，不需設定")

    def test_check_fix(self):
        fs = {a.GDM_CUSTOM: "[security]\nfoo=1"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            self.assertEqual(self.r.check(ctx).current, "AutomaticLoginEnable=未設定")
            self.r.fix(ctx, fx)
            self.assertEqual(self.r.check(ctx).status, PASS)
        self.assertEqual(fs[a.GDM_CUSTOM], "[security]\nfoo=1\n\n[daemon]\nAutomaticLoginEnable=false\n")


# ---- shell 設定 ----

# RHEL8 0238 / RHEL9 0236 Bash shell 閒置時登出時間
class TestTmout(unittest.TestCase):
    def test_fix(self):
        fs = {a.PROFILE: "export TMOUT=1800\n", a.BASHRC: "# bashrc\n", a.TMOUT_FILE: "old\n",
              a.PROFILE_D + "/empty.sh": ""}
        r = rule(a.Tmout)
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            r.fix(ctx, fx)
            self.assertEqual(r.check(ctx).status, PASS)
        self.assertEqual(fs[a.PROFILE], "export TMOUT=900\n")
        self.assertEqual(fs[a.TMOUT_FILE], a.TMOUT_SCRIPT)
        self.assertNotIn(a.PROFILE_D + "/empty.sh", fx.kinds("write"))


# RHEL8 0240 / RHEL9 0238 root 帳號所屬群組
class TestRootGid(unittest.TestCase):
    r = rule(a.RootGid)

    def test_check(self):
        with env({"/etc/passwd": "bin:x:1:1::/bin:/sbin/nologin\n"}):
            self.assertEqual(self.r.check(FakeCtx()).status, ERROR)

    def test_fix_undo_first(self):
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        with env({"/etc/passwd": "root:x:0:10::/root:/bin/bash\n"}):
            self.assertEqual(self.r.check(ctx).status, FAIL)
            self.r.fix(ctx, fx)
        self.assertEqual(fx.events, [("undo", "usermod -g 10 root"), ("run", "usermod -g 0 root")])


# RHEL8 0241 / RHEL9 0239 所有使用者帳號之預設 umask；RHEL9 0309 root 之預設 umask
class TestUmask(unittest.TestCase):
    def test_fix_skips_own_file(self):
        fs = {a.PROFILE: "umask 022\n", a.BASHRC: "", a.UMASK_FILE: "umask 002\n"}
        r = rule(a.Umask)
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            r.fix(ctx, fx)
        self.assertEqual(fs[a.PROFILE], "umask 027\n")
        self.assertIn("umask 027", fs[a.BASHRC])
        self.assertEqual(fs[a.UMASK_FILE], "# GCB 所有使用者帳號之預設 umask（gcb-checker 產生）\numask 027\n")
        self.assertEqual(fx.kinds("write").count(a.UMASK_FILE), 1)

    def test_umask_value_invalid(self):
        self.assertIsNone(a.umask_value(None))
        self.assertIsNone(a.umask_value("u=rwx,bad"))
        self.assertFalse(a.umask_ok(a.umask_value("a+w")))

    def test_root_umask_fix_existing(self):
        fs = {"/root/.bashrc": "umask 022\n", "/root/.bash_profile": "umask 077\n"}
        r = rule(a.RootUmask)
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            r.fix(ctx, fx)
            self.assertEqual(r.check(ctx).status, PASS)
        self.assertEqual(fx.kinds("write"), ["/root/.bashrc"])


# ---- su ----

class FakeGrp(object):
    def __init__(self, groups):
        self.groups = groups

    def getgrnam(self, name):
        if name not in self.groups:
            raise KeyError(name)
        gid, mem = self.groups[name]
        return mock.Mock(gr_gid=gid, gr_mem=mem)


def fake_pwd(users):
    return mock.Mock(getpwall=lambda: [mock.Mock(pw_name=n, pw_gid=g) for n, g in users])


# RHEL8 0243 / RHEL9 0241 可使用 su 指令之群組
class TestSuWheel(unittest.TestCase):
    r = rule(a.SuWheel)

    def _env(self, fs, groups, users=(), environ=None):
        st = env(fs, environ=environ)
        st.enter_context(mock.patch.object(a, "grp", FakeGrp(groups)))
        st.enter_context(mock.patch.object(a, "pwd", fake_pwd(users)))
        return st

    def test_apply_inserts_before_first_auth(self):
        out = a.su_wheel_apply("#%PAM-1.0\nauth substack system-auth\n")
        self.assertEqual(out.splitlines()[1], a.SU_LINE)

    def test_members(self):
        with self._env({}, {}):
            self.assertIsNone(a.wheel_members())
        with self._env({}, {"wheel": (10, ["root", "alice"])}, [("bob", 10), ("carol", 100)]):
            self.assertEqual(a.wheel_members(), ["alice", "bob"])

    def test_check(self):
        with self._env({}, {}):
            self.assertEqual(self.r.check(FakeCtx()).status, ERROR)
        with self._env({a.SU_PAM: a.SU_LINE + "\n"}, {}):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("wheel 群組不存在", c.current)

    def test_precondition(self):
        ctx = FakeCtx()
        with self._env({}, {"wheel": (10, ["root"])}):
            self.assertIn("沒有非 root 的成員", self.r.precondition(ctx))
        with self._env({}, {"wheel": (10, ["admin"])}, environ={"SUDO_USER": "ops"}):
            why = self.r.precondition(ctx)
        self.assertIn("gcbtest", why)
        self.assertIn("ops", why)
        with self._env({}, {"wheel": (10, ["ops", "gcbtest"])}, environ={"SUDO_USER": "ops"}):
            self.assertIsNone(self.r.precondition(ctx))
        with self._env({}, {"wheel": (10, ["gcbtest"])}, environ={"SUDO_USER": "root"}):
            self.assertIsNone(self.r.precondition(ctx))

    def test_fix(self):
        fs = {a.SU_PAM: "auth\t\tsufficient\tpam_rootok.so\n#auth\t\trequired\tpam_wheel.so use_uid\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with self._env(fs, {"wheel": (10, ["alice"])}):
            self.r.fix(ctx, fx)
        self.assertTrue(a.su_wheel_status(fs[a.SU_PAM])[0])
        self.assertIn("alice", fx.notes[0])


# ---- RHEL 9 新增 ----

# RHEL9 0312 啟用 without-nullok
class TestWithoutNullok(unittest.TestCase):
    r = rule(a.WithoutNullok)

    def test_check(self):
        fs = pam_fs("auth sufficient pam_unix.so nullok\n")
        with env(fs, which=False):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "未使用 authselect；pam_unix.so 帶 nullok：system-auth auth、password-auth auth")

    def test_precondition_and_fix(self):
        with env({"/etc/shadow": "root:$6$x:1:0:99999:7:::\nguest::1:0:99999:7:::\n"}):
            self.assertIn("guest", self.r.precondition(FakeCtx()))
        with env({"/etc/shadow": "root:$6$x:1:0:99999:7:::\n"}):
            self.assertIsNone(self.r.precondition(FakeCtx()))
        fx = FakeFx(FakeCtx())
        with mock.patch.object(a, "authselect_enable") as en:
            self.r.fix(fx.ctx, fx)
        en.assert_called_once_with(fx, "without-nullok")


# RHEL9 0313 啟用 pam_pwquality、0314 啟用 pam_unix
class TestPamModuleEnabled(unittest.TestCase):
    def test_check(self):
        r = [x for x in a.RULES if isinstance(x, a.PamModuleEnabled) and x.module == "pam_unix.so"][0]
        with env(pam_fs()):
            c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("system-auth auth", c.current)
        full = "".join("%s required pam_unix.so\n" % t for t in ("auth", "account", "password", "session"))
        with env(pam_fs(full)):
            self.assertEqual(r.check(FakeCtx()).status, PASS)


# ---- 僅檢測路徑補強（不依賴容器測試） ----

# RHEL8 0209 / RHEL9 0207 強制 root 通行碼須符合通行碼規則（設定檔旗標）
class TestEnforceForRootConf(unittest.TestCase):
    def test_conf_flag_passes(self):
        fs = pam_fs()
        fs[a.PWQ] = "minlen = 12\nenforce_for_root\n"
        with env(fs):
            c = rule(a.EnforceForRoot).check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "pwquality.conf 已設定 enforce_for_root（與 PAM 參數效果相同）"))


# RHEL8 0221 / RHEL9 0219 帳戶鎖定時間（未設定）
class TestFaillockUnlockUnset(unittest.TestCase):
    def test_default_600(self):
        with env(pam_fs()):
            c = rule(a.FaillockUnlock).check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "unlock_time=未設定（預設 600）、pam_faillock:已啟用")


# RHEL8 0222 / RHEL9 0220 強制執行通行碼歷程記錄（check）
class TestPwHistoryCheck(unittest.TestCase):
    HIST = "password    requisite     pam_pwhistory.so use_authtok\n"

    def test_conf_value_and_reference_file(self):
        fs = pam_fs(self.HIST, pa=UNIX_LINE)
        fs[a.PWHISTORY_CONF] = "remember = 5\n"
        with env(fs):
            c = rule(a.PwHistory).check(FakeCtx())
        # 只以 system-auth 判定；password-auth 僅供參考
        self.assertEqual(c.status, PASS)
        self.assertEqual(c.current, "system-auth pam_pwhistory remember=5（pwhistory.conf）；"
                                    "password-auth 未設定 remember（參考）")

    def test_not_set(self):
        with env(pam_fs()):
            c = rule(a.PwHistory).check(FakeCtx())
        self.assertEqual(c.status, FAIL)


# RHEL8 0224 / RHEL9 0222 通行碼雜湊演算法（合格）
class TestHashSha512Pass(unittest.TestCase):
    def test_all_sha512(self):
        fs = pam_fs()
        fs[a.LIBUSER_CONF] = "[defaults]\ncrypt_style = sha512\n"
        fs[a.LOGIN_DEFS] = "ENCRYPT_METHOD SHA512\n"
        with env(fs):
            c = rule(a.HashSha512).check(FakeCtx())
        self.assertEqual((c.status, c.current),
                         (PASS, "crypt_style=sha512；ENCRYPT_METHOD=SHA512；PAM：pam_unix.so sha512"))


# RHEL8 0231 / RHEL9 0229 要求使用者必須經過身分鑑別才能提升權限
class TestSudoers(unittest.TestCase):
    FS = {"/etc/sudoers": ("Defaults env_reset\n@include /etc/sudoers.local\n#includedir /etc/sudoers.d\n"
                           "#includedir /etc/sudoers.d\n%wheel ALL=(ALL) ALL\n"),
          "/etc/sudoers.local": "ops ALL=(ALL) NOPASSWD: ALL\n",
          "/etc/sudoers.d/90-cloud": "# x NOPASSWD\ncloud ALL=(ALL) NOPASSWD:ALL\n",
          "/etc/sudoers.d/old.bak": "Defaults !authenticate\n"}

    def test_files(self):
        with env(self.FS):
            self.assertEqual(a.sudoers_files(), ["/etc/sudoers", "/etc/sudoers.local",
                                                 "/etc/sudoers.d/90-cloud", "/etc/sudoers.d/old.bak"])

    def test_when_and_check(self):
        r = rule(a.SudoAuth)
        with env({}):
            self.assertEqual(r.when(FakeCtx()), "未安裝 sudo，沒有 sudo 設定需要檢查")
        with env(self.FS):
            self.assertIsNone(r.when(FakeCtx()))
            c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "發現 NOPASSWD/!authenticate：/etc/sudoers.local:1（sudo 不讀取此檔）、"
                                    "/etc/sudoers.d/90-cloud:2、/etc/sudoers.d/old.bak:1（sudo 不讀取此檔）")
        with env({"/etc/sudoers": "root ALL=(ALL) ALL\n"}):
            self.assertEqual(r.check(FakeCtx()).status, PASS)


# RHEL8 0232 / RHEL9 0230 限制每個帳號可同時登入之數量（未設定）
class TestMaxLoginsUnset(unittest.TestCase):
    def test_unset(self):
        with env(pam_fs()):
            c = rule(a.MaxLogins).check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "未設定 * hard maxlogins"))


# RHEL8 0238 / RHEL9 0236 Bash shell 閒置時登出時間（check）
class TestTmoutCheck(unittest.TestCase):
    def test_missing_and_too_long(self):
        fs = {a.PROFILE: "readonly TMOUT=1200; export TMOUT\n", a.BASHRC: "# none\n"}
        with env(fs):
            c = rule(a.Tmout).check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "/etc/bashrc 未設定 TMOUT；/etc/profile(.d)：TMOUT=1200（profile）、"
                                    "readonly:有、export:有")


# RHEL8 0241 / RHEL9 0239 所有使用者帳號之預設 umask（check）
class TestUmaskCheck(unittest.TestCase):
    def test_check(self):
        r = rule(a.Umask)
        fs = {a.PROFILE: "umask 027\n", a.BASHRC: "umask 022\n"}
        with env(fs):
            c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "/etc/bashrc 未設定 umask 027；umask 027（/etc/profile）、umask 022（/etc/bashrc）")
        fs[a.BASHRC] = "umask 077\n"
        fs[a.PROFILE_D + "/x.sh"] = "umask 002\n"
        with env(fs):
            self.assertEqual(r.check(FakeCtx()).status, FAIL)  # profile.d 較寬鬆也不合格
        del fs[a.PROFILE_D + "/x.sh"]
        with env(fs):
            self.assertEqual(r.check(FakeCtx()).status, PASS)


# RHEL8 0242 / RHEL9 0240 在 /etc/login.defs 設定所有使用者之預設 umask
class TestLoginDefsUmask(unittest.TestCase):
    def test_check_fix(self):
        r = rule(a.LoginDefsUmask)
        fs = {a.LOGIN_DEFS: "UMASK\t\t022\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            self.assertEqual(r.check(ctx).current, "UMASK=022")
            r.fix(ctx, fx)
            self.assertEqual(r.check(ctx).status, PASS)
        self.assertEqual(fs[a.LOGIN_DEFS], "UMASK\t\t027\n")
        self.assertTrue(fx.notes)


# RHEL9 0309 root 之預設 umask（未設定時附加）
class TestRootUmaskMissing(unittest.TestCase):
    def test_check_and_append(self):
        r = rule(a.RootUmask)
        fs = {"/root/.bashrc": "# .bashrc\n. /etc/bashrc\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs):
            c = r.check(ctx)
            r.fix(ctx, fx)
            self.assertEqual(r.check(ctx).status, PASS)
        self.assertEqual(c.current, "/root/.bash_profile 未設定 umask；/root/.bashrc 未設定 umask")
        self.assertTrue(fs["/root/.bashrc"].startswith("# .bashrc\n. /etc/bashrc\n"))  # 附加在 source 之後
        self.assertEqual(fx.modes["/root/.bash_profile"], 0o644)


# RHEL9 0312 啟用 without-nullok（authselect 已啟用）
class TestWithoutNullokEnabled(unittest.TestCase):
    def test_pass(self):
        runner = FakeRunner({"current --raw": res(0, "sssd without-nullok\n")})
        with env(pam_fs(), runner):
            c = rule(a.WithoutNullok).check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "authselect sssd：without-nullok 已啟用"))


if __name__ == "__main__":
    unittest.main()
