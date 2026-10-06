# -*- coding: utf-8 -*-
"""ubuntu/access.py 補充單元測試：所有檔案、帳號／群組查詢與指令皆以模擬環境取代。"""
import collections
import contextlib
import fnmatch
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import FakeCtx, FakeFx, FakeRunner, fs_reader, mock, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS, Check  # noqa: E402
from gcb.rules.ubuntu import access as acc  # noqa: E402
from gcb.rules.ubuntu.helpers import U  # noqa: E402

Grp = collections.namedtuple("Grp", "gr_name gr_gid gr_mem")
Pw = collections.namedtuple("Pw", "pw_name pw_gid")


class _St(object):
    def __init__(self, mode=0o100600, uid=0, gid=0):
        self.st_mode, self.st_uid, self.st_gid = mode, uid, gid


@contextlib.contextmanager
def env(fs, which=(), pkgs=(), stats=None, extra_exists=()):
    """模擬 read_text／which／glob／os.path.exists／isfile／os.stat 與套件查詢。"""
    stats = stats or {}

    def _glob(pat):
        return sorted(p for p in fs if fnmatch.fnmatch(p, pat))

    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch.object(acc, "read_text", fs_reader(fs)))
        st.enter_context(mock.patch.object(acc, "which", lambda n: n in which))
        st.enter_context(mock.patch.object(acc.glob, "glob", _glob))
        st.enter_context(mock.patch.object(acc.os.path, "exists",
                                           lambda p: p in fs or p in stats or p in extra_exists))
        st.enter_context(mock.patch.object(acc.os.path, "isfile", lambda p: p in fs or p in stats))
        st.enter_context(mock.patch.object(acc.os, "stat", lambda p: stats.get(p, _St())))
        st.enter_context(mock.patch.object(acc.pkgsvc, "pkg_installed", lambda osi, p: p in pkgs))
        yield


def fx_for(fs, runner=None, dry_run=False):
    return FakeFx(FakeCtx("ubuntu2204", dry_run=dry_run), fs=fs, runner=runner or FakeRunner())


def ctx():
    return FakeCtx("ubuntu2204")


def idx(events, ev):
    return events.index(ev)


STOCK = """Name: Unix authentication
Default: yes
Priority: 256
Conflicts: foo
Auth-Type: Primary
Auth:
\t[success=end default=ignore]\tpam_unix.so nullok try_first_pass
Password-Type: Primary
Password:
\t[success=end default=ignore]\tpam_unix.so obscure sha512
"""
STACK = {"/etc/pam.d/common-auth": "auth [success=1 default=ignore] pam_unix.so nullok\n",
         "/etc/pam.d/common-account": "account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\n",
         acc.COMMON_PASSWORD: "password [success=1 default=ignore] pam_unix.so obscure yescrypt remember=3\n"}


def pam_fs(**extra):
    fs = dict(STACK)
    fs[acc.STOCK_UNIX] = STOCK
    fs["/var/lib/pam/seen"] = ""
    fs.update(extra)
    return fs


# pam-auth-update 共用流程（0180、0181 使用）
class ApplyGcbUnixTest(unittest.TestCase):
    def test_unix_profile_adds_unix_conflict(self):
        out = acc.unix_profile(STOCK, acc.with_remember(3))
        self.assertIn("Conflicts: foo, unix", out)
        self.assertIn("pam_unix.so obscure sha512 remember=3", out)

    def test_guards(self):
        with env({}):
            self.assertRaises(ManualRequired, acc.apply_gcb_unix, fx_for({}), acc.with_yescrypt, "x")
        with env({acc.STOCK_UNIX: "Name: x\n"}, which={"pam-auth-update"}):
            self.assertRaises(ManualRequired, acc.apply_gcb_unix, fx_for({}), acc.with_yescrypt, "x")

    def test_success_order(self):
        fs = pam_fs()
        fx = fx_for(fs)
        with env(fs, which={"pam-auth-update"}):
            acc.apply_gcb_unix(fx, acc.with_yescrypt, "x")
        ev = fx.events
        self.assertEqual(ev[0], ("undo", "pam-auth-update --package"))
        self.assertIn(("backup", "/var/lib/pam/seen"), ev)
        self.assertLess(idx(ev, ("write", acc.GCB_UNIX)), idx(ev, ("run", "pam-auth-update --enable gcb_unix")))
        self.assertIn("pam_unix.so obscure yescrypt", fs[acc.GCB_UNIX])
        self.assertIn(acc.GCB_UNIX, fx.notes[0])

    def test_local_modifications_refused(self):
        fs = pam_fs()
        fx = fx_for(fs, FakeRunner({"pam-auth-update": res(0, "local modifications to /etc/pam.d/common-*")}))
        with env(fs, which={"pam-auth-update"}):
            self.assertRaises(FixError, acc.apply_gcb_unix, fx, acc.with_yescrypt, "x")

    def test_stack_verification_fails(self):
        fs = pam_fs(**{"/etc/pam.d/common-auth": "auth required pam_unix.so\nauth required pam_unix.so\n"})
        fx = fx_for(fs)
        with env(fs, which={"pam-auth-update"}):
            with self.assertRaises(FixError) as cm:
                acc.apply_gcb_unix(fx, acc.with_yescrypt, "x")
        self.assertIn("2 行", str(cm.exception))


# TWGCB-01-014-0156 開機載入程式啟用 AppArmor
class GrubArgsTest(unittest.TestCase):
    def _rule(self):
        return acc.GrubArgs("開機載入程式啟用 AppArmor", ["apparmor=1", "security=apparmor"], U(156))

    def test_check_status(self):
        r = self._rule()
        with mock.patch.object(r.subs[0], "check", return_value=Check(PASS, "a")), \
                mock.patch.object(r.subs[1], "check", return_value=Check(ERROR, "b")):
            self.assertEqual(r.check(ctx()).status, ERROR)
        with mock.patch.object(r.subs[0], "check", return_value=Check(PASS, "a")), \
                mock.patch.object(r.subs[1], "check", return_value=Check(FAIL, "b")):
            c = r.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "apparmor=1：a；security=apparmor：b"))

    def test_fix_dropin_when_overridden(self):
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX=""\n'}
        fx = fx_for(fs)
        with mock.patch.object(acc, "grub_effective_cmdline", return_value="apparmor=1 console=ttyS0"):
            self._rule().fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/default/grub"], 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"\n')
        self.assertEqual(fs["/etc/default/grub.d/99-gcb-apparmor.cfg"],
                         'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX security=apparmor"\n')
        self.assertLess(idx(fx.events, ("undo", "update-grub")), idx(fx.events, ("write", "/etc/default/grub")))
        self.assertEqual(fx.kinds("run"), ["update-grub"])

    def test_fix_dry_run(self):
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX=""\n'}
        fx = fx_for(fs, dry_run=True)
        self._rule().fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/default/grub"], 'GRUB_CMDLINE_LINUX=""\n')


# TWGCB-01-014-0171 at.allow 與 cron.allow 檔案所有權、0172 檔案權限
class CronAllowTest(unittest.TestCase):
    def test_check(self):
        rule = acc.CronAllow("x", U(171), "owner")
        stats = {"/etc/cron.allow": _St(uid=1, gid=0), "/etc/at.deny": _St()}
        with env({}, pkgs={"cron", "at"}, stats=stats):
            c = rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "/etc/cron.allow uid=1 gid=0；/etc/at.deny 存在；/etc/at.allow 不存在")
        # 只裝 cron、未裝 at：GCB 仍要求 at.allow，不可略過
        rule = acc.CronAllow("x", U(172), "perm")
        with env({}, pkgs={"cron"}, stats={"/etc/cron.allow": _St(0o100600)}):
            c = rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "/etc/at.allow 不存在；/etc/cron.allow 符合"))
        stats = {"/etc/cron.allow": _St(0o100600), "/etc/at.allow": _St(0o100600)}
        with env({}, pkgs={"cron"}, stats=stats):
            c = rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "/etc/cron.allow 符合；/etc/at.allow 符合"))

    def test_fix_creates_at_allow_without_at(self):
        rule = acc.CronAllow("x", U(171), "owner")
        fs = {}
        fx = fx_for(fs)
        with env(fs, pkgs={"cron"}, stats={"/etc/cron.allow": _St(0o100600)}):
            rule.fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/at.allow"], "")
        self.assertEqual(fx.modes["/etc/at.allow"], 0o600)

    def test_fix_owner(self):
        rule = acc.CronAllow("x", U(171), "owner")
        fs = {}
        fx = fx_for(fs)
        stats = {"/etc/cron.deny": _St(), "/etc/cron.allow": _St(uid=5, gid=5)}
        with env(fs, pkgs={"cron"}, stats=stats):
            rule.fix(fx.ctx, fx)
        ev = fx.events
        self.assertLess(idx(ev, ("backup", "/etc/cron.deny")), idx(ev, ("run", "rm -f /etc/cron.deny")))
        self.assertIn(("chown", "/etc/cron.allow", "root:root"), ev)
        self.assertEqual(fx.notes, [acc.CronAllow.NOTE])

    def test_fix_perm_creates_allow(self):
        rule = acc.CronAllow("x", U(172), "perm")
        fs = {}
        fx = fx_for(fs)
        with env(fs, pkgs={"at"}, stats={}):
            # 寫入後 fs 有此路徑，os.stat 預設回傳 0600
            rule.fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/at.allow"], "")
        self.assertEqual(fx.modes["/etc/at.allow"], 0o600)
        self.assertEqual(fx.kinds("chmod"), [])
        fs = {"/etc/at.allow": ""}
        fx = fx_for(fs)
        with env(fs, pkgs={"at"}, stats={"/etc/at.allow": _St(0o100644)}):
            rule.fix(fx.ctx, fx)
        self.assertIn(("chmod", "/etc/at.allow", 0o600), fx.events)

    def test_fix_dry_run_skips_attr(self):
        rule = acc.CronAllow("x", U(172), "perm")
        fs = {}
        fx = fx_for(fs, dry_run=True)
        with env(fs, pkgs={"cron"}):
            rule.fix(fx.ctx, fx)
        self.assertEqual(fs, {})
        self.assertEqual(fx.kinds("chmod"), [])


# TWGCB-01-014-0174 通行碼必須至少包含數字個數
class PwqualityTest(unittest.TestCase):
    rule = acc.Pwquality("通行碼必須至少包含數字個數", U(174), "dcredit")

    def test_check_extras(self):
        base = Check(PASS, "dcredit=-1")
        with env({}), mock.patch.object(acc.KvSetting, "check", return_value=base):
            c = self.rule.check(ctx())
        self.assertIn("未安裝 libpam-pwquality", c.current)
        fs = {acc.COMMON_PASSWORD: "password requisite pam_unix.so\n"}
        with env(fs, pkgs={"libpam-pwquality"}), mock.patch.object(acc.KvSetting, "check", return_value=base):
            c = self.rule.check(ctx())
        self.assertIn("未啟用 pam_pwquality", c.current)
        fs = {acc.COMMON_PASSWORD: "password requisite pam_pwquality.so dcredit=1 dcredit=0\n"}
        with env(fs, pkgs={"libpam-pwquality"}), mock.patch.object(acc.KvSetting, "check", return_value=base):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("PAM 參數覆寫：dcredit=0", c.current)

    def test_fix_installs_and_flags_partial(self):
        fs = {"/var/lib/pam/password": ""}
        fx = fx_for(fs)
        with env(fs), mock.patch.object(acc.KvSetting, "fix") as kv_fix:
            self.rule.fix(fx.ctx, fx)
        kv_fix.assert_called_once()
        ev = fx.events
        self.assertLess(idx(ev, ("backup", acc.COMMON_PASSWORD)), idx(ev, ("pkg_install", "libpam-pwquality")))
        self.assertIn(("backup", "/var/lib/pam/password"), ev)
        self.assertTrue(fx.partial)
        self.assertIn("pam-auth-update --enable pwquality", fx.notes[0])

    def test_fix_pam_override_note(self):
        fs = {acc.COMMON_PASSWORD: "password requisite pam_pwquality.so dcredit=2\n"}
        fx = fx_for(fs)
        with env(fs, pkgs={"libpam-pwquality"}), mock.patch.object(acc.KvSetting, "fix"):
            self.rule.fix(fx.ctx, fx)
        self.assertTrue(fx.partial)
        self.assertEqual(len(fx.notes), 1)
        self.assertIn("dcredit=2", fx.notes[0])


# TWGCB-01-014-0179 帳戶鎖定時間
class FaillockTimeTest(unittest.TestCase):
    def setUp(self):
        self.rule = acc.FaillockTime(U(179))

    def test_check_pam_override(self):
        fs = {acc.FAILLOCK_CONF: "fail_interval = 900\nunlock_time = 900\n",
              "/etc/pam.d/common-auth": "auth required pam_faillock.so preauth unlock_time=60\n"}
        with env(fs), mock.patch.object(self.rule._fl, "_pam_active", return_value=True):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("PAM 參數覆寫：common-auth unlock_time=60", c.current)

    def test_fix_permanent_lock_and_enable(self):
        fs = {acc.FAILLOCK_CONF: "fail_interval = 900\nunlock_time = 0\n",
              "/etc/pam.d/common-account": "account required pam_faillock.so fail_interval=0\n"}
        fx = fx_for(fs)
        with env(fs), mock.patch.object(self.rule._fl, "_pam_active", return_value=False):
            self.rule.fix(fx.ctx, fx)
        # unlock_time=0 不自動改
        self.assertEqual(acc.te.get_kv(fs[acc.FAILLOCK_CONF], "unlock_time"), "0")
        self.assertTrue(fx.partial)
        self.assertIn("永久鎖定", fx.notes[0])
        self.assertIn(("run", "pam-auth-update --enable gcb_faillock gcb_faillock_notify"), fx.events)
        for p in acc.UBUNTU_FAILLOCK_PROFILES:
            self.assertIn(p, fs)
        self.assertIn("common-account fail_interval=0", fx.notes[-1])


# TWGCB-01-014-0180 強制執行通行碼歷程記錄
class PassRememberTest(unittest.TestCase):
    rule = acc.PassRemember(U(180))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).current, "common-password 未找到 pam_unix.so")
        fs = {acc.COMMON_PASSWORD: "password required pam_pwhistory.so\npassword required pam_unix.so\n"}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "pam_pwhistory.so remember=10（預設）"))

    def test_fix_creates_opasswd(self):
        fs = pam_fs()
        fx = fx_for(fs)
        with env(fs, which={"pam-auth-update"}):
            self.rule.fix(fx.ctx, fx)
        self.assertIn("remember=3", fs[acc.GCB_UNIX])
        self.assertEqual(fs[acc.PassRemember.OPASSWD], "")
        self.assertEqual(fx.modes[acc.PassRemember.OPASSWD], 0o600)


# TWGCB-01-014-0181 系統通行碼雜湊演算法
class HashAlgorithmTest(unittest.TestCase):
    def test_fix_applies_profile_when_not_yescrypt(self):
        fs = pam_fs(**{acc.COMMON_PASSWORD: "password [success=1] pam_unix.so obscure sha512\n",
                       "/etc/login.defs": "ENCRYPT_METHOD SHA512\n"})
        fx = fx_for(fs)
        with env(fs, which={"pam-auth-update"}):
            # 驗證堆疊時 common-password 仍為一行 pam_unix.so
            acc.HashAlgorithm(U(181)).fix(fx.ctx, fx)
        self.assertIn(("run", "pam-auth-update --enable gcb_unix"), fx.events)
        self.assertIn("pam_unix.so obscure yescrypt", fs[acc.GCB_UNIX])
        self.assertEqual(acc.te.get_kv(fs["/etc/login.defs"], "ENCRYPT_METHOD"), "yescrypt")


# TWGCB-01-014-0182 使用者通行碼雜湊演算法
class UserHashTest(unittest.TestCase):
    rule = acc.UserHashAlgorithm(U(182))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).status, ERROR)
        fs = {"/etc/shadow": "root:!:1::::::\na:$y$x:1::::::\nb:$6$x:1::::::\nc:$9$x:1::::::\n",
              "/etc/login.defs": "ENCRYPT_METHOD YESCRYPT\n"}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("b(sha512), c(未知($9$))", c.current)
        with env({"/etc/shadow": "a:$y$x:1::::::\n", "/etc/login.defs": "ENCRYPT_METHOD yescrypt\n"}):
            self.assertEqual(self.rule.check(ctx()).status, PASS)


# TWGCB-01-014-0183 通行碼最短使用期限、0186 帳號停用前之天數
class ShadowAgingTest(unittest.TestCase):
    def _inactive(self):
        return [r for r in acc.RULES if r.ids == U(186)][0]

    def test_check(self):
        rule = [r for r in acc.RULES if r.ids == U(183)][0]
        with env({}):
            self.assertEqual(rule.check(ctx()).status, ERROR)
        shadow = "short:line\n" + "".join("u%d:$y$h:19000:0:99999:7:::\n" % i for i in range(22))
        with env({"/etc/shadow": shadow, "/etc/login.defs": "PASS_MIN_DAYS\t1\n"}):
            c = rule.check(ctx())
            self.assertEqual(len(acc.read_shadow()), 22)  # 欄位不足的行略過
        self.assertEqual(c.status, FAIL)
        self.assertIn("…共 22 個", c.current)

    def test_fix_guard_and_chage_order(self):
        rule = self._inactive()
        shadow = "old:$y$h:100:0:10:7:::\nok:$y$h:20000:0:99999:7:45:\n"
        fs = {"/etc/shadow": shadow, "/etc/default/useradd": "INACTIVE=-1\n"}
        fx = fx_for(fs)
        with env(fs), mock.patch.object(acc, "_today", return_value=20010):
            rule.fix(fx.ctx, fx)
        self.assertEqual(acc.te.get_kv(fs["/etc/default/useradd"], "INACTIVE"), "30")
        self.assertTrue(fx.partial)
        self.assertIn("帳號 old", fx.notes[0])
        ev = fx.events
        self.assertNotIn(("run", "chage --inactive 30 old"), ev)
        self.assertLess(idx(ev, ("undo", "chage --inactive 45 ok")), idx(ev, ("run", "chage --inactive 30 ok")))


# TWGCB-01-014-0187 要求使用者必須經過身分鑑別才能提升權限
class SudoAuthTest(unittest.TestCase):
    rule = acc.SudoAuth(U(187))

    def test_check_skips_non_file_and_unreadable(self):
        # /etc/sudoers.d/sub 為目錄（不在 fs、isfile 為 False）
        fs = {"/etc/sudoers": "root ALL=(ALL) ALL\n"}
        with env(fs), mock.patch.object(acc.glob, "glob", return_value=["/etc/sudoers.d/sub"]):
            self.assertEqual(self.rule.check(ctx()).status, PASS)
        with env({}, stats={"/etc/sudoers": _St()}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (ERROR, "無法讀取 /etc/sudoers"))


# TWGCB-01-014-0188 通行碼最後變更日期
class PassLastChangeTest(unittest.TestCase):
    def test_check(self):
        rule = acc.PassLastChange(U(188))
        with env({}):
            self.assertEqual(rule.check(ctx()).status, ERROR)
        with env({"/etc/shadow": "a:$y$h:99999:0:99999:7:::\nb:$y$h:100:0:99999:7:::\n"}), \
                mock.patch.object(acc, "_today", return_value=20000):
            c = rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "最後變更日期在未來的帳號：a"))


# TWGCB-01-014-0189 系統帳號登入方式
class SystemAccountsTest(unittest.TestCase):
    def test_check(self):
        rule = acc.SystemAccounts(U(189))
        with env({}):
            self.assertEqual(rule.check(ctx()).status, ERROR)
        fs = {"/etc/shadow": "daemon:*:1::::::\nsvc:$y$h:1::::::\n",
              "/etc/passwd": "root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n"
                             "svc:x:200:200::/:/bin/bash\nuser:x:1000:1000::/:/bin/bash\n"}
        with env(fs):
            c = rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "可登入殼層：svc(/bin/bash)；未鎖定：svc"))


# TWGCB-01-014-0190 Bash shell 閒置時登出時間
class TmoutTest(unittest.TestCase):
    def test_fix(self):
        fs = {"/etc/profile": "TMOUT=3600\n", acc.TMOUT_FILE: "old\n"}
        fx = fx_for(fs)
        with env(fs):
            acc.Tmout(U(190)).fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/profile"], "TMOUT=900\n")
        self.assertEqual(fs[acc.TMOUT_FILE], acc.TMOUT_SCRIPT)
        self.assertNotIn(("write", "/etc/bash.bashrc"), fx.events)


# TWGCB-01-014-0191 root 帳號所屬群組
class RootGidTest(unittest.TestCase):
    rule = acc.RootGid(U(191))

    def test_check_no_root(self):
        with env({"/etc/passwd": "a:x:1:1::/:/bin/sh\n"}):
            self.assertEqual(self.rule.check(ctx()).status, ERROR)

    def test_fix_undo_before_usermod(self):
        fx = fx_for({})
        with env({"/etc/passwd": "root:x:0:10::/root:/bin/bash\n"}):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("undo", "usermod -g 10 root"), ("run", "usermod -g 0 root")])


# TWGCB-01-014-0192 所有使用者帳號之預設 umask
class UmaskTest(unittest.TestCase):
    def test_symbolic_invalid(self):
        self.assertIsNone(acc.umask_value("u+rwx"))

    def test_fix(self):
        fs = {"/etc/profile": "umask 022 # x\n", acc.UMASK_FILE: "old\n", "/etc/login.defs": "UMASK 022\n",
              "/etc/bash.bashrc": "# system-wide .bashrc"}
        fx = fx_for(fs)
        with env(fs):
            acc.Umask(U(192)).fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/profile"], "umask 027 # x\n")
        self.assertEqual(fs["/etc/bash.bashrc"], "# system-wide .bashrc\n# GCB TWGCB-01-014-0192 預設 umask（gcb-checker 加入）\numask 027\n")
        self.assertTrue(fs[acc.UMASK_FILE].endswith("umask 027\n"))
        self.assertEqual(fs["/etc/login.defs"], "UMASK 022\n")
        self.assertIn("UMASK=022", fx.notes[0])


SU_TEXT = "auth sufficient pam_rootok.so\nauth required pam_wheel.so deny group=nosu\n@include common-auth\n"


# TWGCB-01-014-0193 可使用 su 指令之群組
class SuGroupTest(unittest.TestCase):
    rule = acc.SuGroup(U(193))

    @contextlib.contextmanager
    def accounts(self, groups, users):
        def getgrnam(n):
            if n not in groups:
                raise KeyError(n)
            return groups[n]
        with mock.patch.object(acc.grp, "getgrnam", getgrnam), \
                mock.patch.object(acc.pwd, "getpwall", lambda: users):
            yield

    def test_apply_keeps_deny_and_no_rootok(self):
        out = acc.su_wheel_apply(SU_TEXT)
        self.assertIn("auth required pam_wheel.so deny group=nosu", out.splitlines())
        self.assertEqual(out.splitlines()[1], acc.SU_LINE)
        out = acc.su_wheel_apply("# c\nauth required pam_wheel.so group=wheel\n@include common-auth\n")
        # 既有的 pam_wheel 限制行被註解，GCB 設定行插在第一個 auth 之前
        self.assertEqual(out.splitlines(), ["# c", acc.te.MARK + "auth required pam_wheel.so group=wheel",
                                            acc.SU_LINE, "@include common-auth"])

    def test_sugroup_admins(self):
        groups = {"sugroup": Grp("sugroup", 900, ["alice", "root", "bob"]), "sudo": Grp("sudo", 27, ["alice"])}
        users = [Pw("carol", 900), Pw("carol2", 27)]
        with self.accounts(groups, users):
            self.assertEqual(acc.sugroup_admins(), ["alice"])
        groups["admin"] = Grp("admin", 28, ["bob"])
        with self.accounts(groups, users + [Pw("carol", 28)]):
            self.assertEqual(acc.sugroup_admins(), ["alice", "bob", "carol"])
        with self.accounts({}, []):
            self.assertIsNone(acc.sugroup_admins())

    def test_check_and_precondition(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).status, ERROR)
        groups = {"sugroup": Grp("sugroup", 900, ["alice"]), "sudo": Grp("sudo", 27, ["alice"])}
        with self.accounts(groups, []):
            self.assertIsNone(self.rule.precondition(ctx()))
        with self.accounts({}, []):
            self.assertIn("sugroup", self.rule.precondition(ctx()))

    def test_fix(self):
        fs = {acc.SU_PAM: SU_TEXT}
        fx = fx_for(fs)
        groups = {"sugroup": Grp("sugroup", 900, ["alice"]), "sudo": Grp("sudo", 27, ["alice"])}
        with env(fs), self.accounts(groups, []):
            self.rule.fix(fx.ctx, fx)
        self.assertTrue(acc.su_wheel_status(fs[acc.SU_PAM])[0])
        self.assertIn("alice", fx.notes[0])


# 適用條件：TWGCB-01-014-0156 GRUB、0171 cron/at、0187 sudo
class WhenTest(unittest.TestCase):
    def test_when(self):
        grub = acc.GrubArgs("x", ["apparmor=1"], U(156))
        cron = acc.CronAllow("x", U(171), "owner")
        sudo = acc.SudoAuth(U(187))
        with env({}):
            self.assertIn("未使用 GRUB", grub.when(ctx()))
            self.assertEqual(cron.when(ctx()), "未安裝 cron 與 at，沒有排程設定需要限制")
            self.assertEqual(sudo.when(ctx()), "未安裝 sudo，沒有 sudo 設定需要檢查")
        with env({"/etc/default/grub": "", "/etc/sudoers": ""}, pkgs={"at"}):
            self.assertIsNone(grub.when(ctx()))
            self.assertIsNone(cron.when(ctx()))
            self.assertIsNone(sudo.when(ctx()))


# TWGCB-01-014-0174 通行碼必須至少包含數字個數（合格）
class PwqualityPassTest(unittest.TestCase):
    def test_pass_returns_base(self):
        rule = acc.Pwquality("x", U(174), "dcredit")
        base = Check(PASS, "dcredit=-1")
        fs = {acc.COMMON_PASSWORD: "password requisite pam_pwquality.so retry=3 dcredit=-1\n"}
        with env(fs, pkgs={"libpam-pwquality"}), mock.patch.object(acc.KvSetting, "check", return_value=base):
            self.assertIs(rule.check(ctx()), base)


# TWGCB-01-014-0179 帳戶鎖定時間（修改 faillock.conf）
class FaillockTimeFixTest(unittest.TestCase):
    def test_fix_sets_both(self):
        rule = acc.FaillockTime(U(179))
        fs = {acc.FAILLOCK_CONF: "# deny = 3\nfail_interval = 0\nunlock_time = 60\n"}
        fx = fx_for(fs)
        with env(fs), mock.patch.object(rule._fl, "_pam_active", return_value=True):
            rule.fix(fx.ctx, fx)
        text = fs[acc.FAILLOCK_CONF]
        self.assertEqual((acc.te.get_kv(text, "fail_interval"), acc.te.get_kv(text, "unlock_time")), ("900", "900"))
        self.assertFalse(fx.partial)
        self.assertEqual(fx.kinds("run"), [])  # pam_faillock 已啟用
        with env(fs), mock.patch.object(rule._fl, "_pam_active", return_value=True):
            self.assertEqual(rule.check(ctx()).status, PASS)


# TWGCB-01-014-0180 強制執行通行碼歷程記錄（檢查）
class PassRememberCheckTest(unittest.TestCase):
    rule = acc.PassRemember(U(180))

    def test_check(self):
        with env({acc.COMMON_PASSWORD: "password [success=1] pam_unix.so remember=5\n"}):
            self.assertEqual(self.rule.check(ctx()).current, "pam_unix.so remember=5")
        with env({acc.COMMON_PASSWORD: "password required pam_pwhistory.so remember=2\npassword x pam_unix.so\n"}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "pam_unix.so remember=未設定"))


# TWGCB-01-014-0181 系統通行碼雜湊演算法（檢查與只改 login.defs）
class HashAlgorithmCheckTest(unittest.TestCase):
    rule = acc.HashAlgorithm(U(181))

    def test_check(self):
        fs = {acc.COMMON_PASSWORD: "password x pam_unix.so obscure yescrypt\n", "/etc/login.defs": "ENCRYPT_METHOD YESCRYPT\n"}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "pam_unix.so：yescrypt；ENCRYPT_METHOD=YESCRYPT"))
        with env({}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "pam_unix.so：未找到；ENCRYPT_METHOD=未設定"))
        with env({acc.COMMON_PASSWORD: "password x pam_unix.so yescrypt sha512\n"}):
            self.assertIn("yescrypt sha512", self.rule.check(ctx()).current)

    def test_fix_pam_ok_only_login_defs(self):
        fs = {acc.COMMON_PASSWORD: "password x pam_unix.so yescrypt\n", "/etc/login.defs": "ENCRYPT_METHOD SHA512\n"}
        fx = fx_for(fs)
        with env(fs):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), ["/etc/login.defs"])
        self.assertEqual(fx.kinds("run"), [])


# TWGCB-01-014-0187 要求使用者必須經過身分鑑別才能提升權限
class SudoAuthHitsTest(unittest.TestCase):
    def test_hits(self):
        fs = {"/etc/sudoers": "# x NOPASSWD\nroot ALL=(ALL) ALL\n",
              "/etc/sudoers.d/cloud": "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
              "/etc/sudoers.d/old.bak": "Defaults !authenticate\n"}
        with env(fs):
            c = acc.SudoAuth(U(187)).check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "發現 NOPASSWD/!authenticate：/etc/sudoers.d/cloud:1、"
                                    "/etc/sudoers.d/old.bak:1（sudo 不讀取此檔）")


# TWGCB-01-014-0188 通行碼最後變更日期（合格）
class PassLastChangePassTest(unittest.TestCase):
    def test_pass(self):
        with env({"/etc/shadow": "a:$y$h:100:0:99999:7:::\nb:!:99999:0:99999:7:::\n"}), \
                mock.patch.object(acc, "_today", return_value=20000):
            self.assertEqual(acc.PassLastChange(U(188)).check(ctx()).status, PASS)


# TWGCB-01-014-0190 Bash shell 閒置時登出時間（檢查）
class TmoutCheckTest(unittest.TestCase):
    rule = acc.Tmout(U(190))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).current, "未設定 TMOUT")
        with env({acc.TMOUT_FILE: acc.TMOUT_SCRIPT}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "TMOUT=900（%s）；readonly:有、export:有" % acc.TMOUT_FILE))
        with env({"/etc/profile": "TMOUT=1800\n"}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "TMOUT=1800（/etc/profile）；readonly:無、export:無"))


# TWGCB-01-014-0191 root 帳號所屬群組（合格）
class RootGidPassTest(unittest.TestCase):
    def test_pass(self):
        with env({"/etc/passwd": "root:x:0:0::/root:/bin/bash\n"}):
            self.assertEqual(acc.RootGid(U(191)).check(ctx()).current, "GID 0")


# TWGCB-01-014-0192 所有使用者帳號之預設 umask（檢查）
class UmaskCheckTest(unittest.TestCase):
    rule = acc.Umask(U(192))

    def test_check(self):
        with env({"/etc/login.defs": "UMASK 022\n"}):
            c = self.rule.check(ctx())
        self.assertEqual(c.current, "shell 設定檔未設定 umask；login.defs UMASK=022（pam_umask，僅供參考）")
        # 只有 /etc/profile 設定：GCB 也要求 /etc/bash.bashrc（非登入的互動式 shell）
        with env({"/etc/profile": "umask u=rwx,g=rx,o=\n"}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current),
                         (FAIL, "umask u=rwx,g=rx,o=（/etc/profile）；/etc/bash.bashrc 未設定 umask（非登入的互動式 shell 不會套用）"
                                "；login.defs UMASK=未設定（pam_umask，僅供參考）"))
        with env({"/etc/profile": "umask u=rwx,g=rx,o=\n", "/etc/bash.bashrc": "umask 027\n"}):
            self.assertEqual(self.rule.check(ctx()).status, PASS)
        with env({"/etc/bash.bashrc": "umask 002\n"}):
            self.assertEqual(self.rule.check(ctx()).status, FAIL)


# TWGCB-01-014-0193 可使用 su 指令之群組（檢查）
class SuGroupCheckTest(unittest.TestCase):
    rule = acc.SuGroup(U(193))

    def test_check(self):
        good = "auth sufficient pam_rootok.so\n" + acc.SU_LINE + "\n@include common-auth\n"
        groups = {"sugroup": Grp("sugroup", 900, []), "sudo": Grp("sudo", 27, ["alice"])}

        def getgrnam(n):
            if n not in groups:
                raise KeyError(n)
            return groups[n]
        with env({acc.SU_PAM: good}), mock.patch.object(acc.grp, "getgrnam", getgrnam), \
                mock.patch.object(acc.pwd, "getpwall", lambda: []):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, PASS)
        self.assertTrue(c.current.endswith("sugroup 管理帳號：無"))
        with env({acc.SU_PAM: good}), mock.patch.object(acc.grp, "getgrnam", side_effect=KeyError("x")):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)  # 群組不存在
        self.assertTrue(c.current.endswith("sugroup 不存在"))


if __name__ == "__main__":
    unittest.main()
