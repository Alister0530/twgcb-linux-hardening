# -*- coding: utf-8 -*-
"""ubuntu/audit.py 補充單元測試：所有指令、檔案與目錄查詢皆以模擬環境取代（find_privileged 用暫存目錄）。"""
import contextlib
import fnmatch
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import FakeCtx, FakeFx, FakeRunner, fs_reader, mock, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, NA, PASS, Check  # noqa: E402
from gcb.rules.ubuntu import audit as au  # noqa: E402
from gcb.rules.ubuntu.helpers import U  # noqa: E402


class _St(object):
    def __init__(self, mode):
        self.st_mode = mode


@contextlib.contextmanager
def env(fs, runner=None, which=(), dirs=(), pkgs=(), modes=None):
    """模擬 read_text／run／which／glob／os.path.isdir／os.stat 與套件查詢；glob 依 fs 路徑比對。"""
    runner = runner or FakeRunner()
    dirs = set(dirs)
    modes = modes or {}

    def _glob(pat):
        return sorted(p for p in fs if fnmatch.fnmatch(p, pat))

    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch.object(au, "read_text", fs_reader(fs)))
        st.enter_context(mock.patch.object(au, "run", runner))
        st.enter_context(mock.patch.object(au, "which", lambda n: n in which))
        st.enter_context(mock.patch.object(au.glob, "glob", _glob))
        st.enter_context(mock.patch.object(au.os.path, "isdir", lambda p: p in dirs))
        st.enter_context(mock.patch.object(au.os, "stat", lambda p: _St(modes.get(p, 0o100600))))
        st.enter_context(mock.patch.object(au.pkgsvc, "pkg_installed", lambda osi, p: p in pkgs))
        yield runner


def fx_for(fs, runner=None, dry_run=False):
    return FakeFx(FakeCtx("ubuntu2204", dry_run=dry_run), fs=fs, runner=runner or FakeRunner())


def ctx():
    return FakeCtx("ubuntu2204")


def idx(events, ev):
    return events.index(ev)


GRUB_CFG_OK = "menuentry x {\n  linux /vmlinuz ro audit_backlog_limit=8192\n}\n"
GRUB_CFG_BAD = "menuentry x {\n  linux /vmlinuz ro quiet\n}\n"


# TWGCB-01-014-0115 稽核待辦事項數量限制
class BacklogLimitTest(unittest.TestCase):
    rule = au.AuditBacklogLimit(U(115))

    def test_cmdline_value_non_numeric(self):
        self.assertIsNone(au.cmdline_value(["audit_backlog_limit=x"], "audit_backlog_limit"))

    def test_check_errors(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).status, ERROR)
        with env({"/etc/default/grub": ""}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (ERROR, "找不到 /boot/grub/grub.cfg"))

    def test_check_pass_needs_reboot(self):
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n',
              "/etc/default/grub.d/50-x.cfg": 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit_backlog_limit=8192"\n',
              au.AuditBacklogLimit.GRUB_CFG: GRUB_CFG_OK, "/proc/cmdline": "ro quiet"}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, PASS)
        self.assertIn("需重開機生效", c.current)

    def test_check_fail_bad_entry(self):
        # 本工具 drop-in 最後套用
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n',
              au.AuditBacklogLimit.DROPIN: 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit_backlog_limit=8192"\n',
              au.AuditBacklogLimit.GRUB_CFG: GRUB_CFG_BAD, "/proc/cmdline": "audit_backlog_limit=8192"}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("GRUB 設定：8192、開機項目不足：1 個", c.current)

    def test_fix_missing_default(self):
        with env({}):
            self.assertRaises(ManualRequired, self.rule.fix, ctx(), fx_for({}))

    def test_fix_updates_default_and_runs_update_grub(self):
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX="quiet"\n'}
        fx = fx_for(fs)
        with env(fs):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fs["/etc/default/grub"], 'GRUB_CMDLINE_LINUX="quiet audit_backlog_limit=8192"\n')
        self.assertNotIn(self.rule.DROPIN, fs)
        self.assertLess(idx(fx.events, ("undo", "update-grub")), idx(fx.events, ("write", "/etc/default/grub")))
        self.assertEqual(fx.kinds("run"), ["update-grub"])

    def test_fix_grub_d_override_uses_dropin(self):
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"\n',
              "/etc/default/grub.d/50-cloud.cfg": 'GRUB_CMDLINE_LINUX="console=ttyS0"\n'}
        fx = fx_for(fs)
        with env(fs):
            self.rule.fix(fx.ctx, fx)
        self.assertNotIn(("write", "/etc/default/grub"), fx.events)
        self.assertIn("$GRUB_CMDLINE_LINUX audit_backlog_limit=8192", fs[self.rule.DROPIN])


# TWGCB-01-014-0116 稽核日誌檔案權限（log_group）
class AuditLogPermTest(unittest.TestCase):
    def _rule(self, target="file"):
        return au.AuditLogPerm("稽核日誌檔案權限", U(116), target, owner="root", max_mode=0o600)

    def test_check(self):
        with env({}), mock.patch.object(au.FilePerm, "check", return_value=Check(NA, "x")):
            self.assertEqual(self._rule().check(ctx()).status, PASS)
        bad = Check(FAIL, "權限 644")
        with env({}), mock.patch.object(au.FilePerm, "check", return_value=bad):
            self.assertIs(self._rule().check(ctx()), bad)
        conf = {au.AUDITD_CONF: "log_group = adm\n"}
        with env(conf), mock.patch.object(au.FilePerm, "check", return_value=Check(NA, "x")):
            c = self._rule().check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("root:adm 0640", c.current)
        with env(conf), mock.patch.object(au.FilePerm, "check", return_value=Check(PASS, "ok")):
            c = self._rule().check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("log_group=adm", c.current)

    def test_fix_sets_log_group_root(self):
        fs = {au.AUDITD_CONF: "log_group = adm\n"}
        fx = fx_for(fs)
        with env(fs), mock.patch.object(au.FilePerm, "fix") as base_fix:
            self._rule().fix(fx.ctx, fx)
        base_fix.assert_called_once()
        self.assertEqual(au.te.get_kv(fs[au.AUDITD_CONF], "log_group"), "root")
        self.assertLess(idx(fx.events, ("undo", "service auditd reload")), idx(fx.events, ("write", au.AUDITD_CONF)))
        self.assertIn(("run", "service auditd reload"), fx.events)


# TWGCB-01-014-0126 保護稽核工具
class AideAuditToolsTest(unittest.TestCase):
    rule = au.AideAuditTools(U(126))

    def test_check_missing(self):
        with env({au.AideAuditTools.CONF: ""}, pkgs={"aide"}):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("augenrules", c.current)

    def test_fix_appends_to_conf_and_comments_weak(self):
        fs = {au.AideAuditTools.CONF: "/usr/sbin/auditd p+i"}
        fx = fx_for(fs)
        with env(fs, pkgs={"aide"}):
            self.rule.fix(fx.ctx, fx)
        text = fs[au.AideAuditTools.CONF]
        self.assertTrue(text.startswith(au.te.MARK + "/usr/sbin/auditd p+i\n# Audit Tools"))
        self.assertIn("/usr/sbin/augenrules %s\n" % au.AIDE_ATTRS, text)
        self.assertNotIn(au.AideAuditTools.DROPIN, fs)
        self.assertIn("aideinit", fx.notes[-1])

    def test_fix_uses_dropin_and_check_fails(self):
        fs = {au.AideAuditTools.CONF: "@@x_include /etc/aide/aide.conf.d ^[a-zA-Z0-9_-]+$\n"}
        fx = fx_for(fs, runner=FakeRunner({"aide --config-check": res(1, "bad")}))
        with env(fs, FakeRunner({"aide --config-check": res(0)}), which={"aide"}, pkgs={"aide"}):
            self.assertRaises(FixError, self.rule.fix, fx.ctx, fx)
        self.assertIn("/usr/sbin/auditctl", fs[au.AideAuditTools.DROPIN])


# TWGCB-01-014-0129 稽核規則（共用 AuditRuleSet）
class AuditRuleSetTest(unittest.TestCase):
    LINE = "-w /etc/sudoers -p wa -k scope"
    SKIP = "-w /no/such/x -p wa -k scope"

    def setUp(self):
        self.rule = au.AuditRuleSet("記錄系統管理者活動", U(129), [self.LINE, self.SKIP])
        self.path = au.AUDIT_RULES_DIR + "/gcb-0129.rules"

    def test_empty(self):
        empty = au.AuditRuleSet("x", U(129), [])
        with env({}, which={"auditctl", "augenrules"}):
            self.assertEqual(empty.check(ctx()).current, "無需設定的規則")
            self.assertRaises(ManualRequired, empty.fix, ctx(), fx_for({}))

    def test_check_loaded(self):
        fs = {self.path: self.LINE + "\n"}
        with env(fs, FakeRunner({"auditctl -l": res(0, self.LINE)}), which={"auditctl"}, dirs={"/etc"}):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, PASS)
        self.assertIn("1 條規則皆已生效", c.current)
        self.assertIn("/no/such/x", c.current)

    def test_check_locked(self):
        fs = {self.path: self.LINE + "\n"}
        runner = FakeRunner({"auditctl -l": res(0, ""), "auditctl -s": res(0, "enabled 2\n")})
        with env(fs, runner, which={"auditctl"}, dirs={"/etc"}):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, PASS)
        self.assertIn("-e 2", c.current)

    def test_fix(self):
        fs = {}
        fx = fx_for(fs)
        with env(fs, FakeRunner({"auditctl -s": res(0, "enabled 2\n")}), which={"augenrules"},
                 dirs={"/etc"}, modes={self.path: 0o100644}):
            self.rule.fix(fx.ctx, fx)
        self.assertIn(self.LINE, fs[self.path])
        self.assertNotIn(self.SKIP, fs[self.path])
        self.assertEqual(fx.modes[self.path], 0o600)
        self.assertIn(("chmod", self.path, 0o600), fx.events)
        self.assertLess(idx(fx.events, ("undo", "augenrules --load")), idx(fx.events, ("write", self.path)))
        self.assertIn("/no/such/x", fx.notes[0])
        self.assertIn("-e 2", fx.notes[-1])


# TWGCB-01-014-0139 記錄特權指令使用情形
class PrivilegedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_local_mounts_skips_bad_lines(self):
        self.assertEqual(au.local_mounts("garbage\n23 1 8:1 - ext4\n22 1 8:1 / / rw - ext4 /dev/sda1\n"), ["/"])

    def test_find_privileged(self):
        sub = os.path.join(self.tmp, "bin")
        os.mkdir(sub)
        os.mkdir(os.path.join(self.tmp, "gone"))
        for n, m in (("suid", 0o4755), ("plain", 0o755), ("vanish", 0o4755)):
            p = os.path.join(sub, n)
            open(p, "w").close()
            os.chmod(p, m)
        real = os.lstat

        def flaky(p):
            if os.path.basename(p) in ("gone", "vanish"):
                raise OSError("消失")
            return real(p)
        with mock.patch.object(au.os, "lstat", flaky):
            out = au.find_privileged(self.tmp)
        self.assertEqual(out, [os.path.join(sub, "suid")])
        self.assertEqual(au.find_privileged(os.path.join(self.tmp, "nope")), [])

    def test_empty_text(self):
        rule = au.PrivilegedCommands("記錄特權指令使用情形", U(139))
        with env({"/proc/self/mountinfo": ""}, which={"auditctl"}):
            self.assertIn("未找到 setuid", rule.check(ctx()).current)


# TWGCB-01-014-0148 auditd 設定不變模式
class ImmutableTest(unittest.TestCase):
    rule = au.AuditImmutable(U(148))

    def test_fix(self):
        fs = {au.AUDIT_RULES_DIR + "/audit.rules": "-e 1\n"}
        fx = fx_for(fs)
        with env(fs, which={"augenrules"}):
            self.rule.fix(fx.ctx, fx)
        self.assertTrue(fs[self.rule.FILE].endswith("-e 2\n"))
        self.assertEqual(fx.modes[self.rule.FILE], 0o600)
        self.assertLess(idx(fx.events, ("undo", "augenrules")), idx(fx.events, ("write", self.rule.FILE)))
        self.assertIn(("run", "augenrules --load"), fx.events)
        self.assertIn("重新開機", fx.notes[0])

    def test_fix_later_file_overrides(self):
        fs = {au.AUDIT_RULES_DIR + "/zzz-local.rules": "-e 1\n"}
        fx = fx_for(fs)
        with env(fs, which={"augenrules"}):
            self.assertRaises(FixError, self.rule.fix, fx.ctx, fx)
        self.assertNotIn(("run", "augenrules --load"), fx.events)


# TWGCB-01-014-0151 設定 rsyslog 日誌檔案預設權限
class RsyslogModeTest(unittest.TestCase):
    rule = au.RsyslogFileMode(U(151))

    def test_helpers(self):
        self.assertFalse(au.mode_ok("abc"))
        self.assertEqual(au.rsyslog_fix_text("*.* /var/log/x\n", False), "$FileCreateMode 0640\n*.* /var/log/x\n")

    def test_check(self):
        with env({"/etc/rsyslog.conf": ""}):
            self.assertIn("未設定", self.rule.check(ctx()).current)
        with env({"/etc/rsyslog.conf": "$FileCreateMode 0644\n"}):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("權限過寬：0644", c.current)

    def test_fix_validate_fails(self):
        fs = {"/etc/rsyslog.conf": "$FileCreateMode 0644\n"}
        fx = fx_for(fs, runner=FakeRunner({"rsyslogd -N1": res(1, "err")}))
        with env(fs, which={"rsyslogd"}):
            self.assertRaises(FixError, self.rule.fix, fx.ctx, fx)
        self.assertEqual(fs["/etc/rsyslog.conf"], "$FileCreateMode 0640\n")
        self.assertLess(idx(fx.events, ("undo", "systemctl restart rsyslog")),
                        idx(fx.events, ("write", "/etc/rsyslog.conf")))


# TWGCB-01-014-0152 journald 參數
class JournaldTest(unittest.TestCase):
    def _rule(self):
        return au.JournaldSetting("Storage", U(152), "Storage", "persistent")

    def test_fix_non_etc_override_is_manual(self):
        fs = {"/usr/lib/systemd/journald.conf.d/90-x.conf": "[Journal]\nStorage=volatile\n"}
        with env(fs):
            self.assertRaises(ManualRequired, self._rule().fix, ctx(), fx_for(fs))

    def test_fix_comments_later_etc_dropin(self):
        later = "/etc/systemd/journald.conf.d/90-x.conf"
        fs = {later: "[Journal]\nStorage=volatile\n"}
        fx = fx_for(fs)
        with env(fs):
            self._rule().fix(fx.ctx, fx)
        self.assertIsNone(au.te.get_kv(fs[later], "Storage"))
        self.assertEqual(au.te.get_kv(fs[au.JOURNALD_OWN], "Storage"), "persistent")
        self.assertLess(idx(fx.events, ("undo", "systemctl restart systemd-journald")), idx(fx.events, ("write", later)))
        self.assertEqual(fx.kinds("run"), ["systemctl restart systemd-journald"])


# TWGCB-01-014-0112 auditd 套件；0116～0128 未安裝 auditd 時判定（NeedsAuditd）
class PackagesAndWrapperTest(unittest.TestCase):
    def test_packages(self):
        rule = au.AuditPackages(U(112))
        with env({}, pkgs={"auditd"}):
            c = rule.check(ctx())
            fx = fx_for({})
            rule.fix(fx.ctx, fx)
        self.assertEqual((c.status, c.current), (FAIL, "未安裝：audispd-plugins"))
        self.assertEqual(fx.kinds("pkg_install"), ["audispd-plugins"])
        with env({}, pkgs={"auditd", "audispd-plugins"}):
            self.assertEqual(rule.check(ctx()).current, "已安裝")

    def test_needs_auditd(self):
        inner = mock.Mock(title="t", category="c", ids=U(116), risk="A", expected="e",
                          needs_reboot=False, manual_hint="")
        inner.check.return_value = Check(PASS, "ok")
        inner.precondition.return_value = "原因"
        rule = au.NeedsAuditd(inner)
        self.assertEqual(rule.ids, U(116))
        with env({}):
            self.assertEqual(rule.check(ctx()).current, "未安裝 auditd")
            self.assertRaises(ManualRequired, rule.fix, ctx(), fx_for({}))
        inner.fix.assert_not_called()
        with env({}, pkgs={"auditd"}):
            self.assertEqual(rule.check(ctx()).status, PASS)
            fx = fx_for({})
            rule.fix(fx.ctx, fx)
        inner.fix.assert_called_once()
        self.assertEqual(rule.precondition(ctx()), "原因")


# TWGCB-01-014-0116～0119 稽核日誌檔案／目錄（路徑依 log_file）
class AuditLogTargetsTest(unittest.TestCase):
    def test_targets_follow_log_file(self):
        conf = {au.AUDITD_CONF: "log_file = /data/audit/a.log\n"}
        f = au.AuditLogPerm("x", U(116), "file", owner="root")
        d = au.AuditLogPerm("x", U(118), "dir", owner="root")
        with env(conf), mock.patch.object(au.FilePerm, "_targets", lambda self: list(self.paths)):
            self.assertEqual(f._targets(), ["/data/audit/a.log", "/data/audit/a.log.[0-9]*"])
            self.assertEqual(d._targets(), ["/data/audit"])
        with env({}):
            self.assertEqual(au.audit_log_file(), "/var/log/audit/audit.log")
        c = Check(FAIL, "x")
        with env({au.AUDITD_CONF: "log_group = adm\n"}), mock.patch.object(au.FilePerm, "check", return_value=c):
            self.assertIs(d.check(ctx()), c)  # 目錄項目不看 log_group


# TWGCB-01-014-0126 保護稽核工具（基本路徑）
class AideBasicTest(unittest.TestCase):
    rule = au.AideAuditTools(U(126))

    def test_not_installed(self):
        with env({}):
            self.assertIn("未安裝 AIDE", self.rule.check(ctx()).current)
            self.assertRaises(ManualRequired, self.rule.fix, ctx(), fx_for({}))

    def test_pass_with_dropin(self):
        block = "".join("%s %s\n" % (p, au.AIDE_ATTRS) for p in au.AUDIT_TOOLS)
        fs = {au.AideAuditTools.CONF: "", au.AideAuditTools.DROPIN: block, au.AideAuditTools.DIR + "/x.bak": block}
        with env(fs, pkgs={"aide"}):
            self.assertEqual(self.rule._files(), [au.AideAuditTools.CONF, au.AideAuditTools.DROPIN])
            self.assertEqual(self.rule.check(ctx()).status, PASS)


# TWGCB-01-014-0129～0147 稽核規則（基本路徑）
class AuditRuleSetBasicTest(unittest.TestCase):
    def test_syscall_exists_cached(self):
        au._SYSCALL_CACHE.clear()
        self.addCleanup(au._SYSCALL_CACHE.clear)
        with env({}, FakeRunner({"ausyscall b64 foo": res(1)})) as r:
            self.assertFalse(au.syscall_exists("b64", "foo"))
            self.assertTrue(au.syscall_exists("b64", "open"))
            self.assertFalse(au.syscall_exists("b64", "foo"))
        self.assertEqual(len(r.calls), 2)

    def test_not_installed_and_fail(self):
        rule = au.AuditRuleSet("x", U(129), ["-w /etc/sudoers -p wa -k scope"])
        with env({}):
            self.assertEqual(rule.check(ctx()).current, "未安裝 auditd")
            self.assertRaises(ManualRequired, rule.fix, ctx(), fx_for({}))
        with env({}, which={"auditctl"}, dirs={"/etc"}):
            c = rule.check(ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("未生效 1 條、未寫入設定檔 1 條", c.current)

    def test_privileged_lines(self):
        rule = au.PrivilegedCommands("x", U(139))
        mi = "22 1 8:1 / / rw - ext4 /dev/sda1\n"
        with env({"/proc/self/mountinfo": mi}), \
                mock.patch.object(au, "find_privileged", return_value=["/usr/bin/su", "/opt/a b"]):
            self.assertEqual(rule._lines(ctx()), [rule.TPL % "/usr/bin/su"])  # 含空白的路徑略過

    def test_find_privileged_not_dir(self):
        fd, p = tempfile.mkstemp()
        os.close(fd)
        self.addCleanup(os.unlink, p)
        self.assertEqual(au.find_privileged(p), [])


# TWGCB-01-014-0142 記錄系統管理者活動日誌變更
class SudoLogTest(unittest.TestCase):
    def test_logfiles(self):
        fs = {"/etc/sudoers": "# Defaults logfile=/x\nroot ALL=(ALL) ALL\nDefaults logfile=\"/var/log/a.log\"\n",
              "/etc/sudoers.d/b": "Defaults logfile=/var/log/b.log, use_pty\nDefaults logfile=/var/log/a.log\n",
              "/etc/sudoers.d/c.bak": "Defaults logfile=/var/log/c.log\n", "/etc/sudoers.d/d~": "Defaults logfile=/d\n"}
        rule = au.SudoLogRule("x", U(142))
        with env(fs):
            self.assertEqual(au.sudo_logfiles(), ["/var/log/a.log", "/var/log/b.log"])
            self.assertEqual(rule._lines(ctx())[1], "-w /var/log/b.log -p wa -k sudo_log_file")
        with env({}):
            self.assertEqual(rule._lines(ctx()), ["-w /var/log/sudo.log -p wa -k sudo_log_file"])


# TWGCB-01-014-0148 auditd 設定不變模式（檢查）
class ImmutableCheckTest(unittest.TestCase):
    rule = au.AuditImmutable(U(148))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(ctx()).current, "未安裝 auditd")
            self.assertRaises(ManualRequired, self.rule.fix, ctx(), fx_for({}))
        fs = {au.AUDIT_RULES_DIR + "/zz.rules": "-e 2\n"}
        with env(fs, FakeRunner({"auditctl -s": res(0, "enabled 1\n")}), which={"auditctl"}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (PASS, "rules.d 設定：-e 2；目前 enabled=1（重新載入規則或重新開機後生效）"))
        with env({}, FakeRunner({"auditctl -s": res(1)}), which={"auditctl"}):
            c = self.rule.check(ctx())
        self.assertEqual((c.status, c.current), (FAIL, "rules.d 設定：未設定；目前 enabled=無法取得"))


# TWGCB-01-014-0151 設定 rsyslog 日誌檔案預設權限（基本路徑）
class RsyslogBasicTest(unittest.TestCase):
    rule = au.RsyslogFileMode(U(151))

    def test_check_and_fix(self):
        self.assertEqual(au.rsyslog_modes("# $FileCreateMode 0777\n$FileCreateMode 0600\n"), ["0600"])
        with env({}):
            self.assertIn("未安裝 rsyslog", self.rule.check(ctx()).current)
            self.assertRaises(ManualRequired, self.rule.fix, ctx(), fx_for({}))
        fs = {"/etc/rsyslog.conf": "$FileCreateMode 0640\n", "/etc/rsyslog.d/a.conf": "$FileCreateMode 0600\n"}
        with env(fs):
            c = self.rule.check(ctx())
        self.assertEqual(c.status, PASS)
        fx = fx_for(fs)
        with env(fs):
            self.rule.fix(fx.ctx, fx)
        # 只有主設定檔需檢查；值已合格不改；無 rsyslogd 時不檢查語法，直接重啟
        self.assertEqual(fx.kinds("write"), [])
        self.assertEqual(fx.kinds("run"), ["systemctl restart rsyslog"])


# TWGCB-01-014-0152 journald 參數（檢查）
class JournaldCheckTest(unittest.TestCase):
    def test_check(self):
        rule = au.JournaldSetting("Storage", U(152), "Storage", "persistent")
        with env({}):
            self.assertEqual(rule.check(ctx()).current, "Storage 未設定")
        fs = {au.JOURNALD_CONF: "[Journal]\nStorage=auto\n",
              "/usr/lib/systemd/journald.conf.d/50-x.conf": "[Journal]\nStorage=volatile\n",
              "/etc/systemd/journald.conf.d/50-x.conf": "[Journal]\nStorage=persistent\n"}
        with env(fs):
            c = rule.check(ctx())
        # 同名 drop-in 以 /etc 優先
        self.assertEqual((c.status, c.current),
                         (PASS, "Storage=persistent（/etc/systemd/journald.conf.d/50-x.conf）"))


if __name__ == "__main__":
    unittest.main()
