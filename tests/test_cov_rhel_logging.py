# -*- coding: utf-8 -*-
"""rhel/logging.py 補充單元測試：所有指令、檔案與目錄查詢皆以模擬環境取代。"""
import contextlib
import fnmatch
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import FakeCtx, FakeFx, FakeRunner, fs_reader, mock, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, NA, PASS, Check  # noqa: E402
from gcb.rules.rhel import logging as lg  # noqa: E402
from gcb.rules.rhel.helpers import R  # noqa: E402


class _St(object):
    def __init__(self, mode):
        self.st_mode = mode


@contextlib.contextmanager
def env(fs, runner=None, which=(), dirs=(), pkgs=(), modes=None):
    """模擬 read_text／run／which／glob／os.path 與套件查詢；glob 依 fs 與 dirs 的路徑比對。"""
    runner = runner or FakeRunner()
    dirs = set(dirs)
    modes = modes or {}

    def _glob(pat):
        return sorted(p for p in list(fs) + list(dirs) if fnmatch.fnmatch(p, pat))

    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch.object(lg, "read_text", fs_reader(fs)))
        st.enter_context(mock.patch.object(lg, "run", runner))
        st.enter_context(mock.patch.object(lg, "which", lambda n: n in which))
        st.enter_context(mock.patch.object(lg.glob, "glob", _glob))
        st.enter_context(mock.patch.object(lg.os.path, "isdir", lambda p: p in dirs))
        st.enter_context(mock.patch.object(lg.os.path, "isfile", lambda p: p in fs))
        st.enter_context(mock.patch.object(lg.os.path, "exists", lambda p: p in fs or p in dirs))
        st.enter_context(mock.patch.object(lg.os, "stat", lambda p: _St(modes.get(p, 0o100644))))
        st.enter_context(mock.patch.object(lg.pkgsvc, "pkg_installed", lambda osi, p: p in pkgs))
        yield runner


def fx_for(fs, key="rhel9", runner=None, dry_run=False):
    return FakeFx(FakeCtx(key, dry_run=dry_run), fs=fs, runner=runner or FakeRunner())


def idx(events, ev):
    return events.index(ev)


GRUBBY = '''kernel="/boot/vmlinuz-a"
args="ro quiet"
kernel="/boot/vmlinuz-b"
args="ro audit_backlog_limit=64"
kernel="/boot/vmlinuz-c"
args="ro audit_backlog_limit=16384"
'''
GRUBBY_OK = 'kernel="/boot/vmlinuz-a"\nargs="ro audit_backlog_limit=8192"\n'
DEFAULT_GRUB = 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="rhgb quiet"\n'


# TWGCB-01-012-0135 稽核待辦事項數量限制
class BacklogLimitTest(unittest.TestCase):
    rule = lg.AuditBacklogLimit(R(r8=135, r9=135))

    def test_cmdline_value_non_numeric(self):
        self.assertIsNone(lg.cmdline_value(["audit_backlog_limit=8192", "audit_backlog_limit=abc"],
                                           "audit_backlog_limit"))

    def test_grub_env_files(self):
        fs = {"/boot/loader/entries/b.conf": "", "/boot/loader/entries/a.conf": "",
              "/boot/grub2/grubenv": "", "/boot/efi/EFI/rocky/grubenv": ""}
        with env(fs):
            self.assertEqual(lg.grub_env_files(), [
                "/boot/loader/entries/a.conf", "/boot/loader/entries/b.conf",
                "/boot/grub2/grubenv", "/boot/efi/EFI/rocky/grubenv"])

    def test_check_errors(self):
        with env({}):
            self.assertEqual(self.rule.check(FakeCtx()).status, ERROR)
        with env({"/etc/default/grub": DEFAULT_GRUB}):
            c = self.rule.check(FakeCtx())
            self.assertEqual((c.status, c.current), (ERROR, "找不到 grubby"))
        with env({"/etc/default/grub": DEFAULT_GRUB}, FakeRunner({"grubby": res(1)}), which={"grubby"}):
            c = self.rule.check(FakeCtx())
            self.assertEqual((c.status, c.current), (ERROR, "grubby 執行失敗"))

    def test_check_pass_needs_reboot_and_fail(self):
        fs = {"/etc/default/grub": 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"\n',
              "/proc/cmdline": "ro quiet"}
        with env(fs, FakeRunner({"grubby": res(0, GRUBBY_OK)}), which={"grubby"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("需重開機生效", c.current)
        with env(fs, FakeRunner({"grubby": res(0, GRUBBY)}), which={"grubby"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("2/3", c.current)

    def test_fix_guards(self):
        with env({}):
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for({}))
        with env({"/etc/default/grub": DEFAULT_GRUB}):
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for({}))

    def test_fix_updates_only_short_entries(self):
        fs = {"/etc/default/grub": DEFAULT_GRUB, "/boot/grub2/grubenv": "x"}
        fx = fx_for(fs)
        with env(fs, FakeRunner({"grubby --info": res(0, GRUBBY)}), which={"grubby"}):
            self.rule.fix(fx.ctx, fx)
        self.assertIn("audit_backlog_limit=8192", fs["/etc/default/grub"])
        self.assertIn(("backup", "/boot/grub2/grubenv"), fx.events)
        ev = fx.events
        # 原本沒有參數：回滾為移除；先登記回滾再修改
        a_undo = ("undo", "grubby --update-kernel /boot/vmlinuz-a --remove-args audit_backlog_limit")
        a_run = ("run", "grubby --update-kernel /boot/vmlinuz-a --args audit_backlog_limit=8192")
        self.assertLess(idx(ev, a_undo), idx(ev, a_run))
        # 原值 64：回滾還原 64；先移除舊值再加入
        b_undo = ("undo", "grubby --update-kernel /boot/vmlinuz-b --args audit_backlog_limit=64")
        b_rm = ("run", "grubby --update-kernel /boot/vmlinuz-b --remove-args audit_backlog_limit")
        b_add = ("run", "grubby --update-kernel /boot/vmlinuz-b --args audit_backlog_limit=8192")
        self.assertLess(idx(ev, b_undo), idx(ev, b_rm))
        self.assertLess(idx(ev, b_rm), idx(ev, b_add))
        # 已 16384 的項目不動
        self.assertFalse([e for e in ev if "vmlinuz-c" in e[1]])


# TWGCB-01-012-0136 稽核處理失敗時通知系統管理者
class PostmasterTest(unittest.TestCase):
    rule = lg.PostmasterAlias(R(r8=136, r9=136))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(FakeCtx()).status, FAIL)
        with env({"/etc/aliases": "abuse: root\n"}):
            c = self.rule.check(FakeCtx())
            self.assertEqual((c.status, c.current), (FAIL, "未設定 postmaster 別名"))

    def test_fix_with_newaliases(self):
        fs = {"/etc/aliases": "postmaster: admin\n"}
        fx = fx_for(fs)
        with env(fs, which={"newaliases"}):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(lg.alias_target(fs["/etc/aliases"]), "root")
        self.assertLess(idx(fx.events, ("undo", "newaliases")), idx(fx.events, ("write", "/etc/aliases")))
        self.assertLess(idx(fx.events, ("write", "/etc/aliases")), idx(fx.events, ("run", "newaliases")))

    def test_fix_without_mta(self):
        fs = {"/etc/aliases": ""}
        fx = fx_for(fs)
        with env(fs):
            self.rule.fix(fx.ctx, fx)
        self.assertIn("postmaster:\troot", fs["/etc/aliases"])
        self.assertEqual(fx.kinds("run"), [])
        self.assertIn("newaliases", fx.notes[0])


# TWGCB-01-012-0137 稽核日誌檔案權限（log_group 處理）
class AuditLogPermTest(unittest.TestCase):
    def _rule(self, target="file"):
        return lg.AuditLogPerm("稽核日誌檔案權限", R(r8=137, r9=137), target, owner="root", max_mode=0o600)

    def test_check_log_group(self):
        conf = {lg.AUDITD_CONF: "log_group = adm\n"}
        with env(conf), mock.patch.object(lg.FilePerm, "check", return_value=Check(NA, "x")):
            c = self._rule().check(FakeCtx())
            self.assertEqual(c.status, FAIL)
            self.assertIn("log_group=adm", c.current)
        with env(conf), mock.patch.object(lg.FilePerm, "check", return_value=Check(PASS, "root:adm 640")):
            c = self._rule().check(FakeCtx())
            self.assertEqual(c.status, FAIL)
            self.assertIn("auditd 會依此重設", c.current)
        bad = Check(FAIL, "權限 644")
        with env({}), mock.patch.object(lg.FilePerm, "check", return_value=bad):
            self.assertIs(self._rule().check(FakeCtx()), bad)

    def test_fix_non_root_group_is_partial(self):
        fx = fx_for({})
        with env({lg.AUDITD_CONF: "log_group = adm\n"}), mock.patch.object(lg.FilePerm, "fix") as base_fix:
            self._rule().fix(fx.ctx, fx)
        base_fix.assert_called_once()
        self.assertTrue(fx.partial)
        self.assertIn("log_group=adm", fx.notes[0])
        fx = fx_for({})
        with env({}), mock.patch.object(lg.FilePerm, "fix"):
            self._rule("dir").fix(fx.ctx, fx)
        self.assertFalse(fx.partial)


AIDE_WEAK = "/usr/sbin/auditctl p+i\n@@include /etc/aide.d\n@@include /etc/aide.extra\n"


# TWGCB-01-012-0145 保護稽核工具
class AideAuditToolsTest(unittest.TestCase):
    rule = lg.AideAuditTools(R(r8=145, r9=145))

    def test_includes(self):
        fs = {"/etc/aide.d/a": "", "/etc/aide.d/b": ""}
        with env(fs, dirs={"/etc/aide.d"}):
            self.assertEqual(lg.aide_includes("@@include /etc/aide.d\n@@include /etc/x.conf\n"),
                             ["/etc/aide.d/a", "/etc/aide.d/b", "/etc/x.conf"])

    def test_check_missing(self):
        with env({"/etc/aide.conf": "/usr/sbin/auditctl p+i\n"}, pkgs={"aide"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("auditctl", c.current)

    def test_fix_comments_weak_rule_and_appends(self):
        fs = {"/etc/aide.conf": AIDE_WEAK}
        fx = fx_for(fs)
        with env(fs, which=set(), pkgs={"aide"}):
            self.rule.fix(fx.ctx, fx)
        text = fs["/etc/aide.conf"]
        self.assertIn(lg.te.MARK + "/usr/sbin/auditctl p+i", text)
        for p in lg.AIDE_TOOLS:
            self.assertIn("%s %s" % (p, lg.AIDE_ATTRS), text)
        # aide 不存在時不做語法檢查
        self.assertEqual(fx.kinds("run"), [])
        self.assertIn("aide --update", fx.notes[-1])

    def test_fix_config_check_fails(self):
        fs = {"/etc/aide.conf": "x\n"}
        fx = fx_for(fs, runner=FakeRunner({"aide --config-check": res(1, "", "syntax error")}))
        with env(fs, FakeRunner({"aide --config-check": res(0)}), which={"aide"}, pkgs={"aide"}):
            with self.assertRaises(FixError):
                self.rule.fix(fx.ctx, fx)


# TWGCB-01-012-0148 稽核規則（共用 AuditRuleSet）
class AuditRuleSetTest(unittest.TestCase):
    LINE = "-w /etc/sudoers -p wa -k scope"

    def setUp(self):
        self.rule = lg.AuditRuleSet("記錄系統管理者活動", R(r8=148, r9=148), [self.LINE])
        self.path = lg.AUDIT_RULES_DIR + "/gcb-0148.rules"
        p = mock.patch.object(lg, "is_x86", return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def test_uid_min_invalid(self):
        with env({"/etc/login.defs": "UID_MIN abc\n"}):
            self.assertEqual(lg.uid_min(), 1000)

    def test_prepare_skips_missing_syscall(self):
        with env({}, which={"ausyscall"}):
            req, skipped = lg.prepare_audit_lines(["-a always,exit -F arch=b64 -S foo -k x"],
                                                  exists=lambda a, n: False)
        self.assertEqual(req, [])
        self.assertIn("系統呼叫不存在", skipped[0])

    def test_check_empty_and_loaded(self):
        empty = lg.AuditRuleSet("x", R(r8=148, r9=148), [])
        with env({}, which={"auditctl"}):
            c = empty.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "無需設定的規則"))
        fs = {self.path: self.LINE + "\n"}
        with env(fs, FakeRunner({"auditctl -l": res(0, self.LINE)}), which={"auditctl"}, dirs={"/etc"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("皆已生效", c.current)

    def test_check_locked_counts_disk(self):
        fs = {self.path: self.LINE + "\n"}
        runner = FakeRunner({"auditctl -l": res(0, ""), "auditctl -s": res(0, "enabled 2\n")})
        with env(fs, runner, which={"auditctl"}, dirs={"/etc"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("-e 2", c.current)

    def test_fix_no_rules(self):
        empty = lg.AuditRuleSet("x", R(r8=148, r9=148), [])
        with env({}, which={"augenrules"}):
            self.assertRaises(ManualRequired, empty.fix, FakeCtx(), fx_for({}))

    def test_fix_writes_0600_and_notes_locked(self):
        fs = {self.path: "old\n"}
        fx = fx_for(fs)
        with env(fs, FakeRunner({"auditctl -s": res(0, "enabled 2\n")}), which={"augenrules"},
                 dirs={"/etc"}, modes={self.path: 0o100644}):
            self.rule.fix(fx.ctx, fx)
        self.assertIn(self.LINE, fs[self.path])
        self.assertEqual(fx.modes[self.path], 0o600)
        self.assertIn(("chmod", self.path, 0o600), fx.events)
        self.assertLess(idx(fx.events, ("undo", "augenrules --load")), idx(fx.events, ("write", self.path)))
        self.assertIn("-e 2", fx.notes[-1])


MOUNTINFO = """garbage line
22 1 253:0 / / rw - xfs /dev/root rw
23 1 253:0
24 1 0:5 / /proc rw - proc proc rw
"""


# TWGCB-01-012-0158 記錄特權指令使用情形
class PrivilegedTest(unittest.TestCase):
    def setUp(self):
        lg._PRIV_CACHE.clear()
        self.addCleanup(lg._PRIV_CACHE.clear)

    def test_local_mounts_skips_bad_lines(self):
        self.assertEqual(lg.local_mounts(MOUNTINFO + "25 1 8:1 x - ext4\n"), ["/"])

    def test_find_errors(self):
        with env({}, FakeRunner({"find": res(124)}), dirs={"/"}):
            self.assertRaises(RuntimeError, lg.find_privileged, "/")
        with env({}, FakeRunner({"find": res(2, "", "boom")}), dirs={"/"}):
            with self.assertRaises(RuntimeError) as cm:
                lg.find_privileged("/")
        self.assertIn("boom", str(cm.exception))

    def test_empty_text(self):
        rule = lg.PrivilegedCommands("記錄特權指令使用情形", R(r8=158, r9=158))
        with env({"/proc/self/mountinfo": ""}, which={"auditctl"}), \
                mock.patch.object(lg, "is_x86", return_value=True):
            c = rule.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("未找到 setuid", c.current)


# TWGCB-01-012-0171 記錄 Pam_Faillock 日誌檔案
class FaillockNoteTest(unittest.TestCase):
    def test_no_note_when_log_dir(self):
        rule = lg.FaillockLogRule("x", R(r8=171, r9=171))
        with env({"/etc/security/faillock.conf": "dir = /var/log/faillock/\n"}):
            self.assertEqual(rule._extra_note(FakeCtx()), "")


# TWGCB-01-012-0173 auditd 設定不變模式
class ImmutableTest(unittest.TestCase):
    rule = lg.AuditImmutable(R(r8=173, r9=173))

    def test_file_sorts_last(self):
        names = [lg.AUDIT_RULES_DIR + "/" + n for n in ("audit.rules", "gcb-0173.rules", "99-finalize.rules")]
        self.assertEqual(sorted(names + [self.rule.FILE])[-1], self.rule.FILE)

    def test_fix_writes_and_notes_reboot(self):
        fs = {lg.AUDIT_RULES_DIR + "/audit.rules": "-e 1\n"}
        fx = fx_for(fs)
        with env(fs, which={"augenrules"}):
            self.rule.fix(fx.ctx, fx)
        self.assertTrue(fs[self.rule.FILE].endswith("--loginuid-immutable\n-e 2\n"))
        self.assertEqual(fx.modes[self.rule.FILE], 0o600)
        self.assertEqual(fx.kinds("run"), [])  # 不立即載入
        self.assertIn("重開機", fx.notes[0])

    def test_fix_later_file_overrides(self):
        fs = {lg.AUDIT_RULES_DIR + "/zzz-local.rules": "-e 1\n"}
        fx = fx_for(fs)
        with env(fs, which={"augenrules"}):
            self.assertRaises(FixError, self.rule.fix, fx.ctx, fx)

    def test_dry_run_no_write(self):
        fs = {}
        fx = fx_for(fs, dry_run=True)
        with env(fs, which={"augenrules"}):
            self.rule.fix(fx.ctx, fx)
        self.assertNotIn(self.rule.FILE, fs)


# TWGCB-01-012-0176 設定 rsyslog 日誌檔案預設權限
class RsyslogModeTest(unittest.TestCase):
    rule = lg.RsyslogFileMode(R(r8=176, r9=176))

    def test_helpers(self):
        self.assertFalse(lg.mode_ok("rw"))
        self.assertEqual(lg.rsyslog_fix_text("$FileCreateMode 0644\n", True), "$FileCreateMode 0640\n")
        self.assertEqual(lg.rsyslog_fix_text("*.* /var/log/x\n", False), "$FileCreateMode 0640\n*.* /var/log/x\n")

    def test_check(self):
        with env({lg.RSYSLOG_CONF: "*.* /var/log/messages\n"}):
            c = self.rule.check(FakeCtx())
            self.assertEqual(c.status, FAIL)
            self.assertIn("未設定", c.current)
        fs = {lg.RSYSLOG_CONF: "$FileCreateMode 0640\n", "/etc/rsyslog.d/a.conf": "$FileCreateMode 0666\n"}
        with env(fs):
            c = self.rule.check(FakeCtx())
            self.assertEqual(c.status, FAIL)
            self.assertIn("0666", c.current)

    def test_fix_validate_fails(self):
        fs = {lg.RSYSLOG_CONF: "$FileCreateMode 0644\n"}
        fx = fx_for(fs, runner=FakeRunner({"rsyslogd -N1": res(1, "", "error")}))
        with env(fs, which={"rsyslogd"}):
            self.assertRaises(FixError, self.rule.fix, fx.ctx, fx)
        self.assertEqual(fs[lg.RSYSLOG_CONF], "$FileCreateMode 0640\n")
        self.assertLess(idx(fx.events, ("undo", "systemctl restart rsyslog")),
                        idx(fx.events, ("write", lg.RSYSLOG_CONF)))
        self.assertNotIn(("run", "systemctl restart rsyslog"), fx.events)


# TWGCB-01-012-0177 設定 rsyslog 日誌記錄規則
class RsyslogSecureTest(unittest.TestCase):
    def test_parse_skip_and_none(self):
        got = lg.rsyslog_secure_facilities(["mark;*.*;daemon.none /var/log/secure\n"])
        self.assertEqual(got, {"auth", "authpriv"})

    def test_check_missing(self):
        rule = lg.RsyslogSecure(R(r8=177, r9=177))
        with env({lg.RSYSLOG_CONF: "authpriv.* /var/log/secure\n"}):
            c = rule.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("auth、daemon", c.current)


ROT_OK = lg.LOGROTATE_STANZA
ROT_WEAK = "# x\n/var/log/rsyslog/*.log {\n    daily\n}\n"


# TWGCB-01-012-0308 rsyslog logrotate
class LogrotateTest(unittest.TestCase):
    rule = lg.RsyslogLogrotate(R(r9=308))

    def test_inline_block(self):
        b = lg.logrotate_blocks("/var/log/a { }\n")
        self.assertEqual((b[0]["paths"], b[0]["start"], b[0]["end"]), (["/var/log/a"], 0, 0))

    def test_check_problems(self):
        fs = {lg.LOGROTATE_FILE: ROT_WEAK + ROT_OK, "/etc/logrotate.d/other": "/var/log/rsyslog/x.log {\n}\n"}
        with env(fs, pkgs={"rsyslog"}, dirs={lg.LOGROTATE_DIR}, modes={lg.LOGROTATE_DIR: 0o40755}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        for s in ("權限 755", "重複出現 2 次", "/etc/logrotate.d/other"):
            self.assertIn(s, c.current)
        with env({lg.LOGROTATE_FILE: ROT_WEAK}, pkgs={"rsyslog"}):
            c = self.rule.check(FakeCtx())
        self.assertIn("不存在", c.current)
        self.assertIn("輪替區塊缺少：weekly", c.current)
        with env({}, pkgs={"rsyslog"}):
            self.assertIn("沒有", self.rule.check(FakeCtx()).current)
        with env({lg.LOGROTATE_FILE: ROT_OK}, pkgs={"rsyslog"}, dirs={lg.LOGROTATE_DIR},
                 modes={lg.LOGROTATE_DIR: 0o40750}):
            self.assertEqual(self.rule.check(FakeCtx()).status, PASS)

    def test_fix_guards(self):
        with env({}):
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for({}))
        fs = {"/etc/logrotate.d/other": "/var/log/rsyslog/x.log {\n}\n"}
        with env(fs, pkgs={"rsyslog"}):
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for(fs))
        fs = {lg.LOGROTATE_FILE: "/var/log/rsyslog/*.log /var/log/y {\n}\n"}
        with env(fs, pkgs={"rsyslog"}):
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for(fs))

    def test_fix_replaces_block_and_tightens_dir(self):
        fs = {lg.LOGROTATE_FILE: ROT_WEAK}
        fx = fx_for(fs)
        with env(fs, FakeRunner({"logrotate -d": res(0)}), which={"logrotate"}, pkgs={"rsyslog"},
                 dirs={lg.LOGROTATE_DIR}, modes={lg.LOGROTATE_DIR: 0o40775}):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fs[lg.LOGROTATE_FILE], "# x\n" + ROT_OK)
        self.assertIn(("chmod", lg.LOGROTATE_DIR, 0o750), fx.events)

    def test_fix_validate_fails_after_edit(self):
        fs = {lg.LOGROTATE_FILE: "/var/log/x {\n}\n"}
        fx = fx_for(fs)
        results = [res(0), res(1)]
        runner = FakeRunner({"logrotate -d": lambda s: results.pop(0)})
        with env(fs, runner, which={"logrotate"}, pkgs={"rsyslog"}, dirs={lg.LOGROTATE_DIR},
                 modes={lg.LOGROTATE_DIR: 0o40750}):
            self.assertRaises(FixError, self.rule.fix, fx.ctx, fx)
        self.assertTrue(fs[lg.LOGROTATE_FILE].endswith(ROT_OK))


# TWGCB-01-012-0181 journald 參數
class JournaldTest(unittest.TestCase):
    def _rule(self):
        return lg.JournaldSetting("Compress", R(r8=181, r9=181), "Compress", "yes")

    def test_check_equivalent_value(self):
        with env({lg.JOURNALD_CONF: "[Journal]\nCompress=true\n"}):
            c = self._rule().check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("與 yes 等價", c.current)

    def test_fix_non_etc_override_is_manual(self):
        fs = {"/run/systemd/journald.conf.d/90-x.conf": "[Journal]\nCompress=no\n"}
        with env(fs):
            self.assertRaises(ManualRequired, self._rule().fix, FakeCtx(), fx_for(fs))

    def test_fix_comments_later_etc_dropin(self):
        later = "/etc/systemd/journald.conf.d/90-x.conf"
        fs = {later: "[Journal]\nCompress=no\n"}
        fx = fx_for(fs)
        with env(fs):
            self._rule().fix(fx.ctx, fx)
        self.assertIsNone(lg.te.get_kv(fs[later], "Compress"))
        self.assertEqual(lg.te.get_kv(fs[lg.JOURNALD_OWN], "Compress"), "yes")
        self.assertLess(idx(fx.events, ("undo", "systemctl restart systemd-journald")),
                        idx(fx.events, ("write", later)))


# TWGCB-01-012-0132 auditd 套件；0137～0147 未安裝 audit 時判定（NeedsAudit）
class PackagesAndWrapperTest(unittest.TestCase):
    def test_packages(self):
        rule = lg.AuditPackages(R(r8=132, r9=132))
        with env({}, pkgs={"audit"}):
            c = rule.check(FakeCtx())
            fx = fx_for({})
            rule.fix(fx.ctx, fx)
        self.assertEqual((c.status, c.current), (FAIL, "未安裝：audit-libs"))
        self.assertEqual(fx.kinds("pkg_install"), ["audit-libs"])
        with env({}, pkgs={"audit", "audit-libs"}):
            self.assertEqual(rule.check(FakeCtx()).status, PASS)

    def test_needs_audit(self):
        inner = mock.Mock(title="t", category="c", ids=R(r9=137), risk="A", expected="e",
                          needs_reboot=False, manual_hint="")
        inner.check.return_value = Check(PASS, "ok")
        inner.precondition.return_value = None
        rule = lg.NeedsAudit(inner)
        with env({}):
            self.assertEqual(rule.check(FakeCtx()).current, "未安裝 audit 套件")
            self.assertRaises(ManualRequired, rule.fix, FakeCtx(), fx_for({}))
        inner.fix.assert_not_called()
        with env({}, pkgs={"audit"}):
            self.assertEqual(rule.check(FakeCtx()).status, PASS)
            fx = fx_for({})
            rule.fix(fx.ctx, fx)
        inner.fix.assert_called_once()
        self.assertIsNone(rule.precondition(FakeCtx()))


# TWGCB-01-012-0136 稽核處理失敗時通知系統管理者（檢查）
class PostmasterCheckTest(unittest.TestCase):
    def test_values(self):
        rule = lg.PostmasterAlias(R(r8=136, r9=136))
        with env({"/etc/aliases": "postmaster: root\n"}):
            self.assertEqual(rule.check(FakeCtx()).status, PASS)
        with env({"/etc/aliases": "postmaster: admin\n"}):
            c = rule.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "postmaster: admin"))


# TWGCB-01-012-0137～0140 稽核日誌檔案／目錄（路徑依 log_file）
class AuditLogTargetsTest(unittest.TestCase):
    def test_targets_and_root_group(self):
        conf = {lg.AUDITD_CONF: "log_file = /data/audit/a.log\n"}
        f = lg.AuditLogPerm("x", R(r9=137), "file", owner="root")
        d = lg.AuditLogPerm("x", R(r9=139), "dir", owner="root")
        with env(conf), mock.patch.object(lg.FilePerm, "_targets", lambda self: list(self.paths)):
            self.assertEqual(f._targets(), ["/data/audit/a.log", "/data/audit/a.log.[0-9]*"])
            self.assertEqual(d._targets(), ["/data/audit"])
        with env({}):
            self.assertEqual(lg.audit_log_file(), "/var/log/audit/audit.log")
        c = Check(FAIL, "x")
        with env({lg.AUDITD_CONF: "log_group = adm\n"}), mock.patch.object(lg.FilePerm, "check", return_value=c):
            self.assertIs(d.check(FakeCtx()), c)
        with env({}), mock.patch.object(lg.FilePerm, "check", return_value=Check(NA, "x")):
            c = f.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "尚未產生日誌檔；log_group=root"))


# TWGCB-01-012-0145 保護稽核工具（基本路徑）
class AideBasicTest(unittest.TestCase):
    rule = lg.AideAuditTools(R(r8=145, r9=145))

    def test_not_installed_and_pass(self):
        with env({}):
            self.assertIn("未安裝 AIDE", self.rule.check(FakeCtx()).current)
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for({}))
        block = "".join("%s %s\n" % (p, lg.AIDE_ATTRS) for p in lg.AIDE_TOOLS)
        with env({"/etc/aide.conf": block}, pkgs={"aide"}):
            self.assertEqual(self.rule.check(FakeCtx()).status, PASS)


# TWGCB-01-012-0148～0172 稽核規則（基本路徑）
class AuditRuleSetBasicTest(unittest.TestCase):
    def setUp(self):
        lg._SYSCALL_CACHE.clear()
        self.addCleanup(lg._SYSCALL_CACHE.clear)

    def test_syscall_exists_cached(self):
        with env({}, FakeRunner({"ausyscall b64 foo": res(1)})) as r:
            self.assertFalse(lg.syscall_exists("b64", "foo"))
            self.assertTrue(lg.syscall_exists("b64", "open"))
            self.assertFalse(lg.syscall_exists("b64", "foo"))
        self.assertEqual(len(r.calls), 2)

    def test_is_x86(self):
        with mock.patch.object(lg.os, "uname", return_value=("Linux", "h", "r", "v", "aarch64")):
            self.assertFalse(lg.is_x86())
        with mock.patch.object(lg.os, "uname", return_value=("Linux", "h", "r", "v", "x86_64")):
            self.assertTrue(lg.is_x86())

    def test_versioned_lines_and_fail(self):
        rule = lg.AuditRuleSet("x", R(r8=153, r9=153), {"rhel8": ["-w /etc/a -p wa -k k"],
                                                        "rhel9": ["-w /etc/b -p wa -k k"]})
        self.assertEqual(rule._lines(FakeCtx("rhel8")), ["-w /etc/a -p wa -k k"])
        with env({}):
            self.assertEqual(rule.check(FakeCtx()).current, "未安裝 audit 套件")
            self.assertRaises(ManualRequired, rule.fix, FakeCtx(), fx_for({}))
        with env({}, which={"auditctl"}, dirs={"/etc"}), mock.patch.object(lg, "is_x86", return_value=True):
            c = rule.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("未生效 1 條、未寫入設定檔 1 條（例：-w /etc/b -p wa -k k）", c.current)

    def test_fix_notes_skipped(self):
        rule = lg.AuditRuleSet("x", R(r8=148, r9=148), ["-w /etc/x -p wa -k k", "-w /no/dir/x -p wa -k k"])
        fs = {}
        fx = fx_for(fs)
        with env(fs, which={"augenrules"}, dirs={"/etc"}), mock.patch.object(lg, "is_x86", return_value=True):
            rule.fix(fx.ctx, fx)
        path = lg.AUDIT_RULES_DIR + "/gcb-0148.rules"
        self.assertNotIn("/no/dir", fs[path])
        self.assertIn("上層目錄不存在：/no/dir/x", fx.notes[0])
        self.assertEqual(fx.kinds("run"), ["augenrules --load"])


# TWGCB-01-012-0158 記錄特權指令使用情形（掃描與快取）
class PrivilegedScanTest(unittest.TestCase):
    def setUp(self):
        lg._PRIV_CACHE.clear()
        self.addCleanup(lg._PRIV_CACHE.clear)

    def test_find_and_cache(self):
        runner = FakeRunner({"find": res(1, "/usr/bin/su\0/usr/bin/passwd\0")})
        with env({}, runner, dirs={"/"}):
            self.assertEqual(lg.find_privileged("/"), ["/usr/bin/passwd", "/usr/bin/su"])
            self.assertEqual(lg.find_privileged("/"), ["/usr/bin/passwd", "/usr/bin/su"])
            self.assertEqual(lg.find_privileged("/nope"), [])
        self.assertEqual(len(runner.calls), 1)  # 第二次使用快取

    def test_lines(self):
        rule = lg.PrivilegedCommands("x", R(r8=158, r9=158))
        with env({"/proc/self/mountinfo": "22 1 8:1 / / rw - xfs /dev/sda1\n"}), \
                mock.patch.object(lg, "find_privileged", return_value=["/usr/bin/su", "/opt/a b"]):
            self.assertEqual(rule._lines(FakeCtx()), [rule.TPL % "/usr/bin/su"])


# TWGCB-01-012-0161 記錄系統管理者活動日誌變更、0171 記錄 Pam_Faillock 日誌檔案
class SudoAndFaillockTest(unittest.TestCase):
    def test_sudo_logfiles(self):
        fs = {"/etc/sudoers": "# Defaults logfile=/x\nroot ALL=(ALL) ALL\nDefaults logfile=\"/var/log/a.log\"\n",
              "/etc/sudoers.d/b": "Defaults logfile=/var/log/b.log\nDefaults logfile=/var/log/a.log\n",
              "/etc/sudoers.d/c.bak": "Defaults logfile=/c\n", "/etc/sudoers.d/d~": "Defaults logfile=/d\n"}
        rule = lg.SudoLogRule("x", R(r8=161, r9=161))
        with env(fs):
            self.assertEqual(rule._lines(FakeCtx()), ["-w /var/log/a.log -p wa -k actions",
                                                      "-w /var/log/b.log -p wa -k actions"])
        with env({}):
            self.assertEqual(rule._lines(FakeCtx()), ["-w /var/log/sudo.log -p wa -k actions"])

    def test_faillock_note(self):
        rule = lg.FaillockLogRule("x", R(r8=171, r9=171))
        with env({}):
            self.assertIn("/var/run/faillock", rule._extra_note(FakeCtx()))


# TWGCB-01-012-0173 auditd 設定不變模式（檢查）
class ImmutableCheckTest(unittest.TestCase):
    rule = lg.AuditImmutable(R(r8=173, r9=173))

    def test_check(self):
        with env({}):
            self.assertEqual(self.rule.check(FakeCtx()).current, "未安裝 audit 套件")
            self.assertRaises(ManualRequired, self.rule.fix, FakeCtx(), fx_for({}))
        fs = {self.rule.FILE: "--loginuid-immutable\n-e 2\n"}
        runner = FakeRunner({"auditctl -s": res(0, "enabled 1\nloginuid_immutable 0 unlocked\n")})
        with env(fs, runner, which={"auditctl"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertEqual(c.current, "rules.d 設定：-e 2、--loginuid-immutable：有；目前 enabled=1、"
                                    "loginuid_immutable=0（需重開機生效）")
        with env({self.rule.FILE: "-e 2\n"}, FakeRunner({"auditctl -s": res(1)}), which={"auditctl"}):
            c = self.rule.check(FakeCtx())
        self.assertEqual(c.status, FAIL)  # 缺 --loginuid-immutable
        self.assertIn("enabled=無法取得、loginuid_immutable=無法取得", c.current)


# TWGCB-01-012-0176 rsyslog 檔案權限、0177 rsyslog 日誌記錄規則（基本路徑）
class RsyslogBasicTest(unittest.TestCase):
    def test_helpers(self):
        self.assertEqual(lg.rsyslog_modes("# $FileCreateMode 0777\n$FileCreateMode 0600\n"), ["0600"])
        self.assertEqual(lg.rsyslog_fix_text("*.* /x\n$IncludeConfig /etc/rsyslog.d/*.conf\n", False),
                         "*.* /x\n$FileCreateMode 0640\n$IncludeConfig /etc/rsyslog.d/*.conf\n")
        self.assertEqual(lg.rsyslog_secure_facilities(["\n# c\nauth,authpriv.* /var/log/secure\n"]),
                         {"auth", "authpriv"})

    def test_file_mode(self):
        rule = lg.RsyslogFileMode(R(r8=176, r9=176))
        with env({}):
            self.assertIn("未安裝 rsyslog", rule.check(FakeCtx()).current)
            self.assertRaises(ManualRequired, rule.fix, FakeCtx(), fx_for({}))
        fs = {lg.RSYSLOG_CONF: "$FileCreateMode 0640\n"}
        with env(fs):
            self.assertEqual(rule.check(FakeCtx()).current, "0640（/etc/rsyslog.conf）")
        fx = fx_for(fs)
        with env(fs):
            rule.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), [])
        self.assertEqual(fx.kinds("run"), ["systemctl restart rsyslog"])
        self.assertIn("既有日誌檔權限不會改變", fx.notes[0])

    def test_secure(self):
        rule = lg.RsyslogSecure(R(r8=177, r9=177))
        with env({}):
            self.assertIn("未安裝 rsyslog", rule.check(FakeCtx()).current)
            self.assertRaises(ManualRequired, rule.fix, FakeCtx(), fx_for({}))
        fs = {lg.RSYSLOG_CONF: "auth.*,authpriv.*,daemon.* /var/log/secure\n"}
        with env(fs):
            self.assertEqual(rule.check(FakeCtx()).status, PASS)
        fx = fx_for(fs, runner=FakeRunner())
        with env(fs, which={"rsyslogd"}):
            rule.fix(fx.ctx, fx)
        self.assertEqual(fs[rule.DROPIN], "# GCB TWGCB-01-012-0177（gcb-checker 產生）\n%s\n" % lg.SECURE_LINE)
        ev = fx.events
        self.assertLess(idx(ev, ("undo", "systemctl restart rsyslog")), idx(ev, ("write", rule.DROPIN)))
        self.assertLess(idx(ev, ("run", "rsyslogd -N1")), idx(ev, ("run", "systemctl restart rsyslog")))
        self.assertIn("daemon", fx.notes[0])


# TWGCB-01-012-0308 rsyslog logrotate（目錄建立）
class LogrotateCreateTest(unittest.TestCase):
    rule = lg.RsyslogLogrotate(R(r9=308))

    def test_check_not_installed(self):
        with env({}):
            self.assertIn("未安裝 rsyslog", self.rule.check(FakeCtx()).current)

    def test_fix_creates_dir_and_appends(self):
        fs = {lg.LOGROTATE_FILE: "/var/log/x {\n}"}
        fx = fx_for(fs)
        with env(fs, pkgs={"rsyslog"}, modes={lg.LOGROTATE_DIR: 0o40750}):
            self.rule.fix(fx.ctx, fx)
        ev = fx.events
        self.assertLess(idx(ev, ("undo", "rmdir --ignore-fail-on-non-empty /var/log/rsyslog")),
                        idx(ev, ("run", "mkdir -m 750 /var/log/rsyslog")))
        self.assertEqual(fx.kinds("chmod"), [])
        self.assertEqual(fs[lg.LOGROTATE_FILE], "/var/log/x {\n}\n" + lg.LOGROTATE_STANZA)


# TWGCB-01-012-0181 journald 參數（未設定）
class JournaldUnsetTest(unittest.TestCase):
    def test_unset_with_default(self):
        rule = lg.JournaldSetting("Compress", R(r8=181, r9=181), "Compress", "yes", default="yes")
        with env({}):
            c = rule.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "Compress 未設定（systemd 預設 yes，GCB 要求明確設定）"))


if __name__ == "__main__":
    unittest.main()
