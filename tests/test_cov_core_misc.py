# -*- coding: utf-8 -*-
"""共用工具與小模組測試：util、pkgsvc、osinfo、textedit、auditrules、rules/base、rules/__init__。"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fakes import FakeRunner, fs_reader, make_osi, res  # noqa: E402
from gcb import auditrules, osinfo, pkgsvc, rules, util  # noqa: E402
from gcb import textedit as te  # noqa: E402
from gcb.fixer import ManualRequired  # noqa: E402
from gcb.rules import base  # noqa: E402


class TestUtil(unittest.TestCase):
    def test_run_timeout_and_oserror(self):
        with mock.patch.object(util, "HEARTBEAT", 0.2):
            r = util.run(["sleep", "5"], timeout=1)
        self.assertEqual((r.rc, r.err), (124, "執行逾時（1 秒）"))
        with mock.patch.object(util.subprocess, "Popen", side_effect=OSError("no such file")):
            r = util.run(["nope"])
        self.assertEqual((r.rc, r.cmd), (127, "nope"))

    def test_run_passes_env_and_input(self):
        r = util.run("echo $A $LC_ALL; cat", env={"A": "1"}, input_text="輸入")
        self.assertEqual((r.rc, r.out), (0, "1 C\n輸入"))

    def test_run_stdin_not_terminal(self):
        # 指令要求輸入時讀到結尾立即結束，不會等鍵盤輸入而卡住
        r = util.run(["cat"], timeout=5)
        self.assertEqual((r.rc, r.out), (0, ""))

    def test_run_reports_progress_with_activity(self):
        seen = []
        util.set_progress(lambda what, sec: seen.append((what, sec)))
        self.addCleanup(util.set_progress, None)
        with mock.patch.object(util, "HEARTBEAT", 0.2):
            with util.activity("修復 TWGCB-01-014-0033 AIDE"):
                r = util.run(["sleep", "0.7"], timeout=10)
            util.run(["sleep", "0.3"], timeout=10)   # 無工作說明時以指令本身顯示
        self.assertTrue(r.ok)
        whats = [w for w, s in seen]
        self.assertIn("修復 TWGCB-01-014-0033 AIDE", whats)
        self.assertIn("sleep 0.3", whats)
        self.assertTrue(all(s > 0 for w, s in seen))
        self.assertEqual(util._activity, [])

    def test_elapsed_str(self):
        self.assertEqual([util.elapsed_str(s) for s in (5, 60, 754.6)], ["5 秒", "1 分 00 秒", "12 分 34 秒"])

    def test_which_fallback(self):
        with mock.patch.object(util.shutil, "which", return_value=None), \
                mock.patch.object(util.os, "access", lambda p, m: p == "/sbin/sshd"):
            self.assertEqual(util.which("sshd"), "/sbin/sshd")
            self.assertIsNone(util.which("nothing"))

    def test_write_atomic_cleans_tmp_on_error(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "a")
        with mock.patch.object(util.os, "replace", side_effect=OSError("disk full")), \
                mock.patch.object(util, "restorecon", lambda p: None):
            with self.assertRaises(OSError):
                util.write_text_atomic(p, "x")
        self.assertEqual(os.listdir(d), [])

    def test_write_atomic_follows_symlink(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        real = os.path.join(d, "real.conf")
        with open(real, "w") as f:
            f.write("a")
        os.chmod(real, 0o640)
        os.symlink(real, os.path.join(d, "link.conf"))
        with mock.patch.object(util, "restorecon", lambda p: None):
            util.write_text_atomic(os.path.join(d, "link.conf"), "b")
        self.assertTrue(os.path.islink(os.path.join(d, "link.conf")))
        self.assertEqual(util.read_text(real), "b")
        self.assertEqual(os.stat(real).st_mode & 0o7777, 0o640)

    def test_restorecon(self):
        runner = FakeRunner()
        with mock.patch.object(util, "which", return_value="/sbin/restorecon"), \
                mock.patch.object(util.os.path, "exists", return_value=True), \
                mock.patch.object(util, "run", runner):
            util.restorecon("/etc/x")
        self.assertEqual(runner.calls, ["/sbin/restorecon -R /etc/x"])

    def test_primary_ip(self):
        with mock.patch.object(util, "run", FakeRunner({"hostname": res(0, "10.0.0.5 172.17.0.1\n")})):
            self.assertEqual(util.primary_ip(), "10.0.0.5")
        with mock.patch.object(util, "run", FakeRunner({"hostname": res(1)})), \
                mock.patch.object(util.socket, "gethostbyname", return_value="10.1.1.1"):
            self.assertEqual(util.primary_ip(), "10.1.1.1")
        with mock.patch.object(util, "run", FakeRunner({"hostname": res(0, "")})), \
                mock.patch.object(util.socket, "gethostbyname", side_effect=socket.error):
            self.assertEqual(util.primary_ip(), "")

    def test_diff_summary_limit(self):
        out = util.diff_summary("", "\n".join(str(i) for i in range(50)), limit=3)
        self.assertEqual(out.splitlines()[-1], "...（其餘 47 行省略）")
        self.assertEqual(util.diff_summary("a", "a"), "（無差異）")
        self.assertEqual(util.split_csv(" a, ,b "), ["a", "b"])


class TestPkgsvc(unittest.TestCase):
    def test_pkg_installed_and_list(self):
        r8, u = make_osi("rhel8"), make_osi("ubuntu2204")
        runner = FakeRunner({"rpm -qa": res(0, "bash\naide\n"), "rpm -q aide": res(0), "rpm -q": res(1),
                             "${Status}' hold": res(0, "hold ok installed"),
                             "${Status}' cfg": res(0, "deinstall ok config-files"),
                             "${Package}": res(0, "bash install ok installed\nold deinstall ok config-files\nx\n")})
        with mock.patch.object(pkgsvc, "run", runner):
            self.assertTrue(pkgsvc.pkg_installed(r8, "aide"))
            self.assertFalse(pkgsvc.pkg_installed(r8, "telnet"))
            self.assertTrue(pkgsvc.pkg_installed(u, "hold"))
            self.assertFalse(pkgsvc.pkg_installed(u, "cfg"))
            self.assertFalse(pkgsvc.pkg_installed(u, "none"))
            self.assertEqual(pkgsvc.pkg_list(r8), {"bash", "aide"})
            self.assertEqual(pkgsvc.pkg_list(u), {"bash"})
        self.assertEqual(pkgsvc.pkg_remove_cmd(r8, "x"), ["dnf", "-y", "remove", "x"])
        self.assertEqual(pkgsvc.pkg_remove_cmd(u, "x"), ["apt-get", "-y", "purge", "x"])

    def test_sysctl_runtime(self):
        fs = {"/proc/sys/net/ipv4/ip_forward": "1\n"}
        with mock.patch.object(pkgsvc, "read_text", fs_reader(fs)):
            self.assertEqual(pkgsvc.sysctl_runtime("net.ipv4.ip_forward"), "1")
            self.assertIsNone(pkgsvc.sysctl_runtime("net.ipv6.conf.all.forwarding"))

    def test_dependents_rhel_failure(self):
        with mock.patch.object(pkgsvc, "run", FakeRunner({"whatrequires": res(1, "no package requires x")})):
            self.assertEqual(pkgsvc.pkg_dependents(make_osi("rhel9"), "x"), [])
        with mock.patch.object(pkgsvc, "run", FakeRunner({"whatrequires": res(0, "a\n\nb\n")})):
            self.assertEqual(pkgsvc.pkg_dependents(make_osi("rhel9"), "x"), ["a", "b"])
        out = "Purg x [1]\nRemv y [2]\nInst z\n"
        with mock.patch.object(pkgsvc, "run", FakeRunner({"purge": res(0, out)})):
            self.assertEqual(pkgsvc.pkg_dependents(make_osi("ubuntu2204"), "x"), ["y"])

    def test_svc_state(self):
        with mock.patch.object(pkgsvc, "which", return_value=None):
            self.assertEqual(pkgsvc.svc_state("x"), ("not-found", "unknown"))
            self.assertFalse(pkgsvc.svc_exists("x"))
        runner = FakeRunner({"is-enabled": res(1, "", "Failed to get unit file state for x: No such file"),
                             "is-active": res(3, "inactive\n")})
        with mock.patch.object(pkgsvc, "which", return_value="/bin/systemctl"), mock.patch.object(pkgsvc, "run", runner):
            self.assertEqual(pkgsvc.svc_state("x"), ("not-found", "inactive"))
            runner.add("is-enabled", res(0, "alias\nenabled\n"))
            self.assertTrue(pkgsvc.svc_exists("x"))
            self.assertEqual(pkgsvc.svc_state("x")[0], "enabled")

    def test_sysctl_files_order_and_dedup(self):
        globs = {"/etc/sysctl.d/*.conf": ["/etc/sysctl.d/99-sysctl.conf", "/etc/sysctl.d/10-a.conf"],
                 "/usr/lib/sysctl.d/*.conf": ["/usr/lib/sysctl.d/10-a.conf", "/usr/lib/sysctl.d/50-b.conf"]}
        real = {"/etc/sysctl.d/99-sysctl.conf": "/etc/sysctl.conf", "/usr/lib/sysctl.d/50-b.conf": "/etc/sysctl.d/10-a.conf"}
        with mock.patch.object(pkgsvc.glob, "glob", lambda p: globs.get(p, [])), \
                mock.patch.object(pkgsvc.os.path, "realpath", lambda p: real.get(p, p)), \
                mock.patch.object(pkgsvc.os.path, "exists", lambda p: True):
            self.assertEqual(pkgsvc.sysctl_files(), ["/etc/sysctl.d/10-a.conf", "/etc/sysctl.d/99-sysctl.conf"])
        # /etc/sysctl.conf 沒有被連結時附加在最後
        real = {}
        fs = {"/etc/sysctl.d/10-a.conf": "x = 1\n", "/etc/sysctl.conf": "x = 2\n"}
        with mock.patch.object(pkgsvc.glob, "glob", lambda p: ["/etc/sysctl.d/10-a.conf"] if p.startswith("/etc") else []), \
                mock.patch.object(pkgsvc.os.path, "exists", lambda p: True), \
                mock.patch.object(pkgsvc, "read_text", fs_reader(fs)):
            self.assertEqual(pkgsvc.sysctl_files(), ["/etc/sysctl.d/10-a.conf", "/etc/sysctl.conf"])
            self.assertEqual(pkgsvc.sysctl_persistent("x"),
                             ("2", "/etc/sysctl.conf", [("/etc/sysctl.d/10-a.conf", "1"), ("/etc/sysctl.conf", "2")]))


class TestOsinfo(unittest.TestCase):
    def test_version_and_parse(self):
        self.assertEqual(osinfo.OSInfo("rhel9", "rhel", "x", "rocky", "9.x").version_tuple(), (0,))
        d = osinfo.parse_os_release("# 註解\n\nID=rocky\nNAME\nVERSION_ID='9.5'\n")
        self.assertEqual(d, {"ID": "rocky", "VERSION_ID": "9.5"})
        self.assertEqual(make_osi("rhel9").compatible_note, "rocky 與 RHEL 相容，套用 RHEL 規範")
        self.assertEqual(make_osi("ubuntu2204").compatible_note, "")


class TestTextedit(unittest.TestCase):
    def test_parse_sysctl(self):
        text = "# c\n; c\nkernel.x\n-net/ipv4/ip_forward = 0\nfs.a=1\n"
        self.assertEqual(te.parse_sysctl(text), [("net.ipv4.ip_forward", "0"), ("fs.a", "1")])

    def test_comment_kv_keep(self):
        text = "minlen = 8\n# minlen = 1\nminlen = 14\nother = 1\n"
        out = te.comment_kv(text, "minlen", keep=lambda v: int(v) >= 12)
        self.assertEqual(out, te.MARK + "minlen = 8\n# minlen = 1\nminlen = 14\nother = 1\n")
        self.assertEqual(te.comment_kv("", "x"), "")

    def test_sshd_duplicate_and_match(self):
        text = "PermitRootLogin yes\npermitrootlogin prohibit-password\nMatch User a\n  PermitRootLogin yes\n"
        out = te.sshd_set_option(text, "PermitRootLogin", "no")
        self.assertEqual(out.splitlines()[:2], ["PermitRootLogin no", te.MARK + "permitrootlogin prohibit-password"])
        self.assertEqual(out.splitlines()[-1], "  PermitRootLogin yes")       # Match 區塊內不改
        drop = "PermitRootLogin yes\nPermitRootLogin no\nMatch Address 10.0.0.1\nPermitRootLogin yes\n"
        self.assertEqual(te.sshd_comment_option(drop, "PermitRootLogin", "no"),
                         te.MARK + "PermitRootLogin yes\nPermitRootLogin no\nMatch Address 10.0.0.1\nPermitRootLogin yes\n")


class TestAuditrules(unittest.TestCase):
    def test_parse_edge_cases(self):
        self.assertIsNone(auditrules.parse('-w "/etc/passwd -p wa'))     # 引號不完整
        r = auditrules.parse("-a always,exit -F arch=b64 -F success -S open extra -k k")
        self.assertIn("success", r["fields"])
        self.assertEqual(r["syscalls"], {"open"})
        self.assertTrue(auditrules.satisfied("# 註解", []))


class _R(base.Rule):
    pass


class TestRuleBase(unittest.TestCase):
    def test_defaults(self):
        r = _R()
        with self.assertRaises(NotImplementedError):
            r.check(None)
        with self.assertRaises(ManualRequired) as cm:
            r.fix(None, None)
        self.assertEqual(str(cm.exception), "此項目需人工處理")
        r.manual_hint = "請人工確認"
        with self.assertRaises(ManualRequired) as cm:
            r.fix(None, None)
        self.assertEqual(str(cm.exception), "請人工確認")

    def test_manual_reason(self):
        r = _R()
        r.manual_reason = "自訂原因"
        self.assertEqual(base.manual_reason_for(r), "自訂原因")
        r2 = _R()
        r2.title = "某項目"
        self.assertTrue(base.manual_reason_for(r2).startswith("自動修改可能影響系統運作"))
        r2.manual_hint = "需重新規劃磁區"
        self.assertTrue(base.manual_reason_for(r2).startswith("需要重新規劃磁碟分割"))

    def test_expected_for_dict(self):
        r = _R()
        r.expected = {"rhel9": "九", "rhel": "紅帽"}
        self.assertEqual(r.expected_for(make_osi("rhel9")), "九")
        self.assertEqual(r.expected_for(make_osi("rhel8")), "紅帽")
        self.assertEqual(r.expected_for(make_osi("ubuntu2204")), "")


class TestRulesFor(unittest.TestCase):
    def test_duplicate_id_raises(self):
        a, b = _R(), _R()
        a.ids = b.ids = {"rhel9": "TWGCB-01-012-0001"}
        with mock.patch.object(rules, "_catalogs", lambda: [[a], [b]]):
            with self.assertRaises(RuntimeError):
                rules.rules_for(make_osi("rhel9"))

    def test_sorted_and_skips_other_os(self):
        a, b, c = _R(), _R(), _R()
        a.ids = {"rhel9": "TWGCB-01-012-0002"}
        b.ids = {"rhel9": "TWGCB-01-012-0001"}
        c.ids = {"rhel8": "TWGCB-01-008-0001"}
        with mock.patch.object(rules, "_catalogs", lambda: [[a, c], [b]]):
            self.assertEqual(rules.rules_for(make_osi("rhel9")), [("TWGCB-01-012-0001", b), ("TWGCB-01-012-0002", a)])


if __name__ == "__main__":
    unittest.main()
