# -*- coding: utf-8 -*-
"""Ubuntu 22.04 系統設定與維護（0029–0078）的純函式測試。"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.rules.ubuntu import system as s  # noqa: E402


class Sudoers(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.main = os.path.join(self.d, "sudoers")
        self.dd = os.path.join(self.d, "sudoers.d")
        os.mkdir(self.dd)

    def tearDown(self):
        shutil.rmtree(self.d)

    def _write(self, path, text):
        with open(path, "w") as f:
            f.write(text)

    def _eval(self, rule, extra=None):
        return rule.evaluate(s.sudoers_defaults(extra, self.main))

    def test_flag_and_order(self):
        self._write(self.main, "Defaults\tenv_reset\nDefaults use_pty\n@includedir %s\n" % self.dd)
        self._write(os.path.join(self.dd, "50-x"), "Defaults !use_pty  # comment\n")
        self._write(os.path.join(self.dd, "ignored.conf"), "Defaults use_pty\n")
        r = s.SudoDefault("t", {}, "flag", "use_pty", "", "")
        self.assertFalse(self._eval(r)[0])
        ok, cur = self._eval(r, {os.path.join(self.dd, "99-gcb-0030"): "Defaults use_pty\n"})
        self.assertTrue(ok, cur)

    def test_logfile(self):
        self._write(self.main, '#includedir %s\n' % self.dd)
        r = s.SudoDefault("t", {}, "logfile", "logfile", "", "")
        self.assertFalse(self._eval(r)[0])
        self._write(os.path.join(self.dd, "a"), 'Defaults mail_badpass, logfile="/var/log/sudo.log"\n')
        self.assertTrue(self._eval(r)[0])

    def test_timeout(self):
        self._write(self.main, "Defaults env_reset,timestamp_timeout=15\n@includedir %s\n" % self.dd)
        r = s.SudoDefault("t", {}, "timeout", "timestamp_timeout", "", "")
        self.assertFalse(self._eval(r)[0])
        self._write(os.path.join(self.dd, "99-gcb-0032"), "Defaults env_reset,timestamp_timeout=5\n")
        self.assertTrue(self._eval(r)[0])
        self._write(os.path.join(self.dd, "zz"), "Defaults:alice timestamp_timeout=-1\n")
        ok, cur = self._eval(r)
        self.assertFalse(ok)
        self.assertIn("個別設定", cur)

    def test_timeout_zero_and_continuation(self):
        self._write(self.main, "Defaults env_reset,\\\n  timestamp_timeout = 0\n")
        r = s.SudoDefault("t", {}, "timeout", "timestamp_timeout", "", "")
        self.assertFalse(self._eval(r)[0])

    def test_includes_dir(self):
        self.assertTrue(s.sudoers_includes_dir("@includedir /etc/sudoers.d\n"))
        self.assertTrue(s.sudoers_includes_dir("#includedir /etc/sudoers.d/\n"))
        self.assertFalse(s.sudoers_includes_dir("# includedir /etc/sudoers.d\n"))


class Cron(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(s._cron_fields("0 5 * * * /usr/bin/aide --check", False), (True, "/usr/bin/aide --check"))
        self.assertEqual(s._cron_fields("0 5 * * 1 root aide --check", True)[0], False)
        self.assertEqual(s._cron_fields("@daily root /usr/bin/aide --check", True), (True, "/usr/bin/aide --check"))
        self.assertIsNone(s._cron_fields("# 0 5 * * * aide --check", False))
        self.assertIsNone(s._cron_fields("MAILTO=root", True))

    def test_is_aide(self):
        self.assertTrue(s._is_aide_check("/usr/bin/aide --config /etc/aide/aide.conf --check"))
        self.assertFalse(s._is_aide_check("/usr/bin/aide --init"))
        self.assertFalse(s._is_aide_check("/usr/bin/guide --check"))


class Misc(unittest.TestCase):
    def test_fstab_set_opts(self):
        t = "UUID=1 / ext4 defaults 0 1\nUUID=2 /boot/efi vfat umask=0077,uid=1000 0 1\n"
        out = s.fstab_set_opts(t, "/boot/efi", {"uid": "0", "gid": "0"})
        self.assertIn("umask=0077,gid=0,uid=0", out)
        self.assertIn("UUID=1 / ext4 defaults 0 1", out)

    def test_limits(self):
        good, bad = s.limits_core([("a", "* hard core 0\n"), ("b", "* - core unlimited\n@x hard core 5\n")])
        self.assertTrue(good)
        self.assertEqual(len(bad), 1)
        self.assertTrue(s._limits_comment("* hard core 100\n* hard core 0\n").startswith("#"))

    def test_path(self):
        self.assertEqual(s.path_problems("/usr/bin:/bin"), [])
        self.assertEqual(len(s.path_problems("/usr/bin::.:bin:..:")), 5)

    def test_accounts(self):
        pw = s.parse_passwd("root:x:0:0::/root:/bin/bash\ntoor:abc:0:0::/root:/bin/sh\na:x:1000:1000::/home/a:/bin/bash\n"
                            "a:x:1001:999::/home/b:/bin/bash\n")
        gr = s.parse_group("root:x:0:\na:x:1000:\nb:x:1000:\nshadow:x:42:a\n")
        self.assertEqual(s.bad_uid0(pw, gr), ["toor（UID 0）"])
        self.assertEqual(len(s.bad_passwd_field(pw, gr)), 1)
        self.assertEqual(len(s.bad_passwd_gid(pw, gr)), 1)
        self.assertEqual(len(s.bad_dup_uid(pw, gr)), 1)
        self.assertEqual(len(s.bad_dup_gid(pw, gr)), 1)
        self.assertEqual(len(s.bad_dup_user(pw, gr)), 1)
        self.assertEqual(s.bad_dup_group(pw, gr), [])
        self.assertEqual(s.shadow_group_problems(pw, gr), (["a"], []))

    def test_login_users(self):
        text = ("root:x:0:0::/root:/bin/bash\nsync:x:4:65534::/bin:/bin/sync\nwww:x:33:33::/var/www:/bin/bash\n"
                "pg:x:1001:1001::/var/lib/pg:/bin/bash\nu1:x:1000:1000::/home/u1:/bin/bash\n"
                "u2:x:1002:1002::/home/sh:/bin/bash\nu3:x:1003:1003::/home/sh:/bin/bash\n"
                "n:x:1004:1004::/home/n:/usr/sbin/nologin\n")
        users, skipped = s.login_users(passwd_text=text)
        self.assertEqual([u["name"] for u in users], ["root", "u1"])
        self.assertEqual(len(skipped), 3)
        users, _ = s.login_users(include_root=False, regular_only=False, passwd_text=text)
        self.assertEqual([u["name"] for u in users], ["www", "pg", "u1", "u2", "u3"])


class HomeRhostsTest(unittest.TestCase):
    """0071：.rhosts 備份後移除，回滾放回原位（內容、權限不變）。"""
    def setUp(self):
        from unittest import mock
        from gcb import journal
        from gcb.fixer import Fx
        self.base = tempfile.mkdtemp()
        self.home = os.path.join(self.base, "home")
        os.mkdir(self.home)
        self.rh = os.path.join(self.home, ".rhosts")
        with open(self.rh, "w") as f:
            f.write("host1 user1\n")
        os.chmod(self.rh, 0o600)
        run_dir = os.path.join(self.base, "run")
        os.mkdir(run_dir)
        self.j = journal.Journal(run_dir)
        ctx = mock.Mock(dry_run=False, journal=self.j)
        self.ctx, self.fx = ctx, Fx(ctx, "TWGCB-01-014-0071")
        p = mock.patch.object(s, "login_users", return_value=([{"home": self.home}], None))
        p.start()
        self.addCleanup(p.stop)
        self.rule = s.HomeRhosts({"ubuntu2204": "TWGCB-01-014-0071"})

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_fix_and_rollback(self):
        from gcb import journal
        self.assertEqual(self.rule.risk, "B")
        self.assertEqual(self.rule.check(self.ctx).status, s.FAIL)
        self.rule.fix(self.ctx, self.fx)
        self.assertFalse(os.path.exists(self.rh))
        self.assertEqual(self.rule.check(self.ctx).status, s.PASS)
        ok, fail = journal.rollback(self.j, None, lambda *a: None)
        self.assertEqual(fail, 0)
        with open(self.rh) as f:
            self.assertEqual(f.read(), "host1 user1\n")
        self.assertEqual(os.stat(self.rh).st_mode & 0o777, 0o600)

    def test_dry_run_keeps_file(self):
        self.ctx.dry_run = True
        from gcb.fixer import Fx
        self.rule.fix(self.ctx, Fx(self.ctx, "TWGCB-01-014-0071"))
        self.assertTrue(os.path.exists(self.rh))

    def test_precondition_blocks_when_rsh_installed(self):
        from unittest import mock
        with mock.patch.object(s.pkgsvc, "pkg_installed", side_effect=lambda osi, p: p == "rsh-server"):
            self.assertIn("rsh-server", self.rule.precondition(self.ctx))
        with mock.patch.object(s.pkgsvc, "pkg_installed", return_value=False):
            self.assertIsNone(self.rule.precondition(self.ctx))


if __name__ == "__main__":
    unittest.main()
