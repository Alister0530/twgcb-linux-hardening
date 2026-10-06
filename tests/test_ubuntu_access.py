# -*- coding: utf-8 -*-
"""Ubuntu 22.04 帳號與存取控制（access.py）純函式測試。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.rules.ubuntu import access as a  # noqa: E402

UNIX = """Name: Unix authentication
Default: yes
Priority: 256
Auth-Type: Primary
Auth:
\t[success=end default=ignore]\tpam_unix.so nullok try_first_pass
Password-Type: Primary
Password:
\t[success=end default=ignore]\tpam_unix.so obscure use_authtok try_first_pass sha512
Password-Initial:
\t[success=end default=ignore]\tpam_unix.so obscure sha512
"""

SU = """auth       sufficient pam_rootok.so
# auth       required   pam_wheel.so
session       required   pam_env.so readenv=1
@include common-auth
@include common-account
"""


class TestPam(unittest.TestCase):
    def test_pam_args(self):
        text = "#password x pam_unix.so remember=9\npassword\t[success=1 default=ignore]\tpam_unix.so obscure remember=3\n"
        args = a.pam_args(text, "password", "pam_unix.so")
        self.assertEqual(args, [["obscure", "remember=3"]])
        self.assertEqual(a.arg_value(args[0], "remember"), "3")
        self.assertEqual(a.pam_args(text, "auth", "pam_unix.so"), [])

    def test_unix_profile(self):
        out = a.unix_profile(UNIX, a.with_remember(3))
        self.assertIn("Name: " + a.GCB_UNIX_NAME, out)
        self.assertIn("Conflicts: unix", out)
        self.assertIn("pam_unix.so obscure use_authtok try_first_pass sha512 remember=3", out)
        self.assertIn("pam_unix.so obscure sha512 remember=3", out)
        self.assertIn("pam_unix.so nullok try_first_pass\n", out)  # Auth 不變
        out2 = a.unix_profile(out, a.with_yescrypt)  # 再次套用不重複 Conflicts
        self.assertEqual(out2.count("Conflicts:"), 1)
        self.assertIn("pam_unix.so obscure use_authtok try_first_pass remember=3 yescrypt", out2)
        self.assertNotIn("sha512", out2)


class TestShell(unittest.TestCase):
    def test_tmout_script_passes(self):
        vals, ro, ex = a.tmout_scan([(a.TMOUT_FILE, a.TMOUT_SCRIPT)])
        self.assertEqual(vals, [(a.TMOUT_FILE, 900)])
        self.assertTrue(ro and ex)

    def test_tmout_scan(self):
        vals, ro, ex = a.tmout_scan([("f", "# TMOUT=10\nTMOUT=3600\nexport TMOUT\n")])
        self.assertEqual(vals, [("f", 3600)])
        self.assertFalse(ro)
        self.assertTrue(ex)

    def test_umask(self):
        self.assertEqual(a.umask_value("027"), 0o27)
        self.assertEqual(a.umask_value("u=rwx,g=rx,o="), 0o27)
        self.assertTrue(a.umask_ok(0o077))
        self.assertFalse(a.umask_ok(0o022))
        found = a.umask_scan([("f", "umask 022\n# umask 000\n[ x ] && umask 0077\n")])
        self.assertEqual([x[1] for x in found], ["022", "0077"])
        self.assertEqual(a._fix_umask_line("  umask 022 # x"), "  umask 027 # x")


class TestSu(unittest.TestCase):
    def test_apply(self):
        self.assertFalse(a.su_wheel_status(SU)[0])
        new = a.su_wheel_apply(SU)
        self.assertTrue(a.su_wheel_status(new)[0])
        lines = new.splitlines()
        self.assertEqual(lines[1], a.SU_LINE)

    def test_wrong_position(self):
        text = "auth sufficient pam_rootok.so\n@include common-auth\n" + a.SU_LINE + "\n"
        self.assertFalse(a.su_wheel_status(text)[0])


class TestShadow(unittest.TestCase):
    def test_would_disable(self):
        today = a._today()
        self.assertTrue(a.would_disable_now({"lastchg": str(today - 200), "max": "90"}, 30))
        self.assertFalse(a.would_disable_now({"lastchg": str(today - 100), "max": "90"}, 30))
        self.assertFalse(a.would_disable_now({"lastchg": "0", "max": "90"}, 30))
        self.assertFalse(a.would_disable_now({"lastchg": str(today - 200), "max": ""}, 30))


if __name__ == "__main__":
    unittest.main()
