# -*- coding: utf-8 -*-
"""RHEL 8 / 9 帳號與存取控制（rhel/accounts.py）純函式測試。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.rules.rhel import accounts as a  # noqa: E402

SYSTEM_AUTH = """auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok
-auth       required      pam_faillock.so authfail
password    requisite     pam_pwquality.so local_users_only retry=5
password    sufficient    pam_unix.so sha512 shadow nullok use_authtok
#password   sufficient    pam_unix.so md5
session     required      pam_limits.so
"""

SU = """#%PAM-1.0
auth\t\tsufficient\tpam_rootok.so
#auth\t\tsufficient\tpam_wheel.so trust use_uid
#auth\t\trequired\tpam_wheel.so use_uid
auth\t\tsubstack\tsystem-auth
"""


class TestConf(unittest.TestCase):
    def test_conf_get_set_case_insensitive(self):
        text = "# retry = 1\nRetry = 5\nminlen = 12\n"
        self.assertEqual(a.conf_get(text, "retry"), "5")
        out = a.conf_set(text, "retry", "3")
        self.assertIn("\nretry = 3\n", out)
        self.assertNotIn("Retry = 5", out.replace(a.te.MARK + "Retry = 5", ""))
        self.assertEqual(a.conf_get(out, "retry"), "3")
        self.assertEqual(a.conf_get(a.conf_set("", "dcredit", "-1"), "dcredit"), "-1")

    def test_conf_comment_and_flags(self):
        self.assertIsNone(a.conf_get(a.conf_comment("difok = 1\n", "difok"), "difok"))
        self.assertFalse(a.flag_present("# enforce_for_root\n", "enforce_for_root"))
        out = a.flag_set("minlen = 12\n", "enforce_for_root")
        self.assertTrue(a.flag_present(out, "enforce_for_root"))
        self.assertEqual(a.flag_set(out, "enforce_for_root"), out)
        # 文件寫法（兩個參數同一行）不算啟用
        self.assertFalse(a.flag_present("even_deny_root root_unlock_time=60\n", "even_deny_root"))
        self.assertEqual(a.FaillockRoot._combined("even_deny_root root_unlock_time=60\n"),
                         ["even_deny_root root_unlock_time=60"])

    def test_comparators(self):
        self.assertTrue(a.rng(1, 3)("3") and not a.rng(1, 3)("0") and not a.rng(1, 3)(None))
        self.assertTrue(a.le(-1)("-2") and not a.le(-1)("0"))
        self.assertTrue(a.ge(4)("4") and not a.ge(4)("x"))
        self.assertTrue(a.unlock_ok("900") and not a.unlock_ok("0") and not a.unlock_ok("never"))
        self.assertTrue(a.idle_ok("uint32 900") and not a.idle_ok("uint32 0") and not a.idle_ok("901"))


class TestPam(unittest.TestCase):
    def test_pam_args(self):
        self.assertEqual(a.pam_args(SYSTEM_AUTH, "password", "pam_pwquality.so"),
                         [["local_users_only", "retry=5"]])
        self.assertEqual(len(a.pam_args(SYSTEM_AUTH, "password", "pam_unix.so")), 1)  # 註解行不算
        self.assertEqual(a.pam_args(SYSTEM_AUTH, "auth", "pam_faillock.so"), [["authfail"]])  # -auth
        self.assertEqual(a.arg_value(["retry=1", "retry=5"], "retry"), "5")

    def test_lastlog_lines(self):
        text = ("session optional pam_umask.so silent\n"
                "session [default=1] pam_lastlog.so nowtmp showfailed\n"
                "session optional pam_lastlog.so silent noupdate\n")
        self.assertEqual(a.lastlog_lines(text), [("[default=1]", ["nowtmp", "showfailed"])])
        self.assertEqual(a.lastlog_lines("#session required pam_lastlog.so showfailed\n"), [])

    def test_su_wheel(self):
        self.assertFalse(a.su_wheel_status(SU)[0])
        out = a.su_wheel_apply(SU)
        self.assertTrue(a.su_wheel_status(out)[0])
        self.assertIn("#auth\t\tsufficient\tpam_wheel.so trust use_uid", out)  # trust 行維持註解
        out2 = a.su_wheel_apply("auth sufficient pam_rootok.so\nauth substack system-auth\n")
        self.assertEqual(out2.splitlines()[1], a.SU_LINE)
        self.assertFalse(a.su_wheel_status("auth required pam_wheel.so use_uid group=staff\n")[0])


class TestIni(unittest.TestCase):
    def test_ini_set_existing_section(self):
        text = "[defaults]\n# crypt_style = md5\ncrypt_style = md5\nmodules = files\n\n[import]\nx = 1\n"
        out = a.ini_set(text, "defaults", "crypt_style", "sha512", sep=" = ")
        self.assertEqual(a.ini_get(out, "defaults", "crypt_style"), "sha512")
        self.assertEqual(a.ini_get(out, "import", "x"), "1")

    def test_ini_set_new_key_and_section(self):
        out = a.ini_set("[daemon]\n\n[security]\n", "daemon", "AutomaticLoginEnable", "false")
        self.assertEqual(out.splitlines()[:2], ["[daemon]", "AutomaticLoginEnable=false"])
        out = a.ini_set("", "org/gnome/desktop/session", "idle-delay", "uint32 900")
        self.assertEqual(out, "[org/gnome/desktop/session]\nidle-delay=uint32 900\n")
        self.assertEqual(a.ini_get(out, "org/gnome/desktop/session", "idle-delay"), "uint32 900")


class TestLimits(unittest.TestCase):
    def test_maxlogins(self):
        texts = [("limits.conf", "* hard maxlogins 20\n#* hard maxlogins 1\n@g hard maxlogins 2\n* soft maxlogins 3\n"),
                 ("x.conf", "*  -  maxlogins  5\n")]
        self.assertEqual(a.maxlogins_entries(texts), [("limits.conf", "20"), ("x.conf", "5")])
        out = a.maxlogins_comment(texts[0][1], a.rng(1, 10))
        self.assertEqual(a.maxlogins_entries([("f", out)]), [])
        self.assertIn("@g hard maxlogins 2", out)


class TestShell(unittest.TestCase):
    def test_tmout_script_and_block(self):
        vals, ro, ex = a.tmout_scan([("f", a.TMOUT_SCRIPT)])
        self.assertEqual(vals, [("f", 900)])
        self.assertTrue(ro and ex)
        once = a.bashrc_tmout_block("# bashrc\nalias x=y\n")
        self.assertEqual(a.bashrc_tmout_block(once), once)  # 重複套用不重複加入
        self.assertEqual(once.count(a.BASHRC_BEGIN), 1)
        self.assertTrue(a.tmout_scan([("f", once)])[1])

    def test_umask(self):
        rhel8 = "if [ $UID -gt 199 ]; then\n    umask 002\nelse\n    umask 022\nfi\n"
        out = a.fix_umask_text(rhel8)
        self.assertEqual([x[1] for x in a.umask_scan([("f", out)])], ["027", "027"])
        rhel9 = "    [ `umask` -eq 0 ] && umask 022\n"
        self.assertEqual(a.umask_scan([("f", a.fix_umask_text(rhel9))])[0][1], "027")
        self.assertTrue(a.umask_ok(a.umask_value("077")) and not a.umask_ok(a.umask_value("022")))
        self.assertTrue(a.umask_ok(a.umask_value("u=rwx,g=rx,o=")))
        self.assertEqual(a.umask_scan([("f", a.append_umask(""))])[0][1], "027")


class TestAging(unittest.TestCase):
    def test_would_disable_now(self):
        u = {"lastchg": "100", "max": "99999"}
        self.assertTrue(a.would_disable_now(u, 30, today=220))   # 以 90 天計：100+90+30
        self.assertFalse(a.would_disable_now(u, 30, today=219))
        self.assertTrue(a.would_disable_now({"lastchg": "0", "max": "90"}, 30, today=1))
        self.assertFalse(a.would_disable_now({"lastchg": "", "max": "90"}, 30, today=1))


class TestRules(unittest.TestCase):
    def test_rule_ids(self):
        r8 = sorted(int(r.ids["rhel8"][-4:]) for r in a.RULES if "rhel8" in r.ids)
        r9 = sorted(int(r.ids["rhel9"][-4:]) for r in a.RULES if "rhel9" in r.ids)
        common8, common9 = {210, 220, 227}, {208, 218, 225}
        self.assertEqual(set(r8), set(range(208, 244)) - common8)
        self.assertEqual(set(r9), (set(range(206, 242)) - common9) | set(range(309, 315)))
        for r in a.RULES:
            if "rhel8" in r.ids and "rhel9" in r.ids:
                self.assertEqual(int(r.ids["rhel8"][-4:]) - 2, int(r.ids["rhel9"][-4:]))


if __name__ == "__main__":
    unittest.main()
