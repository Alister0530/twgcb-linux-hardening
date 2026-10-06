# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.hints import explain  # noqa: E402


class HintsTest(unittest.TestCase):
    def assertCause(self, text, keyword):
        res = explain(text)
        self.assertTrue(res, "沒有對應說明：%s" % text)
        self.assertIn(keyword, res[0])

    def test_sysctl_container(self):
        self.assertCause('sysctl: permission denied on key "net.ipv4.ip_forward"', "核心參數無法修改")
        self.assertCause('sysctl: setting key "net.ipv4.ip_forward": Read-only file system', "核心參數無法修改")

    def test_specific_beats_generic(self):
        res = explain('sysctl: permission denied on key "x"')
        self.assertEqual(len(res), 1)
        self.assertNotIn("權限不足；", res[0])

    def test_generic_fallback(self):
        self.assertCause("chmod: changing permissions of '/etc/x': Permission denied", "權限不足")
        self.assertCause("chattr: Operation not permitted", "不可修改屬性")

    def test_systemd(self):
        self.assertCause("System has not been booted with systemd as init system (PID 1).", "systemd")

    def test_package(self):
        self.assertCause("Error: Failed to download metadata for repo 'appstream'", "無法連線套件庫")
        self.assertCause("E: Unable to locate package auditd", "找不到此套件")
        self.assertCause("This system is not registered with an entitlement server.", "註冊訂閱")
        self.assertCause("E: Could not get lock /var/lib/dpkg/lock-frontend", "佔用")

    def test_pam_and_ssh(self):
        self.assertCause("pam-auth-update 失敗（PAM 設定可能曾被手動修改）", "pam-auth-update")
        self.assertCause("gcbtest@127.0.0.1: Permission denied (publickey).", "SSH 金鑰登入被拒")
        self.assertCause("sshd 設定語法錯誤，不重新載入服務", "sshd 設定")

    def test_not_effective(self):
        self.assertCause("修復後檢測仍不合格：net.ipv4.ip_forward 目前=1", "沒有生效")

    def test_no_match(self):
        self.assertEqual(explain("一切正常"), [])
        self.assertEqual(explain(None), [])


if __name__ == "__main__":
    unittest.main()
