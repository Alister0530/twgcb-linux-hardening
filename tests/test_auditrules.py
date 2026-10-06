# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import auditrules as ar  # noqa: E402

# auditctl -l 實際輸出的格式
LOADED = """-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S settimeofday,adjtimex,stime -F key=time-change
-w /etc/group -p wa -k identity
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged
"""


class AuditRulesTest(unittest.TestCase):
    def test_syscall_order_and_key_form(self):
        self.assertTrue(ar.satisfied("-a always,exit -F arch=b64 -S settimeofday -S adjtimex -k time-change",
                                     ar.parse_all(LOADED)))

    def test_auid_unset_equivalence(self):
        self.assertTrue(ar.satisfied("-a exit,always -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
                                     ar.parse_all(LOADED)))
        self.assertTrue(ar.satisfied("-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
                                     ar.parse_all(LOADED)))

    def test_watch_and_path_forms(self):
        self.assertTrue(ar.satisfied("-w /etc/group -p aw -k identity", ar.parse_all(LOADED)))
        self.assertTrue(ar.satisfied(
            "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
            ar.parse_all(LOADED)))

    def test_missing(self):
        miss = ar.missing(["-w /etc/passwd -p wa -k identity", "-w /etc/group -p wa -k identity"], LOADED)
        self.assertEqual(miss, ["-w /etc/passwd -p wa -k identity"])

    def test_wrong_key_not_satisfied(self):
        self.assertFalse(ar.satisfied("-w /etc/group -p wa -k other", ar.parse_all(LOADED)))

    def test_dash_s_all_path_form(self):
        loaded = ar.parse_all("-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F key=priv\n")
        self.assertTrue(ar.satisfied("-w /usr/bin/sudo -p x -k priv", loaded))

    def test_trailing_slash_dir(self):
        loaded = ar.parse_all("-w /etc/sudoers.d -p wa -k scope\n")
        self.assertTrue(ar.satisfied("-w /etc/sudoers.d/ -p wa -k scope", loaded))

    def test_filter_syscalls(self):
        from gcb.rules.generic import audit_filter_syscalls
        have = {"init_module", "delete_module"}
        ex = lambda arch, n: n in have
        self.assertEqual(audit_filter_syscalls("-a always,exit -F arch=b64 -S init_module,create_module -k m", ex),
                         "-a always,exit -F arch=b64 -S init_module -k m")
        self.assertIsNone(audit_filter_syscalls("-a always,exit -F arch=b64 -S create_module -k m", ex))
        self.assertEqual(audit_filter_syscalls("-w /etc/passwd -p wa -k id", ex), "-w /etc/passwd -p wa -k id")

    def test_ignore_control_lines(self):
        self.assertIsNone(ar.parse("-e 2"))
        self.assertIsNone(ar.parse("# comment"))


if __name__ == "__main__":
    unittest.main()
