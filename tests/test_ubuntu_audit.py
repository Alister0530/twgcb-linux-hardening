# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import auditrules as ar  # noqa: E402
from gcb.rules.ubuntu import audit as a  # noqa: E402

# auditctl -l 實際顯示：目錄監看無結尾 /、path 規則帶 -S all
LOADED = """-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
"""


class AuditHelpersTest(unittest.TestCase):
    def test_normalize_runtime(self):
        loaded = a.normalize_audit_text(LOADED)
        for line in ("-w /etc/sudoers.d/ -p wa -k scope",
                     "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"):
            self.assertEqual(ar.missing([a.normalize_audit_text(line)], loaded), [])

    def test_loadable(self):
        self.assertTrue(a.audit_loadable("-w /etc/network/ -p wa -k system-locale"))
        self.assertTrue(a.audit_loadable("-a always,exit -F path=/usr/bin/no-such -F perm=x"))
        self.assertFalse(a.audit_loadable("-w /no/such/dir/x -p wa -k k"))
        self.assertTrue(a.audit_loadable("-a always,exit -F arch=b64 -S mount -k mounts"))

    def test_filter_syscalls(self):
        orig = a.which
        a.which = lambda n: "/usr/bin/ausyscall"
        self.addCleanup(setattr, a, "which", orig)
        arm = lambda arch, n: arch == "b64" and n not in ("rename", "create_module")
        self.assertEqual(a.filter_syscalls("-a always,exit -F arch=b64 -S rename,unlink -k delete", arm),
                         "-a always,exit -F arch=b64 -S unlink -k delete")
        self.assertIsNone(a.filter_syscalls("-a always,exit -F arch=b32 -S mount -k mounts", arm))
        self.assertEqual(a.filter_syscalls("-w /etc/hosts -p wa -k x", arm), "-w /etc/hosts -p wa -k x")

    def test_grub_backlog(self):
        base = 'GRUB_CMDLINE_LINUX="quiet audit_backlog_limit=64"\n'
        self.assertEqual(a.cmdline_value(a.grub_effective_cmdline([base]).split(), "audit_backlog_limit"), 64)
        drop = 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit_backlog_limit=8192"\n'
        self.assertEqual(a.cmdline_value(a.grub_effective_cmdline([base, drop]).split(), "audit_backlog_limit"), 8192)
        override = 'GRUB_CMDLINE_LINUX="console=ttyS0"\n'
        self.assertIsNone(a.cmdline_value(a.grub_effective_cmdline([base, override]).split(), "audit_backlog_limit"))

    def test_last_e(self):
        self.assertEqual(a.last_e_setting(["-D\n-e 1\n", "# -e 0\n-e 2\n"]), "2")
        self.assertEqual(a.last_e_setting(["-e 2\n", "-e 1\n"]), "1")
        self.assertIsNone(a.last_e_setting(["--backlog_wait_time 2000\n"]))

    def test_aide_attrs(self):
        conf = "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512\n!/usr/sbin/auditd\n# /usr/sbin/ausearch p\n"
        need = set(a.AIDE_ATTRS.split("+"))
        self.assertTrue(any(need <= s for s in a.aide_rule_attrs([conf], "/usr/sbin/auditctl")))
        self.assertEqual(a.aide_rule_attrs([conf], "/usr/sbin/auditd"), [])
        self.assertEqual(a.aide_rule_attrs([conf], "/usr/sbin/ausearch"), [])

    def test_rsyslog_mode(self):
        self.assertTrue(a.mode_ok("0640"))
        self.assertTrue(a.mode_ok("0600"))
        self.assertFalse(a.mode_ok("0644"))
        self.assertFalse(a.mode_ok("0577"))
        self.assertEqual(a.rsyslog_modes('$FileCreateMode 0644\naction(type="omfile" fileCreateMode="0600")\n'),
                         ["0644", "0600"])
        fixed = a.rsyslog_fix_text("$FileCreateMode 0644\n", True)
        self.assertEqual(a.rsyslog_modes(fixed), ["0640"])
        added = a.rsyslog_fix_text("module(load=\"imuxsock\")\n$IncludeConfig /etc/rsyslog.d/*.conf\n", False)
        self.assertLess(added.index("$FileCreateMode 0640"), added.index("$IncludeConfig"))

    def test_local_mounts(self):
        mi = ("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
              "30 22 7:0 / /snap/core/1 ro - squashfs /dev/loop0 ro\n"
              "31 22 0:40 / /mnt/nfs rw - nfs4 srv:/x rw\n"
              "32 22 8:1 / /mnt/bind rw - ext4 /dev/sda1 rw\n"
              "33 22 0:50 / /var/lib/docker/overlay2/x/merged rw - overlay overlay rw\n")
        self.assertEqual(a.local_mounts(mi), ["/"])


if __name__ == "__main__":
    unittest.main()
