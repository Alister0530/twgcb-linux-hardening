# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import auditrules as ar  # noqa: E402
from gcb.osinfo import OSInfo  # noqa: E402
from gcb.rules import rules_for  # noqa: E402
from gcb.rules.rhel import logging as lg  # noqa: E402

GRUBBY = '''index=0
kernel="/boot/vmlinuz-5.14.0-427.el9.x86_64"
args="ro crashkernel=1G-4G:192M rhgb quiet audit_backlog_limit=64"
root="/dev/mapper/rl-root"
index=1
kernel="/boot/vmlinuz-0-rescue"
args="ro audit_backlog_limit=8192 audit_backlog_limit=16384"
'''

LOGROTATE = """/var/log/cron
/var/log/messages
/var/log/secure
{
    missingok
    sharedscripts
    postrotate
        /usr/bin/systemctl -s HUP kill rsyslog.service >/dev/null 2>&1 || true
    endscript
}
"""


class LoggingHelpersTest(unittest.TestCase):
    def test_ids(self):
        for key, extra, absent in (("rhel8", "TWGCB-01-008-0180", "TWGCB-01-008-0308"),
                                   ("rhel9", "TWGCB-01-012-0308", "TWGCB-01-012-0180")):
            ids = dict(rules_for(OSInfo(key, "rhel", "x", "rocky", key[-1])))
            pre = "TWGCB-01-%s-" % ("008" if key == "rhel8" else "012")
            for n in range(132, 183):
                rid = pre + "%04d" % n
                if rid != absent:
                    self.assertIn(rid, ids)
            self.assertIn(extra, ids)
            self.assertNotIn(absent, ids)

    def test_grubby(self):
        e = lg.parse_grubby_info(GRUBBY)
        self.assertEqual(len(e), 2)
        self.assertEqual(lg.cmdline_value(e[0][1].split(), "audit_backlog_limit"), 64)
        self.assertEqual(lg.cmdline_value(e[1][1].split(), "audit_backlog_limit"), 16384)
        self.assertIsNone(lg.cmdline_value(["quiet"], "audit_backlog_limit"))

    def test_aliases(self):
        self.assertEqual(lg.alias_target("# postmaster: x\npostmaster:\troot\n"), "root")
        self.assertEqual(lg.alias_target("postmaster: root, admin\n"), "root,admin")
        self.assertIsNone(lg.alias_target("mailer-daemon: postmaster\n"))
        out = lg.alias_set("postmaster: admin\npostmaster: x\n")
        self.assertEqual(lg.alias_target(out), "root")
        self.assertIn("postmaster:\troot", lg.alias_set("abuse: root\n"))

    def test_prepare_lines(self):
        lines = ["-a always,exit -F arch=b64 -S rename -S unlink -F auid>=1000 -F auid!=4294967295 -k delete",
                 "-a always,exit -F arch=b32 -S mount -F auid>=1000 -k mounts",
                 "-w /no/such/dir/x -p wa -k k",
                 "-w /etc/hosts -p wa -k x"]
        arm = lambda arch, n: n != "rename"
        req, skipped = lg.prepare_audit_lines(lines, uid=500, x86=False, exists=arm)
        if lg.which("ausyscall"):
            self.assertEqual(req[0], "-a always,exit -F arch=b64 -S unlink -F auid>=500 -F auid!=4294967295 -k delete")
        self.assertIn("auid>=500", req[0])
        self.assertEqual(req[-1], "-w /etc/hosts -p wa -k x")
        self.assertEqual(len(req), 2)
        self.assertEqual(len(skipped), 2)

    def test_runtime_match(self):
        loaded = """-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-w /etc/sysconfig/network-scripts -p wa -k system-locale
-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S execve -F auid!=-1 -C uid!=euid -F key=execpriv
"""
        req = ["-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
               "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale",
               "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng",
               "-a always,exit -F arch=b64 -F auid!=unset -S execve -C uid!=euid -F key=execpriv"]
        self.assertEqual(ar.missing(req, loaded), [])

    def test_immutable(self):
        texts = ["-D\n-e 1\n", "--loginuid-immutable\n-e 2\n"]
        self.assertEqual(lg.last_e_setting(texts), "2")
        self.assertTrue(lg.has_loginuid_immutable(texts))
        self.assertFalse(lg.has_loginuid_immutable(["# --loginuid-immutable\n"]))

    def test_rsyslog_secure(self):
        self.assertEqual(lg.rsyslog_secure_facilities(["authpriv.* /var/log/secure\n"]), {"authpriv"})
        self.assertEqual(lg.rsyslog_secure_facilities([lg.SECURE_LINE + "\n"]), set(lg.SECURE_FACILITIES))
        self.assertEqual(lg.rsyslog_secure_facilities(["auth.*;daemon.* -/var/log/secure\n",
                                                       "*.info;authpriv.none /var/log/messages\n"]),
                         {"auth", "daemon"})
        self.assertEqual(lg.rsyslog_secure_facilities(["auth.info /var/log/secure\n"]), set())

    def test_logrotate(self):
        b = lg.logrotate_blocks(LOGROTATE)
        self.assertEqual(len(b), 1)
        self.assertEqual(b[0]["paths"], ["/var/log/cron", "/var/log/messages", "/var/log/secure"])
        self.assertEqual((b[0]["start"], b[0]["end"]), (0, 9))
        b2 = lg.logrotate_blocks(LOGROTATE + lg.LOGROTATE_STANZA)
        self.assertEqual(b2[1]["paths"], [lg.LOGROTATE_PATTERN])
        self.assertEqual(lg.logrotate_block_ok(b2[1]), [])
        self.assertEqual(len(lg.logrotate_block_ok(b2[0])), 5)
        conf = lg.logrotate_blocks("weekly\nrotate 4\ninclude /etc/logrotate.d\n/var/log/wtmp {\n monthly\n}\n")
        self.assertEqual(conf[0]["paths"], ["/var/log/wtmp"])


if __name__ == "__main__":
    unittest.main()
