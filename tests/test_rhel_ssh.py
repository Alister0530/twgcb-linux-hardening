# -*- coding: utf-8 -*-
"""RHEL SSH 規則（gcb/rules/rhel/ssh.py）純函式測試。"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.rules.rhel import ssh as s  # noqa: E402

UNIT8 = """[Unit]
Description=OpenSSH server daemon

[Service]
Type=notify
EnvironmentFile=-/etc/crypto-policies/back-ends/opensshserver.config
EnvironmentFile=-/etc/sysconfig/sshd
ExecStart=/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY
ExecReload=/bin/kill -HUP $MAINPID
"""

BACKEND8 = ("CRYPTO_POLICY='-oCiphers=aes256-gcm@openssh.com,aes256-ctr "
            "-oMACs=hmac-sha2-256-etm@openssh.com -oKexAlgorithms=curve25519-sha256'\n")


class TestUnit(unittest.TestCase):
    def test_parse_and_expand(self):
        env, files, ex = s.parse_service([("u", UNIT8), ("d", "[Service]\nEnvironment=\"A=1 2\" B=3\n")])
        self.assertEqual([f for _, f in files], ["-/etc/crypto-policies/back-ends/opensshserver.config",
                                                  "-/etc/sysconfig/sshd"])
        self.assertEqual(env, [("d", "A", "1 2"), ("d", "B", "3")])
        e = s.parse_env_file(BACKEND8 + "# CRYPTO_POLICY=\nOPTIONS=\"-u0\"\n")
        args = s.expand_exec(ex, e)
        self.assertEqual(args, ["-u0", "-oCiphers=aes256-gcm@openssh.com,aes256-ctr",
                                "-oMACs=hmac-sha2-256-etm@openssh.com", "-oKexAlgorithms=curve25519-sha256"])
        self.assertEqual(s.expand_exec("/usr/sbin/sshd -D ${X} -o$Y", {"X": "a b", "Y": "z"}), ["a b", "-oz"])

    def test_reset(self):
        _, files, ex = s.parse_service([("u", UNIT8), ("d", "[Service]\nEnvironmentFile=\nExecStart=\nExecStart=/x -D\n")])
        self.assertEqual(files, [])
        self.assertEqual(ex, "/x -D")


class TestCompare(unittest.TestCase):
    def test_startups(self):
        self.assertTrue(s.startups_ok("10:30:60"))
        self.assertFalse(s.startups_ok("5:20:50"))   # rate 20 < 30，較寬鬆
        self.assertTrue(s.startups_ok("5:50:50"))
        self.assertFalse(s.startups_ok("10:30:100"))
        self.assertTrue(s.startups_ok("10"))          # 等同 10:100:10，較嚴格
        self.assertFalse(s.startups_ok("x"))

    def test_value_ok(self):
        self.assertTrue(s.value_ok("INFO", "in", ["VERBOSE", "INFO"]))
        self.assertFalse(s.value_ok("DEBUG", "in", ["VERBOSE", "INFO"]))
        self.assertTrue(s.value_ok("4", "range", (1, 4)))
        self.assertFalse(s.value_ok("0", "range", (1, 4)))
        self.assertFalse(s.value_ok(None, "eq", "no"))

    def test_crypto(self):
        good = {"ciphers": ["aes256-ctr,aes128-ctr"], "macs": ["hmac-sha2-512"],
                "kexalgorithms": ["ecdh-sha2-nistp256,diffie-hellman-group14-sha256"]}
        self.assertEqual(s.crypto_violations(good), [])
        bad = dict(good, macs=["hmac-sha2-512,hmac-sha2-256-etm@openssh.com"])
        self.assertEqual(s.crypto_violations(bad), [("MACs", ["hmac-sha2-256-etm@openssh.com"])])
        self.assertEqual(s.crypto_violations({})[0][0], "Ciphers")


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def _w(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_lines_and_first(self):
        os.mkdir(os.path.join(self.d, "d"))
        self._w("d/50-redhat.conf", "Compression yes\nX11Forwarding yes\n")
        main = self._w("main", "Include %s/d/*.conf\nCompression delayed\nMatch User x\n  Compression no\n" % self.d)
        lines = s.config_lines(main)
        self.assertEqual(s.first_global(lines, "compression")[1], "yes")
        self.assertFalse(lines[-1][3])

    def test_comment_bad(self):
        text = "MaxAuthTries 3\nMaxAuthTries 6\nMatch User a\n  MaxAuthTries 9\n"
        out = s.comment_bad(text, "MaxAuthTries", lambda v: s.value_ok(v, "range", (1, 4)))
        self.assertEqual(out.splitlines(), ["MaxAuthTries 3", s.te.MARK + "MaxAuthTries 6",
                                            "Match User a", "  MaxAuthTries 9"])

    def test_comment_crypto_policy(self):
        out = s.comment_crypto_policy("# x\nCRYPTO_POLICY=\nOPTIONS=\n")
        self.assertEqual(out, "# x\n%sCRYPTO_POLICY=\nOPTIONS=\n" % s.te.MARK)


if __name__ == "__main__":
    unittest.main()
