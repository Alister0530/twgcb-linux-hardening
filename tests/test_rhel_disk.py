# -*- coding: utf-8 -*-
"""RHEL 磁碟與檔案系統、系統設定（disk.py）的純函式測試。"""
import base64
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.osinfo import OSInfo  # noqa: E402
from gcb.rules.rhel import disk as d  # noqa: E402


class Modules(unittest.TestCase):
    def test_usb_storage_spelling(self):
        self.assertEqual(d.modprobe_disabled(["install usb_storage /bin/true\nblacklist usb-storage\n"],
                                             "usb-storage"), (True, True))

    def test_ext_never_ext4(self):
        r = [x for x in d.RULES if x.rule_id(OSInfo("rhel9", "rhel", "", "rocky", "9")) == "TWGCB-01-012-0293"][0]
        self.assertEqual(r.module, "ext")
        self.assertEqual(r.names, ["ext"])
        self.assertEqual(d.modprobe_disabled(["install ext4 /bin/true\nblacklist ext4\n"], "ext"), (False, False))

    def test_fat_has_block(self):
        r = [x for x in d.RULES if x.rule_id(OSInfo("rhel9", "rhel", "", "rocky", "9")) == "TWGCB-01-012-0294"][0]
        self.assertIs(r.block, d.fat_block)
        self.assertEqual(r.risk, "B")

    def test_fstype_match(self):
        self.assertTrue(d.fstype_match("fuse.sshfs", ("fuse",)))
        self.assertFalse(d.fstype_match("fusectl", ("fuse",)))


class Fstab(unittest.TestCase):
    TEXT = "# c\nUUID=1 / xfs defaults 0 0\nsrv:/x /mnt/nfs nfs defaults,nodev 0 0\nsrv:/y /mnt/y nfs4 rw 0 0\n"

    def test_entries_and_add(self):
        e = d.fstab_entries(self.TEXT)
        self.assertEqual([x[2] for x in e], ["/", "/mnt/nfs", "/mnt/y"])
        out = d.fstab_add_option_lines(self.TEXT, lambda dev, mp, fs: fs in ("nfs", "nfs4"), "nodev")
        self.assertIn("defaults,nodev\t", out.replace(" ", "\t"))
        self.assertEqual(out.count("nodev"), 2)
        self.assertIn("# c", out)
        self.assertIn("UUID=1 / xfs defaults 0 0", out)

    def test_mount_of(self):
        mounts = [("/dev/a", "/", "xfs", []), ("/dev/b", "/gcbt/home", "xfs", []), ("/dev/c", "/gcbt/home2", "xfs", [])]
        self.assertEqual(d.mount_of("/gcbt/home2/u", mounts)[1], "/gcbt/home2")
        self.assertEqual(d.mount_of("/gcbt/home/u", mounts)[1], "/gcbt/home")
        self.assertEqual(d.mount_of("/var", mounts)[1], "/")


class Gpg(unittest.TestCase):
    def test_main(self):
        t = "[main]\ngpgcheck=1\ninstallonly_limit=3\n\n[other]\nx=1\n"
        self.assertEqual(d.ini_main_values(t), {"gpgcheck": "1"})
        out = d.ini_set_main(t, {"gpgcheck": "1", "localpkg_gpgcheck": "1"})
        self.assertEqual(d.ini_main_values(out), {"gpgcheck": "1", "localpkg_gpgcheck": "1"})
        self.assertLess(out.index("localpkg_gpgcheck"), out.index("[other]"))
        self.assertEqual(d.ini_main_values(d.ini_set_main("", {"gpgcheck": "1"})), {"gpgcheck": "1"})

    def test_repo(self):
        t = "[a]\ngpgcheck = 0\n[b]\ngpgcheck=1\n# gpgcheck=0\n"
        out = d.ini_fix_gpgcheck(t)
        self.assertEqual([v for s, k, v, i in d.ini_items(out) if k == "gpgcheck"], ["1", "1"])
        self.assertIn("# gpgcheck=0", out)


class Aide(unittest.TestCase):
    def test_db_paths(self):
        t = ("@@define DBDIR /var/lib/aide\ndatabase=file:@@{DBDIR}/aide.db.gz\n"
             "database_out=file:@@{DBDIR}/aide.db.new.gz\n")
        self.assertEqual(d.aide_db_paths(t), ("/var/lib/aide/aide.db.gz", "/var/lib/aide/aide.db.new.gz"))
        self.assertEqual(d.aide_db_paths("")[0], "/var/lib/aide/aide.db.gz")

    def test_cron(self):
        self.assertTrue(d._cron_fields("0 5 * * * root /usr/sbin/aide --check", True)[0])
        self.assertFalse(d._cron_fields("0 5 * * 1 root /usr/sbin/aide --check", True)[0])
        self.assertTrue(d.is_aide_check("/usr/sbin/aide --check"))
        self.assertFalse(d.is_aide_check("/usr/sbin/aide --init"))


class Grub(unittest.TestCase):
    def test_password(self):
        cfg = "### 01_users\nif [ -n \"${GRUB2_PASSWORD}\" ]; then\n  set superusers=\"root\"\n" \
              "  password_pbkdf2 root ${GRUB2_PASSWORD}\nfi\n"
        ok, cur = d.grub_password_status([("/boot/grub2/user.cfg", "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.AB\n")], cfg)
        self.assertTrue(ok, cur)
        self.assertFalse(d.grub_password_status([], cfg)[0])
        direct = 'set superusers="admin"\npassword_pbkdf2 admin grub.pbkdf2.sha512.10000.XY\n'
        self.assertTrue(d.grub_password_status([], direct)[0])


class Units(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.dirs = [os.path.join(self.t, x) for x in ("etc", "run", "usr")]
        for x in self.dirs:
            os.makedirs(x)

    def tearDown(self):
        shutil.rmtree(self.t)

    def _w(self, p, text):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)

    def test_dropin_override(self):
        self._w(os.path.join(self.dirs[2], "rescue.service"),
                "[Service]\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue\n")
        files = d.unit_files("rescue.service", self.dirs)
        execs, force = d.unit_exec_start([open(f).read() for f in files])
        self.assertTrue(d._sulogin_ok(execs))
        self._w(os.path.join(self.dirs[0], "rescue.service.d", "x.conf"), "[Service]\nExecStart=\nExecStart=/bin/sh\n")
        files = d.unit_files("rescue.service", self.dirs)
        execs, force = d.unit_exec_start([open(f).read() for f in files])
        self.assertEqual(execs, ["/bin/sh"])
        self.assertFalse(d._sulogin_ok(execs))


class Rsa(unittest.TestCase):
    def _key(self, bits):
        def s(b):
            return struct.pack(">I", len(b)) + b
        n = b"\x00" + b"\xc0" + b"\x01" * (bits // 8 - 1)
        return base64.b64encode(s(b"ssh-rsa") + s(b"\x01\x00\x01") + s(n)).decode()

    def test_bits(self):
        self.assertEqual(d.rsa_bits(self._key(2048)), 2048)
        self.assertEqual(d.rsa_bits(self._key(3072)), 3072)
        self.assertIsNone(d.rsa_bits("!!"))

    def test_short_keys(self):
        t = tempfile.mkdtemp()
        try:
            p = os.path.join(t, "authorized_keys")
            with open(p, "w") as f:
                f.write('from="10.0.0.1" ssh-rsa %s a@b\nssh-rsa %s c@d\n# ssh-rsa %s\n'
                        % (self._key(2048), self._key(4096), self._key(1024)))
            self.assertEqual(d.short_rsa_keys([p]), [(p, 2048)])
        finally:
            shutil.rmtree(t)


if __name__ == "__main__":
    unittest.main()
