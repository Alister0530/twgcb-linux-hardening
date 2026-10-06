# -*- coding: utf-8 -*-
"""RHEL 8 / 9 系統設定與維護（0048–0091、0301–0307）的純函式測試。"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb.osinfo import OSInfo  # noqa: E402
from gcb.rules.rhel import system as s  # noqa: E402


class Ids(unittest.TestCase):
    def test_passwd_dash_mode_differs(self):
        r8 = [r for r in s.RULES if r.ids.get("rhel8", "").endswith("0054")][0]
        r9 = [r for r in s.RULES if r.ids.get("rhel9", "").endswith("0054")][0]
        self.assertEqual(r8.max_mode, 0o600)
        self.assertEqual(r9.max_mode, 0o644)
        self.assertNotIn("rhel9", r8.ids)

    def test_ranges(self):
        for key, n in (("rhel8", 42), ("rhel9", 49)):
            self.assertEqual(len([r for r in s.RULES if key in r.ids]), n)
        osi = OSInfo("rhel9", "rhel", "x", "rocky", "9")
        self.assertEqual(s.RULES[0].rule_id(osi), "TWGCB-01-012-0049")


class Text(unittest.TestCase):
    def test_plus_lines(self):
        t = "root:x:0:0::/root:/bin/bash\n+:::::::\n+@ng\n-bob\n"
        self.assertEqual(s.plus_lines(t), ["+:::::::", "+@ng"])
        self.assertEqual(s.remove_plus_lines(t), "root:x:0:0::/root:/bin/bash\n-bob\n")

    def test_nss_compat(self):
        self.assertEqual(s.nss_compat("passwd: files sss\ngroup: compat\n# shadow: compat\n"), ["group"])

    def test_nologin(self):
        t = "/bin/sh\n/bin/bash\n/usr/sbin/nologin\n# /sbin/nologin\n/sbin/nologin  \n"
        self.assertEqual(s.nologin_lines(t), ["/usr/sbin/nologin", "/sbin/nologin"])
        self.assertEqual(s.remove_nologin(t), "/bin/sh\n/bin/bash\n# /sbin/nologin\n")

    def test_chrony(self):
        self.assertEqual(s.chrony_eval(s.chrony_tokens('OPTIONS="-F 2"\n')), (False, "2"))
        toks = s.chrony_tokens('# c\nOPTIONS="-4 -u root -F 1"\n')
        self.assertEqual(s.chrony_eval(toks), (True, "1"))
        self.assertEqual(s.chrony_fixed(toks), ["-4", "-F", "2"])
        self.assertEqual(s.chrony_fixed(["-uroot", "-F-1"]), ["-F", "2"])
        self.assertEqual(s.chrony_fixed([]), ["-F", "2"])
        self.assertEqual(s.chrony_tokens(""), [])
        self.assertIsNone(s.chrony_tokens('OPTIONS="-F 2\n'))

    def test_path(self):
        self.assertEqual(s.path_problems("/usr/bin:/bin"), [])
        self.assertEqual(len(s.path_problems(".:/bin::bin:")), 4)

    def test_fs_scan_parse(self):
        out = "W\t/a b\0U\t1234\t/x\0G\t55\t/y\0D\t1000\t/d\0E\t1001\t/e\0"
        r = s.parse_fs_scan(out)
        self.assertEqual(r["ww"], ["/a b"])
        self.assertEqual(r["nouser"], [("1234", "/x")])
        self.assertEqual(r["wwdir_uid"], [("1000", "/d")])
        self.assertEqual(r["wwdir_gid"], [("1001", "/e")])

    def test_scan_roots_excludes_network(self):
        m = [("/dev/sda1", "/", "xfs", []), ("srv:/x", "/mnt/nfs", "nfs4", []),
             ("//srv/x", "/mnt/cifs", "cifs", []), ("proc", "/proc", "proc", []),
             ("sshfs", "/mnt/f", "fuse.sshfs", [])]
        self.assertEqual(s.scan_roots(m), ["/"])


class Accounts(unittest.TestCase):
    PW = ("root:x:0:0:root:/root:/bin/bash\nbin:x:1:1::/bin:/sbin/nologin\n"
          "toor:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
          "svc:x:1001:1001::/var/lib/svc:/bin/bash\nbob:x:1002:9999::/home/bob:/bin/bash\n"
          "sys2:x:500:500::/home/sys2:/bin/bash\nhalt:x:7:0::/sbin:/sbin/halt\n")
    GR = "root:x:0:\nbin:x:1:\nalice:x:1000:\nsvc:x:1001:\nshadow:x:42:alice\n"

    def setUp(self):
        self.pw = s.parse_passwd(self.PW)
        self.gr = s.parse_group(self.GR)

    def test_db(self):
        self.assertEqual(s.bad_uid0(self.pw, self.gr), ["toor（UID 0）"])
        self.assertEqual(len(s.bad_passwd_gid(self.pw, self.gr)), 2)
        self.assertEqual(s.bad_dup_uid(self.pw, self.gr), ["UID 0：root,toor"])
        self.assertEqual(s.bad_dup_user(self.pw, self.gr, ["a", "a"]), ["/etc/shadow 帳號名稱重複：a"])
        self.assertEqual(s.shadow_group_problems(self.pw, self.gr), (["alice"], []))

    def test_login_users(self):
        keep, skipped = s.login_users(passwd_text=self.PW, uid_range=(1000, 60000))
        names = [u["name"] for u in keep]
        self.assertEqual(names, ["alice", "bob"])  # root/toor 共用 /root；svc 為系統目錄；sys2 為系統帳號
        self.assertTrue(any(x.startswith("svc") for x in skipped))
        self.assertTrue(any(x.startswith("root") for x in skipped))


class Tree(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.d, "bin"))
        self.f = os.path.join(self.d, "bin", "a")
        with open(self.f, "w") as f:
            f.write("x")
        os.chmod(self.f, 0o4777)
        os.symlink("a", os.path.join(self.d, "bin", "link"))
        os.symlink("missing", os.path.join(self.d, "bin", "broken"))
        os.symlink(self.d, os.path.join(self.d, "bin", "loop"))
        os.symlink("bin", os.path.join(self.d, "bin2"))

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_scan(self):
        r = s.tree_scan((os.path.join(self.d, "bin"), os.path.join(self.d, "bin2")))
        self.assertEqual(len(r["roots"]), 1)  # bin2 → bin 去重
        reals = [i[1] for i in r["file_mode"]]
        self.assertEqual(reals, [os.path.realpath(self.f)])  # 連結與目標只列一次，壞連結略過
        self.assertEqual(r["file_mode"][0][2] & ~0o022, 0o4755)  # 修復值保留 setuid


if __name__ == "__main__":
    unittest.main()
