# -*- coding: utf-8 -*-
"""Ubuntu disk.py 規則的 check／precondition／fix 測試（全部以假資料模擬，不碰真實系統）。"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402
from fakes import FakeCtx, FakeFx, FakeRunner, res  # noqa: E402
from gcb.fixer import ManualRequired  # noqa: E402
from gcb.rules.base import FAIL, PASS  # noqa: E402
from gcb.rules.ubuntu import disk as ud  # noqa: E402


def find(n):
    osi = fakes.make_osi("ubuntu2204")
    rs = [r for r in ud.RULES if (r.rule_id(osi) or "").endswith("-%04d" % n)]
    assert len(rs) == 1, (n, rs)
    return rs[0]


class Base(unittest.TestCase):
    def setUp(self):
        self.fs = {}
        self.bins = set()
        self.runner = FakeRunner()
        for name, val in (("read_text", fakes.fs_reader(self.fs)), ("run", self.runner),
                          ("which", lambda n: "/usr/bin/" + n if n in self.bins else None)):
            pt = mock.patch.object(ud, name, val)
            pt.start()
            self.addCleanup(pt.stop)

    def fx(self, **kw):
        return FakeFx(FakeCtx("ubuntu2204", **kw), fs=self.fs, runner=self.runner)


# TWGCB-01-014-0003 udf 檔案系統（Azure 或有 udf 掛載時略過）
class AzureUdfTest(Base):
    def test_azure_and_mounts(self):
        self.fs["/sys/class/dmi/id/sys_vendor"] = "Microsoft Corporation\n"
        self.bins.add("waagent")
        self.assertIn("Azure", ud.azure_udf_in_use(FakeCtx()))
        self.bins.clear()
        with mock.patch.object(os.path, "isdir", lambda p: False):
            self.assertIsNone(ud.azure_udf_in_use(FakeCtx()))
            self.fs["/proc/self/mounts"] = "/dev/sr0 /mnt/cd udf ro 0 0\n"
            self.assertEqual(ud.azure_udf_in_use(FakeCtx()), "目前有 udf 掛載：/mnt/cd")
            why = find(3).precondition(FakeCtx(include_risky=False))
        self.assertIn("--include-risky", why)


# TWGCB-01-014-0002 squashfs 檔案系統（snap 使用中時略過）
class SnapSquashfsTest(Base):
    def test_in_use(self):
        self.assertIsNone(ud.snap_squashfs_in_use(FakeCtx()))
        self.fs["/proc/self/mounts"] = "/dev/loop0 /snap/core/1 squashfs ro 0 0\n/dev/loop1 /snap/lxd/2 squashfs ro 0 0\n"
        self.assertEqual(ud.snap_squashfs_in_use(FakeCtx()), "系統有 2 個 squashfs 掛載（snap 套件）")
        self.assertEqual(find(2).risk, "B")


# TWGCB-01-014-0004 設定 /tmp 目錄之檔案系統（tmpfs）
class TmpTmpfsTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.r = find(4)

    def test_check_states(self):
        self.runner.rules = [("findmnt", res(0, out="")), ("is-enabled tmp.mount", res(0, out="enabled\n"))]
        c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "目前：根檔案系統；開機設定：tmp.mount 已啟用（需重開機生效）"))
        self.runner.rules[1] = ("is-enabled tmp.mount", res(1, out="disabled\n"))
        c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "目前：根檔案系統；開機設定：未設定"))
        self.fs["/etc/fstab"] = "# /tmp\ntmpfs /tmp tmpfs defaults 0 0\n"
        self.runner.rules[0] = ("findmnt", res(0, out="tmpfs\n"))
        self.assertEqual(self.r.check(FakeCtx()).current, "目前：tmpfs；開機設定：fstab：tmpfs")

    def test_fix(self):
        self.fs["/etc/fstab"] = "UUID=1 / ext4 defaults 0 1"
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("undo", "systemctl daemon-reload"), ("write", "/etc/fstab"),
                                     ("run", "systemctl daemon-reload")])
        self.assertEqual(self.fs["/etc/fstab"], "UUID=1 / ext4 defaults 0 1\n%s\n" % self.r.LINE)

    def test_fix_refuses_existing_tmp_entry(self):
        self.fs["/etc/fstab"] = "/dev/sdb1 /tmp ext4 defaults 0 2\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_dry_run(self):
        self.fs["/etc/fstab"] = ""
        fx = self.fx(dry_run=True)
        self.r.fix(fx.ctx, fx)
        self.assertEqual(self.fs["/etc/fstab"], "")
        self.assertEqual(self.runner.calls, [])


if __name__ == "__main__":
    unittest.main()
