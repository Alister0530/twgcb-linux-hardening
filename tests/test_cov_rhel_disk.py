# -*- coding: utf-8 -*-
"""RHEL disk.py 規則的 check／precondition／fix 測試（全部以假資料模擬，不碰真實系統）。"""
import base64
import collections
import fnmatch
import os
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402
from fakes import FakeCtx, FakeFx, FakeRunner, res  # noqa: E402
from gcb import pkgsvc  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules import generic  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS  # noqa: E402
from gcb.rules.rhel import disk as d  # noqa: E402

PW = collections.namedtuple("PW", "pw_name pw_uid pw_dir")
REAL = {n: getattr(os.path, n) for n in ("exists", "isdir", "isfile", "islink")}


class FakeGlob(object):
    """取代模組的 glob：以 fnmatch 比對預先登記的路徑。"""

    def __init__(self, paths):
        self.paths = paths

    def glob(self, pat):
        return sorted(p for p in self.paths if fnmatch.fnmatchcase(p, pat))


class Fx(FakeFx):
    """FakeFx 加上 AutofsDisabled 使用的 _record_service。"""

    def _record_service(self, unit):
        self.events.append(("record", unit))
        return "enabled", "active"


def find(n, key="rhel9", cls=None):
    osi = fakes.make_osi(key)
    rs = [r for r in d.RULES if (r.rule_id(osi) or "").endswith("-%04d" % n) and (cls is None or isinstance(r, cls))]
    assert len(rs) == 1, (n, rs)
    return rs[0]


def idx(events, ev):
    return events.index(ev)


def rsa_key(bits):
    def s(b):
        return struct.pack(">I", len(b)) + b
    n = b"\x00" + b"\xc0" + b"\x01" * (bits // 8 - 1)
    return base64.b64encode(s(b"ssh-rsa") + s(b"\x01\x00\x01") + s(n)).decode()


class Base(unittest.TestCase):
    """共用模擬環境：檔案內容、掛載、指令、服務、套件、路徑存在與否。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.fs = {}
        self.mounts = []
        self.bins = set(["systemctl"])
        self.svc = {}
        self.pkgs = set()
        self.builtin = set()
        self.exist, self.dirs, self.links = set(), set(), set()
        self.globs = []
        self.runner = FakeRunner()
        reader = fakes.fs_reader(self.fs)
        self.p(d, "read_text", reader)
        self.p(generic, "read_text", reader)
        self.p(d, "proc_mounts", lambda: list(self.mounts))
        self.p(d, "which", lambda n: "/usr/bin/" + n if n in self.bins else None)
        self.p(d, "run", self.runner)
        self.p(d, "glob", FakeGlob(self.globs))
        self.p(d, "module_builtin", lambda m: m in self.builtin)
        self.p(d, "modprobe_files", lambda: sorted(p for p in self.fs if p.startswith("/etc/modprobe.d/")))
        self.p(pkgsvc, "svc_state", lambda u: self.svc.get(u, ("disabled", "inactive")))
        self.p(pkgsvc, "pkg_installed", lambda osi, p: p in self.pkgs)
        self.p(os.path, "exists", self._path("exists", lambda p: p in self.exist or p in self.dirs))
        self.p(os.path, "isdir", self._path("isdir", lambda p: p in self.dirs))
        self.p(os.path, "isfile", self._path("isfile", lambda p: p in self.exist))
        self.p(os.path, "islink", self._path("islink", lambda p: p in self.links))

    def _path(self, name, fake):
        real = REAL[name]
        return lambda p: real(p) if str(p).startswith(self.tmp) else fake(p)

    def p(self, obj, name, val):
        pt = mock.patch.object(obj, name, val)
        pt.start()
        self.addCleanup(pt.stop)

    def fx(self, key="rhel9", **kw):
        return Fx(FakeCtx(key, **kw), fs=self.fs, runner=self.runner)


# ====================================================================
# 核心模組
# ====================================================================

# RHEL8 0003 / RHEL9 0003 udf 檔案系統、RHEL9 0285–0300 檔案系統模組（RhelModule）
class RhelModuleTest(Base):
    def test_check_builtin_and_missing_module(self):
        r = find(3)
        self.builtin.add("udf")
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("已編入核心", c.current)
        self.builtin.clear()
        self.dirs.add("/lib/modules/%s" % os.uname().release)
        self.runner.add("modinfo udf", res(1))
        self.assertIn("核心未提供此模組", r.check(FakeCtx()).current)

    def test_check_pass_and_usage_reason(self):
        r = find(2)  # squashfs
        self.fs["/etc/modprobe.d/squashfs.conf"] = "install squashfs /bin/true\nblacklist squashfs\n"
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        self.mounts.append(("/dev/loop0", "/snap/core/1", "squashfs", ["ro"]))
        c = r.check(FakeCtx())
        self.assertIn("目前有 squashfs 掛載：/snap/core/1", c.current)

    def test_precondition_variants(self):
        # A 類使用中：未加 --include-risky 略過，加了才修
        r = find(2)
        self.mounts.append(("/dev/loop0", "/snap/x", "squashfs", ["ro"]))
        self.assertIn("--include-risky", r.precondition(FakeCtx(include_risky=False)))
        self.assertIsNone(r.precondition(FakeCtx(include_risky=True)))
        self.mounts[:] = []
        self.assertIsNone(r.precondition(FakeCtx(include_risky=False)))
        # B 類使用中：一律略過
        cifs = find(291)
        self.pkgs.add("cifs-utils")
        why = cifs.precondition(FakeCtx(include_risky=True))
        self.assertIn("已安裝 cifs-utils", why)
        self.assertIn("請人工評估", why)

    def test_fat_block_on_uefi(self):
        # RHEL9 0294 fat：UEFI 開機一律略過，fix 也拒絕
        r = find(294)
        self.dirs.add("/sys/firmware/efi")
        why = r.precondition(FakeCtx(include_risky=True))
        self.assertIn("UEFI", why)
        self.assertIn("無法開機", r.check(FakeCtx()).current)
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fat_block_reasons(self):
        self.mounts.append(("/dev/sda1", "/boot/efi", "vfat", ["rw"]))
        self.fs["/proc/modules"] = "vfat 20480 1 - Live 0x0\nfat 86016 1 vfat, Live 0x0\n"
        why = d.fat_block(FakeCtx())
        self.assertIn("/boot/efi 為 vfat", why)
        self.assertIn("vfat 模組使用中", why)
        self.assertIn("fat 模組使用中（參照數 1，被 vfat 使用）", why)
        # 只有 fstab 設定 vfat（目前未掛載）也要略過
        self.mounts[:] = []
        self.fs["/proc/modules"] = ""
        self.fs["/etc/fstab"] = "UUID=AB /boot/efi vfat umask=0077 0 2\n"
        why = d.fat_block(FakeCtx())
        self.assertIn("/etc/fstab 的 /boot/efi 為 vfat", why)
        self.assertIn("/etc/fstab 有 vfat/msdos/fat 掛載設定", why)
        self.fs["/etc/fstab"] = ""
        self.assertIsNone(d.fat_block(FakeCtx()))

    def test_module_usage_sources(self):
        self.globs += ["/etc/auto.misc", "/etc/systemd/system/mnt.mount"]
        self.fs["/etc/auto.misc"] = "data -fstype=cifs ://srv/share\n"
        self.fs["/etc/systemd/system/mnt.mount"] = "[Mount]\nType=ext4\n"
        self.svc["nfs-server.service"] = ("enabled", "active")
        f = d.module_usage("cifs", fstypes=("cifs",), units=("nfs-server.service",))
        why = f(FakeCtx())
        self.assertIn("按需掛載設定：/etc/auto.misc", why)
        self.assertNotIn("mnt.mount", why)
        self.assertIn("nfs-server.service 執行中", why)

    def test_devnode_open(self):
        # RHEL9 0296 fuse：/dev/fuse 被開啟視為使用中
        self.globs += ["/proc/1/fd/0", "/proc/2/fd/3"]
        self.globs.append("/proc/3/fd/9")
        links = {"/proc/1/fd/0": "/dev/null", "/proc/2/fd/3": "/dev/fuse"}

        def readlink(p):
            if p not in links:
                raise OSError("gone")  # 程序已結束
            return links[p]
        with mock.patch.object(os, "readlink", readlink):
            self.assertTrue(d._devnode_open("/dev/fuse"))
            self.assertFalse(d._devnode_open("/dev/zero"))
            why = find(296).precondition(FakeCtx(include_risky=True))
        self.assertIn("有程式開啟 /dev/fuse", why)

    def test_azure_udf(self):
        self.fs["/sys/class/dmi/id/sys_vendor"] = "Microsoft Corporation\n"
        self.bins.add("waagent")
        self.assertIn("Azure", d.azure_udf(FakeCtx()))
        self.bins.discard("waagent")
        self.assertIsNone(d.azure_udf(FakeCtx()))

    def test_fix_writes_conf_and_unloads(self):
        # RHEL9 0289 afs（實際載入名稱 kafs）
        r = find(289)
        self.fs["/proc/modules"] = "kafs 1000 x - Live 0x0\n"  # 參照數無法解析視為 0
        self.runner.add("modprobe -r kafs", res(1, err="FATAL: Module kafs is in use"))
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(self.fs["/etc/modprobe.d/afs.conf"], "install afs /bin/true\nblacklist afs\n")
        self.assertLess(idx(fx.events, ("write", "/etc/modprobe.d/afs.conf")),
                        idx(fx.events, ("run", "modprobe -r kafs")))
        self.assertTrue(fx.partial)
        self.assertIn("in use", fx.notes[0])

    def test_fix_builtin_and_dry_run(self):
        r = find(3)
        self.builtin.add("udf")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            r.fix(fx.ctx, fx)
        self.builtin.clear()
        fx = self.fx(dry_run=True)
        r.fix(fx.ctx, fx)
        self.assertNotIn("/etc/modprobe.d/udf.conf", self.fs)


# ====================================================================
# /tmp 與掛載選項
# ====================================================================

# RHEL8 0004 / RHEL9 0004 設定/tmp 目錄之檔案系統
class TmpTmpfsTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.r = find(4)
        self.fs["/etc/fstab"] = "UUID=1 / xfs defaults 0 0\n"

    def test_persistent_states(self):
        self.svc["tmp.mount"] = ("masked", "inactive")
        self.fs["/etc/fstab"] += "tmpfs /tmp tmpfs defaults 0 0\n"
        c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("masked", c.current)
        self.fs["/etc/fstab"] = ""
        self.exist.add("/usr/lib/systemd/system/tmp.mount")
        self.svc["tmp.mount"] = ("enabled", "active")
        self.mounts.append(("tmpfs", "/tmp", "tmpfs", ["rw"]))
        self.assertEqual(self.r.check(FakeCtx()).status, PASS)
        self.svc["tmp.mount"] = ("static", "inactive")
        self.assertEqual(self.r.check(FakeCtx()).status, FAIL)
        self.exist.clear()
        self.assertIn("未設定（tmp.mount static）", self.r.check(FakeCtx()).current)
        self.fs["/etc/fstab"] = "tmpfs /tmp tmpfs defaults 0 0\n"
        self.mounts[:] = []
        c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "目前：根檔案系統；開機設定：fstab：tmpfs（需重開機生效）"))

    def test_fix_adds_fstab_line_after_undo(self):
        self.svc["tmp.mount"] = ("masked", "inactive")
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        ev = fx.events
        self.assertEqual(ev[0], ("undo", "systemctl daemon-reload"))
        self.assertLess(idx(ev, ("undo", "systemctl mask tmp.mount")), idx(ev, ("run", "systemctl unmask tmp.mount")))
        self.assertLess(idx(ev, ("run", "systemctl unmask tmp.mount")), idx(ev, ("write", "/etc/fstab")))
        self.assertIn(self.r.LINE, self.fs["/etc/fstab"])
        self.assertTrue(self.fs["/etc/fstab"].startswith("UUID=1 / xfs"))
        self.assertEqual(ev[-1], ("run", "systemctl daemon-reload"))
        self.assertFalse(any(e[1].startswith("mount") for e in ev))  # 不即時掛載

    def test_fix_existing_tmpfs_line_and_fstab_error(self):
        self.fs["/etc/fstab"] += "tmpfs /tmp tmpfs defaults 0 0\n"
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), [])
        self.fs["/etc/fstab"] = "UUID=1 / xfs defaults 0 0"  # 無結尾換行
        self.runner.add("findmnt --verify", res(1, out="[E] parse error"))
        fx = self.fx()
        with self.assertRaises(FixError):
            self.r.fix(fx.ctx, fx)
        self.assertIn("xfs defaults 0 0\ntmpfs\t/tmp", self.fs["/etc/fstab"])

    def test_fix_refuses_other_fs(self):
        self.fs["/etc/fstab"] += "/dev/sdb1 /tmp xfs defaults 0 0\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# RHEL8 0005–0007、0010–0012、0016–0019 / RHEL9 同編號 掛載選項（RhelMountOption）
class RhelMountOptionTest(Base):
    def test_persistent_sources(self):
        r = find(7)  # /tmp noexec
        self.fs["/etc/fstab"] = "tmpfs /tmp tmpfs defaults,nodev 0 0\n"
        self.assertEqual(r._persistent(), ("fstab", ["defaults", "nodev"]))
        self.fs["/etc/fstab"] = ""
        self.fs[d.TMP_UNITS[1]] = "[Mount]\nOptions=mode=1777,strictatime,nosuid,nodev\n"
        self.assertEqual(r._persistent()[0], "tmp.mount")
        self.assertIn("nosuid", r._persistent()[1])
        self.fs.clear()
        self.assertEqual(r._persistent(), ("未設定", None))

    def test_fix_unconfigured_mount_is_manual(self):
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            find(12).fix(fx.ctx, fx)  # /var/tmp noexec，非獨立分割
        self.assertIn("需先完成「設定 /var/tmp 目錄之檔案系統」", str(cm.exception))
        self.assertEqual(fx.events, [])
        self.fs["/proc/self/mounts"] = "/dev/sdb2 /var/tmp xfs rw 0 0\n"  # 已掛載但不在 fstab
        with self.assertRaises(ManualRequired) as cm:
            find(12).fix(fx.ctx, fx)
        self.assertIn("systemd 掛載單元", str(cm.exception))

    def test_fix_fstab_and_remount_order(self):
        self.fs["/etc/fstab"] = "UUID=2 /var/tmp xfs defaults 0 0\n"
        self.fs["/proc/self/mounts"] = "/dev/sdb2 /var/tmp xfs rw 0 0\n"
        fx = self.fx()
        find(12).fix(fx.ctx, fx)
        self.assertIn("defaults,noexec", self.fs["/etc/fstab"])
        self.assertLess(idx(fx.events, ("undo", "mount -o remount,exec /var/tmp")),
                        idx(fx.events, ("run", "mount -o remount,noexec /var/tmp")))

    def test_fix_dev_shm_without_fstab(self):
        fx = self.fx()
        find(19).fix(fx.ctx, fx)  # /dev/shm noexec
        self.assertIn("/dev/shm", self.fs["/etc/fstab"])
        self.assertIn("noexec", self.fs["/etc/fstab"])

    def test_fix_tmp_mount_dropin(self):
        self.fs[d.TMP_UNITS[1]] = "[Mount]\nOptions=mode=1777,nosuid\n"
        fx = self.fx()
        find(5).fix(fx.ctx, fx)  # /tmp nodev
        self.assertEqual(self.fs[d.TMP_DROPIN], "[Mount]\nOptions=mode=1777,nodev,nosuid\n")
        self.assertLess(idx(fx.events, ("undo", "systemctl daemon-reload")), idx(fx.events, ("write", d.TMP_DROPIN)))


# ====================================================================
# 可攜式裝置、家目錄、NFS
# ====================================================================

# RHEL8 0020–0028 / RHEL9 0020–0028 可攜式儲存裝置、使用者家目錄、NFS 之 nodev/nosuid/noexec
class MountGroupOptionTest(Base):
    def test_removable_devs_and_dev_name(self):
        self.globs += ["/sys/block/sda", "/sys/block/sdb", "/sys/block/sdb/sdb1"]
        self.fs["/sys/block/sdb/removable"] = "1\n"
        self.fs["/sys/block/sda/removable"] = "0\n"
        self.assertEqual(d.removable_devs(), set(["sdb", "sdb1"]))
        self.assertEqual(d.dev_name('UUID="abc-1"'), "abc-1")
        self.assertEqual(d.dev_name("/dev/sdb1"), "sdb1")
        self.assertIsNone(d.dev_name("tmpfs"))

    def test_uid_min(self):
        self.fs["/etc/login.defs"] = "UID_MIN 500\n"
        self.assertEqual(d.uid_min(), 500)
        self.fs["/etc/login.defs"] = "UID_MIN abc\n"
        self.assertEqual(d.uid_min(), 1000)

    def test_when_reasons(self):
        for n, kind in ((20, "可攜式"), (23, "/home"), (26, "NFS")):
            self.assertIn(kind, find(n).when(FakeCtx()))

    def test_nfs_check_and_fix(self):
        r = find(28)  # NFS noexec
        self.fs["/etc/fstab"] = "UUID=1 / xfs defaults 0 0\nsrv:/x /mnt/nfs nfs defaults 0 0\n"
        self.mounts += [("srv:/x", "/mnt/nfs", "nfs", ["rw"]), ("srv:/z", "/mnt/auto", "nfs4", ["rw"]),
                        ("/dev/sda1", "/", "xfs", ["rw"]), ("srv:/y", "/mnt/ok", "nfs", ["rw", "noexec"])]
        self.assertIsNone(r.when(FakeCtx()))
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("缺少 noexec：/mnt/auto、/mnt/nfs", c.current)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        ev = fx.events
        self.assertLess(idx(ev, ("undo", "systemctl daemon-reload")), idx(ev, ("write", "/etc/fstab")))
        self.assertIn("srv:/x\t/mnt/nfs\tnfs\tdefaults,noexec", self.fs["/etc/fstab"])
        self.assertIn("UUID=1 / xfs defaults 0 0", self.fs["/etc/fstab"])
        for mp in ("/mnt/auto", "/mnt/nfs"):
            self.assertLess(idx(ev, ("undo", "mount -o remount,exec %s" % mp)),
                            idx(ev, ("run", "mount -o remount,noexec %s" % mp)))
        self.assertEqual(len(self.runner.ran("remount,noexec")), 2)  # / 與已有 noexec 的 /mnt/ok 不處理
        self.assertIn("/mnt/auto 未列於 /etc/fstab", fx.notes[0])

    def test_remount_failure_is_partial(self):
        r = find(26)
        self.fs["/etc/fstab"] = "srv:/x /mnt/nfs nfs defaults,nodev 0 0\n"
        self.mounts.append(("srv:/x", "/mnt/nfs", "nfs", ["rw"]))
        self.runner.add("remount,nodev", res(32, err="mount: busy"))
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), [])  # fstab 已有，不修改
        self.assertTrue(fx.partial)
        self.assertIn("busy", fx.notes[0])
        # 全部已設定 → 合格
        self.mounts[:] = [("srv:/x", "/mnt/nfs", "nfs", ["rw", "nodev"])]
        self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_home_only_under_home(self):
        # noexec 只加在 /home，應用程式帳號所在的 /opt 不處理
        r = find(25)
        self.fs["/etc/login.defs"] = "UID_MIN 1000\n"
        self.dirs.update(["/home/alice", "/opt/app"])
        users = [PW("root", 0, "/root"), PW("alice", 1001, "/home/alice"), PW("app", 1002, "/opt/app"),
                 PW("nobody", 65534, "/home/alice"), PW("ghost", 1003, "/nonexist")]
        self.p(d.pwd, "getpwall", lambda: users)
        self.p(os.path, "realpath", lambda p: p)  # 主機上 /home 可能是連結（macOS）
        self.mounts += [("/dev/sda1", "/", "xfs", ["rw"]), ("/dev/sda2", "/home", "xfs", ["rw"]),
                        ("/dev/sda3", "/opt", "xfs", ["rw"])]
        self.fs["/etc/fstab"] = "/dev/sda2 /home xfs defaults 0 0\n/dev/sda3 /opt xfs defaults 0 0\n"
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertIn("/home\txfs\tdefaults,noexec", self.fs["/etc/fstab"])
        self.assertIn("/dev/sda3 /opt xfs defaults 0 0", self.fs["/etc/fstab"])
        self.assertEqual(self.runner.ran("remount"), ["mount -o remount,noexec /home"])

    def test_removable_fix_and_dry_run(self):
        r = find(21)  # removable nosuid
        self.p(d, "removable_devs", lambda: set(["sdb", "sdb1"]))
        self.fs["/etc/fstab"] = "/dev/sdb1 /media/usb vfat defaults 0 0\n/dev/sda1 / xfs defaults 0 0\n"
        before = dict(self.fs)
        self.mounts.append(("/dev/sdb1", "/media/usb", "vfat", ["rw"]))
        fx = self.fx(dry_run=True)
        r.fix(fx.ctx, fx)
        self.assertEqual(self.fs, before)
        self.assertEqual(self.runner.calls, [])
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertIn("/dev/sdb1\t/media/usb\tvfat\tdefaults,nosuid", self.fs["/etc/fstab"])
        self.assertIn("/dev/sda1 / xfs defaults 0 0", self.fs["/etc/fstab"])


# ====================================================================
# 粘滯位、autofs
# ====================================================================

# RHEL8 0029 / RHEL9 0029 設定全域寫入權限目錄之粘滯位
class StickyBitTest(Base):
    def test_roots_and_errors(self):
        self.mounts += [("/dev/x", "/nonexistent-gcb-mp", "xfs", ["rw"]), ("proc", "/proc", "proc", ["rw"]),
                        ("/dev/y", self.tmp, "xfs", ["rw"]), ("/dev/z", self.tmp + "/ro", "xfs", ["ro"])]
        self.assertEqual(d.sticky_roots(), [self.tmp])
        r = find(29)
        self.runner.add("find", res(124))
        self.assertEqual(r.check(FakeCtx()).status, ERROR)
        self.runner.rules[0] = ("find", res(127))
        self.assertIn("找不到 find", r.check(FakeCtx()).current)
        self.mounts[:] = []
        c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (ERROR, "找不到本機檔案系統"))
        fx = self.fx()
        with self.assertRaises(FixError):
            r.fix(fx.ctx, fx)

    def test_check_and_fix(self):
        self.mounts.append(("/dev/y", self.tmp, "xfs", ["rw"]))
        r = find(29)
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        many = [os.path.join(self.tmp, "d%02d" % i) for i in range(12)]
        for p in many:
            os.mkdir(p)
            os.chmod(p, 0o777)
        link = os.path.join(self.tmp, "lnk")
        os.symlink(many[0], link)
        self.runner.add("find", res(0, out="\0".join(many + [link]) + "\0"))
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("等共 13 個", c.current)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("chmod"), many)  # 符號連結不處理
        self.assertTrue(all(e[2] == 0o1777 for e in fx.events))


# RHEL8 0030 / RHEL9 0030 autofs 服務
class AutofsTest(Base):
    def test_check_and_fix(self):
        r = find(30)
        self.svc["autofs.service"] = ("enabled", "active")
        self.assertEqual(r.check(FakeCtx()).status, FAIL)
        self.svc["autofs.service"] = ("disabled", "inactive")
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        self.fs["/etc/auto.master"] = "# x\n/misc /etc/auto.misc\n+auto.master\n"
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events[:2], [("record", "autofs.service"), ("run", "systemctl --now disable autofs.service")])
        self.assertIn("autofs.service", fx.ctx.intended_stops)
        self.assertEqual(len(fx.notes), 1)
        self.assertIn("/misc /etc/auto.misc", fx.notes[0])
        self.assertNotIn("+auto.master", fx.notes[0])


# ====================================================================
# GPG、AIDE
# ====================================================================

# RHEL8 0032 / RHEL9 0032 GPG 簽章驗證
class GpgCheckTest(Base):
    def test_no_conf_and_yum_conf(self):
        r = find(32)
        c = r.check(FakeCtx())
        self.assertIn("找不到 /etc/dnf/dnf.conf", c.current)
        self.exist.update([d.DNF_CONF, d.YUM_CONF])
        self.assertEqual(d._main_confs(), [d.DNF_CONF, d.YUM_CONF])

    def test_fix_skips_repo_without_gpgkey(self):
        r = find(32)
        self.exist.add(d.DNF_CONF)
        self.fs[d.DNF_CONF] = "[main]\ngpgcheck=1\n"
        self.globs += ["/etc/yum.repos.d/a.repo"]
        self.fs["/etc/yum.repos.d/a.repo"] = ("[signed]\ngpgcheck=0\ngpgkey=file:///k\n\n"
                                              "[internal]\nbaseurl=http://x\ngpgcheck=0\n")
        c = r.check(FakeCtx())
        self.assertIn("localpkg_gpgcheck=未設定", c.current)
        self.assertIn("[internal] gpgcheck=0", c.current)
        self.assertEqual(d.repo_sections_without_key(self.fs["/etc/yum.repos.d/a.repo"]), ["internal"])
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(d.ini_main_values(self.fs[d.DNF_CONF]), {"gpgcheck": "1", "localpkg_gpgcheck": "1"})
        repo = self.fs["/etc/yum.repos.d/a.repo"]
        self.assertEqual([(s, v) for s, k, v, i in d.ini_items(repo) if k == "gpgcheck"],
                         [("signed", "1"), ("internal", "0")])
        self.assertTrue(fx.partial)
        self.assertIn("a.repo [internal]", fx.notes[-1])
        self.fs["/etc/yum.repos.d/a.repo"] = "[x]\ngpgcheck=1\n"
        self.assertEqual(r.check(FakeCtx()).status, PASS)


# RHEL8 0036 / RHEL9 0036 AIDE 套件
class AidePackageTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.r = find(36)
        self.db = os.path.join(self.tmp, "aide.db.gz")
        self.new = os.path.join(self.tmp, "aide.db.new.gz")
        self.fs[d.AIDE_CONF] = "@@define DBDIR %s\ndatabase=file:@@{DBDIR}/aide.db.gz\n" \
                               "database_out=file:@@{DBDIR}/aide.db.new.gz\n" % self.tmp

    def test_check(self):
        self.assertEqual(self.r.check(FakeCtx()).current, "未安裝 aide")
        self.pkgs.add("aide")
        self.assertIn("尚未初始化", self.r.check(FakeCtx()).current)
        open(self.db, "w").close()
        self.assertEqual(self.r.check(FakeCtx()).status, PASS)

    def test_fix_installs_and_inits(self):
        def init(cmd):
            open(self.new, "w").close()
            return res(0)
        self.runner.add("aide --init", init)
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        ev = fx.events
        self.assertEqual(ev[0], ("pkg_install", "aide"))
        self.assertLess(idx(ev, ("undo", "rm -f %s %s" % (self.db, self.new))), idx(ev, ("run", "aide --init")))
        self.assertEqual(ev[-1], ("run", "cp -p %s %s" % (self.new, self.db)))

    def test_fix_init_failed_and_existing_db(self):
        self.pkgs.add("aide")
        fx = self.fx()
        with self.assertRaises(FixError):
            self.r.fix(fx.ctx, fx)
        fx = self.fx(dry_run=True)
        self.r.fix(fx.ctx, fx)  # 預覽不檢查結果
        self.assertEqual(fx.events, [("run", "aide --init")])
        open(self.db, "w").close()
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# RHEL8 0037 / RHEL9 0037 定期檢查檔案系統完整性
class AideScheduleTest(Base):
    def test_cron_fields(self):
        self.assertEqual(d._cron_fields("@daily root /usr/sbin/aide --check", True),
                         (True, "/usr/sbin/aide --check"))
        self.assertEqual(d._cron_fields("@weekly", False), (False, ""))
        self.assertIsNone(d._cron_fields("0 5 * *", False))
        self.assertIsNone(d._cron_fields("# 0 5 * * * aide --check", False))
        self.assertIsNone(d._cron_fields("MAILTO=root", True))

    def test_schedules_sources(self):
        self.fs["/var/spool/cron/root"] = "0 5 * * * /usr/sbin/aide --check\n"
        self.globs += ["/etc/cron.d/aide", "/etc/cron.d/aide~", "/etc/cron.d/.hidden", "/etc/cron.daily/aide",
                       "/etc/cron.daily/other"]
        self.fs["/etc/cron.d/aide"] = "0 4 * * * root aide --check\n"
        self.fs["/etc/cron.d/aide~"] = "0 4 * * * root aide --check\n"
        self.fs["/etc/cron.daily/aide"] = "#!/bin/sh\n/usr/sbin/aide --check\n"
        self.fs["/etc/cron.daily/other"] = "#!/bin/sh\n# aide --check\n"
        self.exist.update(["/etc/cron.daily/aide", "/etc/cron.daily/other"])
        self.runner.add("is-enabled aidecheck.timer", res(0, out="enabled\n"))
        with mock.patch.object(os, "access", lambda p, m: True):
            found = d.aide_schedules()
        self.assertEqual(found, ["root crontab", "/etc/cron.d/aide", "/etc/cron.daily/aide", "aidecheck.timer"])

    def test_check(self):
        r = find(37)
        self.bins.discard("systemctl")
        self.assertEqual(r.check(FakeCtx()).current, "未安裝 AIDE")
        self.bins.add("aide")
        self.assertEqual(r.check(FakeCtx()).current, "未設定每日 AIDE 檢查排程")
        self.fs["/etc/crontab"] = "0 5 * * * root /usr/sbin/aide --check\n"
        self.assertIn("未安裝 cronie", r.check(FakeCtx()).current)
        self.bins.add("crond")
        self.assertIn("crond 服務未啟用", r.check(FakeCtx()).current)
        self.svc["crond.service"] = ("enabled", "active")
        self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_fix(self):
        r = find(37)
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            r.fix(fx.ctx, fx)
        self.bins.add("aide")
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events[0], ("pkg_install", "cronie"))
        self.assertEqual(self.fs[r.CRON], "# TWGCB-01-012-0037 (gcb-checker)\n0 5 * * * root /usr/sbin/aide --check\n")
        self.assertEqual(fx.events[-1], ("run", "systemctl --now enable crond.service"))


# ====================================================================
# 開機載入程式
# ====================================================================

# RHEL8 0038、0039 / RHEL9 0038、0039 開機載入程式設定檔之所有權、權限
class GrubCfgPermTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.cfg = os.path.join(self.tmp, "grub.cfg")
        with open(self.cfg, "w") as f:
            f.write("x")
        os.chmod(self.cfg, 0o644)

    def test_grub_files_and_no_grub(self):
        self.p(d, "GRUB2_DIR", self.tmp)
        efi = "/boot/efi/EFI/rocky/grub.cfg"
        self.globs.append(efi)
        self.exist.add(efi)
        self.mounts += [("/dev/sda1", "/boot/efi", "vfat", ["rw"])]
        self.assertEqual(d.grub_files(), ([self.cfg], [efi]))
        self.assertIsNone(d.no_grub(FakeCtx()))
        self.p(d, "GRUB2_DIR", "/nonexistent-gcb")
        self.globs[:] = []
        self.assertIn("未使用 GRUB", d.no_grub(FakeCtx()))

    def test_check_variants(self):
        mode, owner = find(39), find(38)
        self.p(d, "grub_files", lambda: ([self.cfg], []))
        efi = [None]
        self.p(d, "efi_status", lambda kind: efi[0])
        c = mode.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("權限 644", c.current)
        self.assertIsNotNone(owner.check(FakeCtx()).current)
        os.chmod(self.cfg, 0o600)
        efi[0] = (False, False, "/boot/efi 掛載選項：預設")
        c = mode.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("（fstab 不符合）", c.current)
        efi[0] = (True, False, "/boot/efi 掛載選項：預設")
        c = mode.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("需重開機生效", c.current)
        # 非 UEFI 掛載但有 EFI 檔案
        efi[0] = None
        self.p(d, "grub_files", lambda: ([], [self.cfg]))
        c = mode.check(FakeCtx())
        self.assertIn("EFI 檔案：", c.current)

    def test_fix_mode_and_efi_fstab(self):
        r = find(39)
        self.p(d, "grub_files", lambda: ([self.cfg], []))
        efi = [None]
        self.p(d, "efi_status", lambda kind: efi[0])
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chmod", self.cfg, 0o600)])
        self.assertEqual(fx.notes, [d.GRUB_NOTE])
        # /boot/efi 需改 fstab：未加 --include-risky 只列為部分修復
        efi[0] = (False, False, "x")
        self.fs["/etc/fstab"] = "UUID=AB /boot/efi vfat defaults,umask=0077 0 2\n"
        fx = self.fx(include_risky=False)
        r.fix(fx.ctx, fx)
        self.assertTrue(fx.partial)
        self.assertNotIn(("write", "/etc/fstab"), fx.events)
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertLess(idx(fx.events, ("undo", "systemctl daemon-reload")), idx(fx.events, ("write", "/etc/fstab")))
        self.assertIn("umask=0077,fmask=0177", self.fs["/etc/fstab"])
        self.assertEqual(fx.events[-1], ("run", "systemctl daemon-reload"))

    def test_fix_owner_efi(self):
        r = find(38)
        self.p(d, "grub_files", lambda: ([], []))
        self.p(d, "efi_status", lambda kind: (False, False, "x"))
        self.fs["/etc/fstab"] = "UUID=AB /boot/efi vfat uid=1000 0 2\n"
        fx = self.fx()
        r.fix(fx.ctx, fx)
        self.assertIn("vfat\tgid=0,uid=0\t", self.fs["/etc/fstab"])
        self.assertIn("gid=0,uid=0", fx.notes[-1])


# RHEL8 0040 開機載入程式之密碼 / RHEL9 0040 開機載入程式之通行碼（C 類）
class GrubPasswordTest(Base):
    def test_main_cfg(self):
        efi = "/boot/efi/EFI/redhat/grub.cfg"
        self.globs.append(efi)
        self.dirs.add("/sys/firmware/efi")
        self.assertEqual(d.grub_main_cfg(FakeCtx("rhel8")), efi)
        self.assertEqual(d.grub_main_cfg(FakeCtx("rhel9")), efi)  # /boot/grub2/grub.cfg 不存在
        self.exist.add("/boot/grub2/grub.cfg")
        self.assertEqual(d.grub_main_cfg(FakeCtx("rhel9")), "/boot/grub2/grub.cfg")
        self.globs[:] = []
        self.exist.clear()
        self.assertEqual(d.grub_main_cfg(FakeCtx("rhel9")), "/boot/grub2/grub.cfg")

    def test_check(self):
        r = find(40, "rhel9")
        self.assertEqual(r.check(FakeCtx()).status, ERROR)
        self.exist.update(["/boot/grub2/grub.cfg", "/boot/grub2/user.cfg"])
        self.fs["/boot/grub2/grub.cfg"] = "menuentry x {}\n"
        self.fs["/boot/grub2/user.cfg"] = "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.AB\n"
        c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("grub.cfg 未引用", c.current)
        self.fs["/boot/grub2/grub.cfg"] = "password_pbkdf2 root ${GRUB2_PASSWORD}\n"
        self.assertEqual(r.check(FakeCtx()).status, PASS)
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            r.fix(fx.ctx, fx)


# ====================================================================
# 單一使用者模式、核心傾印、加密原則
# ====================================================================

# RHEL8 0041 單一使用者模式身分驗證 / RHEL9 0041 單一使用者模式身分鑑別
class SingleUserAuthTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.r = find(41)
        self.files = {"rescue.service": ["/usr/lib/systemd/system/rescue.service"],
                      "emergency.service": ["/usr/lib/systemd/system/emergency.service"]}
        self.p(d, "unit_files", lambda u: self.files.get(u, []))
        self.fs["/usr/lib/systemd/system/rescue.service"] = "[Service]\nExecStart=-/bin/sh\n"
        self.fs["/usr/lib/systemd/system/emergency.service"] = \
            "[Service]\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency\n"

    def test_unit_helpers(self):
        self.assertEqual(d.unit_exec_start(["# c\n[Unit]\nExecStart=/x\n[Service]\nEnvironment=SYSTEMD_SULOGIN_FORCE=1\n"]),
                         ([], True))

    def test_when_and_check(self):
        self.assertIsNone(self.r.when(FakeCtx()))
        c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("rescue.service ExecStart=-/bin/sh", c.current)

    def test_fix_dropin(self):
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        path = "/etc/systemd/system/rescue.service.d/60-gcb.conf"
        self.assertEqual(self.fs[path], "[Service]\nExecStart=\nExecStart=%s\n" % d.SULOGIN["rescue.service"])
        self.assertNotIn("/etc/systemd/system/emergency.service.d/60-gcb.conf", self.fs)
        self.assertLess(idx(fx.events, ("undo", "systemctl daemon-reload")), idx(fx.events, ("write", path)))
        self.assertEqual(fx.events[-1], ("run", "systemctl daemon-reload"))

    def test_fix_already_ok_and_forced(self):
        self.fs["/usr/lib/systemd/system/rescue.service"] = \
            "[Service]\nExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue\n"
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("undo", "systemctl daemon-reload")])
        self.fs["/usr/lib/systemd/system/rescue.service"] += "Environment=SYSTEMD_SULOGIN_FORCE=1\n"
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


class UnitFilesTest(unittest.TestCase):
    # RHEL8 0041 / RHEL9 0041：找不到主檔時回傳空清單
    def test_missing(self):
        t = tempfile.mkdtemp()
        try:
            self.assertEqual(d.unit_files("rescue.service", [t]), [])
        finally:
            shutil.rmtree(t)


# RHEL8 0042 / RHEL9 0042 核心傾印功能
class CoreDumpTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.r = find(42)
        self.limits = ["/etc/security/limits.conf", "/etc/security/limits.d/90-app.conf"]
        self.p(d, "limits_files", lambda: list(self.limits))
        self.fs["/etc/security/limits.conf"] = "# x\n* soft core 0\n"
        self.fs["/etc/security/limits.d/90-app.conf"] = "* hard core unlimited\napp hard core 100\n"
        self.rt = {"fs.suid_dumpable": "2", "kernel.core_pattern": "core"}
        self.p(pkgsvc, "sysctl_runtime", lambda k: self.rt.get(k))
        self.p(pkgsvc, "sysctl_persistent", lambda k: (None, None, []))

    def test_limits_comment(self):
        out = d._limits_comment(self.fs["/etc/security/limits.d/90-app.conf"])
        self.assertEqual(out, "# [gcb-checker 註解] * hard core unlimited\napp hard core 100\n")
        self.assertEqual(d._limits_comment(""), "")

    def test_check_abrtd(self):
        self.svc["abrtd.service"] = ("enabled", "active")
        c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("abrtd 執行中", c.current)

    def test_check_with_coredump(self):
        self.p(d, "_has_coredump", lambda: True)
        self.p(d, "coredump_values", lambda: {"Storage": "none", "ProcessSizeMax": "0"})
        self.svc["systemd-coredump.socket"] = ("static", "inactive")
        c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("coredump Storage=none ProcessSizeMax=0 socket=static", c.current)

    def test_fix_with_coredump(self):
        self.p(d, "_has_coredump", lambda: True)
        self.svc["abrtd.service"] = ("enabled", "active")
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        ev = fx.events
        self.assertEqual(ev[0], ("undo", "systemctl daemon-reload"))
        self.assertIn("# [gcb-checker 註解] * hard core unlimited", self.fs["/etc/security/limits.d/90-app.conf"])
        self.assertNotIn(("write", "/etc/security/limits.conf"), ev)
        self.assertEqual(self.fs[d.LIMITS_OWN], "# TWGCB-01-012-0042 (gcb-checker)\n* hard core 0\n")
        self.assertEqual(self.fs[d.COREDUMP_OWN], "[Coredump]\nStorage=none\nProcessSizeMax=0\n")
        self.assertLess(idx(ev, ("write", d.COREDUMP_OWN)), idx(ev, ("run", "systemctl daemon-reload")))
        self.assertIn(("mask", "systemd-coredump.socket"), ev)
        self.assertIn(("sysctl", "fs.suid_dumpable", "0"), ev)
        self.assertIn(("sysctl", "kernel.core_pattern", "|/bin/false"), ev)
        self.assertIn("abrtd", fx.notes[-1])

    def test_fix_without_coredump(self):
        self.p(d, "_has_coredump", lambda: False)
        self.rt = {"fs.suid_dumpable": "0", "kernel.core_pattern": "|/bin/false"}
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        self.assertNotIn(("undo", "systemctl daemon-reload"), fx.events)
        self.assertNotIn(d.COREDUMP_OWN, self.fs)
        self.assertEqual(fx.kinds("sysctl"), [])


# RHEL8 0044 / RHEL9 0044 設定全系統加密原則
class CryptoPolicyTest(Base):
    def setUp(self):
        Base.setUp(self)
        self.r = find(44)

    def test_policy_source(self):
        self.assertIsNone(d.crypto_policy())
        self.fs[d.CRYPTO_CONFIG] = "# c\n\nDEFAULT\n"
        self.assertEqual(d.crypto_policy(), "DEFAULT")
        self.assertIsNone(d.rsa_bits(base64.b64encode(b"\x00\x00").decode()))

    def test_check(self):
        self.assertEqual(self.r.check(FakeCtx()).status, ERROR)
        self.fs[d.CRYPTO_CONFIG] = "DEFAULT\n"
        self.assertEqual(self.r.check(FakeCtx()).status, FAIL)
        self.fs[d.CRYPTO_CONFIG] = "FIPS\n"
        self.assertIn("未啟用 FIPS", self.r.check(FakeCtx()).current)
        self.fs["/proc/sys/crypto/fips_enabled"] = "1\n"
        self.fs["/etc/crypto-policies/state/current"] = "DEFAULT\n"
        c = self.r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("目前套用 DEFAULT", c.current)

    def test_precondition(self):
        self.p(d, "_sshd_conf", lambda: {"authorizedkeyscommand": ["/usr/bin/sss_ssh_authorizedkeys"]})
        self.svc["sssd.service"] = ("enabled", "active")
        self.exist.add("/etc/krb5.keytab")
        why = self.r.precondition(FakeCtx())
        for s in ("AuthorizedKeysCommand", "sssd 執行中", "krb5.keytab"):
            self.assertIn(s, why)
        self.p(d, "_sshd_conf", lambda: {})
        self.svc.clear()
        self.exist.clear()
        self.p(d, "_ssh_key_files", lambda: ["/root/.ssh/authorized_keys"])
        self.fs["/root/.ssh/authorized_keys"] = "ssh-rsa %s a@b\n" % rsa_key(2048)
        self.assertIn("authorized_keys（2048 位元）", self.r.precondition(FakeCtx()))
        self.fs["/root/.ssh/authorized_keys"] = "ssh-rsa %s a@b\n" % rsa_key(4096)
        self.assertIsNone(self.r.precondition(FakeCtx()))

    def test_ssh_key_files(self):
        self.p(d.pwd, "getpwall", lambda: [PW("alice", 1000, "/home/alice")])
        self.exist.update(["/home/alice/.ssh/authorized_keys", "/etc/ssh/keys/alice", "/etc/ssh/ssh_host_rsa_key.pub"])
        self.globs.append("/etc/ssh/ssh_host_rsa_key.pub")
        # 無 sshd：使用預設的 AuthorizedKeysFile
        self.assertEqual(d._ssh_key_files(), ["/etc/ssh/ssh_host_rsa_key.pub", "/home/alice/.ssh/authorized_keys"])
        self.bins.add("sshd")
        self.runner.add("sshd -T", res(0, out="authorizedkeysfile /etc/ssh/keys/%u %h/.ssh/authorized_keys\n"))
        self.assertEqual(d._ssh_key_files(), ["/etc/ssh/keys/alice", "/etc/ssh/ssh_host_rsa_key.pub",
                                              "/home/alice/.ssh/authorized_keys"])

    def test_fix_keeps_subpolicy_and_order(self):
        self.bins.add("update-crypto-policies")
        self.runner.add("update-crypto-policies --show", res(0, out="DEFAULT:GCB-SSH\n"))
        self.svc["sshd.service"] = ("enabled", "active")
        fx = self.fx()
        self.r.fix(fx.ctx, fx)
        ev = fx.events
        i_restart = idx(ev, ("undo", "systemctl restart sshd"))
        i_old = idx(ev, ("undo", "update-crypto-policies --set DEFAULT:GCB-SSH"))
        i_set = idx(ev, ("run", "update-crypto-policies --set FUTURE:GCB-SSH"))
        self.assertLess(i_restart, i_old)
        self.assertLess(i_old, i_set)
        self.assertLess(idx(ev, ("backup", d.CRYPTO_CONFIG)), i_set)
        self.assertGreater(idx(ev, ("run", "systemctl restart sshd")), i_set)
        self.assertEqual(len(self.runner.ran("makecache")), 2)

    def test_fix_repo_broken_after(self):
        self.bins.add("update-crypto-policies")
        self.runner.add("update-crypto-policies --show", res(0, out="DEFAULT\n"))
        state = {"n": 0}

        def makecache(cmd):
            state["n"] += 1
            return res(0) if state["n"] == 1 else res(1, err="certificate key too small")
        self.runner.add("makecache", makecache)
        fx = self.fx()
        with self.assertRaises(FixError) as cm:
            self.r.fix(fx.ctx, fx)
        self.assertIn("key too small", str(cm.exception))
        self.assertNotIn(("run", "systemctl restart sshd"), fx.events)

    def test_fix_missing_tool_and_dry_run(self):
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.r.fix(fx.ctx, fx)
        self.bins.add("update-crypto-policies")
        self.runner.add("update-crypto-policies --show", res(0, out="DEFAULT\n"))
        fx = self.fx(dry_run=True)
        self.r.fix(fx.ctx, fx)
        self.assertEqual(self.runner.ran("makecache"), [])
        self.assertEqual(self.runner.ran("--set"), [])


if __name__ == "__main__":
    unittest.main()
