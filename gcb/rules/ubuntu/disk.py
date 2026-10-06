# -*- coding: utf-8 -*-
"""Ubuntu 22.04 磁碟與檔案系統（TWGCB-01-014-0001 ～ 0028）。"""
import os

from ... import textedit as te
from ...fixer import ManualRequired
from ...util import read_text, run, which
from ..base import FAIL, PASS, Check, Rule
from ..common import SeparatePartition
from ..generic import Module, MountOption
from .helpers import U


def azure_udf_in_use(ctx):
    """Azure 佈建使用 UDF 格式的設定光碟（GCB 註明 Azure 上停用可能影響運作）；或目前有 udf 掛載。"""
    vendor = (read_text("/sys/class/dmi/id/sys_vendor") or "").strip()
    if vendor == "Microsoft Corporation" and (which("waagent") or os.path.isdir("/var/lib/waagent")):
        return "偵測到 Microsoft Azure（waagent），佈建光碟使用 UDF"
    mounts = [l.split()[1] for l in (read_text("/proc/self/mounts") or "").splitlines() if " udf " in l]
    return "目前有 udf 掛載：%s" % "、".join(mounts) if mounts else None


def snap_squashfs_in_use(ctx):
    mounts = [l for l in (read_text("/proc/self/mounts") or "").splitlines() if " squashfs " in l]
    return "系統有 %d 個 squashfs 掛載（snap 套件）" % len(mounts) if mounts else None


# ====================================================================
# 客製規則
# ====================================================================

# [TmpTmpfs] TWGCB-01-014-0004 設定 /tmp 目錄之檔案系統（tmpfs）
class TmpTmpfs(Rule):
    category = "磁碟與檔案系統"
    title = "設定/tmp 目錄之檔案系統"
    expected = "tmpfs"
    risk = "B"
    needs_reboot = True
    LINE = "tmpfs\t/tmp\ttmpfs\tdefaults,rw,nosuid,nodev,noexec,relatime,mode=1777\t0\t0"

    def __init__(self, ids):
        self.ids = ids

    def _persistent(self):
        """回傳 (是否已設定 tmpfs, 說明)。"""
        fstab = read_text("/etc/fstab") or ""
        for line in fstab.splitlines():
            p = line.split()
            if line.strip() and not line.strip().startswith("#") and len(p) >= 3 and p[1] == "/tmp":
                return p[2] == "tmpfs", "fstab：%s" % p[2]
        if run(["systemctl", "is-enabled", "tmp.mount"], timeout=15).out.strip() == "enabled":
            return True, "tmp.mount 已啟用"
        return False, "未設定"

    def check(self, ctx):
        rt = run(["findmnt", "-kn", "-o", "FSTYPE", "/tmp"], timeout=15).out.strip() or "根檔案系統"
        ok, src = self._persistent()
        # 已寫入開機設定即視為合格，重開機後才會實際掛載
        return Check(PASS if ok else FAIL, "目前：%s；開機設定：%s%s" % (
            rt, src, "（需重開機生效）" if ok and rt != "tmpfs" else ""))

    def fix(self, ctx, fx):
        if te.fstab_options(read_text("/etc/fstab") or "", "/tmp") is not None:
            raise ManualRequired("/tmp 已有其他 fstab 設定（例如獨立磁區），請人工評估是否改為 tmpfs")
        fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")  # 先登記：回滾時在還原 fstab 之後才 reload
        fx.edit_file("/etc/fstab", lambda t: t + ("" if t.endswith("\n") or not t else "\n") + self.LINE + "\n")
        fx.run(["systemctl", "daemon-reload"], "重新載入 systemd")
        fx.note("已寫入 /etc/fstab，重開機後 /tmp 才會改為 tmpfs")


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

RULES = [
    # 0001 cramfs 檔案系統 → common.py
    # 0002 squashfs 檔案系統（snap 使用中時略過）
    Module("squashfs", U(2), risk="B", in_use=snap_squashfs_in_use),
    # 0003 udf 檔案系統（Azure 或有 udf 掛載時略過）
    Module("udf", U(3), in_use=azure_udf_in_use),
    # 0004 設定 /tmp 目錄之檔案系統
    TmpTmpfs(U(4)),
    # 0005–0007 /tmp 之 nodev、nosuid、noexec 選項
    MountOption("/tmp", "nodev", U(5)),
    MountOption("/tmp", "nosuid", U(6)),
    MountOption("/tmp", "noexec", U(7)),
    # 0008–0010 /dev/shm 之 nodev、nosuid、noexec 選項
    MountOption("/dev/shm", "nodev", U(8)),
    MountOption("/dev/shm", "nosuid", U(9)),
    MountOption("/dev/shm", "noexec", U(10)),
    # 0011 設定 /var 目錄之檔案系統 → common.py
    # 0012–0013 /var 之 nodev、nosuid 選項
    MountOption("/var", "nodev", U(12)),
    MountOption("/var", "nosuid", U(13)),
    # 0014 設定 /var/tmp 目錄之檔案系統
    SeparatePartition("/var/tmp", U(14)),
    # 0015–0017 /var/tmp 之 nodev、nosuid、noexec 選項
    MountOption("/var/tmp", "nodev", U(15)),
    MountOption("/var/tmp", "nosuid", U(16)),
    MountOption("/var/tmp", "noexec", U(17)),
    # 0018 設定 /var/log 目錄之檔案系統
    SeparatePartition("/var/log", U(18)),
    # 0019–0021 /var/log 之 nodev、nosuid、noexec 選項
    MountOption("/var/log", "nodev", U(19)),
    MountOption("/var/log", "nosuid", U(20)),
    MountOption("/var/log", "noexec", U(21)),
    # 0022 設定 /var/log/audit 目錄之檔案系統
    SeparatePartition("/var/log/audit", U(22)),
    # 0023–0025 /var/log/audit 之 nodev、nosuid、noexec 選項
    MountOption("/var/log/audit", "nodev", U(23)),
    MountOption("/var/log/audit", "nosuid", U(24)),
    MountOption("/var/log/audit", "noexec", U(25)),
    # 0026 設定 /home 目錄之檔案系統
    SeparatePartition("/home", U(26)),
    # 0027–0028 /home 之 nodev、nosuid 選項
    MountOption("/home", "nodev", U(27)),
    MountOption("/home", "nosuid", U(28)),
]
