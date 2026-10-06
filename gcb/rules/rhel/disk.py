# -*- coding: utf-8 -*-
"""RHEL 8 / 9 磁碟與檔案系統、系統設定與維護（前段）。

RHEL 8：TWGCB-01-008-0001 ～ 0047
RHEL 9：TWGCB-01-012-0001 ～ 0047、0285 ～ 0300（新增的檔案系統模組）

0001、0008、0045、0046、0047 在 ../common.py，本檔不重複定義。
sudoers 解析、/boot/efi 掛載選項、sysctl、limits、coredump 等與 Ubuntu 相同的工具沿用
../ubuntu/system.py（純函式，不含 Ubuntu 專屬路徑）。
"""
import base64
import glob
import os
import pwd
import re
import struct

from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from ..common import SeparatePartition, modprobe_files
from ..generic import (FilePerm, Module, MountOption, PackagePresent, installed, module_builtin, mount_options,
                       not_separate)
from ..ubuntu.system import (SudoDefault, SysctlValue, coredump_values, efi_status, fstab_set_opts,
                                 limits_core, limits_files, proc_mounts, sysctl_state, sysctl_fix)
from .helpers import R

DISK = "磁碟與檔案系統"
CAT = "系統設定與維護"
INVERSE = {"nodev": "dev", "nosuid": "suid", "noexec": "exec"}


# ====================================================================
# 共用小工具
# ====================================================================

def _active(line):
    s = line.strip()
    return bool(s) and not s.startswith("#")


def fstab_entries(text=None):
    """回傳 [(行號, 裝置, 掛載點, 類型, 選項清單)]（略過註解）。"""
    if text is None:
        text = read_text("/etc/fstab") or ""
    out = []
    for i, line in enumerate(text.splitlines()):
        p = line.split()
        if _active(line) and len(p) >= 4:
            out.append((i, p[0], p[1].replace("\\040", " "), p[2], p[3].split(",")))
    return out


def fstab_add_option_lines(text, pred, option):
    """在 pred(裝置, 掛載點, 類型) 為真的 fstab 行加入選項。"""
    lines = (text or "").splitlines()
    for i, dev, mp, fs, opts in fstab_entries(text):
        if pred(dev, mp, fs) and option not in opts:
            p = lines[i].split()
            p[3] = ",".join(opts + [option])
            lines[i] = "\t".join(p)
    return "\n".join(lines) + "\n" if lines else ""


def mount_of(path, mounts=None):
    """path 所在的掛載點（最長前綴）。回傳 (裝置, 掛載點, 類型, 選項) 或 None。"""
    path = os.path.realpath(path)
    best = None
    for m in (mounts if mounts is not None else proc_mounts()):
        mp = m[1]
        if path == mp or path.startswith(mp.rstrip("/") + "/"):
            if best is None or len(mp) >= len(best[1]):
                best = m  # 同一掛載點多次掛載時取最後一個
    return best


def fstype_match(fs, types):
    """fs 是否屬於 types（"fuse" 也比對 fuse.sshfs 等子類型）。"""
    return any(fs == t or fs.startswith(t + ".") for t in types)


def _verify_fstab(fx):
    r = fx.run(["findmnt", "--verify"], "檢查 fstab 語法", check=False)
    if r is not None and not r.ok and "error" in r.text().lower():
        raise FixError("fstab 檢查失敗，不套用：%s" % r.text()[-200:])


def _reload_undo(fx):
    """登記回滾時 daemon-reload；須在修改 fstab／unit 檔「之前」呼叫（回滾為反向執行，才會在還原檔案之後才 reload）。"""
    if which("systemctl"):
        fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")


def _daemon_reload(fx):
    if which("systemctl"):
        fx.run(["systemctl", "daemon-reload"], "重新載入 systemd", check=False)


def _remount(fx, mp, option):
    """即時重新掛載加入選項；失敗回傳錯誤說明。"""
    fx.add_undo(["mount", "-o", "remount,%s" % INVERSE.get(option, option), mp], "恢復 %s 掛載選項" % mp)
    r = fx.run(["mount", "-o", "remount,%s" % option, mp], "重新掛載 %s（加入 %s）" % (mp, option), check=False)
    if r is not None and not r.ok:
        return r.text()[-150:] or "rc=%s" % r.rc
    return None


def uid_min():
    v = te.get_kv(read_text("/etc/login.defs") or "", "UID_MIN")
    try:
        return int(v)
    except (TypeError, ValueError):
        return 1000


def _efi_vfat():
    """UEFI 開機或 /boot/efi 為 vfat 時回傳說明。"""
    why = []
    if os.path.isdir("/sys/firmware/efi"):
        why.append("系統以 UEFI 開機")
    for dev, mp, fs, opts in proc_mounts():
        if mp == "/boot/efi" and fs in ("vfat", "msdos"):
            why.append("/boot/efi 為 %s" % fs)
            break
    else:
        for i, dev, mp, fs, opts in fstab_entries():
            if mp == "/boot/efi" and fs in ("vfat", "msdos"):
                why.append("/etc/fstab 的 /boot/efi 為 %s" % fs)
    return "、".join(why) or None


# ====================================================================
# 核心模組（0001–0003、0031、RHEL 9 0285–0300）
# ====================================================================

def _mkey(name):
    return name.replace("-", "_")


def loaded_modules():
    """回傳 {模組名稱: (參照數, [使用者模組])}。"""
    out = {}
    for line in (read_text("/proc/modules") or "").splitlines():
        p = line.split()
        if len(p) >= 4:
            try:
                ref = int(p[2])
            except ValueError:
                ref = 0
            out[p[0]] = (ref, [u for u in p[3].split(",") if u and u != "-"])
    return out


def modprobe_disabled(texts, module):
    """回傳 (install 已停用, 已 blacklist)；模組名稱的「-」與「_」視為相同（usb-storage = usb_storage）。"""
    names = set([module, module.replace("-", "_"), module.replace("_", "-")])
    inst = bl = False
    for n in names:
        a, b = te.modprobe_status(texts, n)
        inst, bl = inst or a, bl or b
    return inst, bl


def ondemand_mounts(fstypes):
    """autofs map 與 systemd .mount 單元中，使用指定檔案系統的按需掛載設定。"""
    found = []
    rx = re.compile(r"(-fstype=|Type=)(%s)\b" % "|".join(re.escape(t) for t in fstypes))
    for f in sorted(glob.glob("/etc/auto.*") + glob.glob("/etc/auto.master.d/*")
                    + glob.glob("/etc/systemd/system/*.mount") + glob.glob("/run/systemd/generator/*.mount")):
        if rx.search(read_text(f) or ""):
            found.append(f)
    return found


def module_usage(module, fstypes=(), units=(), refcount=True, devnode=None, pkgs=()):
    """產生「使用中」判斷：模組被參照、有該類型的掛載、fstab、autofs 或 .mount 設定、相關服務執行中、
    裝置檔被開啟，或已安裝使用該模組的套件（例如按需掛載 NFS 的 nfs-utils）。"""
    def _f(ctx):
        why = []
        if refcount:
            info = loaded_modules().get(_mkey(module))
            if info and info[0] > 0:
                why.append("%s 模組使用中（參照數 %d%s）" % (
                    module, info[0], "，被 %s 使用" % "、".join(info[1]) if info[1] else ""))
        if fstypes:
            mnts = [mp for dev, mp, fs, opts in proc_mounts() if fstype_match(fs, fstypes)]
            if mnts:
                why.append("目前有 %s 掛載：%s" % ("/".join(fstypes), "、".join(mnts[:5])))
            fst = [mp for i, dev, mp, fs, opts in fstab_entries() if fstype_match(fs, fstypes)]
            if fst:
                why.append("/etc/fstab 有 %s 掛載設定：%s" % ("/".join(fstypes), "、".join(fst[:5])))
            od = ondemand_mounts(fstypes)
            if od:
                why.append("有 %s 按需掛載設定：%s" % ("/".join(fstypes), "、".join(od[:5])))
        for pk in pkgs:
            if pkgsvc.pkg_installed(ctx.osi, pk):
                why.append("已安裝 %s（可能需要時才掛載）" % pk)
        for u in units:
            if pkgsvc.svc_state(u)[1] == "active":
                why.append("%s 執行中" % u)
        if devnode and _devnode_open(devnode):
            why.append("有程式開啟 %s" % devnode)
        return "；".join(why) or None
    return _f


def _devnode_open(dev):
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if os.readlink(fd) == dev:
                return True
        except OSError:
            continue
    return False


def fat_block(ctx):
    """[決策紀錄] RHEL 9 0294：UEFI 開機或 vfat 使用中時一律略過，否則 /boot/efi 無法掛載、無法開機。"""
    why = []
    efi = _efi_vfat()
    if efi:
        why.append(efi)
    use = module_usage("fat", fstypes=("vfat", "msdos", "fat"))(ctx)
    if use:
        why.append(use)
    vfat = loaded_modules().get("vfat")
    if vfat and vfat[0] > 0:
        why.append("vfat 模組使用中")
    if why:
        return "；".join(why) + "，停用 fat 會使 vfat 無法掛載（UEFI 系統將無法開機）"
    return None


def azure_udf(ctx):
    """Azure 佈建使用 UDF 格式的設定光碟（GCB 註明 Azure 上可能影響運作）。"""
    vendor = (read_text("/sys/class/dmi/id/sys_vendor") or "").strip()
    if vendor == "Microsoft Corporation" and (which("waagent") or os.path.isdir("/var/lib/waagent")):
        return "偵測到 Microsoft Azure（waagent），佈建光碟使用 UDF"
    return module_usage("udf", fstypes=("udf",))(ctx)


# [RhelModule] RHEL8 0002、0003、0031 / RHEL9 0002、0003、0031、0285–0300 停用檔案系統模組
class RhelModule(Module):
    """generic.Module 加上：

    - 模組名稱「-」「_」等價（usb-storage 在 /proc/modules 為 usb_storage）
    - 載入判斷以模組名稱完全比對（避免 ext 誤判為 ext4、fat 誤判為 vfat）
    - usage(ctx)：使用中說明。A 類使用中時略過（可加 --include-risky）；B 類使用中時一律略過
    - block(ctx)：不論 --include-risky 都不可修復的原因（例：UEFI 系統的 fat）
    - loaded_as：其他可能的載入名稱（例：afs 實際模組為 kafs）
    """

    def __init__(self, module, ids, title, risk="A", usage=None, block=None, loaded_as=()):
        Module.__init__(self, module, ids, risk=risk, category=DISK, title=title, in_use=usage)
        self.block = block
        self.names = [_mkey(module)] + [_mkey(n) for n in loaded_as]

    def _loaded(self):
        mods = loaded_modules()
        return [n for n in self.names if n in mods]

    def check(self, ctx):
        texts = [read_text(f) or "" for f in modprobe_files()]
        inst, bl = modprobe_disabled(texts, self.module)
        loaded = self._loaded()
        cur = "install 停用:%s、blacklist:%s、目前已載入:%s" % (
            "是" if inst else "否", "是" if bl else "否", "是（%s）" % "、".join(loaded) if loaded else "否")
        if module_builtin(self.module):
            cur += "；模組已編入核心，無法以 modprobe.d 停用"
        elif not loaded and os.path.isdir("/lib/modules/%s" % os.uname().release) \
                and not run(["modinfo", self.module], timeout=15).ok:
            cur += "；核心未提供此模組"
        for f in (self.block, self.in_use):
            why = f(ctx) if f else None
            if why:
                cur += "；" + why
                break
        return Check(PASS if inst and bl and not loaded else FAIL, cur)

    def precondition(self, ctx):
        if self.block:
            why = self.block(ctx)
            if why:
                return why
        why = self.in_use(ctx) if self.in_use else None
        if not why:
            return None
        if self.risk == "B":
            return why + "，停用會中斷現有功能，請人工評估後處理"
        if not ctx.include_risky:
            return why + "，停用會影響現有功能；確認後可加 --include-risky"
        return None

    def fix(self, ctx, fx):
        why = self.block(ctx) if self.block else None
        if why:
            raise ManualRequired(why)
        if module_builtin(self.module):
            raise ManualRequired("%s 已編入核心，無法以 modprobe.d 停用，需更換核心或接受此項" % self.module)
        path = "/etc/modprobe.d/%s.conf" % self.module
        fx.edit_file(path, lambda t: te.modprobe_conf(t, self.module, "/bin/true"))
        for name in self._loaded():
            r = fx.run(["modprobe", "-r", name], "卸載 %s 模組" % name, check=False)
            if r is not None and not r.ok:
                fx.partial = True
                fx.note("已寫入 %s，但 %s 模組無法卸載（%s）；停止使用後執行 modprobe -r %s，或重開機後生效"
                        % (path, name, r.text()[-150:], name))


# ====================================================================
# 掛載點（0004–0019）
# ====================================================================

TMP_UNITS = ["/etc/systemd/system/tmp.mount", "/usr/lib/systemd/system/tmp.mount"]
TMP_DROPIN = "/etc/systemd/system/tmp.mount.d/60-gcb.conf"


def tmp_unit_state():
    return pkgsvc.svc_state("tmp.mount")[0] if which("systemctl") else "not-found"


# [TmpTmpfs] RHEL8 0004 / RHEL9 0004 設定/tmp 目錄之檔案系統
class TmpTmpfs(Rule):
    category = DISK
    title = "設定/tmp 目錄之檔案系統"
    expected = "tmpfs"
    risk = "B"
    needs_reboot = True
    LINE = "tmpfs\t/tmp\ttmpfs\tdefaults,rw,nosuid,nodev,noexec,relatime\t0\t0"

    def __init__(self, ids):
        self.ids = ids

    def _persistent(self):
        """回傳 (開機時是否為 tmpfs, 說明)。"""
        opts = None
        for i, dev, mp, fs, o in fstab_entries():
            if mp == "/tmp":
                opts = (fs, o)
        state = tmp_unit_state()
        if opts is not None:
            if state == "masked":
                return False, "fstab：%s，但 tmp.mount 被遮蔽（masked），開機不會掛載" % opts[0]
            return opts[0] == "tmpfs", "fstab：%s" % opts[0]
        if state in ("enabled", "enabled-runtime", "static", "generated") and \
                any(os.path.exists(u) for u in TMP_UNITS):
            return state != "static", "tmp.mount %s" % state
        return False, "未設定（tmp.mount %s）" % state

    def check(self, ctx):
        m = [x for x in proc_mounts() if x[1] == "/tmp"]
        rt = m[-1][2] if m else "根檔案系統"
        ok, src = self._persistent()
        return Check(PASS if ok else FAIL, "目前：%s；開機設定：%s%s" % (
            rt, src, "（需重開機生效）" if ok and rt != "tmpfs" else ""))

    def fix(self, ctx, fx):
        fst = [e for e in fstab_entries() if e[2] == "/tmp"]
        if fst and fst[-1][3] != "tmpfs":
            raise ManualRequired("/tmp 已在 /etc/fstab 設定為 %s（例如獨立磁區），請人工評估是否改為 tmpfs" % fst[-1][3])
        _reload_undo(fx)
        if tmp_unit_state() == "masked":
            # 文件作法：systemctl unmask tmp.mount（被遮蔽時 fstab 的 /tmp 也不會掛載）
            fx.add_undo(["systemctl", "mask", "tmp.mount"], "恢復遮蔽 tmp.mount")
            fx.run(["systemctl", "unmask", "tmp.mount"], "解除 tmp.mount 遮蔽")
        if not fst:
            fx.edit_file("/etc/fstab", lambda t: t + ("" if t.endswith("\n") or not t else "\n") + self.LINE + "\n")
            _verify_fstab(fx)
        _daemon_reload(fx)
        # 不即時掛載：會遮住現有 /tmp 內容
        fx.note("已設定開機時以 tmpfs 掛載 /tmp，需重開機生效（tmpfs 佔用記憶體，預設上限為 RAM 的 50%）")


# [RhelMountOption] RHEL8 0005–0007、0010–0012、0016–0019 / RHEL9 同編號 掛載選項
class RhelMountOption(MountOption):
    """generic.MountOption 加上 RHEL 的 tmp.mount 路徑（/usr/lib/systemd/system），沒有開機設定時改為需人工處理。"""

    def __init__(self, mount, option, ids, title):
        MountOption.__init__(self, mount, option, ids)
        self.title = title

    def _persistent(self):
        opts = te.fstab_options(read_text(self.FSTAB) or "", self.mount)
        if opts is not None:
            return "fstab", opts
        if self.mount == "/tmp":
            for f in [TMP_DROPIN] + TMP_UNITS:
                v = te.get_kv(read_text(f) or "", "Options")
                if v:
                    return "tmp.mount", v.split(",")
        return "未設定", None

    def fix(self, ctx, fx):
        src, opts = self._persistent()
        if src == "未設定" and self.mount != "/dev/shm":
            if mount_options(self.mount) is None:
                raise ManualRequired(not_separate(self.mount))
            raise ManualRequired("%s 不是由 /etc/fstab 掛載（可能是 systemd 掛載單元），請人工在其掛載設定加入 %s"
                                 % (self.mount, self.option))
        MountOption.fix(self, ctx, fx)


def _sep(mount, n):
    r = SeparatePartition(mount, R(r8=n, r9=n))
    r.title = "設定%s 目錄之檔案系統" % mount
    return r


# ====================================================================
# 可攜式裝置、家目錄、NFS 掛載選項（0020–0028）
# ====================================================================

def removable_devs():
    """可攜式裝置（removable=1 或經由 USB 連接）及其分割區的核心名稱。"""
    out = set()
    for b in glob.glob("/sys/block/*"):
        name = os.path.basename(b)
        rm = (read_text(b + "/removable") or "").strip() == "1"
        usb = "/usb" in os.path.realpath(b)
        if rm or usb:
            out.add(name)
            out.update(os.path.basename(p) for p in glob.glob("%s/%s*" % (b, name)))
    return out


def dev_name(spec):
    """把 fstab 的裝置欄（/dev/xxx、UUID=、LABEL=、PARTUUID=、PARTLABEL=）轉成核心裝置名稱。"""
    m = re.match(r"^(UUID|LABEL|PARTUUID|PARTLABEL)=(.+)$", spec)
    if m:
        spec = "/dev/disk/by-%s/%s" % (m.group(1).lower(), m.group(2).strip('"'))
    if not spec.startswith("/dev/"):
        return None
    return os.path.basename(os.path.realpath(spec))


# [MountGroupOption] RHEL8 0020–0028 / RHEL9 0020–0028 可攜式儲存裝置、使用者家目錄、NFS 之 nodev/nosuid/noexec
class MountGroupOption(Rule):
    """kind：removable（可攜式裝置）/ home（UID>=UID_MIN 使用者家目錄所在、位於 /home 的掛載點）/ nfs（nfs、nfs4）。

    檢查 /etc/fstab 對應列與目前掛載是否都含選項；修復時修改 fstab 並即時 remount。
    """
    category = DISK
    risk = "B"
    NFS = ("nfs", "nfs4")

    def __init__(self, title, ids, kind, option):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.option = option
        self.expected = "啟用（掛載選項含 %s）" % option

    def _home_mounts(self):
        mounts = proc_mounts()
        mps = set()
        umin = uid_min()
        for p in pwd.getpwall():
            if p.pw_uid < umin or p.pw_name in ("nobody", "nfsnobody") or not os.path.isdir(p.pw_dir):
                continue
            m = mount_of(p.pw_dir, mounts)
            # 只處理 /home 與其下的掛載點：應用程式帳號的家目錄常在 /opt、/var、/srv 等系統掛載點，
            # 對整個掛載點加 noexec / nosuid 會讓其中的服務立即無法執行
            if m and (m[1] == "/home" or m[1].startswith("/home/")):
                mps.add(m[1])
        return mps

    def _pred(self):
        """回傳 (fstab 判斷式, 目前掛載判斷式)。"""
        if self.kind == "nfs":
            return (lambda dev, mp, fs: fs in self.NFS), (lambda dev, mp, fs: fs in self.NFS)
        if self.kind == "home":
            mps = self._home_mounts()
            return (lambda dev, mp, fs: mp in mps), (lambda dev, mp, fs: mp in mps)
        devs = removable_devs()
        return (lambda dev, mp, fs: dev_name(dev) in devs), \
            (lambda dev, mp, fs: dev.startswith("/dev/") and os.path.basename(os.path.realpath(dev)) in devs)

    def _targets(self):
        fpred, rpred = self._pred()
        fst = [(mp, opts) for i, dev, mp, fs, opts in fstab_entries() if fpred(dev, mp, fs)]
        last = {}
        for dev, mp, fs, opts in proc_mounts():
            last[mp] = (dev, fs, opts)
        rt = [(mp, v[2]) for mp, v in sorted(last.items()) if rpred(v[0], mp, v[1])]
        return fst, rt

    def when(self, ctx):
        fst, rt = self._targets()
        if fst or rt:
            return None
        return {"removable": "目前掛載與 /etc/fstab 中都沒有可攜式儲存裝置，沒有需要設定掛載選項的對象",
                "home": "使用者家目錄沒有獨立的 /home 掛載點，沒有需要設定掛載選項的對象"
                        "（其他系統掛載點不處理，避免影響服務）",
                "nfs": "目前掛載與 /etc/fstab 中都沒有 NFS 檔案系統，沒有需要設定掛載選項的對象"}[self.kind]

    def check(self, ctx):
        fst, rt = self._targets()
        bad_f = [mp for mp, opts in fst if self.option not in opts]
        bad_r = [mp for mp, opts in rt if self.option not in opts]
        cur = "fstab：%d 項%s；目前掛載：%d 項%s" % (
            len(fst), "（缺少 %s：%s）" % (self.option, "、".join(bad_f)) if bad_f else "",
            len(rt), "（缺少 %s：%s）" % (self.option, "、".join(bad_r)) if bad_r else "")
        return Check(FAIL if bad_f or bad_r else PASS, cur)

    def fix(self, ctx, fx):
        fpred, rpred = self._pred()
        fst, rt = self._targets()
        if any(self.option not in opts for mp, opts in fst):
            _reload_undo(fx)
            fx.edit_file("/etc/fstab", lambda t: fstab_add_option_lines(t, fpred, self.option))
            _verify_fstab(fx)
            _daemon_reload(fx)
        in_fstab = set(mp for mp, opts in fst)
        for mp, opts in rt:
            if self.option in opts:
                continue
            err = _remount(fx, mp, self.option)
            if err:
                fx.partial = True
                fx.note("%s 無法即時重新掛載（%s），fstab 已設定，重新掛載或重開機後生效" % (mp, err))
            elif mp not in in_fstab:
                fx.note("%s 未列於 /etc/fstab（自動掛載或 autofs），已即時加入 %s；下次掛載需在其掛載設定中加入"
                        % (mp, self.option))


# ====================================================================
# 粘滯位（0029）
# ====================================================================

STICKY_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "f2fs", "tmpfs", "devtmpfs", "overlay")


def sticky_roots():
    roots, devs = [], set()
    for dev, mp, fs, opts in sorted(proc_mounts(), key=lambda m: len(m[1])):
        if fs not in STICKY_FS or "ro" in opts or mp.startswith(("/proc", "/sys")):
            continue
        try:
            d = os.stat(mp).st_dev
        except OSError:
            continue
        if d not in devs and os.path.isdir(mp):
            devs.add(d)
            roots.append(mp)
    return roots


def sticky_missing():
    """回傳 (缺少粘滯位的全域可寫目錄, 錯誤訊息)。"""
    roots = sticky_roots()
    if not roots:
        return None, "找不到本機檔案系統"
    r = run(["find"] + roots + ["-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print0"],
            timeout=1200)
    if r.rc == 124:
        return None, "檔案系統掃描逾時，請於離峰時間人工執行"
    if r.rc == 127:
        return None, "找不到 find 指令"
    return [p for p in r.out.split("\0") if p], ""


# [StickyBit] RHEL8 0029 / RHEL9 0029 設定全域寫入權限目錄之粘滯位
class StickyBit(Rule):
    category = DISK
    title = "設定全域寫入權限目錄之粘滯位"
    expected = "設定粘滯位"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        items, err = sticky_missing()
        if items is None:
            return Check(ERROR, err)
        if not items:
            return Check(PASS, "全域可寫目錄皆已設定粘滯位")
        show = "、".join(items[:10]) + ("…等共 %d 個" % len(items) if len(items) > 10 else "")
        return Check(FAIL, "未設定粘滯位：%s" % show)

    def fix(self, ctx, fx):
        items, err = sticky_missing()
        if items is None:
            raise FixError(err)
        for p in items:
            if os.path.isdir(p) and not os.path.islink(p):
                fx.chmod(p, (os.stat(p).st_mode & 0o7777) | 0o1000)


# [AutofsDisabled] RHEL8 0030 / RHEL9 0030 autofs 服務
class AutofsDisabled(Rule):
    category = DISK
    title = "autofs 服務"
    expected = "停用（systemctl --now disable autofs）"
    risk = "B"
    UNIT = "autofs.service"

    def __init__(self, ids):
        self.ids = ids
        self.when = installed("autofs")

    def check(self, ctx):
        en, act = pkgsvc.svc_state(self.UNIT)
        bad = en in ("enabled", "enabled-runtime") or act in ("active", "activating")
        return Check(FAIL if bad else PASS, "%s / %s" % (en, act))

    def fix(self, ctx, fx):
        maps = [l.strip() for l in (read_text("/etc/auto.master") or "").splitlines()
                if _active(l) and not l.strip().startswith("+")]
        fx._record_service(self.UNIT)
        ctx.intended_stops.add(self.UNIT)
        fx.run(["systemctl", "--now", "disable", self.UNIT], "停用服務 %s" % self.UNIT)
        if maps:
            fx.note("/etc/auto.master 有自動掛載設定（%s），相關目錄將不再自動掛載" % "；".join(maps[:3]))


# ====================================================================
# GPG 簽章驗證（0032）
# ====================================================================

DNF_CONF = "/etc/dnf/dnf.conf"
YUM_CONF = "/etc/yum.conf"
MAIN_KEYS = ("gpgcheck", "localpkg_gpgcheck")
_INI_KV = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$")


def ini_items(text):
    """回傳 [(段落, key, value, 行號)]。"""
    out, sec = [], None
    for i, line in enumerate((text or "").splitlines()):
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            sec = m.group(1).strip()
            continue
        m = _INI_KV.match(line)
        if m:
            out.append((sec, m.group(1), m.group(2), i))
    return out


def ini_main_values(text):
    vals = {}
    for sec, k, v, i in ini_items(text):
        if sec == "main" and k in MAIN_KEYS:
            vals[k] = v
    return vals


def ini_set_main(text, want):
    """在 [main] 設定 key=value（取代既有行，沒有則加在 [main] 段落末）；沒有 [main] 時新增。"""
    lines = (text or "").splitlines()
    done = set()
    for sec, k, v, i in ini_items(text):
        if sec == "main" and k in want:
            lines[i] = "%s=%s" % (k, want[k])
            done.add(k)
    add = ["%s=%s" % (k, want[k]) for k in sorted(want) if k not in done]
    if add:
        start = None
        for i, l in enumerate(lines):
            if l.strip() == "[main]":
                start = i
        if start is None:
            lines = ["[main]"] + add + ([""] if lines else []) + lines
        else:
            end = start + 1
            while end < len(lines) and not lines[end].strip().startswith("["):
                end += 1
            while end > start + 1 and not lines[end - 1].strip():
                end -= 1
            lines[end:end] = add
    return "\n".join(lines) + "\n"


def repo_sections_without_key(text):
    """repo 檔中沒有設定 gpgkey 的段落（未簽章的內部套件庫，強制 gpgcheck=1 會使安裝失敗）。"""
    secs, keyed = [], set()
    for sec, k, v, i in ini_items(text):
        if sec not in secs:
            secs.append(sec)
        if k == "gpgkey" and v.strip():
            keyed.add(sec)
    return [x for x in secs if x not in keyed]


def ini_fix_gpgcheck(text, skip=()):
    """repo 檔中 gpgcheck 不是 1 的設定改為 1（skip 中的段落不改）。"""
    lines = (text or "").splitlines()
    for sec, k, v, i in ini_items(text):
        if k == "gpgcheck" and v != "1" and sec not in skip:
            lines[i] = "gpgcheck=1"
    return "\n".join(lines) + "\n" if lines else ""


def _main_confs():
    files = [DNF_CONF]
    if os.path.exists(YUM_CONF) and os.path.realpath(YUM_CONF) != os.path.realpath(DNF_CONF):
        files.append(YUM_CONF)
    return [f for f in files if os.path.exists(f)]


# [GpgCheck] RHEL8 0032 / RHEL9 0032 GPG 簽章驗證
class GpgCheck(Rule):
    category = CAT
    title = "GPG 簽章驗證"
    expected = "1（[main] gpgcheck=1、localpkg_gpgcheck=1；/etc/yum.repos.d 所有 gpgcheck=1）"

    def __init__(self, ids):
        self.ids = ids

    def _problems(self):
        bad = []
        confs = _main_confs()
        if not confs:
            bad.append("找不到 %s" % DNF_CONF)
        for f in confs:
            vals = ini_main_values(read_text(f) or "")
            for k in MAIN_KEYS:
                if vals.get(k) != "1":
                    bad.append("%s %s=%s" % (f, k, vals.get(k, "未設定")))
        for f in sorted(glob.glob("/etc/yum.repos.d/*.repo")):
            for sec, k, v, i in ini_items(read_text(f) or ""):
                if k == "gpgcheck" and v != "1":
                    bad.append("%s [%s] gpgcheck=%s" % (f, sec, v))
        return bad

    def check(self, ctx):
        bad = self._problems()
        if not bad:
            return Check(PASS, "gpgcheck、localpkg_gpgcheck 皆為 1，repo 檔無停用 gpgcheck")
        return Check(FAIL, "；".join(bad[:8]) + ("…等共 %d 項" % len(bad) if len(bad) > 8 else ""))

    def fix(self, ctx, fx):
        want = dict((k, "1") for k in MAIN_KEYS)
        for f in _main_confs() or [DNF_CONF]:
            fx.edit_file(f, lambda t: ini_set_main(t, want))
        skipped = []
        for f in sorted(glob.glob("/etc/yum.repos.d/*.repo")):
            text = read_text(f) or ""
            nokey = [sec for sec, k, v, i in ini_items(text)
                     if k == "gpgcheck" and v != "1" and sec in repo_sections_without_key(text)]
            skipped += ["%s [%s]" % (f, sec) for sec in nokey]
            fx.edit_file(f, lambda t, nk=tuple(nokey): ini_fix_gpgcheck(t, skip=nk))
        fx.note("localpkg_gpgcheck=1 會使安裝未簽章的本機 RPM 失敗")
        if skipped:
            fx.partial = True
            fx.note("以下套件庫沒有設定 gpgkey（可能是未簽章的內部鏡像站），改為 gpgcheck=1 會使安裝與更新失敗，"
                    "未自動修改，請確認後設定 gpgkey 或改用已簽章的套件庫：" + "、".join(skipped))


# ====================================================================
# AIDE（0036、0037）
# ====================================================================

AIDE_CONF = "/etc/aide.conf"


def aide_db_paths(text=None):
    """依 /etc/aide.conf 回傳 (資料庫, 新資料庫) 路徑。"""
    if text is None:
        text = read_text(AIDE_CONF) or ""
    defs = {"DBDIR": "/var/lib/aide"}
    db = new = None
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^@@define\s+(\w+)\s+(\S+)", s)
        if m:
            defs[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^(database|database_in|database_out)\s*=\s*(\S+)", s)
        if m:
            v = re.sub(r"@@\{(\w+)\}", lambda x: defs.get(x.group(1), ""), m.group(2))
            v = v[5:] if v.startswith("file:") else v
            if m.group(1) == "database_out":
                new = v
            else:
                db = v
    return db or "/var/lib/aide/aide.db.gz", new or "/var/lib/aide/aide.db.new.gz"


# [AidePackage] RHEL8 0036 / RHEL9 0036 AIDE 套件
class AidePackage(Rule):
    category = CAT
    title = "AIDE 套件"
    expected = "安裝（並以 aide --init 建立資料庫）"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "aide"):
            return Check(FAIL, "未安裝 aide")
        db, new = aide_db_paths()
        if not os.path.exists(db):
            return Check(FAIL, "已安裝，但尚未初始化（%s 不存在）" % db)
        return Check(PASS, "已安裝並已初始化（%s）" % db)

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "aide"):
            fx.pkg_install("aide")
        db, new = aide_db_paths()
        if os.path.exists(db):
            return
        rm = [p for p in (db, new) if not os.path.exists(p)]
        fx.add_undo(["rm", "-f"] + rm, "刪除 AIDE 資料庫")
        fx.run(["aide", "--init"], "初始化 AIDE 資料庫（掃描整個檔案系統）", timeout=7200, check=False)
        if not ctx.dry_run:
            if not os.path.exists(new):
                raise FixError("aide --init 未產生 %s" % new)
            fx.run(["cp", "-p", new, db], "複製 %s 為 %s" % (os.path.basename(new), os.path.basename(db)))
        fx.note("AIDE 資料庫記錄的是目前狀態；之後的系統修改會在檢查報告中列為變更，必要時以 aide --init 重新初始化")


def _cron_fields(line, has_user):
    """回傳 (是否至少每天執行, 指令)；非排程行回傳 None。"""
    s = line.strip()
    if not s or s.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
        return None
    if s.startswith("@"):
        p = s.split(None, 2 if has_user else 1)
        return p[0] in ("@daily", "@midnight", "@hourly"), p[-1] if len(p) > (2 if has_user else 1) else ""
    p = s.split(None, 6 if has_user else 5)
    if len(p) < (7 if has_user else 6):
        return None
    return p[2] == "*" and p[3] == "*" and p[4] == "*", p[-1]


def is_aide_check(cmd):
    return bool(re.search(r"(^|[\s/])aide(\s|$)", cmd)) and bool(re.search(r"(--check|\s-C(\s|$))", cmd))


def aide_schedules():
    found = []
    for line in (read_text("/var/spool/cron/root") or "").splitlines():
        r = _cron_fields(line, False)
        if r and r[0] and is_aide_check(r[1]):
            found.append("root crontab")
    for f in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
        if f.endswith(("~", ".rpmsave", ".rpmnew", ".rpmorig")) or os.path.basename(f).startswith("."):
            continue
        for line in (read_text(f) or "").splitlines():
            r = _cron_fields(line, True)
            if r and r[0] and is_aide_check(r[1]):
                found.append(f)
    for f in sorted(glob.glob("/etc/cron.daily/*")):
        if os.path.isfile(f) and os.access(f, os.X_OK) and \
                any(is_aide_check(l) for l in (read_text(f) or "").splitlines() if _active(l)):
            found.append(f)
    if which("systemctl") and run(["systemctl", "is-enabled", "aidecheck.timer"], timeout=15).out.strip() == "enabled":
        found.append("aidecheck.timer")
    return found


# [AideSchedule] RHEL8 0037 / RHEL9 0037 定期檢查檔案系統完整性
class AideSchedule(Rule):
    category = CAT
    title = "定期檢查檔案系統完整性"
    expected = "每天（0 5 * * * /usr/sbin/aide --check）"
    CRON = "/etc/cron.d/gcb-aide"
    LINE = "0 5 * * * root /usr/sbin/aide --check"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if not which("aide"):
            return Check(FAIL, "未安裝 AIDE")
        found = aide_schedules()
        if not found:
            return Check(FAIL, "未設定每日 AIDE 檢查排程")
        if found != ["aidecheck.timer"]:
            if not which("crond"):
                return Check(FAIL, "已設定排程（%s），但未安裝 cronie，排程不會執行" % "、".join(found))
            en, act = pkgsvc.svc_state("crond.service")
            if en != "enabled" or act != "active":
                return Check(FAIL, "已設定排程（%s），但 crond 服務未啟用（%s / %s），排程不會執行"
                             % ("、".join(found), en, act))
        return Check(PASS, "已設定：" + "、".join(found))

    def fix(self, ctx, fx):
        if not which("aide"):
            raise ManualRequired("尚未安裝 AIDE，請先完成「AIDE 套件」項目（0036，需 --include-risky）")
        if not which("crond"):
            fx.pkg_install("cronie")
        if not aide_schedules():
            # 文件使用 root crontab；改寫入 /etc/cron.d 獨立檔案，效果相同且易於回滾
            fx.write_file(self.CRON, "# %s (gcb-checker)\n%s\n" % (self.rule_id(ctx.osi), self.LINE), mode=0o644)
        en, act = pkgsvc.svc_state("crond.service")
        if en != "enabled" or act != "active":
            fx.service_enable("crond.service")


# ====================================================================
# 開機載入程式（0038–0040）
# ====================================================================

GRUB2_DIR = "/boot/grub2"
GRUB_NAMES = ("grub.cfg", "grubenv", "user.cfg")


def grub_files():
    """回傳 (一般檔案, 位於 vfat 的 EFI 檔案)。

    RHEL 9 的實際 grub.cfg 在 /boot/grub2（/boot/efi/EFI/<vendor>/grub.cfg 只是轉接檔）；
    RHEL 8 UEFI 的 grub.cfg、grubenv、user.cfg 在 /boot/efi/EFI/<vendor>/。
    """
    paths = [os.path.join(GRUB2_DIR, n) for n in GRUB_NAMES]
    for n in GRUB_NAMES:
        paths += sorted(glob.glob("/boot/efi/EFI/*/%s" % n))
    mounts = proc_mounts()
    normal, efi = [], []
    for p in paths:
        if not os.path.exists(p) or os.path.islink(p):
            continue
        m = mount_of(p, mounts)
        (efi if m and m[2] in ("vfat", "msdos") else normal).append(p)
    return normal, efi


def no_grub(ctx):
    if os.path.exists(os.path.join(GRUB2_DIR, "grub.cfg")) or glob.glob("/boot/efi/EFI/*/grub.cfg"):
        return None
    return "未使用 GRUB 開機載入程式（找不到 grub.cfg），本項目是 GRUB 設定，不需設定"


GRUB_NOTE = "grub2-mkconfig 重新產生 grub.cfg 後權限可能改變，之後需重新檢測"


# [GrubCfgPerm] RHEL8 0038、0039 / RHEL9 0038、0039 開機載入程式設定檔之所有權、權限
class GrubCfgPerm(Rule):
    category = CAT

    def __init__(self, title, ids, kind, risk):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.risk = risk
        self.expected = "root:root" if kind == "owner" else "600 或更低權限"
        self.when = no_grub

    def _perm(self, files):
        if self.kind == "owner":
            return FilePerm(self.title, CAT, self.ids, files, owner="root", groups=["root"], missing="pass")
        return FilePerm(self.title, CAT, self.ids, files, max_mode=0o600, missing="pass")

    def check(self, ctx):
        normal, efi_files = grub_files()
        c = self._perm(normal).check(ctx) if normal else Check(PASS, "")
        cur = [c.current] if normal else []
        ok = c.status == PASS
        efi = efi_status(self.kind)
        if efi is not None:
            fs_ok, rt_ok, desc = efi
            ok = ok and fs_ok
            cur.append("%s%s%s" % (desc, "（fstab 不符合）" if not fs_ok else "",
                                   "（fstab 已設定，需重開機生效）" if fs_ok and not rt_ok else ""))
        elif efi_files:
            cur.append("EFI 檔案：%s" % self._perm(efi_files).check(ctx).current)
        return Check(PASS if ok else FAIL, "；".join(cur) or "無檔案")

    def fix(self, ctx, fx):
        normal, efi_files = grub_files()
        if normal:
            self._perm(normal).fix(ctx, fx)
            if self.kind == "mode":
                fx.note(GRUB_NOTE)
        efi = efi_status(self.kind)
        if efi is None or efi[0]:
            return
        if not ctx.include_risky:
            fx.partial = True
            fx.note("UEFI /boot/efi 掛載選項需修改 /etc/fstab（重開機生效），屬風險項目；確認後可加 --include-risky")
            return
        kv = {"uid": "0", "gid": "0"} if self.kind == "owner" else {"fmask": "0177"}
        _reload_undo(fx)
        fx.edit_file("/etc/fstab", lambda t: fstab_set_opts(t, "/boot/efi", kv))
        _verify_fstab(fx)
        _daemon_reload(fx)
        fx.note("已修改 /etc/fstab 的 /boot/efi 掛載選項（%s），重開機後生效"
                % ",".join("%s=%s" % x for x in sorted(kv.items())))


def grub_main_cfg(ctx):
    """實際使用的 grub.cfg：RHEL 8 UEFI 為 /boot/efi/EFI/<vendor>/grub.cfg，其餘為 /boot/grub2/grub.cfg。"""
    efi = sorted(glob.glob("/boot/efi/EFI/*/grub.cfg"))
    if ctx.osi.key == "rhel8" and os.path.isdir("/sys/firmware/efi") and efi:
        return efi[0]
    p = os.path.join(GRUB2_DIR, "grub.cfg")
    return p if os.path.exists(p) else (efi[0] if efi else p)


def grub_password_status(user_cfgs, grub_cfg_text):
    """回傳 (合格, 說明)。user_cfgs：[(路徑, 內容)]。"""
    hashed = [p for p, t in user_cfgs
              if re.search(r"^\s*GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.\S+", t or "", re.M)]
    text = grub_cfg_text or ""
    uses_user_cfg = bool(re.search(r"password_pbkdf2\s+\S+\s+\$\{?GRUB2_PASSWORD", text))
    direct = bool(re.search(r"^\s*set\s+superusers=", text, re.M)) and \
        bool(re.search(r"^\s*password_pbkdf2\s+\S+\s+grub\.pbkdf2\.sha512\.\S+", text, re.M))
    if hashed and uses_user_cfg:
        return True, "已以 grub2-setpassword 設定（%s）" % "、".join(hashed)
    if direct:
        return True, "grub.cfg 已設定 superusers 與 password_pbkdf2"
    if hashed:
        return False, "%s 已有通行碼雜湊，但 grub.cfg 未引用（需執行 grub2-mkconfig）" % "、".join(hashed)
    return False, "未設定開機載入程式通行碼"


# [GrubPassword] RHEL8 0040 / RHEL9 0040 開機載入程式之密碼（通行碼）（C 類）
class GrubPassword(Rule):
    category = CAT
    risk = "C"
    manual_hint = ("執行 grub2-setpassword 設定通行碼（寫入 user.cfg）；RHEL 8/9 的 grub.cfg 已透過 01_users 讀取，"
                   "若 grub.cfg 未含 GRUB2_PASSWORD 再執行 grub2-mkconfig -o <實際 grub.cfg 路徑>。"
                   "請妥善保管通行碼，遺失時需以救援媒體開機才能修改開機參數")

    def __init__(self, title, ids, expected):
        self.title = title
        self.ids = ids
        self.expected = expected
        self.when = no_grub

    def check(self, ctx):
        cfg = grub_main_cfg(ctx)
        text = read_text(cfg)
        if text is None:
            return Check(ERROR, "無法讀取 %s" % cfg)
        users = [os.path.join(GRUB2_DIR, "user.cfg")] + sorted(glob.glob("/boot/efi/EFI/*/user.cfg"))
        ok, cur = grub_password_status([(p, read_text(p)) for p in users if os.path.exists(p)], text)
        return Check(PASS if ok else FAIL, cur)


# ====================================================================
# 單一使用者模式、核心傾印、ASLR、加密原則（0041–0044）
# ====================================================================

UNIT_DIRS = ["/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"]
SULOGIN = {"rescue.service": "-/usr/lib/systemd/systemd-sulogin-shell rescue",
           "emergency.service": "-/usr/lib/systemd/systemd-sulogin-shell emergency"}


def unit_files(unit, dirs=None):
    """systemd 讀取 unit 的檔案順序：主檔（/etc > /run > /usr/lib）+ drop-in（同名以 /etc 優先，依檔名排序）。"""
    dirs = dirs or UNIT_DIRS
    main = None
    for d in dirs:
        p = os.path.join(d, unit)
        if os.path.exists(p):
            main = p
            break
    if main is None:
        return []
    chosen = {}
    for d in reversed(dirs):
        for f in glob.glob(os.path.join(d, unit + ".d", "*.conf")):
            chosen[os.path.basename(f)] = f
    return [main] + [chosen[b] for b in sorted(chosen)]


def unit_exec_start(texts):
    """回傳 (最終 ExecStart 清單, 是否設定 SYSTEMD_SULOGIN_FORCE)。"""
    execs, force = [], False
    for text in texts:
        sec = None
        for line in (text or "").splitlines():
            s = line.strip()
            if not s or s[0] in "#;":
                continue
            if s.startswith("["):
                sec = s
                continue
            if sec != "[Service]":
                continue
            if s.startswith("ExecStart="):
                v = s[len("ExecStart="):].strip()
                execs = [] if not v else execs + [v]
            elif s.startswith("Environment") and "SYSTEMD_SULOGIN_FORCE" in s:
                force = True
    return execs, force


def _sulogin_ok(execs):
    return bool(execs) and bool(re.search(r"(systemd-sulogin-shell|/sulogin)(\s|$|;|\")", execs[-1]))


# [SingleUserAuth] RHEL8 0041 / RHEL9 0041 單一使用者模式身分驗證（鑑別）
class SingleUserAuth(Rule):
    category = CAT
    expected = "啟用（rescue/emergency.service 以 systemd-sulogin-shell 啟動）"
    risk = "B"

    def __init__(self, title, ids):
        self.title = title
        self.ids = ids

    def when(self, ctx):
        return None if unit_files("rescue.service") else "未使用 systemd（找不到 rescue.service），本項目是 systemd 救援模式設定，不需設定"

    def _status(self):
        out = {}
        for unit in SULOGIN:
            files = unit_files(unit)
            execs, force = unit_exec_start([read_text(f) for f in files])
            out[unit] = (execs, force, files)
        return out

    def check(self, ctx):
        cur, ok = [], True
        for unit, (execs, force, files) in sorted(self._status().items()):
            good = _sulogin_ok(execs) and not force
            ok = ok and good
            cur.append("%s ExecStart=%s%s" % (unit, execs[-1] if execs else "未設定",
                                              "（設定 SYSTEMD_SULOGIN_FORCE，會略過鑑別）" if force else ""))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        st = self._status()
        forced = [u for u, v in st.items() if v[1]]
        if forced:
            raise ManualRequired("%s 設定了 SYSTEMD_SULOGIN_FORCE，請人工確認後移除" % "、".join(forced))
        # 不修改 /usr/lib 下的套件檔（升級會被覆蓋），改用 drop-in
        _reload_undo(fx)
        changed = False
        for unit, (execs, force, files) in sorted(st.items()):
            if _sulogin_ok(execs):
                continue
            fx.write_file("/etc/systemd/system/%s.d/60-gcb.conf" % unit,
                          "[Service]\nExecStart=\nExecStart=%s\n" % SULOGIN[unit])
            changed = True
        if changed:
            _daemon_reload(fx)
        fx.note("root 帳號被鎖定或未設定通行碼時，sulogin 會拒絕進入救援模式")


LIMITS_OWN = "/etc/security/limits.d/60-gcb-coredump.conf"
COREDUMP_OWN = "/etc/systemd/coredump.conf.d/60-gcb.conf"
CORE_SYSCTL = [("fs.suid_dumpable", "0"), ("kernel.core_pattern", "|/bin/false")]


def _has_coredump():
    return any(os.path.exists(p) for p in ("/usr/lib/systemd/systemd-coredump",
                                          "/usr/lib/systemd/system/systemd-coredump.socket"))


def _limits_comment(text):
    out = []
    for line in (text or "").splitlines():
        p = line.split("#", 1)[0].split()
        if len(p) >= 4 and p[0] == "*" and p[1] in ("hard", "-") and p[2] == "core" and p[3] != "0":
            line = te.MARK + line
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


# [CoreDump] RHEL8 0042 / RHEL9 0042 核心傾印功能
class CoreDump(Rule):
    category = CAT
    title = "核心傾印功能"
    expected = ("停用（* hard core 0、fs.suid_dumpable=0、kernel.core_pattern=|/bin/false；"
                "有 systemd-coredump 時 Storage=none、ProcessSizeMax=0 並遮蔽 systemd-coredump.socket）")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        cur, ok = [], True
        good, bad = limits_core([(f, read_text(f)) for f in limits_files()])
        ok = good and not bad
        cur.append("limits * hard core 0：%s%s" % ("有" if good else "無", "；衝突：" + "、".join(bad) if bad else ""))
        for key, want in CORE_SYSCTL:
            s_ok, s_cur = sysctl_state(key, want)
            ok = ok and s_ok is not False
            cur.append(s_cur)
        if _has_coredump():
            v = coredump_values()
            en = pkgsvc.svc_state("systemd-coredump.socket")[0]
            ok = ok and v.get("Storage", "").lower() == "none" and v.get("ProcessSizeMax") == "0" and en == "masked"
            cur.append("coredump Storage=%s ProcessSizeMax=%s socket=%s" % (
                v.get("Storage", "未設定"), v.get("ProcessSizeMax", "未設定"), en))
        if pkgsvc.svc_state("abrtd.service")[1] == "active":
            cur.append("abrtd 執行中（abrt-ccpp 會改寫 kernel.core_pattern）")
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        coredump = _has_coredump()
        if coredump:
            _reload_undo(fx)
        for f in limits_files():
            if f != LIMITS_OWN and limits_core([(f, read_text(f))])[1]:
                fx.edit_file(f, _limits_comment)
        fx.write_file(LIMITS_OWN, "# %s (gcb-checker)\n* hard core 0\n" % self.rule_id(ctx.osi))
        if coredump:
            fx.write_file(COREDUMP_OWN, "[Coredump]\nStorage=none\nProcessSizeMax=0\n")
            _daemon_reload(fx)
            if pkgsvc.svc_state("systemd-coredump.socket")[0] != "masked":
                fx.service_mask("systemd-coredump.socket")
        for key, want in CORE_SYSCTL:
            sysctl_fix(fx, key, want)
        fx.note("limits 設定對新登入的工作階段生效")
        if pkgsvc.svc_state("abrtd.service")[1] == "active":
            fx.note("abrtd 執行中，abrt-ccpp 啟動時會改寫 kernel.core_pattern，請評估是否停用 abrt")


CRYPTO_CONFIG = "/etc/crypto-policies/config"
CRYPTO_ALLOWED = ("FUTURE", "FIPS")


def crypto_policy():
    """回傳設定的全系統加密原則（例：DEFAULT、FUTURE:AD-SUPPORT）；無法取得回傳 None。"""
    if which("update-crypto-policies"):
        r = run(["update-crypto-policies", "--show"], timeout=30)
        if r.ok and r.out.strip():
            return r.out.strip().splitlines()[-1].strip()
    for line in (read_text(CRYPTO_CONFIG) or "").splitlines():
        s = line.split("#", 1)[0].strip()
        if s:
            return s
    return None


def rsa_bits(b64):
    """ssh-rsa 公鑰（base64）的位元數；格式錯誤回傳 None。"""
    try:
        data = base64.b64decode(b64)
        parts, i = [], 0
        while i < len(data) and len(parts) < 3:
            n = struct.unpack(">I", data[i:i + 4])[0]
            parts.append(data[i + 4:i + 4 + n])
            i += 4 + n
        if len(parts) < 3 or parts[0] != b"ssh-rsa":
            return None
        mod = parts[2].lstrip(b"\x00")
        return len(mod) * 8 - (8 - mod[0].bit_length()) if mod else 0
    except Exception:
        return None


def short_rsa_keys(paths, minimum=3072):
    """回傳 [(檔案, 位元數)]：小於 minimum 位元的 ssh-rsa 公鑰。"""
    out = []
    for p in paths:
        for line in (read_text(p) or "").splitlines():
            if not _active(line):
                continue
            toks = line.split()
            for i, t in enumerate(toks[:-1]):
                if t == "ssh-rsa":
                    bits = rsa_bits(toks[i + 1])
                    if bits and bits < minimum:
                        out.append((p, bits))
                    break
    return out


def _sshd_conf():
    sshd = which("sshd")
    r = run([sshd, "-T"], timeout=30) if sshd else None
    return te.parse_sshd_T(r.out) if r is not None and r.ok else {}


def _ssh_key_files():
    """主機 RSA 公鑰與所有帳號的授權金鑰檔（依 sshd 實際的 AuthorizedKeysFile 設定）。"""
    files = glob.glob("/etc/ssh/ssh_host_rsa_key.pub")
    pats = (_sshd_conf().get("authorizedkeysfile") or [""])[0].split() or [".ssh/authorized_keys", ".ssh/authorized_keys2"]
    users = [("root", "/root")] + [(p.pw_name, p.pw_dir) for p in pwd.getpwall()]
    for name, home in users:
        for pat in pats:
            path = pat.replace("%h", home).replace("%u", name).replace("%%", "%")
            files.append(path if path.startswith("/") else os.path.join(home, path))
    return sorted(set(f for f in files if os.path.isfile(f)))


def _external_auth():
    """偵測無法事先檢查金鑰長度的驗證來源（網域帳號、外部金鑰指令）。"""
    found = []
    cmd = (_sshd_conf().get("authorizedkeyscommand") or ["none"])[0]
    if cmd and cmd != "none":
        found.append("sshd 以 AuthorizedKeysCommand 取得金鑰（%s）" % cmd)
    if pkgsvc.svc_state("sssd.service")[1] == "active":
        found.append("sssd 執行中（可能有 AD / LDAP / IPA 網域帳號）")
    if os.path.exists("/etc/krb5.keytab"):
        found.append("主機已加入 Kerberos 網域（/etc/krb5.keytab）")
    return found


# [CryptoPolicy] RHEL8 0044 / RHEL9 0044 設定全系統加密原則
class CryptoPolicy(Rule):
    category = CAT
    title = "設定全系統加密原則"
    expected = "FUTURE 或 FIPS"
    risk = "B"
    needs_reboot = True
    run_last = True  # FUTURE 會拒絕 2048 位元憑證，可能讓套件庫連不上，所以排在其他修復之後

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _repo_ok():
        """套件庫是否可連線（dnf 下載中繼資料）。"""
        r = run(["dnf", "-q", "makecache", "--refresh"], timeout=180)
        return r.ok, r.text()[-300:]

    def check(self, ctx):
        pol = crypto_policy()
        if pol is None:
            return Check(ERROR, "無法取得全系統加密原則（找不到 update-crypto-policies 與 %s）" % CRYPTO_CONFIG)
        base = pol.split(":")[0].upper()
        cur = "目前原則：%s" % pol
        if base not in CRYPTO_ALLOWED:
            return Check(FAIL, cur)
        if base == "FIPS" and (read_text("/proc/sys/crypto/fips_enabled") or "").strip() != "1":
            return Check(FAIL, cur + "；核心未啟用 FIPS 模式（fips-mode-setup --enable 並重開機）")
        applied = (read_text("/etc/crypto-policies/state/current") or "").strip()
        if applied and applied != pol:
            cur += "（目前套用 %s，需重開機或重新啟動服務生效）" % applied
        return Check(PASS, cur)

    def precondition(self, ctx):
        ext = _external_auth()
        if ext:
            return ("偵測到無法事先檢查金鑰與憑證長度的驗證來源：%s；改為 FUTURE 可能使這些帳號無法登入，"
                    "請人工評估" % "；".join(ext))
        short = short_rsa_keys(_ssh_key_files())
        if short:
            return ("FUTURE 原則要求 RSA 金鑰至少 3072 位元，以下 SSH 金鑰會無法使用（可能無法登入）：%s；"
                    "請先更換金鑰後再處理" % "、".join("%s（%d 位元）" % x for x in short[:5]))
        return None

    def fix(self, ctx, fx):
        old = crypto_policy()
        if old is None or not which("update-crypto-policies"):
            raise ManualRequired("找不到 update-crypto-policies（crypto-policies-scripts 套件），請人工設定")
        # 保留子原則（例：SSH 規則使用的 :GCB-SSH），只把主要原則改為 FUTURE
        new = ":".join(["FUTURE"] + old.split(":")[1:])
        repo_before = self._repo_ok()[0] if not ctx.dry_run else False
        # 回滾依相反順序：先還原原則，最後重新啟動 sshd 套用原本的原則（所以重新啟動要最先登記）
        sshd_active = pkgsvc.svc_state("sshd.service")[1] == "active"
        if sshd_active:
            fx.add_undo(["systemctl", "restart", "sshd"], "重新啟動 SSH 服務（套用原本的加密原則）")
        fx.backup_only(CRYPTO_CONFIG)
        fx.add_undo(["update-crypto-policies", "--set", old], "還原全系統加密原則 %s" % old)
        fx.run(["update-crypto-policies", "--set", new], "設定全系統加密原則 %s（原 %s）" % (new, old), timeout=300)
        # 重新啟動 sshd 讓新原則立即生效（RHEL 8 只在啟動時讀取 $CRYPTO_POLICY），後測的 SSH 登入才測得到影響；
        # 已建立的連線不受影響
        if sshd_active:
            fx.run(["systemctl", "restart", "sshd"], "重新啟動 SSH 服務以套用新原則", check=False)
        if repo_before:
            ok, out = self._repo_ok()
            fx.step("確認套件庫連線", "dnf makecache：%s" % ("正常" if ok else "失敗 " + out), "成功" if ok else "失敗")
            if not ok:
                raise FixError("套用 %s 後無法連線套件庫（伺服器憑證金鑰長度不足 3072 位元），已還原原本的加密原則；"
                               "請確認套件庫（或內部鏡像站）憑證符合 FUTURE 原則後再處理：%s" % (new, out))
        fx.note("FUTURE 原則要求 RSA/DH 金鑰至少 3072 位元並停用 SHA-1：2048 位元的 TLS 憑證、SSH 金鑰及"
                "不支援的對外連線（含 AD/Kerberos）將失敗；需重開機（或重新啟動使用加密的服務）生效")


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

def _mod(module, r8, r9, title, risk="A", usage=None, block=None, loaded_as=()):
    return RhelModule(module, R(r8=r8, r9=r9), title, risk=risk, usage=usage, block=block, loaded_as=loaded_as)


def _mopt(mount, option, n):
    return RhelMountOption(mount, option, R(r8=n, r9=n), "設定%s 目錄之 %s 選項" % (mount, option))


def _fs(module, n, title=None, risk="A", fstypes=None, units=(), block=None, loaded_as=(), refcount=True,
        devnode=None, pkgs=()):
    usage = module_usage(module, fstypes=fstypes if fstypes is not None else (module,), units=units,
                         refcount=refcount, devnode=devnode, pkgs=pkgs)
    return _mod(module, None, n, title or "%s 檔案系統" % module, risk=risk, usage=usage, block=block,
                loaded_as=loaded_as)


RULES = [
    # RHEL8 0001 / RHEL9 0001 cramfs 檔案系統 → common.py
    # RHEL8 0002 / RHEL9 0002 squashfs 檔案系統（有 squashfs 掛載時略過）
    _mod("squashfs", 2, 2, "squashfs 檔案系統", usage=module_usage("squashfs", fstypes=("squashfs",))),
    # RHEL8 0003 / RHEL9 0003 udf 檔案系統（Azure 上略過）
    _mod("udf", 3, 3, "udf 檔案系統", usage=azure_udf),
    # RHEL8 0004 / RHEL9 0004 設定/tmp 目錄之檔案系統
    TmpTmpfs(R(r8=4, r9=4)),
    # RHEL8 0005–0007 / RHEL9 0005–0007 /tmp 之 nodev、nosuid、noexec 選項
    _mopt("/tmp", "nodev", 5),
    _mopt("/tmp", "nosuid", 6),
    _mopt("/tmp", "noexec", 7),
    # RHEL8 0008 / RHEL9 0008 設定/var 目錄之檔案系統 → common.py
    # RHEL8 0009 / RHEL9 0009 設定/var/tmp 目錄之檔案系統
    _sep("/var/tmp", 9),
    # RHEL8 0010–0012 / RHEL9 0010–0012 /var/tmp 之 nodev、nosuid、noexec 選項
    _mopt("/var/tmp", "nodev", 10),
    _mopt("/var/tmp", "nosuid", 11),
    _mopt("/var/tmp", "noexec", 12),
    # RHEL8 0013 / RHEL9 0013 設定/var/log 目錄之檔案系統
    _sep("/var/log", 13),
    # RHEL8 0014 / RHEL9 0014 設定/var/log/audit 目錄之檔案系統
    _sep("/var/log/audit", 14),
    # RHEL8 0015 / RHEL9 0015 設定/home 目錄之檔案系統
    _sep("/home", 15),
    # RHEL8 0016 / RHEL9 0016 /home 之 nodev 選項
    _mopt("/home", "nodev", 16),
    # RHEL8 0017–0019 / RHEL9 0017–0019 /dev/shm 之 nodev、nosuid、noexec 選項
    _mopt("/dev/shm", "nodev", 17),
    _mopt("/dev/shm", "nosuid", 18),
    _mopt("/dev/shm", "noexec", 19),
    # RHEL8 0020–0022 / RHEL9 0020–0022 可攜式儲存裝置之 nodev、nosuid、noexec 選項
    MountGroupOption("設定可攜式儲存裝置之 nodev 選項", R(r8=20, r9=20), "removable", "nodev"),
    MountGroupOption("設定可攜式儲存裝置之 nosuid 選項", R(r8=21, r9=21), "removable", "nosuid"),
    MountGroupOption("設定可攜式儲存裝置之 noexec 選項", R(r8=22, r9=22), "removable", "noexec"),
    # RHEL8 0023–0025 / RHEL9 0023–0025 使用者家目錄之 nodev、nosuid、noexec 選項
    MountGroupOption("設定使用者家目錄之 nodev 選項", R(r8=23, r9=23), "home", "nodev"),
    MountGroupOption("設定使用者家目錄之 nosuid 選項", R(r8=24, r9=24), "home", "nosuid"),
    MountGroupOption("設定使用者家目錄之 noexec 選項", R(r8=25, r9=25), "home", "noexec"),
    # RHEL8 0026–0028 / RHEL9 0026–0028 NFS 檔案系統之 nodev、nosuid、noexec 選項
    MountGroupOption("設定 NFS 檔案系統之 nodev 選項", R(r8=26, r9=26), "nfs", "nodev"),
    MountGroupOption("設定 NFS 檔案系統之 nosuid 選項", R(r8=27, r9=27), "nfs", "nosuid"),
    MountGroupOption("設定 NFS 檔案系統之 noexec 選項", R(r8=28, r9=28), "nfs", "noexec"),
    # RHEL8 0029 / RHEL9 0029 設定全域寫入權限目錄之粘滯位
    StickyBit(R(r8=29, r9=29)),
    # RHEL8 0030 / RHEL9 0030 autofs 服務
    AutofsDisabled(R(r8=30, r9=30)),
    # RHEL8 0031 / RHEL9 0031 USB 儲存裝置（使用中時略過）
    _mod("usb-storage", 31, 31, "USB 儲存裝置", usage=module_usage("usb-storage")),
    # RHEL8 0032 / RHEL9 0032 GPG 簽章驗證
    GpgCheck(R(r8=32, r9=32)),
    # RHEL8 0033 / RHEL9 0033 sudo 套件
    PackagePresent("sudo 套件", "sudo", R(r8=33, r9=33), CAT),
    # RHEL8 0034 / RHEL9 0034 設定 sudo 指令使用 pty
    SudoDefault("設定 sudo 指令使用 pty", R(r8=34, r9=34), "flag", "use_pty", "Defaults use_pty",
                "Defaults use_pty"),
    # RHEL8 0035 / RHEL9 0035 sudo 自定義日誌檔案
    SudoDefault("sudo 自定義日誌檔案", R(r8=35, r9=35), "logfile", "logfile",
                'Defaults logfile="/var/log/sudo.log"', '啟用（例：Defaults logfile="/var/log/sudo.log"）'),
    # RHEL8 0036 / RHEL9 0036 AIDE 套件
    AidePackage(R(r8=36, r9=36)),
    # RHEL8 0037 / RHEL9 0037 定期檢查檔案系統完整性
    AideSchedule(R(r8=37, r9=37)),
    # RHEL8 0038 / RHEL9 0038 開機載入程式設定檔之所有權
    GrubCfgPerm("開機載入程式設定檔之所有權", R(r8=38, r9=38), "owner", "A"),
    # RHEL8 0039 / RHEL9 0039 開機載入程式設定檔之權限
    GrubCfgPerm("開機載入程式設定檔之權限", R(r8=39, r9=39), "mode", "B"),
    # RHEL8 0040 開機載入程式之密碼（C 類）
    GrubPassword("開機載入程式之密碼", R(r8=40), "設定密碼"),
    # RHEL9 0040 開機載入程式之通行碼（C 類）
    GrubPassword("開機載入程式之通行碼", R(r9=40), "設定通行碼"),
    # RHEL8 0041 單一使用者模式身分驗證
    SingleUserAuth("單一使用者模式身分驗證", R(r8=41)),
    # RHEL9 0041 單一使用者模式身分鑑別
    SingleUserAuth("單一使用者模式身分鑑別", R(r9=41)),
    # RHEL8 0042 / RHEL9 0042 核心傾印功能
    CoreDump(R(r8=42, r9=42)),
    # RHEL8 0043 / RHEL9 0043 記憶體位址空間配置隨機載入
    SysctlValue("記憶體位址空間配置隨機載入", R(r8=43, r9=43), "kernel.randomize_va_space", "2"),
    # RHEL8 0044 / RHEL9 0044 設定全系統加密原則（B 類）
    CryptoPolicy(R(r8=44, r9=44)),
    # RHEL8 0045 / RHEL9 0045 /etc/passwd 檔案所有權 → common.py
    # RHEL8 0046 / RHEL9 0046 /etc/passwd 檔案權限 → common.py
    # RHEL8 0047 / RHEL9 0047 /etc/shadow 檔案所有權 → common.py

    # RHEL9 0285 freevxfs 檔案系統
    _fs("freevxfs", 285, fstypes=("vxfs",)),
    # RHEL9 0286 hfs 檔案系統
    _fs("hfs", 286),
    # RHEL9 0287 hfs plus 檔案系統
    _fs("hfsplus", 287, "hfs plus 檔案系統"),
    # RHEL9 0288 jffs2 檔案系統
    _fs("jffs2", 288),
    # RHEL9 0289 afs 檔案系統（Linux 的 AFS 用戶端模組為 kafs）
    _fs("afs", 289, loaded_as=("kafs",)),
    # RHEL9 0290 ceph 檔案系統（B 類，使用中時略過）
    _fs("ceph", 290, risk="B"),
    # RHEL9 0291 cifs 檔案系統（B 類，使用中時略過）
    _fs("cifs", 291, risk="B", fstypes=("cifs", "smb3"), pkgs=("cifs-utils",)),
    # RHEL9 0292 exfat 檔案系統
    _fs("exfat", 292),
    # RHEL9 0293 ext 檔案系統（只處理名為 ext 的模組，絕不延伸到 ext4）
    _fs("ext", 293, fstypes=()),
    # RHEL9 0294 fat 檔案系統（B 類；UEFI 開機或 vfat 使用中時一律略過）
    _fs("fat", 294, risk="B", fstypes=("vfat", "msdos", "fat"), block=fat_block),
    # RHEL9 0295 fscache 檔案系統（B 類；NFS 相依，使用中時略過）
    _fs("fscache", 295, risk="B", fstypes=("nfs", "nfs4"), units=("cachefilesd.service",), pkgs=("nfs-utils",)),
    # RHEL9 0296 fuse 檔案系統（B 類；fusectl 掛載會占用參照數，改以 fuse 掛載與 /dev/fuse 判斷）
    _fs("fuse", 296, risk="B", fstypes=("fuse", "fuseblk"), refcount=False, devnode="/dev/fuse"),
    # RHEL9 0297 gfs2 檔案系統（B 類，使用中時略過）
    _fs("gfs2", 297, risk="B", units=("pacemaker.service",)),
    # RHEL9 0298 nfs_common 檔案系統（RHEL 無此模組，照文件寫入設定）
    _fs("nfs_common", 298, fstypes=()),
    # RHEL9 0299 nfsd 檔案系統（B 類；NFS 伺服器執行中時略過）
    _fs("nfsd", 299, risk="B", units=("nfs-server.service",)),
    # RHEL9 0300 smbfs_common 檔案系統（B 類；cifs 相依，使用中時略過）
    _fs("smbfs_common", 300, risk="B", fstypes=("cifs", "smb3"), pkgs=("cifs-utils",)),
]
