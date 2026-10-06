# -*- coding: utf-8 -*-
"""跨作業系統共用的規則（RHEL 8 / 9、Ubuntu 22.04）。

每條規則：
  ids       各 OS 對應的 TWGCB-ID（沒有該 OS 代表不適用）
  risk      A=自動修復  B=有風險，需 --include-risky  C=僅檢測，需人工
  check()   回傳 Check
  fix()     透過 Fx 執行修復（所有動作自動寫 log 與回滾紀錄）
"""
import glob
import grp
import os
import pwd
import re
import time

from .. import pkgsvc
from .. import textedit as te
from ..fixer import FixError, ManualRequired
from ..util import read_text, run, which
from .base import ERROR, FAIL, NA, PASS, Check, Rule

# ====================================================================
# 磁碟與檔案系統
# ====================================================================

def module_loaded(module):
    """模組是否已載入：以名稱完全比對（ext 不可誤配 ext4、fat 不可誤配 vfat）；- 與 _ 視為相同。"""
    want = module.replace("-", "_")
    for line in (read_text("/proc/modules") or "").splitlines():
        if line and line.split()[0].replace("-", "_") == want:
            return True
    return False


def modprobe_files():
    """modprobe 設定檔：/etc、/run、/usr/lib、/lib 的 modprobe.d（同檔名以前者優先）。"""
    chosen = {}
    for d in ("/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"):
        for f in sorted(glob.glob(os.path.join(d, "*.conf"))):
            chosen.setdefault(os.path.basename(f), f)
    real, out = set(), []
    for b in sorted(chosen):
        rp = os.path.realpath(chosen[b])
        if rp not in real:
            real.add(rp)
            out.append(chosen[b])
    return out


# [ModuleDisabled] 停用核心模組。用於：cramfs 檔案系統（008-0001、012-0001、014-0001）；Ubuntu 其他檔案系統模組見 ubuntu/disk.py
class ModuleDisabled(Rule):
    category = "磁碟與檔案系統"

    def __init__(self, module, ids):
        self.module = module
        self.ids = ids
        self.title = "%s 檔案系統" % module
        tpl = "停用（modprobe.d 設定 install %s %s 與 blacklist %s，且未載入）"
        self.expected = {"rhel": tpl % (module, "/bin/true", module),
                         "debian": tpl % (module, "/bin/false", module)}

    def _target(self, osi):
        return "/bin/false" if osi.family == "debian" else "/bin/true"

    def check(self, ctx):
        texts = [read_text(f) or "" for f in modprobe_files()]
        inst, bl = te.modprobe_status(texts, self.module)
        loaded = module_loaded(self.module)
        cur = "install 停用:%s、blacklist:%s、目前已載入:%s" % (
            "是" if inst else "否", "是" if bl else "否", "是" if loaded else "否")
        return Check(PASS if inst and bl and not loaded else FAIL, cur)

    def fix(self, ctx, fx):
        path = "/etc/modprobe.d/%s.conf" % self.module
        fx.edit_file(path, lambda t: te.modprobe_conf(t, self.module, self._target(ctx.osi)))
        if module_loaded(self.module):
            fx.run(["modprobe", "-r", self.module], "卸載 %s 模組" % self.module)


# [SeparatePartition] 獨立分割區（C 類，只檢測）。用於：/var（008-0008、012-0008、014-0011）
class SeparatePartition(Rule):
    category = "磁碟與檔案系統"
    risk = "C"

    def __init__(self, mount, ids):
        self.mount = mount
        self.ids = ids
        self.title = "設定 %s 目錄之檔案系統" % mount
        self.expected = "使用獨立之分割磁區或邏輯磁區"
        self.manual_hint = "需重新規劃磁區（建議安裝時建立，或備份後以 LVM 建立 %s 並搬移資料），無法自動修復" % mount

    def check(self, ctx):
        for line in (read_text("/proc/self/mounts") or "").splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[1] == self.mount:
                return Check(PASS, "獨立掛載：%s (%s)" % (parts[0], parts[2]))
        return Check(FAIL, "%s 未獨立掛載（位於根目錄分割區）" % self.mount)


# ====================================================================
# 系統設定與維護
# ====================================================================

def _owner(st):
    try:
        u = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        u = str(st.st_uid)
    try:
        g = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        g = str(st.st_gid)
    return u, g


# [FileOwner] 檔案擁有者。用於：/etc/passwd（008-0045、012-0045、014-0043）、/etc/shadow（008-0047、012-0047、014-0045）
class FileOwner(Rule):
    category = "系統設定與維護"

    def __init__(self, path, groups, ids):
        self.path = path
        self.groups = groups
        self.ids = ids
        self.title = "%s 檔案所有權" % path
        self.expected = " 或 ".join("root:" + g for g in groups)

    def check(self, ctx):
        if not os.path.exists(self.path):
            return Check(ERROR, "檔案不存在")
        u, g = _owner(os.stat(self.path))
        return Check(PASS if u == "root" and g in self.groups else FAIL, "%s:%s" % (u, g))

    def fix(self, ctx, fx):
        _, g = _owner(os.stat(self.path))
        group = g if g in self.groups else self.groups[0]
        fx.chown(self.path, 0, grp.getgrnam(group).gr_gid, "root:" + group)


# [FileMode] 檔案權限上限。用於：/etc/passwd（008-0046、012-0046、014-0044）、/etc/shadow（008-0048、012-0048、014-0046）
class FileMode(Rule):
    category = "系統設定與維護"

    def __init__(self, path, max_mode, ids):
        self.path = path
        self.max_mode = max_mode
        self.ids = ids
        self.title = "%s 檔案權限" % path
        self.expected = "%03o" % max_mode if max_mode == 0 else "%03o 或更低權限" % max_mode

    def check(self, ctx):
        if not os.path.exists(self.path):
            return Check(ERROR, "檔案不存在")
        mode = os.stat(self.path).st_mode & 0o7777
        return Check(PASS if mode & ~self.max_mode == 0 else FAIL, "%03o" % mode)

    def fix(self, ctx, fx):
        mode = os.stat(self.path).st_mode & 0o7777
        fx.chmod(self.path, mode & self.max_mode)


# [EmptyPassword] 帳號不使用空白通行碼（C 類）。用於：008-0072、012-0072、014-0062
class EmptyPassword(Rule):
    category = "系統設定與維護"
    risk = "C"
    title = "帳號不使用空白通行碼"
    expected = "帳號必須具有通行碼或被鎖定"
    manual_hint = "請確認帳號用途後，以 passwd <帳號> 設定通行碼或 passwd -l <帳號> 鎖定"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text("/etc/shadow")
        if text is None:
            return Check(ERROR, "無法讀取 /etc/shadow")
        empty = [u["name"] for u in te.parse_shadow(text) if u["pw"] == ""]
        if empty:
            return Check(FAIL, "空白通行碼帳號：" + ", ".join(empty))
        return Check(PASS, "無空白通行碼帳號")


# ====================================================================
# 系統服務 / 安裝與維護軟體
# ====================================================================

# [ServiceDisabled] 停用並遮蔽服務。用於：avahi-daemon（008-0095、012-0095、014-0079）
class ServiceDisabled(Rule):
    category = "系統服務"

    def __init__(self, title, units, ids):
        self.title = title
        self.units = units
        self.ids = ids
        self.expected = "停用（systemctl --now mask）"

    def check(self, ctx):
        states = [(u,) + pkgsvc.svc_state(u) for u in self.units]
        present = [s for s in states if s[1] != "not-found"]
        if not present:
            return Check(PASS, "未安裝")
        bad = [s for s in present if s[2] in ("active", "activating") or s[1] in ("enabled", "enabled-runtime")]
        cur = "、".join("%s=%s/%s" % s for s in present)
        return Check(FAIL if bad else PASS, cur)

    def fix(self, ctx, fx):
        for u in self.units:
            if pkgsvc.svc_exists(u):
                fx.service_mask(u)


# [ServiceEnabled] 安裝並啟用服務。用於：auditd（008-0133、012-0133、014-0113）、rsyslog（008-0175、012-0175、014-0150）
class ServiceEnabled(Rule):
    def __init__(self, title, category, unit, pkgs, ids):
        self.title = title
        self.category = category
        self.unit = unit
        self.pkgs = pkgs
        self.ids = ids
        self.expected = "啟用（已安裝、開機啟動且運作中）"

    def check(self, ctx):
        pkg = self.pkgs[ctx.osi.family]
        if not pkgsvc.pkg_installed(ctx.osi, pkg):
            return Check(FAIL, "未安裝套件 %s" % pkg)
        en, act = pkgsvc.svc_state(self.unit)
        return Check(PASS if en == "enabled" and act == "active" else FAIL, "%s / %s" % (en, act))

    def fix(self, ctx, fx):
        pkg = self.pkgs[ctx.osi.family]
        if not pkgsvc.pkg_installed(ctx.osi, pkg):
            fx.pkg_install(pkg)
        en, act = pkgsvc.svc_state(self.unit)
        if en == "masked":
            fx.run(["systemctl", "unmask", self.unit], "解除 %s 遮蔽" % self.unit)
        fx.service_enable(self.unit)


# [PackageAbsent] 移除套件。用於：telnet 用戶端（008-0103、012-0103、014-0088）
class PackageAbsent(Rule):
    category = "安裝與維護軟體"

    def __init__(self, title, pkg, ids):
        self.title = title
        self.pkg = pkg
        self.ids = ids
        self.expected = "移除"

    def check(self, ctx):
        inst = pkgsvc.pkg_installed(ctx.osi, self.pkg)
        return Check(FAIL if inst else PASS, "已安裝" if inst else "未安裝")

    def fix(self, ctx, fx):
        fx.pkg_remove(self.pkg)


# ====================================================================
# 網路設定（sysctl）
# ====================================================================

VIRT_UNITS = ("docker", "containerd", "kubelet", "k3s", "crio", "libvirtd", "podman")
VIRT_IFACES = ("docker0", "cni0", "virbr0", "flannel.1", "cali", "kube-ipvs0")


# [Sysctl] 核心參數。用於：IP 轉送（008-0108、012-0108、014-0089）、ICMP 重新導向 all（008-0109、012-0109、014-0090）、default（008-0110、012-0110、014-0091）
def sysctl_override_path(path):
    """/etc 以外的套件檔（例：/usr/lib/sysctl.d/10-x.conf）不直接修改，改寫 /etc/sysctl.d 同名檔覆蓋。

    同檔名時 /etc/sysctl.d 優先，套件更新也不會蓋掉。/etc 底下的檔案（含連結指向的實際檔）照常修改。
    """
    real = os.path.realpath(path) if os.path.islink(path) else path
    if real.startswith("/etc/"):
        return path
    return os.path.join("/etc/sysctl.d", os.path.basename(path))


# ---- rp_filter：各介面實際值 ----
# 核心對每個介面取 all 與該介面 rp_filter 的較大者；systemd 的 50-default.conf 以
# net.ipv4.conf.*.rp_filter = 2 把各介面設為寬鬆模式，此時 all=1 並不會讓嚴格模式生效
RP_GLOB = "net.ipv4.conf.*.rp_filter"


def rp_filter_loose():
    """回傳 ([(介面, 值)] 執行中為寬鬆模式者, 開機時萬用字元設定值, 來源檔)。"""
    loose = []
    for p in sorted(glob.glob("/proc/sys/net/ipv4/conf/*/rp_filter")):
        name = p.split("/")[-2]
        v = (read_text(p) or "").strip()
        if name not in ("all", "default") and v.isdigit() and int(v) > 1:
            loose.append((name, v))
    pv, src, _ = pkgsvc.sysctl_persistent(RP_GLOB)
    return loose, pv, src


class RpFilterIfaces(object):
    """0102（Ubuntu）／0121（RHEL）所有網路介面 rp_filter：除 all 外，一併確認各介面實際為嚴格模式。"""

    def _rp_check(self, c):
        if c.status not in (PASS, FAIL):
            return c
        loose, pv, src = rp_filter_loose()
        bad = []
        if loose:
            bad.append("介面 %s 為寬鬆模式（核心取 all 與介面值的較大者，嚴格模式未生效）"
                       % "、".join("%s rp_filter=%s" % x for x in loose))
        if pv is not None and pv.isdigit() and int(pv) > 1:
            bad.append("%s 設定 %s=%s，重開機後各介面會回到寬鬆模式" % (src, RP_GLOB, pv))
        if bad:
            c.status = FAIL
            c.current += "；" + "；".join(bad)
        return c

    def _rp_fix(self, fx, own):
        loose, pv, src = rp_filter_loose()
        if pv is not None and pv != "1":
            # 本工具設定檔排序在 50-default.conf 之後，以萬用字元覆寫各介面的開機值
            fx.edit_file(own, lambda t: te.set_kv(t, RP_GLOB, "1"))
        for name, _ in loose:
            fx.sysctl_set("net.ipv4.conf.%s.rp_filter" % name, "1")


class Sysctl(Rule):
    category = "網路設定"

    def __init__(self, title, settings, ids, forwarding=False):
        self.title = title
        self.settings = settings
        self.ids = ids
        self.forwarding = forwarding
        self.expected = "、".join("%s=%s" % kv for kv in settings)

    def _status(self):
        rows = []
        for key, want in self.settings:
            rt = pkgsvc.sysctl_runtime(key)
            if rt is None:
                continue  # 例如 IPv6 停用時沒有此參數
            pv, src, _ = pkgsvc.sysctl_persistent(key)
            rows.append((key, want, rt, pv, src))
        return rows

    def check(self, ctx):
        rows = self._status()
        if not rows:
            return Check(NA, "核心沒有此參數（相關功能未編入或未載入），無法也不需設定")
        cur, ok = [], True
        for key, want, rt, pv, src in rows:
            good = rt == want and pv == want
            ok = ok and good
            cur.append("%s 目前=%s 開機=%s%s" % (key, rt, pv if pv is not None else "未設定",
                                                "（%s）" % src if src else ""))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def precondition(self, ctx):
        if not self.forwarding or ctx.include_risky:
            return None
        found = [u for u in VIRT_UNITS if pkgsvc.svc_state(u)[1] == "active"]
        ifaces = os.listdir("/sys/class/net") if os.path.isdir("/sys/class/net") else []
        found += [i for i in ifaces if i.startswith(VIRT_IFACES)]
        if found:
            return "偵測到容器/虛擬化環境（%s），停用 IP 轉送會中斷其網路；確認後可加 --include-risky" % ", ".join(found)
        return None

    def fix(self, ctx, fx):
        own = "/etc/sysctl.d/60-gcb-checker.conf"
        v6 = False
        for key, want, rt, pv, src in self._status():
            v6 = v6 or key.startswith("net.ipv6")
            # 依文件作法：註解其他檔案中衝突的設定，再寫入固定檔案
            for f, v in pkgsvc.sysctl_persistent(key)[2]:
                if v != want and f != own:
                    fx.edit_file(sysctl_override_path(f), lambda t, k=key, w=want, src=f:
                                 te.comment_sysctl(t or read_text(src) or "", k, w))
            fx.edit_file(own, lambda t, k=key, w=want: te.set_kv(t, k, w))
            if rt != want:
                fx.sysctl_set(key, want)
        fx.run(["sysctl", "-w", "net.ipv4.route.flush=1"], "刷新 IPv4 路由快取", check=False)
        if v6:
            fx.run(["sysctl", "-w", "net.ipv6.route.flush=1"], "刷新 IPv6 路由快取", check=False)


# ====================================================================
# 日誌與稽核（GRUB 開機參數）
# ====================================================================

def grub_effective_cmdline():
    """依 grub-mkconfig 的載入順序（/etc/default/grub、/etc/default/grub.d/*.cfg）求最終的 GRUB_CMDLINE_LINUX。"""
    val = ""
    for f in ["/etc/default/grub"] + sorted(glob.glob("/etc/default/grub.d/*.cfg")):
        for line in (read_text(f) or "").splitlines():
            m = re.match(r'^\s*GRUB_CMDLINE_LINUX=(["\']?)(.*?)\1\s*(#.*)?$', line)
            if m:
                val = m.group(2).replace("${GRUB_CMDLINE_LINUX}", val).replace("$GRUB_CMDLINE_LINUX", val)
    return val


# [GrubArg] GRUB 開機參數（B 類）。用於：audit=1（008-0134、012-0134、014-0114）
class GrubArg(Rule):
    category = "日誌與稽核"
    risk = "B"
    needs_reboot = True

    def __init__(self, title, arg, ids):
        self.title = title
        self.arg = arg
        self.ids = ids
        self.expected = "GRUB_CMDLINE_LINUX 加入 %s（啟用）" % arg

    def _entries_missing(self, ctx):
        """回傳 (缺少參數的開機項目, 錯誤訊息)。"""
        if ctx.osi.family == "rhel":
            if not which("grubby"):
                return None, "找不到 grubby"
            r = run(["grubby", "--info=ALL"], timeout=60)
            if not r.ok:
                return None, "grubby 執行失敗"
            missing, kernel = [], None
            for line in r.out.splitlines():
                if line.startswith("kernel="):
                    kernel = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("args=") and kernel:
                    if self.arg not in line.split("=", 1)[1].strip().strip('"').split():
                        missing.append(kernel)
            return missing, ""
        cfg = "/boot/grub/grub.cfg"
        text = read_text(cfg)
        if text is None:
            return None, "找不到 %s" % cfg
        bad = [l.strip() for l in text.splitlines()
               if re.match(r"^\s*linux\s", l) and self.arg not in l.split()]
        return bad, ""

    def check(self, ctx):
        default = read_text("/etc/default/grub")
        if default is None:
            return Check(ERROR, "找不到 /etc/default/grub")
        # Ubuntu 的 grub.d/*.cfg（雲端映像檔常見）可能覆寫 GRUB_CMDLINE_LINUX，以最終生效值判斷
        eff = grub_effective_cmdline() if ctx.osi.family == "debian" else te.grub_cmdline_get(default)
        in_default = self.arg in (eff or "").split()
        missing, err = self._entries_missing(ctx)
        if missing is None:
            return Check(ERROR, err)
        running = self.arg in (read_text("/proc/cmdline") or "").split()
        cur = "/etc/default/grub:%s、開機項目缺少:%d 個、目前核心已生效:%s" % (
            "有" if in_default else "無", len(missing), "是" if running else "否（需重開機）")
        return Check(PASS if in_default and not missing else FAIL, cur)

    def fix(self, ctx, fx):
        if ctx.osi.family == "debian":
            fx.add_undo(["update-grub"], "重新產生 grub.cfg")
            fx.edit_file("/etc/default/grub", lambda t: te.grub_cmdline_add(t, self.arg))
            if not fx.dry and self.arg not in grub_effective_cmdline().split():
                # grub.d 覆寫了 GRUB_CMDLINE_LINUX：以排序最後的 drop-in 附加參數
                name = re.sub(r"[^A-Za-z0-9_]", "_", self.arg.split("=")[0])
                fx.write_file("/etc/default/grub.d/99-gcb-%s.cfg" % name,
                              'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX %s"\n' % self.arg)
            fx.run(["update-grub"], "更新 GRUB 設定", timeout=300)
            return
        fx.edit_file("/etc/default/grub", lambda t: te.grub_cmdline_add(t, self.arg))
        missing, err = self._entries_missing(ctx)
        if missing is None:
            raise FixError(err)
        # RHEL 使用 BLS，以 grubby 更新所有開機項目才會生效；grubby 會改寫開機項目檔，先備份
        for f in sorted(glob.glob("/boot/loader/entries/*.conf")) + ["/boot/grub2/grubenv"]:
            fx.backup_only(f)
        for k in missing:
            fx.add_undo(["grubby", "--update-kernel", k, "--remove-args", self.arg], "移除 %s 的 %s" % (k, self.arg))
            fx.run(["grubby", "--update-kernel", k, "--args", self.arg], "加入開機參數 %s → %s" % (self.arg, k))


# ====================================================================
# SELinux / AppArmor
# ====================================================================

# [SELinuxEnforcing] SELinux 強制模式（B 類）。用於：008-0188、012-0186
class SELinuxEnforcing(Rule):
    category = "SELinux"
    risk = "B"
    title = "SELinux 啟用狀態"
    expected = "enforcing"

    def __init__(self, ids):
        self.ids = ids

    def _state(self):
        cfg = te.get_kv(read_text("/etc/selinux/config") or "", "SELINUX")
        r = run(["getenforce"], timeout=10)
        return (cfg or "未設定"), (r.out.strip() if r.ok else "未知")

    def check(self, ctx):
        if not which("getenforce"):
            return Check(ERROR, "找不到 getenforce")
        cfg, rt = self._state()
        ok = cfg.lower() == "enforcing" and rt.lower() == "enforcing"
        return Check(PASS if ok else FAIL, "設定檔=%s、目前=%s" % (cfg, rt))

    def fix(self, ctx, fx):
        cfg, rt = self._state()
        if rt.lower() == "disabled":
            # 停用 → 強制要分兩階段：先 permissive 並重新標記檔案系統，重開機後再改 enforcing。
            # 直接改 enforcing 時，標籤錯誤可能讓服務無法啟動、甚至無法登入。
            fx.edit_file("/etc/selinux/config", lambda t: te.set_kv(t, "SELINUX", "permissive", sep="="))
            fx.write_file("/.autorelabel", "")
            fx.partial = True
            fx.note("SELinux 原為 disabled：第 1 階段已設為 permissive 並安排重開機時重新標記檔案系統（耗時較長）；"
                    "重開機完成後請再執行一次 sudo ./gcb.sh run --include-risky，第 2 階段才會改為 enforcing")
            return
        fx.edit_file("/etc/selinux/config", lambda t: te.set_kv(t, "SELINUX", "enforcing", sep="="))
        if rt.lower() == "permissive":
            fx.add_undo(["setenforce", "0"], "恢復 permissive")
            fx.run(["setenforce", "1"], "切換為 enforcing")


# [AppArmorEnforce] AppArmor 強制模式（B 類）。用於：014-0157
class AppArmorEnforce(Rule):
    category = "AppArmor"
    risk = "B"
    title = "AppArmor 啟用狀態"
    expected = "Enforce（所有設定檔為強制模式）"

    def __init__(self, ids):
        self.ids = ids

    def _loaded(self):
        """已載入的設定檔 [(名稱, 模式)]；無法讀取回傳 None。"""
        text = read_text("/sys/kernel/security/apparmor/profiles")
        if text is None:
            return None
        return [tuple(l.rsplit(" (", 1)) for l in text.splitlines() if " (" in l]

    def _profiles(self):
        loaded = self._loaded()
        return None if loaded is None else [n for n, m in loaded if m.rstrip(")") == "complain"]

    @staticmethod
    def _complain_files():
        """設定為 complain 且未被停用（disable/ 下沒有連結）的設定檔。"""
        out = []
        for f in sorted(glob.glob("/etc/apparmor.d/*")):
            if not os.path.isfile(f) or os.path.exists(os.path.join("/etc/apparmor.d/disable", os.path.basename(f))):
                continue
            if re.search(r"flags\s*=\s*\([^)]*\bcomplain\b", read_text(f) or ""):
                out.append(f)
        return out

    def check(self, ctx):
        enabled = (read_text("/sys/module/apparmor/parameters/enabled") or "").strip() == "Y"
        if not enabled:
            return Check(FAIL, "AppArmor 未啟用")
        complain = self._profiles()
        if complain is None:
            return Check(ERROR, "無法讀取 AppArmor 設定檔狀態")
        if not self._loaded():
            return Check(FAIL, "AppArmor 已啟用，但沒有載入任何設定檔")
        if complain:
            return Check(FAIL, "complain 模式設定檔 %d 個：%s" % (len(complain), ", ".join(complain[:8])))
        return Check(PASS, "已啟用，無 complain 模式設定檔")

    def fix(self, ctx, fx):
        if (read_text("/sys/module/apparmor/parameters/enabled") or "").strip() != "Y":
            raise ManualRequired("核心未啟用 AppArmor，需先設定開機參數 apparmor=1 security=apparmor 並重開機")
        if not which("aa-enforce"):
            fx.pkg_install("apparmor-utils")
        fx.add_undo(["systemctl", "reload", "apparmor"], "重新載入 AppArmor")
        fx.backup_dir("/etc/apparmor.d")
        # 只切換 complain 的設定檔；GCB 文件的 aa-enforce /etc/apparmor.d/* 會連同被套件或管理者停用（disable/）
        # 的設定檔一起重新啟用並載入，可能使服務受限中斷
        files = self._complain_files()
        if files:
            fx.run(["aa-enforce"] + files, "將 complain 模式的 AppArmor 設定檔切換為 Enforce", timeout=300, check=False)
        disabled = sorted(os.path.basename(f) for f in glob.glob("/etc/apparmor.d/disable/*"))
        if disabled:
            fx.note("以下設定檔已被停用（disable/），未重新啟用：" + "、".join(disabled[:10]))


# ====================================================================
# 帳號與存取控制
# ====================================================================

# [PassMaxDays] 通行碼最長使用期限 90 天。用於：008-0227、012-0225、014-0184
class PassMaxDays(Rule):
    category = "帳號與存取控制"
    title = "通行碼最長使用期限"
    expected = "90 天以下，但須大於 0（login.defs 與既有帳號）"

    def __init__(self, ids):
        self.ids = ids

    def _bad_users(self):
        users = []
        for u in te.parse_shadow(read_text("/etc/shadow") or ""):
            if not te.has_usable_password(u["pw"]):
                continue
            try:
                m = int(u["max"])
            except ValueError:
                m = None
            if m is None or m <= 0 or m > 90:
                users.append(u)
        return users

    def check(self, ctx):
        v = te.get_kv(read_text("/etc/login.defs") or "", "PASS_MAX_DAYS")
        try:
            ok = 0 < int(v) <= 90
        except (TypeError, ValueError):
            ok = False
        bad = self._bad_users()
        cur = "PASS_MAX_DAYS=%s" % (v or "未設定")
        if bad:
            cur += "；不符合之帳號：" + ", ".join("%s(%s)" % (u["name"], u["max"] or "未設定") for u in bad)
        return Check(PASS if ok and not bad else FAIL, cur)

    def fix(self, ctx, fx):
        fx.edit_file("/etc/login.defs", lambda t: te.set_kv(t, "PASS_MAX_DAYS", "90", sep="\t"))
        today = int(time.time() // 86400)
        for u in self._bad_users():
            try:
                age = today - int(u["lastchg"])
            except ValueError:
                age = 9999
            if age >= 90 and not ctx.include_risky:
                fx.partial = True
                fx.note("帳號 %s 通行碼已使用 %d 天，套用後會立即過期（可能影響自動化登入），"
                        "已略過；請人工處理或加 --include-risky" % (u["name"], age))
                continue
            fx.chage_max(u["name"], u["max"], 90)


# [PassMinLen] 通行碼最小長度 12。用於：008-0210、012-0208、014-0173
class PassMinLen(Rule):
    category = "帳號與存取控制"
    title = "通行碼最小長度"
    expected = {"rhel": "login.defs PASS_MIN_LEN 12、pwquality minlen = 12（12 個字元以上）",
                "debian": "pwquality minlen=12（12 個字元以上）"}

    PAM_FILES = {"rhel": ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"],
                 "debian": ["/etc/pam.d/common-password"]}

    def __init__(self, ids):
        self.ids = ids

    def _pwq_values(self):
        """所有 pwquality 設定檔中的 minlen：[(file, value)]。"""
        files = ["/etc/security/pwquality.conf"] + sorted(glob.glob("/etc/security/pwquality.conf.d/*.conf"))
        out = []
        for f in files:
            v = te.get_kv(read_text(f) or "", "minlen")
            if v is not None:
                out.append((f, v))
        return out

    def _pam_override(self, osi):
        bad = []
        for f in self.PAM_FILES[osi.family]:
            for line in (read_text(f) or "").splitlines():
                if "pam_pwquality.so" in line and not line.strip().startswith("#"):
                    m = re.search(r"\bminlen=(\d+)", line)
                    if m and int(m.group(1)) < 12:
                        bad.append("%s minlen=%s" % (f, m.group(1)))
        return bad

    @staticmethod
    def _ge12(v):
        try:
            return int(v) >= 12
        except (TypeError, ValueError):
            return False

    def check(self, ctx):
        osi = ctx.osi
        cur, ok = [], True
        vals = self._pwq_values()
        main = [v for f, v in vals if f == "/etc/security/pwquality.conf"]
        if not main or not self._ge12(main[-1]) or not all(self._ge12(v) for f, v in vals):
            ok = False
        cur.append("pwquality: " + ("、".join("%s=%s" % (os.path.basename(f), v) for f, v in vals) or "未設定"))
        if osi.family == "rhel":
            v = te.get_kv(read_text("/etc/login.defs") or "", "PASS_MIN_LEN")
            ok = ok and self._ge12(v)
            cur.append("PASS_MIN_LEN=%s" % (v or "未設定"))
        else:
            if not pkgsvc.pkg_installed(osi, "libpam-pwquality"):
                ok = False
                cur.append("未安裝 libpam-pwquality（設定不會生效）")
            elif not re.search(r"^\s*password\s.*pam_pwquality\.so", read_text("/etc/pam.d/common-password") or "", re.M):
                ok = False
                cur.append("common-password 未啟用 pam_pwquality（設定不會生效，PAM 可能曾被手動修改）")
        pam = self._pam_override(osi)
        if pam:
            ok = False
            cur.append("PAM 參數覆寫：" + "、".join(pam))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        osi = ctx.osi
        if osi.family == "debian" and not pkgsvc.pkg_installed(osi, "libpam-pwquality"):
            # 安裝時 pam-auth-update 會改寫 common-password，先備份
            fx.backup_only("/etc/pam.d/common-password")
            for f in sorted(glob.glob("/var/lib/pam/*")):
                fx.backup_only(f)
            fx.pkg_install("libpam-pwquality", track=["/etc/pam.d/common-password"])
        sep = " = " if osi.family == "rhel" else "="
        fx.edit_file("/etc/security/pwquality.conf", lambda t: te.set_kv(t, "minlen", "12", sep=sep))
        for f, v in self._pwq_values():
            if f != "/etc/security/pwquality.conf" and not self._ge12(v):
                fx.edit_file(f, lambda t: te.comment_kv(t, "minlen"))
        if osi.family == "rhel":
            fx.edit_file("/etc/login.defs", lambda t: te.set_kv(t, "PASS_MIN_LEN", "12", sep="\t"))
        if self._pam_override(osi):
            fx.partial = True
            fx.note("PAM 設定中的 minlen 參數低於 12，會覆寫設定檔，請人工修改：" + "、".join(self._pam_override(osi)))


UBUNTU_FAILLOCK_PROFILES = {
    "/usr/share/pam-configs/gcb_faillock": (
        "Name: GCB - pam_faillock deny access (gcb-checker)\n"
        "Default: yes\nPriority: 0\nAuth-Type: Primary\nAuth:\n"
        "\t[default=die]\tpam_faillock.so authfail\n"),
    "/usr/share/pam-configs/gcb_faillock_notify": (
        "Name: GCB - pam_faillock preauth and reset (gcb-checker)\n"
        "Default: yes\nPriority: 1024\nAuth-Type: Primary\nAuth:\n"
        "\trequired\tpam_faillock.so preauth\n"
        "Account-Type: Primary\nAccount:\n"
        "\trequired\tpam_faillock.so\n"),
    # GCB 範本的 auth sufficient pam_faillock.so authsucc：Priority -1 讓它排在 Additional 區最後
    # （其他套件多為 0，例如 pam_cap），sufficient 成功時才不會略過其他模組；帳號已鎖定時 authsucc 不會重設計數
    "/usr/share/pam-configs/gcb_faillock_authsucc": (
        "Name: GCB - pam_faillock reset on success (gcb-checker)\n"
        "Default: yes\nPriority: -1\nAuth-Type: Additional\nAuth:\n"
        "\tsufficient\tpam_faillock.so authsucc\n"),
}
# common-auth 須具備 GCB 範本的三行（preauth、authfail、authsucc），common-account 須有 pam_faillock
UBUNTU_FAILLOCK_AUTH = (r"^\s*auth\s+required\s+pam_faillock\.so\s+preauth\b",
                        r"^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail\b",
                        r"^\s*auth\s+sufficient\s+pam_faillock\.so\s+authsucc\b")


# [Faillock] 帳戶鎖定閾值 deny=5（B 類）。用於：008-0220、012-0218、014-0178
class Faillock(Rule):
    category = "帳號與存取控制"
    risk = "B"
    title = "帳戶鎖定閾值"
    expected = "deny=5（5 次以下，但須大於 0），且 pam_faillock 已啟用"
    CONF = "/etc/security/faillock.conf"

    def __init__(self, ids):
        self.ids = ids

    RHEL_PAM = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]

    def _pam_active(self, osi):
        if osi.family == "rhel":
            return all(re.search(r"^\s*(auth|account)\s.*pam_faillock\.so", read_text(f) or "", re.M)
                       for f in self.RHEL_PAM)
        auth = read_text("/etc/pam.d/common-auth") or ""
        account = read_text("/etc/pam.d/common-account") or ""
        return all(re.search(rx, auth, re.M) for rx in UBUNTU_FAILLOCK_AUTH) and \
            bool(re.search(r"^\s*account\s.*pam_faillock\.so", account, re.M))

    def check(self, ctx):
        v = te.get_kv(read_text(self.CONF) or "", "deny")
        try:
            ok = 0 < int(v) <= 5
        except (TypeError, ValueError):
            ok = False
        active = self._pam_active(ctx.osi)
        return Check(PASS if ok and active else FAIL,
                     "deny=%s、pam_faillock:%s" % (v or "未設定", "已啟用" if active else "未啟用"))

    def fix(self, ctx, fx):
        osi = ctx.osi
        if osi.family == "rhel" and osi.key == "rhel8" and osi.version_tuple() < (8, 2):
            raise ManualRequired("RHEL 8.1 以前需依 GCB 文件建立自訂 authselect profile，請人工處理")
        fx.edit_file(self.CONF, lambda t: te.set_kv(t, "deny", "5"))
        if self._pam_active(osi):
            return
        if osi.family == "rhel":
            if not run(["authselect", "current"], timeout=30).ok:
                raise ManualRequired("系統未使用 authselect 管理 PAM，請人工設定 pam_faillock")
            # 回滾順序（反向）：先 disable-feature，再以備份還原原始檔案（含產生時間戳）；
            # /var/lib/authselect/ 是 authselect check 比對用的副本，需一併還原
            for f in sorted(glob.glob("/etc/authselect/*") + glob.glob("/var/lib/authselect/*")):
                if os.path.isfile(f):
                    fx.backup_only(f)
            fx.add_undo(["authselect", "disable-feature", "with-faillock"], "停用 with-faillock")
            fx.run_tracked(["authselect", "enable-feature", "with-faillock"], "啟用 authselect with-faillock",
                           self.RHEL_PAM)
            return
        # Ubuntu：以 pam-auth-update 官方機制產生與文件相同的 common-auth 設定
        pam = ["/etc/pam.d/common-auth", "/etc/pam.d/common-account", "/etc/pam.d/common-password",
               "/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive"]
        for f in pam + sorted(glob.glob("/var/lib/pam/*")):
            fx.backup_only(f)
        for path, content in UBUNTU_FAILLOCK_PROFILES.items():
            fx.write_file(path, content)
        r = fx.run_tracked(["pam-auth-update", "--enable"] + [os.path.basename(p) for p in sorted(UBUNTU_FAILLOCK_PROFILES)],
                           "以 pam-auth-update 啟用 pam_faillock", pam, env=pkgsvc.APT_ENV, check=False)
        if r is not None and (not r.ok or "local modifications" in r.text().lower()):
            raise FixError("pam-auth-update 失敗（PAM 設定可能曾被手動修改）")


# sshd 啟動時由 systemd 帶入的額外參數（RHEL 8 的 $CRYPTO_POLICY）。由 rhel/ssh.py 登記取得方式；
# 未登記或取得失敗時為空，sshd -T / -t 的結果才會與實際啟動的 sshd 一致。
SSHD_ARGS_HOOK = None


def sshd_args(ctx):
    if SSHD_ARGS_HOOK is None:
        return []
    try:
        return list(SSHD_ARGS_HOOK(ctx))
    except Exception:
        return []


# [SshdOption] sshd 參數（B 類）。用於：PermitRootLogin no（008-0277、012-0269）
class SshdOption(Rule):
    category = "SSH 設定"
    risk = "B"
    MAIN = "/etc/ssh/sshd_config"

    def __init__(self, title, opt, value, ids):
        self.title = title
        self.opt = opt
        self.value = value
        self.ids = ids
        self.expected = value

    def check(self, ctx):
        if not which("sshd"):
            return Check(NA, "未安裝 SSH 伺服器，沒有 SSH 設定需要檢查")
        r = run([which("sshd"), "-T"] + sshd_args(ctx), timeout=30)
        if not r.ok:
            return Check(ERROR, "sshd -T 執行失敗：" + r.text()[-200:])
        vals = te.parse_sshd_T(r.out).get(self.opt.lower(), ["未設定"])
        return Check(PASS if vals[0].lower() == self.value.lower() else FAIL, "%s %s" % (self.opt, vals[0]))

    def precondition(self, ctx):
        pre = ctx.pre_health_status
        if pre.get("H04") != "通過" or pre.get("H05") != "通過":
            return "前測未確認一般帳號可 SSH 登入並使用 sudo，為避免鎖死 root 登入而略過"
        return None

    def fix(self, ctx, fx):
        sshd = which("sshd")
        fx.add_undo(["systemctl", "reload", ctx.osi.ssh_unit], "重新載入 SSH 服務")
        fx.edit_file(self.MAIN, lambda t: te.sshd_set_option(t, self.opt, self.value))
        # drop-in（sshd_config.d）中衝突的設定會優先生效，一併註解
        for pat in te.sshd_includes(read_text(self.MAIN) or ""):
            for f in sorted(glob.glob(pat)):
                fx.edit_file(f, lambda t: te.sshd_comment_option(t, self.opt, self.value))
        r = fx.run([sshd, "-t"] + sshd_args(ctx), "檢查 sshd 設定語法", check=False)
        if r is not None and not r.ok:
            raise FixError("sshd 設定語法錯誤，不重新載入服務")
        fx.run(["systemctl", "reload", ctx.osi.ssh_unit], "重新載入 SSH 服務")


# ====================================================================
# 規則清單
# ====================================================================

def _ids(u=None, r8=None, r9=None):
    d = {}
    if u:
        d["ubuntu2204"] = "TWGCB-01-014-%04d" % u
    if r8:
        d["rhel8"] = "TWGCB-01-008-%04d" % r8
    if r9:
        d["rhel9"] = "TWGCB-01-012-%04d" % r9
    return d


# 規則清單（依 GCB 文件順序）。_ids(Ubuntu, RHEL8, RHEL9) 的數字為各文件中的項次編號：
#   Ubuntu → TWGCB-01-014-NNNN、RHEL 8 → TWGCB-01-008-NNNN、RHEL 9 → TWGCB-01-012-NNNN
RULES = [
    # cramfs 檔案系統｜014-0001、008-0001、012-0001
    ModuleDisabled("cramfs", _ids(1, 1, 1)),
    # 設定 /var 目錄之檔案系統｜014-0011、008-0008、012-0008
    SeparatePartition("/var", _ids(11, 8, 8)),
    # /etc/passwd 檔案所有權｜014-0043、008-0045、012-0045
    FileOwner("/etc/passwd", ["root"], _ids(43, 45, 45)),
    # /etc/passwd 檔案權限｜014-0044、008-0046、012-0046
    FileMode("/etc/passwd", 0o644, _ids(44, 46, 46)),
    # /etc/shadow 檔案所有權｜014-0045、008-0047、012-0047
    FileOwner("/etc/shadow", ["root", "shadow"], _ids(45, 47, 47)),
    # /etc/shadow 檔案權限｜014-0046、008-0048、012-0048
    FileMode("/etc/shadow", 0o000, _ids(46, 48, 48)),
    # 帳號不使用空白通行碼｜014-0062、008-0072、012-0072
    EmptyPassword(_ids(62, 72, 72)),
    # avahi-daemon 服務｜014-0079、008-0095、012-0095
    ServiceDisabled("avahi-daemon 服務", ["avahi-daemon.service", "avahi-daemon.socket"], _ids(79, 95, 95)),
    # telnet 用戶端套件｜014-0088、008-0103、012-0103
    PackageAbsent("telnet 用戶端套件", "telnet", _ids(88, 103, 103)),
    # IP 轉送｜014-0089、008-0108、012-0108
    Sysctl("IP 轉送", [("net.ipv4.ip_forward", "0"), ("net.ipv6.conf.all.forwarding", "0")],
           _ids(89, 108, 108), forwarding=True),
    # 所有網路介面禁止傳送 ICMP 重新導向封包｜014-0090、008-0109、012-0109
    Sysctl("所有網路介面禁止傳送 ICMP 重新導向封包", [("net.ipv4.conf.all.send_redirects", "0")],
           _ids(90, 109, 109)),
    # 預設網路介面禁止傳送 ICMP 重新導向封包｜014-0091、008-0110、012-0110
    Sysctl("預設網路介面禁止傳送 ICMP 重新導向封包", [("net.ipv4.conf.default.send_redirects", "0")],
           _ids(91, 110, 110)),
    # auditd 服務｜014-0113、008-0133、012-0133
    ServiceEnabled("auditd 服務", "日誌與稽核", "auditd", {"rhel": "audit", "debian": "auditd"},
                   _ids(113, 133, 133)),
    # 稽核 auditd 服務啟動前之程序（開機參數 audit=1）｜014-0114、008-0134、012-0134
    GrubArg("稽核 auditd 服務啟動前之程序", "audit=1", _ids(114, 134, 134)),
    # rsyslog 服務｜014-0150、008-0175、012-0175
    ServiceEnabled("rsyslog 服務", "日誌與稽核", "rsyslog", {"rhel": "rsyslog", "debian": "rsyslog"},
                   _ids(150, 175, 175)),
    # AppArmor 啟用狀態｜014-0157（僅 Ubuntu）
    AppArmorEnforce(_ids(u=157)),
    # SELinux 啟用狀態｜008-0188、012-0186（僅 RHEL）
    SELinuxEnforcing(_ids(r8=188, r9=186)),
    # 通行碼最小長度｜014-0173、008-0210、012-0208
    PassMinLen(_ids(173, 210, 208)),
    # 帳戶鎖定閾值｜014-0178、008-0220、012-0218
    Faillock(_ids(178, 220, 218)),
    # 通行碼最長使用期限｜014-0184、008-0227、012-0225
    PassMaxDays(_ids(184, 227, 225)),
    # SSH PermitRootLogin 參數｜008-0277、012-0269（僅 RHEL，Ubuntu 文件無此項）
    SshdOption("SSH PermitRootLogin 參數", "PermitRootLogin", "no", _ids(r8=277, r9=269)),
]
