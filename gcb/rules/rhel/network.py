# -*- coding: utf-8 -*-
"""RHEL 8 / 9 系統服務、安裝與維護軟體、網路設定（兩版皆為 0092–0131，編號相同）。"""
import glob
import os
import re

from ... import pkgsvc
from ... import textedit as te
from ...fixer import ManualRequired
from ...util import read_text, run, which
from ..base import FAIL, PASS, Check, Rule
from ..common import PackageAbsent, RpFilterIfaces, ServiceDisabled, Sysctl, modprobe_files
from ..generic import Module, module_builtin
from .helpers import R

OWN_SYSCTL = "/etc/sysctl.d/60-gcb-checker.conf"


def _both(n):
    """兩版編號相同的規則。"""
    return R(r8=n, r9=n)


# ====================================================================
# 共用小工具
# ====================================================================

def svc_active(unit):
    return pkgsvc.svc_state(unit)[1] in ("active", "activating")


def nm_active():
    return bool(which("nmcli")) and pkgsvc.svc_state("NetworkManager.service")[1] == "active"


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


def module_in_use(module):
    """模組已載入且被使用中時回傳說明，否則 None。"""
    info = loaded_modules().get(module)
    if not info or info[0] <= 0:
        return None
    users = "，被 %s 使用" % "、".join(info[1]) if info[1] else ""
    return "%s 模組使用中（參照數 %d%s）" % (module, info[0], users)


def default_route_ifaces():
    """目前 IPv4 / IPv6 預設路由使用的介面。"""
    ifaces = set()
    for line in (read_text("/proc/net/route") or "").splitlines()[1:]:
        p = line.split()
        if len(p) > 7 and p[1] == "00000000" and p[7] == "00000000":
            ifaces.add(p[0])
    for line in (read_text("/proc/net/ipv6_route") or "").splitlines():
        p = line.split()
        if len(p) >= 10 and p[0] == "0" * 32 and p[1] == "00" and p[9] != "lo":
            ifaces.add(p[9])
    return ifaces


def ra_default_routes():
    """由路由器公告（proto ra）取得的 IPv6 預設路由。"""
    if not which("ip"):
        return []
    r = run(["ip", "-6", "route", "show", "default"], timeout=15)
    return [l.strip() for l in r.out.splitlines() if " proto ra " in " %s " % l] if r.ok else []


def nsswitch_uses(name, text=None):
    """nsswitch.conf 中使用 name 作為來源的資料庫。"""
    if text is None:
        text = read_text("/etc/nsswitch.conf") or ""
    used = []
    for line in text.splitlines():
        s = line.split("#", 1)[0]
        if ":" in s and name in s.split(":", 1)[1].split():
            used.append(s.split(":", 1)[0].strip())
    return used


# ---------- INI（dnf.conf） ----------

_SECTION_RX = re.compile(r"^\s*\[([^\]]+)\]\s*$")


def ini_get(text, section, key):
    """取 [section] 中 key 的最後一個值；不存在回傳 None。"""
    cur, val = None, None
    rx = re.compile(r"^\s*" + re.escape(key) + r"\s*=\s*(.*?)\s*$")
    for line in (text or "").splitlines():
        m = _SECTION_RX.match(line)
        if m:
            cur = m.group(1).strip()
            continue
        if cur == section and line.strip() and line.strip()[0] not in "#;":
            m = rx.match(line)
            if m:
                val = m.group(1)
    return val


def ini_set(text, section, key, value):
    """在 [section] 中設定 key=value：取代第一個設定行、註解重複行；沒有則加在段落末端；段落不存在則新增。"""
    lines = (text or "").splitlines()
    rx = re.compile(r"^\s*" + re.escape(key) + r"\s*=")
    out, cur, done, last = [], None, False, None
    for line in lines:
        m = _SECTION_RX.match(line)
        if m:
            cur = m.group(1).strip()
        elif cur == section and line.strip() and line.strip()[0] not in "#;" and rx.match(line):
            if done:
                out.append(te.MARK + line)
            else:
                out.append("%s=%s" % (key, value))
                done = True
            last = len(out) - 1
            continue
        out.append(line)
        if cur == section and (m or line.strip()):
            last = len(out) - 1
    if not done:
        if last is None:
            if out and out[-1].strip():
                out.append("")
            out += ["[%s]" % section, "%s=%s" % (key, value)]
        else:
            out.insert(last + 1, "%s=%s" % (key, value))
    return "\n".join(out) + "\n"


# ---------- chrony ----------

def chrony_sources(conf="/etc/chrony.conf"):
    """解析 chrony.conf 與 include／confdir／sourcedir 引用的檔案，回傳 [(檔案, server/pool 行)]。"""
    found, seen, queue = [], set(), [conf]
    while queue:
        f = queue.pop(0)
        if f in seen:
            continue
        seen.add(f)
        for line in (read_text(f) or "").splitlines():
            parts = line.strip().split()
            if not parts or parts[0][0] in "#;!%":
                continue
            d = parts[0].lower()
            if d in ("server", "pool") and len(parts) > 1:
                found.append((f, line.strip()))
            elif d == "include" and len(parts) > 1:
                queue += sorted(glob.glob(parts[1]))
            elif d == "confdir":
                for p in parts[1:]:
                    queue += sorted(glob.glob(os.path.join(p, "*.conf")))
            elif d == "sourcedir":
                for p in parts[1:]:
                    queue += sorted(glob.glob(os.path.join(p, "*.sources")))
    return found


# ---------- SNMP ----------

SNMP_V12_RX = re.compile(r"^\s*(com2sec6?|rocommunity6?|rwcommunity6?)\b|^\s*group\s+\S+\s+(v1|v2c)\b", re.I)


def snmp_conf_files(conf="/etc/snmp/snmpd.conf"):
    files, seen, queue = [], set(), [conf]
    while queue:
        f = queue.pop(0)
        if f in seen or not os.path.isfile(f):
            continue
        seen.add(f)
        files.append(f)
        for line in (read_text(f) or "").splitlines():
            p = line.split("#", 1)[0].split()
            if len(p) >= 2 and p[0] == "includeFile":
                queue.append(p[1])
            elif len(p) >= 2 and p[0] == "includeDir":
                queue += sorted(glob.glob(os.path.join(p[1], "*.conf")))
    return files


def snmp_v1v2_lines(files):
    bad = []
    for f in files:
        for line in (read_text(f) or "").splitlines():
            if SNMP_V12_RX.match(line.split("#", 1)[0]):
                bad.append("%s：%s" % (f, " ".join(line.split())[:60]))
    return bad


def snmp_v3_users(files, var="/var/lib/net-snmp/snmpd.conf"):
    users = []
    for line in (read_text(var) or "").splitlines():
        p = line.split()
        if p and p[0] in ("usmUser", "createUser"):
            users.append(p[0])
    for f in files:
        for line in (read_text(f) or "").splitlines():
            p = line.split("#", 1)[0].split()
            if p and p[0] in ("rouser", "rwuser", "createUser"):
                users.append(" ".join(p[:2]))
    return users


# ====================================================================
# 客製規則
# ====================================================================

# [PkgAbsent] RHEL8 0092 / RHEL9 0092 xinetd 套件、0104 telnet 伺服器套件、0105 rsh 伺服器套件、0106 tftp 伺服器套件
class PkgAbsent(PackageAbsent):
    """移除套件；units 為套件提供的服務，運作中時（A 類）先略過，修復時登記回滾後要恢復的服務狀態。"""

    def __init__(self, title, pkg, ids, category="安裝與維護軟體", risk="A", units=()):
        PackageAbsent.__init__(self, title, pkg, ids)
        self.category = category
        self.risk = risk
        self.units = units

    def _running(self):
        return [u for u in self.units if svc_active(u)]

    def precondition(self, ctx):
        if ctx.include_risky:
            return None
        run_ = self._running()
        if run_:
            return "%s 運作中，移除 %s 會中斷該服務；確認後可加 --include-risky" % ("、".join(run_), self.pkg)
        return None

    def fix(self, ctx, fx):
        for u in self.units:
            en, act = pkgsvc.svc_state(u)
            # 回滾時套件先重新安裝（較晚登記先執行），再恢復服務
            if en in ("enabled", "enabled-runtime"):
                fx.add_undo(["systemctl", "enable", u], "恢復 %s 開機啟動" % u)
            if act == "active":
                fx.add_undo(["systemctl", "start", u], "恢復 %s 運作" % u)
                fx.note("移除前 %s 運作中，已隨套件移除停止" % u)
        PackageAbsent.fix(self, ctx, fx)


# [NisClientAbsent] RHEL8 0102 / RHEL9 0102 NIS 用戶端套件
class NisClientAbsent(PkgAbsent):
    def fix(self, ctx, fx):
        used = nsswitch_uses("nis")
        if used:
            raise ManualRequired("/etc/nsswitch.conf 的 %s 仍以 NIS 查詢帳號資訊（ypbind 目前%s），移除 ypbind 會使 NIS "
                                 "帳號無法登入；請先改用其他帳號來源（authselect select 其他 profile）後再移除"
                                 % ("、".join(used), "運作中" if svc_active("ypbind.service") else "未運作"))
        PkgAbsent.fix(self, ctx, fx)


# [ChronySource] RHEL8 0093 / RHEL9 0093 chrony 校時設定（C 類）
class ChronySource(Rule):
    category = "系統服務"
    risk = "C"
    title = "chrony 校時設定"
    expected = "設定 1 個以上校時來源（server 或 pool）"
    manual_hint = ("校時伺服器位址需由管理者提供：於 /etc/chrony.conf（或 /etc/chrony.d/*.conf）加入 "
                   "server <機關 NTP 伺服器> iburst，執行 systemctl restart chronyd，再以 chronyc sources 確認")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "chrony"):
            return Check(FAIL, "未安裝 chrony")
        src = chrony_sources()
        en, act = pkgsvc.svc_state("chronyd.service")
        svc = "chronyd %s/%s" % (en, act)
        if not src:
            return Check(FAIL, "未設定 server 或 pool；%s" % svc)
        cur = "%d 個校時來源：%s；%s" % (len(src), "、".join(l for _, l in src[:3]), svc)
        if all(".pool.ntp.org" in l for _, l in src):
            cur += "（僅使用公用 NTP 池，隔離網段請改用機關內部 NTP 伺服器）"
        if act != "active":
            cur += "（chronyd 未運作，校時不會生效）"
        return Check(PASS, cur)


# [SnmpV3Only] RHEL8 0096 / RHEL9 0096 SNMP 服務（B 類）
class SnmpV3Only(Rule):
    category = "系統服務"
    risk = "B"
    title = "SNMP 服務"
    expected = "停用 SNMP 服務或僅啟用 SNMPv3 功能"
    UNIT = "snmpd.service"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        en, act = pkgsvc.svc_state(self.UNIT)
        if en == "not-found":
            return Check(PASS, "未安裝")
        if act not in ("active", "activating") and en not in ("enabled", "enabled-runtime"):
            return Check(PASS, "已停用（%s/%s）" % (en, act))
        files = snmp_conf_files()
        v12 = snmp_v1v2_lines(files)
        v3 = snmp_v3_users(files)
        if not v12 and v3:
            return Check(PASS, "%s/%s，僅啟用 SNMPv3（使用者設定 %d 筆）" % (en, act, len(v3)))
        cur = "%s/%s" % (en, act)
        if v12:
            cur += "；SNMPv1/v2c 設定：" + "；".join(v12[:3]) + ("…" if len(v12) > 3 else "")
        if not v3:
            cur += "；未設定 SNMPv3 使用者"
        return Check(FAIL, cur)

    def fix(self, ctx, fx):
        # 方案 (1) 停用服務；方案 (2) 改用 SNMPv3 需設定帳號密碼，只能人工處理
        fx.service_mask(self.UNIT)
        fx.note("已依 GCB 方案 (1) 停用 snmpd；若監控系統需要 SNMP，請回滾本項，改以 net-snmp-create-v3-user "
                "建立 SNMPv3 使用者並註解 com2sec、group、view、access 行（方案 2）")


# [Kdump] RHEL8 0101 / RHEL9 0101 kdump 服務（B 類）
class Kdump(Rule):
    category = "系統服務"
    risk = "B"
    title = "kdump 服務"
    expected = "啟用"
    UNIT = "kdump.service"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def crash_size():
        """crashkernel 保留的記憶體大小；無法讀取回傳 None。"""
        v = read_text("/sys/kernel/kexec_crash_size")
        try:
            return int(v.strip()) if v is not None else None
        except ValueError:
            return None

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "kexec-tools"):
            return Check(FAIL, "未安裝 kexec-tools")
        en, act = pkgsvc.svc_state(self.UNIT)
        cur = "%s / %s" % (en, act)
        if self.crash_size() == 0:
            cur += "；未保留 crashkernel 記憶體（kexec_crash_size=0），服務無法啟動"
        return Check(PASS if en == "enabled" and act == "active" else FAIL, cur)

    def fix(self, ctx, fx):
        if self.crash_size() == 0:
            cmd = ("grubby --update-kernel=ALL --args=crashkernel=auto" if ctx.osi.key == "rhel8"
                   else "kdumpctl reset-crashkernel --kernel=ALL")
            raise ManualRequired("核心未保留 crashkernel 記憶體，kdump 無法啟動；需先執行 %s 並重開機（會占用部分記憶體，"
                                 "小記憶體主機請評估），再執行 systemctl --now enable kdump.service" % cmd)
        if not pkgsvc.pkg_installed(ctx.osi, "kexec-tools"):
            # 依規格不自動安裝：kexec-tools 會連帶安裝 dracut、NetworkManager 等大量套件，回滾時難以完整移除
            raise ManualRequired("未安裝 kexec-tools，請確認需求後執行 dnf install kexec-tools，"
                                 "並確認已保留 crashkernel 記憶體後再執行 systemctl --now enable kdump.service")
        if pkgsvc.svc_state(self.UNIT)[0] == "masked":
            fx.add_undo(["systemctl", "mask", self.UNIT], "恢復 %s 遮蔽" % self.UNIT)
            fx.run(["systemctl", "unmask", self.UNIT], "解除 %s 遮蔽" % self.UNIT)
        fx.service_enable(self.UNIT)


# [DnfCleanRequirements] RHEL8 0107 / RHEL9 0107 更新套件後移除舊版本元件
class DnfCleanRequirements(Rule):
    category = "安裝與維護軟體"
    title = "更新套件後移除舊版本元件"
    expected = "True（/etc/yum.conf 與 /etc/dnf/dnf.conf 設定 clean_requirements_on_remove=True）"
    KEY = "clean_requirements_on_remove"
    FILES = ("/etc/dnf/dnf.conf", "/etc/yum.conf")

    def __init__(self, ids):
        self.ids = ids

    def _files(self):
        """兩個檔案常為連結關係，以實際路徑去重；/etc/yum.conf 不存在時不處理。"""
        out, seen = [], set()
        for f in self.FILES:
            if f != self.FILES[0] and not os.path.exists(f):
                continue
            rp = os.path.realpath(f)
            if rp not in seen:
                seen.add(rp)
                out.append(f)
        return out

    def check(self, ctx):
        cur, ok = [], True
        for f in self._files():
            v = ini_get(read_text(f), "main", self.KEY)
            good = v is not None and v.lower() == "true"
            ok = ok and good
            note = ""
            if v is not None and not good and v.lower() in ("1", "yes", "on"):
                note = "（dnf 視為等同 True，但與 GCB 設定值不同）"
            cur.append("%s：%s%s" % (f, v if v is not None else "未設定", note))
        return Check(PASS if ok else FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        for f in self._files():
            v = ini_get(read_text(f), "main", self.KEY)
            if v is None or v.lower() != "true":
                fx.edit_file(f, lambda t: ini_set(t, "main", self.KEY, "True"))


# [RhelSysctl] RHEL8 0111–0125 / RHEL9 0111–0125 網路核心參數
class RhelSysctl(Sysctl):
    """沿用 common.Sysctl 的檢測；修復時不修改套件擁有的 /usr/lib/sysctl.d 等檔案：
    其中排序在 60-gcb-checker.conf 之後的衝突設定，於 /etc/sysctl.d 建立同名檔案覆寫（內容相同但註解衝突行）。
    文件 0121、0123 的 sed/grep 樣式有誤（0121 永遠比對不到、0123 會註解所有值），一律只註解值不同的行。
    """

    def __init__(self, title, settings, ids, risk="A", fix_note=None):
        Sysctl.__init__(self, title, settings, ids)
        self.risk = risk
        self.fix_note = fix_note

    @staticmethod
    def _vendor(f):
        # 檔案本身是連結時看實際指向（/etc 的連結若指向 /usr/lib 也算套件檔）
        target = os.path.realpath(f) if os.path.islink(f) else f
        return not target.startswith(("/etc/", "/run/"))

    def fix(self, ctx, fx):
        v6 = False
        own_base = os.path.basename(OWN_SYSCTL)
        for key, want, rt, pv, src in self._status():
            v6 = v6 or key.startswith("net.ipv6")
            for f, v in pkgsvc.sysctl_persistent(key)[2]:
                if v == want or f == OWN_SYSCTL:
                    continue
                if not self._vendor(f):
                    fx.edit_file(f, lambda t, k=key, w=want: te.comment_sysctl(t, k, w))
                elif os.path.basename(f) > own_base:
                    override = os.path.join("/etc/sysctl.d", os.path.basename(f))
                    base = read_text(override) or read_text(f) or ""
                    fx.write_file(override, te.comment_sysctl(base, key, want))
                    fx.note("%s 設定 %s=%s 會覆寫本工具設定，已建立 %s 覆寫（套件檔案不修改）" % (f, key, v, override))
                # 排序在前的套件檔案會被 60-gcb-checker.conf 覆寫，不需處理
            fx.edit_file(OWN_SYSCTL, lambda t, k=key, w=want: te.set_kv(t, k, w))
            if rt != want:
                fx.sysctl_set(key, want)
        fx.run(["sysctl", "-w", "net.ipv4.route.flush=1"], "刷新 IPv4 路由快取", check=False)
        if v6:
            fx.run(["sysctl", "-w", "net.ipv6.route.flush=1"], "刷新 IPv6 路由快取", check=False)
        if self.fix_note:
            fx.note(self.fix_note)


RA_NM_NOTE = ("NetworkManager 管理的介面由 NetworkManager 自行處理路由器公告（不受 accept_ra 影響），"
              "僅設定 sysctl 不一定能阻擋；如需完全阻擋請以 nmcli connection modify <連線> ipv6.method manual 或 disabled 調整")


# [AcceptRa] RHEL8 0124、0125 / RHEL9 0124、0125 阻擋 IPv6 路由器公告訊息（B 類）
class AcceptRa(RhelSysctl):
    def __init__(self, title, key, ids):
        RhelSysctl.__init__(self, title, [(key, "0")], ids, risk="B")

    def check(self, ctx):
        c = RhelSysctl.check(self, ctx)
        if c.status in (PASS, FAIL) and nm_active():
            c.current += "；NetworkManager 運作中，其管理的介面可能仍會處理路由器公告"
        return c

    def fix(self, ctx, fx):
        ra = ra_default_routes()
        RhelSysctl.fix(self, ctx, fx)
        if ra:
            fx.note("目前有經由路由器公告取得的 IPv6 預設路由（%s），阻擋後可能失去 IPv6 連線，若有異常請回滾本項"
                    % "；".join(ra[:2]))
        if nm_active():
            fx.note(RA_NM_NOTE)


# [NetModule] RHEL8 0126–0129 / RHEL9 0126–0129 DCCP、SCTP、RDS、TIPC 協定
class NetModule(Module):
    """generic.Module 加上「使用中」判斷：使用中時略過；加 --include-risky 時寫入設定，無法卸載列為部分修復。"""

    def __init__(self, module, n, title):
        Module.__init__(self, module, _both(n), category="網路設定", title=title,
                        in_use=lambda ctx, m=module: module_in_use(m))

    def check(self, ctx):
        c = Module.check(self, ctx)
        why = module_in_use(self.module)
        if why:
            c.current += "；" + why
        return c

    def fix(self, ctx, fx):
        if module_builtin(self.module):
            raise ManualRequired("%s 已編入核心，無法以 modprobe.d 停用，需更換核心或接受此項" % self.module)
        path = "/etc/modprobe.d/%s.conf" % self.module
        fx.edit_file(path, lambda t: te.modprobe_conf(t, self.module, "/bin/true"))
        if self.module not in loaded_modules():
            return
        why = module_in_use(self.module)
        r = fx.run(["modprobe", "-r", self.module], "卸載 %s 模組" % self.module, check=False)
        if r is not None and not r.ok:
            fx.partial = True
            fx.note("已寫入 %s，但 %s 模組無法卸載（%s）；請停止使用該協定的程式後執行 modprobe -r %s，或重開機後生效"
                    % (path, self.module, why or r.text()[-200:], self.module))


# [Wireless] RHEL8 0130 / RHEL9 0130 無線網路介面（B 類）
class Wireless(Rule):
    category = "網路設定"
    title = "無線網路介面"
    expected = "停用（nmcli radio all off，或以 modprobe.d 封鎖無線網卡驅動）"
    risk = "B"
    CONF = "/etc/modprobe.d/disable_wireless.conf"

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _ifaces():
        found = set()
        for pat in ("/sys/class/net/*/wireless", "/sys/class/net/*/phy80211"):
            for p in glob.glob(pat):
                found.add(os.path.basename(os.path.dirname(p)))
        return sorted(found)

    @staticmethod
    def _radio():
        out = {}
        for kind in ("wifi", "wwan"):
            r = run(["nmcli", "radio", kind], timeout=15)
            out[kind] = r.out.strip() if r.ok else "未知"
        return out

    def _modules(self):
        """回傳 ({介面: 驅動模組}, [找不到模組的介面])。"""
        mods, missing = {}, []
        for i in self._ifaces():
            link = "/sys/class/net/%s/device/driver/module" % i
            if os.path.exists(link):
                mods[i] = os.path.basename(os.path.realpath(link))
            else:
                missing.append(i)
        return mods, missing

    def check(self, ctx):
        if not self._ifaces():
            return Check(PASS, "系統沒有無線網路介面（已符合停用）")
        if nm_active():
            radio = self._radio()
            ok = all(v == "disabled" for v in radio.values())
            return Check(PASS if ok else FAIL, "NetworkManager：wifi=%s、wwan=%s" % (radio["wifi"], radio["wwan"]))
        mods, missing = self._modules()
        texts = [read_text(f) or "" for f in modprobe_files()]
        loaded = loaded_modules()
        cur, ok, reboot = [], not missing, False
        for i, m in sorted(mods.items()):
            inst, bl = te.modprobe_status(texts, m)
            ok = ok and inst and bl
            reboot = reboot or (inst and bl and m in loaded)
            cur.append("%s（驅動 %s）：%s" % (i, m, "已封鎖" if inst and bl else "未封鎖"))
        if missing:
            cur.append("找不到驅動模組：%s" % "、".join(missing))
        text = "；".join(cur)
        if ok and reboot:
            text += "（模組仍載入中，需重開機生效）"
        return Check(PASS if ok else FAIL, text)

    def fix(self, ctx, fx):
        via = sorted(set(self._ifaces()) & default_route_ifaces())
        if via:
            raise ManualRequired("目前預設路由經由無線介面 %s，停用會中斷網路連線；請先改用有線網路後再處理" % "、".join(via))
        if nm_active():
            radio = self._radio()
            for kind in ("wifi", "wwan"):
                if radio[kind] == "enabled":
                    fx.add_undo(["nmcli", "radio", kind, "on"], "恢復 %s 無線電" % kind)
            fx.run(["nmcli", "radio", "all", "off"], "以 nmcli 關閉所有無線電（原 wifi=%s、wwan=%s）"
                   % (radio["wifi"], radio["wwan"]))
            return
        mods, missing = self._modules()
        if missing:
            raise ManualRequired("無法取得無線介面 %s 的驅動模組（可能已編入核心），請人工於 BIOS 或以 rfkill 停用"
                                 % "、".join(missing))

        def _edit(t):
            for m in sorted(set(mods.values())):
                t = te.modprobe_conf(t, m, "/bin/true")
            return t
        fx.edit_file(self.CONF, _edit)
        fx.note("已封鎖無線網卡驅動（%s），模組目前仍載入中，需重開機生效" % "、".join(sorted(set(mods.values()))))


# [Promisc] RHEL8 0131 / RHEL9 0131 網路介面混雜模式（C 類）
class Promisc(Rule):
    category = "網路設定"
    risk = "C"
    title = "網路介面混雜模式"
    expected = "停用"
    manual_hint = ("確認混雜模式的用途（橋接器成員、虛擬化／容器網路、IDS、tcpdump 屬正常使用）後，"
                   "以 ip link set dev <介面> promisc off 關閉；不要照文件同時執行 multicast off，"
                   "會使 IPv6 鄰居探索、VRRP／keepalived 等多播功能失效")

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def interfaces(base="/sys/class/net"):
        """回傳 [(介面, 說明)]，只列出處於混雜模式者。"""
        out = []
        for d in sorted(glob.glob(os.path.join(base, "*"))):
            try:
                flags = int((read_text(os.path.join(d, "flags")) or "0").strip(), 16)
            except ValueError:
                continue
            if not flags & 0x100:  # IFF_PROMISC
                continue
            name = os.path.basename(d)
            kind = []
            if os.path.exists(os.path.join(d, "brport")):
                kind.append("橋接器成員")
            elif os.path.exists(os.path.join(d, "bonding_slave")) or os.path.exists(os.path.join(d, "master")):
                kind.append("bond／team 成員")
            iflink = (read_text(os.path.join(d, "iflink")) or "").strip()
            ifindex = (read_text(os.path.join(d, "ifindex")) or "").strip()
            if iflink and ifindex and iflink != ifindex:
                kind.append("veth 或虛擬介面")
            out.append((name, "、".join(kind)))
        return out

    def check(self, ctx):
        found = self.interfaces()
        if not found:
            return Check(PASS, "沒有處於混雜模式的網路介面")
        return Check(FAIL, "混雜模式介面：" + "、".join("%s（%s）" % (n, k) if k else n for n, k in found))


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

# [RpFilterAll] RHEL8 0121 / RHEL9 0121 所有網路介面啟用逆向路徑過濾功能（含各介面實際值）
class RpFilterAll(RpFilterIfaces, RhelSysctl):
    def check(self, ctx):
        return self._rp_check(RhelSysctl.check(self, ctx))

    def fix(self, ctx, fx):
        RhelSysctl.fix(self, ctx, fx)
        self._rp_fix(fx, OWN_SYSCTL)


RP_NOTE = ("rp_filter=1 為嚴格模式：多網卡且路由不對稱（封包從 A 介面進、從 B 介面回）的主機會丟棄合法封包，"
           "若有連線異常請檢查路由或回滾本項")


def _sysctl2(t8, t9, settings, n, **kw):
    """兩版設定相同、但 GCB 原則設定名稱不同：各建一個規則物件。"""
    return [RhelSysctl(t8, settings, R(r8=n), **kw), RhelSysctl(t9, settings, R(r9=n), **kw)]


def _svc(title, units, n, risk="B"):
    r = ServiceDisabled(title, units, _both(n))
    r.risk = risk
    return r


RULES = [
    # RHEL8 0092 / RHEL9 0092 xinetd 套件
    PkgAbsent("xinetd 套件", "xinetd", _both(92), category="系統服務", units=("xinetd.service",)),
    # RHEL8 0093 / RHEL9 0093 chrony 校時設定（C 類：校時伺服器位址需環境資訊）
    ChronySource(_both(93)),
    # RHEL8 0094 / RHEL9 0094 rsyncd 服務（rsync-daemon 另有 rsyncd.socket，一併遮蔽）
    _svc("rsyncd 服務", ["rsyncd.service", "rsyncd.socket"], 94),
    # RHEL8 0095 / RHEL9 0095 avahi-daemon 服務 → common.py
    # RHEL8 0096 / RHEL9 0096 SNMP 服務
    SnmpV3Only(_both(96)),
    # RHEL8 0097 / RHEL9 0097 Squid 服務
    _svc("Squid 服務", ["squid.service"], 97),
    # RHEL8 0098 / RHEL9 0098 Samba 服務
    _svc("Samba 服務", ["smb.service"], 98),
    # RHEL8 0099 / RHEL9 0099 FTP 伺服器
    _svc("FTP 伺服器", ["vsftpd.service"], 99),
    # RHEL8 0100 / RHEL9 0100 NIS 伺服器
    _svc("NIS 伺服器", ["ypserv.service"], 100),
    # RHEL8 0101 / RHEL9 0101 kdump 服務
    Kdump(_both(101)),
    # RHEL8 0102 / RHEL9 0102 NIS 用戶端套件
    NisClientAbsent("NIS 用戶端套件", "ypbind", _both(102), risk="B", units=("ypbind.service",)),
    # RHEL8 0103 / RHEL9 0103 telnet 用戶端套件 → common.py
    # RHEL8 0104 / RHEL9 0104 telnet 伺服器套件
    PkgAbsent("telnet 伺服器套件", "telnet-server", _both(104), units=("telnet.socket",)),
    # RHEL8 0105 / RHEL9 0105 rsh 伺服器套件
    PkgAbsent("rsh 伺服器套件", "rsh-server", _both(105),
              units=("rsh.socket", "rlogin.socket", "rexec.socket")),
    # RHEL8 0106 / RHEL9 0106 tftp 伺服器套件
    PkgAbsent("tftp 伺服器套件", "tftp-server", _both(106), risk="B", units=("tftp.socket", "tftp.service")),
    # RHEL8 0107 / RHEL9 0107 更新套件後移除舊版本元件
    DnfCleanRequirements(_both(107)),
    # RHEL8 0108 / RHEL9 0108 IP 轉送 → common.py
    # RHEL8 0109 / RHEL9 0109 所有網路介面禁止傳送 ICMP 重新導向封包 → common.py
    # RHEL8 0110 / RHEL9 0110 預設網路介面禁止傳送 ICMP 重新導向封包 → common.py
]

RULES += (
    # RHEL8 0111 所有網路介面接受來源路由封包 / RHEL9 0111 所有網路介面阻擋來源路由封包
    _sysctl2("所有網路介面接受來源路由封包", "所有網路介面阻擋來源路由封包",
             [("net.ipv4.conf.all.accept_source_route", "0"), ("net.ipv6.conf.all.accept_source_route", "0")], 111)
    # RHEL8 0112 預設網路介面接受來源路由封包 / RHEL9 0112 預設網路介面阻擋來源路由封包
    + _sysctl2("預設網路介面接受來源路由封包", "預設網路介面阻擋來源路由封包",
               [("net.ipv4.conf.default.accept_source_route", "0"),
                ("net.ipv6.conf.default.accept_source_route", "0")], 112)
    # RHEL8 0113 所有網路介面接受 ICMP 重新導向封包 / RHEL9 0113 所有網路介面阻擋 ICMP 重新導向封包
    + _sysctl2("所有網路介面接受 ICMP 重新導向封包", "所有網路介面阻擋 ICMP 重新導向封包",
               [("net.ipv4.conf.all.accept_redirects", "0"), ("net.ipv6.conf.all.accept_redirects", "0")], 113)
    # RHEL8 0114 預設網路介面接受 ICMP 重新導向封包 / RHEL9 0114 預設網路介面阻擋 ICMP 重新導向封包
    + _sysctl2("預設網路介面接受 ICMP 重新導向封包", "預設網路介面阻擋 ICMP 重新導向封包",
               [("net.ipv4.conf.default.accept_redirects", "0"),
                ("net.ipv6.conf.default.accept_redirects", "0")], 114)
    # RHEL8 0115 所有網路介面接受安全的 ICMP 重新導向封包 / RHEL9 0115 所有網路介面阻擋安全之 ICMP 重新導向封包
    + _sysctl2("所有網路介面接受安全的 ICMP 重新導向封包", "所有網路介面阻擋安全之 ICMP 重新導向封包",
               [("net.ipv4.conf.all.secure_redirects", "0")], 115)
    # RHEL8 0116 預設網路介面接受安全的 ICMP 重新導向封包 / RHEL9 0116 預設網路介面阻擋安全之 ICMP 重新導向封包
    + _sysctl2("預設網路介面接受安全的 ICMP 重新導向封包", "預設網路介面阻擋安全之 ICMP 重新導向封包",
               [("net.ipv4.conf.default.secure_redirects", "0")], 116)
)

RULES += [
    # RHEL8 0117 / RHEL9 0117 所有網路介面記錄可疑封包
    RhelSysctl("所有網路介面記錄可疑封包", [("net.ipv4.conf.all.log_martians", "1")], _both(117)),
    # RHEL8 0118 / RHEL9 0118 預設網路介面記錄可疑封包
    RhelSysctl("預設網路介面記錄可疑封包", [("net.ipv4.conf.default.log_martians", "1")], _both(118)),
    # RHEL8 0119 / RHEL9 0119 不回應 ICMP 廣播要求
    RhelSysctl("不回應 ICMP 廣播要求", [("net.ipv4.icmp_echo_ignore_broadcasts", "1")], _both(119)),
    # RHEL8 0120 / RHEL9 0120 忽略偽造之 ICMP 錯誤訊息
    RhelSysctl("忽略偽造之 ICMP 錯誤訊息", [("net.ipv4.icmp_ignore_bogus_error_responses", "1")], _both(120)),
    # RHEL8 0121 / RHEL9 0121 所有網路介面啟用逆向路徑過濾功能（文件 sed 樣式有誤，不照抄；B 類同 Ubuntu）
    RpFilterAll("所有網路介面啟用逆向路徑過濾功能", [("net.ipv4.conf.all.rp_filter", "1")], _both(121),
               risk="B", fix_note=RP_NOTE),
    # RHEL8 0122 / RHEL9 0122 預設網路介面啟用逆向路徑過濾功能
    RhelSysctl("預設網路介面啟用逆向路徑過濾功能", [("net.ipv4.conf.default.rp_filter", "1")], _both(122),
               risk="B", fix_note=RP_NOTE),
    # RHEL8 0123 / RHEL9 0123 TCP SYN cookies（文件 grep 樣式會註解所有行，改為只註解值不為 1 的行）
    RhelSysctl("TCP SYN cookies", [("net.ipv4.tcp_syncookies", "1")], _both(123)),
    # RHEL8 0124 所有網路介面接受 IPv6 路由器公告訊息 / RHEL9 0124 所有網路介面阻擋 IPv6 路由器公告訊息
    AcceptRa("所有網路介面接受 IPv6 路由器公告訊息", "net.ipv6.conf.all.accept_ra", R(r8=124)),
    AcceptRa("所有網路介面阻擋 IPv6 路由器公告訊息", "net.ipv6.conf.all.accept_ra", R(r9=124)),
    # RHEL8 0125 預設網路介面接受 IPv6 路由器公告訊息 / RHEL9 0125 預設網路介面阻擋 IPv6 路由器公告訊息
    AcceptRa("預設網路介面接受 IPv6 路由器公告訊息", "net.ipv6.conf.default.accept_ra", R(r8=125)),
    AcceptRa("預設網路介面阻擋 IPv6 路由器公告訊息", "net.ipv6.conf.default.accept_ra", R(r9=125)),
    # RHEL8 0126 / RHEL9 0126 DCCP 協定
    NetModule("dccp", 126, "DCCP 協定"),
    # RHEL8 0127 / RHEL9 0127 SCTP 協定
    NetModule("sctp", 127, "SCTP 協定"),
    # RHEL8 0128 / RHEL9 0128 RDS 協定
    NetModule("rds", 128, "RDS 協定"),
    # RHEL8 0129 / RHEL9 0129 TIPC 協定
    NetModule("tipc", 129, "TIPC 協定"),
    # RHEL8 0130 / RHEL9 0130 無線網路介面
    Wireless(_both(130)),
    # RHEL8 0131 / RHEL9 0131 網路介面混雜模式（C 類：只回報）
    Promisc(_both(131)),
]
