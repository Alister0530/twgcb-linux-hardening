# -*- coding: utf-8 -*-
"""Ubuntu 22.04 系統服務、安裝與維護軟體、網路設定（TWGCB-01-014-0079 ～ 0111）。"""
import glob
import os

from ... import pkgsvc
from ... import textedit as te
from ...fixer import ManualRequired
from ...util import read_text, run, which
from ..base import FAIL, PASS, Check, Rule
from ..common import (PackageAbsent, RpFilterIfaces, ServiceDisabled, Sysctl, modprobe_files,
                      sysctl_override_path)
from ..generic import Module, module_builtin
from .helpers import U

OWN_SYSCTL = "/etc/sysctl.d/60-gcb-checker.conf"


# ====================================================================
# 共用小工具
# ====================================================================

def _svc(title, units, n, risk="A", precondition=None):
    r = ServiceDisabled(title, units, U(n))
    r.risk = risk
    if precondition:
        r.precondition = precondition
    return r


def _rsync_daemon_in_use(ctx):
    """rsync 以 daemon 模式運作中（有 /etc/rsyncd.conf 且服務執行中）時先略過。"""
    if ctx.include_risky or not os.path.exists("/etc/rsyncd.conf"):
        return None
    if pkgsvc.svc_state("rsync.service")[1] == "active":
        return "rsync.service 執行中且存在 /etc/rsyncd.conf，可能有檔案同步作業依賴此服務；確認後可加 --include-risky"
    return None


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


def ufw_enabled():
    v = te.get_kv(read_text("/etc/ufw/ufw.conf") or "", "ENABLED") or ""
    return v.strip("\"'").lower() == "yes"


def ufw_sysctl_file():
    """ufw 啟動時套用的 sysctl 檔（/etc/default/ufw 的 IPT_SYSCTL）。"""
    v = te.get_kv(read_text("/etc/default/ufw") or "", "IPT_SYSCTL")
    return v.strip("\"'") if v else "/etc/ufw/sysctl.conf"


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


# ====================================================================
# 客製規則
# ====================================================================

# [PackagePurge] TWGCB-01-014-0085 NIS 用戶端套件、0086 rsh 用戶端套件、0087 talk 用戶端套件
class PackagePurge(PackageAbsent):
    """apt purge 前先備份套件的設定檔（conffiles），回滾重新安裝後還原。"""

    def __init__(self, title, pkg, ids, nsswitch_key=None):
        PackageAbsent.__init__(self, title, pkg, ids)
        self.nsswitch_key = nsswitch_key

    def _conffiles(self):
        r = run(["dpkg-query", "-W", "-f=${Conffiles}\n", self.pkg], timeout=30)
        files = []
        for line in r.out.splitlines() if r.ok else []:
            p = line.split()
            if p and p[0].startswith("/") and os.path.isfile(p[0]):
                files.append(p[0])
        return files

    def _nsswitch_uses(self):
        if not self.nsswitch_key:
            return []
        used = []
        for line in (read_text("/etc/nsswitch.conf") or "").splitlines():
            s = line.split("#", 1)[0]
            if ":" in s and self.nsswitch_key in s.split(":", 1)[1].split():
                used.append(s.split(":", 1)[0].strip())
        return used

    def fix(self, ctx, fx):
        used = self._nsswitch_uses()
        if used:
            raise ManualRequired("/etc/nsswitch.conf 的 %s 仍使用 %s 查詢帳號資訊，移除套件可能導致無法登入；"
                                 "請先改用其他帳號來源並移除 nsswitch.conf 中的 %s 後再移除套件"
                                 % ("、".join(used), self.nsswitch_key, self.nsswitch_key))
        for f in self._conffiles():
            fx.backup_only(f)
        fx.pkg_remove(self.pkg)


# [NetSysctl] TWGCB-01-014-0092 ～ 0106 網路核心參數（含 ufw 的 sysctl 覆寫檢查）
class NetSysctl(Sysctl):
    """沿用 common.Sysctl，另外：
    - ufw 啟用時會在啟動時套用 /etc/ufw/sysctl.conf，其中的衝突值（例如 log_martians=0）一併檢查與註解
    - 修改設定檔時寫入連結的實際檔案（/etc/sysctl.d/99-sysctl.conf 是指向 /etc/sysctl.conf 的連結）
    """

    def __init__(self, title, settings, n, risk="A", fix_note=None):
        Sysctl.__init__(self, title, settings, U(n))
        self.risk = risk
        self.fix_note = fix_note

    def _ufw_conflicts(self):
        path = ufw_sysctl_file()
        last = dict(te.parse_sysctl(read_text(path)))
        bad = []
        for key, want in self.settings:
            if pkgsvc.sysctl_runtime(key) is None:
                continue
            if key in last and last[key] != want:
                bad.append((key, last[key]))
        return path, bad

    def check(self, ctx):
        c = Sysctl.check(self, ctx)
        if c.status not in (PASS, FAIL):
            return c
        path, bad = self._ufw_conflicts()
        if bad:
            kv = "、".join("%s=%s" % b for b in bad)
            if ufw_enabled():
                c.status = FAIL
                c.current += "；ufw 啟用中，%s 設定 %s 會在 ufw 啟動時覆寫" % (path, kv)
            else:
                c.current += "；%s 設定 %s（ufw 未啟用，啟用後會覆寫）" % (path, kv)
        return c

    def fix(self, ctx, fx):
        v6 = False
        for key, want, rt, pv, src in self._status():
            v6 = v6 or key.startswith("net.ipv6")
            # 依文件作法：註解其他檔案中衝突的設定，再寫入固定檔案
            for f, v in pkgsvc.sysctl_persistent(key)[2]:
                if v != want and f != OWN_SYSCTL:
                    # /etc 以外（/usr/lib、/run）的檔案不直接修改，改寫 /etc/sysctl.d 同名檔覆蓋
                    fx.edit_file(sysctl_override_path(f), lambda t, k=key, w=want, src=f:
                                 te.comment_sysctl(t or read_text(src) or "", k, w))
            fx.edit_file(OWN_SYSCTL, lambda t, k=key, w=want: te.set_kv(t, k, w))
            if rt != want:
                fx.sysctl_set(key, want)
        # ufw 未啟用也一併註解，避免之後啟用 ufw 時被覆寫
        path, bad = self._ufw_conflicts()
        for key, _ in bad:
            fx.edit_file(os.path.realpath(path), lambda t, k=key, w=dict(self.settings)[key]: te.comment_sysctl(t, k, w))
        fx.run(["sysctl", "-w", "net.ipv4.route.flush=1"], "刷新 IPv4 路由快取", check=False)
        if v6:
            fx.run(["sysctl", "-w", "net.ipv6.route.flush=1"], "刷新 IPv6 路由快取", check=False)
        if self.fix_note:
            fx.note(self.fix_note)


# [NetModule] TWGCB-01-014-0107 DCCP、0108 SCTP、0109 RDS、0110 TIPC 協定
class NetModule(Module):
    """generic.Module 加上「使用中」判斷：使用中時略過；加 --include-risky 時寫入設定，無法卸載列為部分修復。"""

    def __init__(self, module, n, title):
        Module.__init__(self, module, U(n), category="網路設定", title=title,
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
        fx.edit_file(path, lambda t: te.modprobe_conf(t, self.module, "/bin/false"))
        if self.module not in loaded_modules():
            return
        why = module_in_use(self.module)
        r = fx.run(["modprobe", "-r", self.module], "卸載 %s 模組" % self.module, check=False)
        if r is not None and not r.ok:
            fx.partial = True
            fx.note("已寫入 %s，但 %s 模組無法卸載（%s）；請停止使用該協定的程式後執行 modprobe -r %s，或重開機後生效"
                    % (path, self.module, why or r.text()[-200:], self.module))


# [Wireless] TWGCB-01-014-0111 無線網路介面
class Wireless(Rule):
    category = "網路設定"
    title = "無線網路介面"
    expected = "停用（nmcli radio all off，或以 modprobe.d 封鎖無線網卡驅動）"
    risk = "B"
    needs_reboot = True
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
    def _nm():
        return bool(which("nmcli")) and pkgsvc.svc_state("NetworkManager.service")[1] == "active"

    @staticmethod
    def _radio():
        """回傳 {wifi: enabled/disabled, wwan: ...}。"""
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
        if not self._ifaces():  # 與 GCB 修復腳本一致：沒有無線介面即已符合「停用」
            return Check(PASS, "系統沒有無線網路介面（已符合停用）")
        if self._nm():
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
        ifaces = self._ifaces()
        via = sorted(set(ifaces) & default_route_ifaces())
        if via:
            raise ManualRequired("目前預設路由經由無線介面 %s，停用會中斷網路連線；請先改用有線網路後再處理" % "、".join(via))
        if self._nm():
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
                t = te.modprobe_conf(t, m, "/bin/false")
            return t
        fx.edit_file(self.CONF, _edit)
        fx.note("已封鎖無線網卡驅動（%s），模組目前仍載入中，需重開機生效" % "、".join(sorted(set(mods.values()))))


# [RpFilterAll] TWGCB-01-014-0102 所有網路介面啟用逆向路徑過濾功能（含各介面實際值）
class RpFilterAll(RpFilterIfaces, NetSysctl):
    def check(self, ctx):
        return self._rp_check(NetSysctl.check(self, ctx))

    def fix(self, ctx, fx):
        NetSysctl.fix(self, ctx, fx)
        self._rp_fix(fx, OWN_SYSCTL)


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

RP_NOTE = ("rp_filter=1 為嚴格模式：多網卡且路由不對稱（封包從 A 介面進、從 B 介面回）的主機會丟棄合法封包，"
           "若有連線異常請檢查路由或回滾本項")
RA_NOTE = ("accept_ra=0 於重開機後套用到新建立的介面：以 SLAAC/路由器公告取得 IPv6 位址或預設路由的主機"
           "（非 systemd-networkd 管理）重開機後可能失去 IPv6 連線；systemd-networkd 會自行處理路由器公告，"
           "若需完全阻擋請在 netplan 設定 accept-ra: false")

RULES = [
    # 0079 avahi-daemon 服務 → common.py
    # 0080 Samba 服務
    _svc("Samba 服務", ["smbd.service"], 80, risk="B"),
    # 0081 Squid 服務
    _svc("Squid 服務", ["squid.service"], 81, risk="B"),
    # 0082 SNMP 服務
    _svc("SNMP 服務", ["snmpd.service"], 82, risk="B"),
    # 0083 FTP 伺服器
    _svc("FTP 伺服器", ["vsftpd.service"], 83, risk="B"),
    # 0084 rsync 服務（Ubuntu 22.04 的 unit 為 rsync.service）
    _svc("rsync 服務", ["rsync.service"], 84, precondition=_rsync_daemon_in_use),
    # 0085 NIS 用戶端套件
    PackagePurge("NIS 用戶端套件", "nis", U(85), nsswitch_key="nis"),
    # 0086 rsh 用戶端套件
    PackagePurge("rsh 用戶端套件", "rsh-client", U(86)),
    # 0087 talk 用戶端套件
    PackagePurge("talk 用戶端套件", "talk", U(87)),
    # 0088 telnet 用戶端套件 → common.py
    # 0089 IP 轉送 → common.py
    # 0090 所有網路介面禁止傳送 ICMP 重新導向封包 → common.py
    # 0091 預設網路介面禁止傳送 ICMP 重新導向封包 → common.py
    # 0092 所有網路介面阻擋來源路由封包
    NetSysctl("所有網路介面阻擋來源路由封包", [("net.ipv4.conf.all.accept_source_route", "0"),
                                              ("net.ipv6.conf.all.accept_source_route", "0")], 92),
    # 0093 預設網路介面阻擋來源路由封包
    NetSysctl("預設網路介面阻擋來源路由封包", [("net.ipv4.conf.default.accept_source_route", "0"),
                                              ("net.ipv6.conf.default.accept_source_route", "0")], 93),
    # 0094 所有網路介面阻擋 ICMP 重新導向封包
    NetSysctl("所有網路介面阻擋 ICMP 重新導向封包", [("net.ipv4.conf.all.accept_redirects", "0"),
                                                     ("net.ipv6.conf.all.accept_redirects", "0")], 94),
    # 0095 預設網路介面阻擋 ICMP 重新導向封包
    NetSysctl("預設網路介面阻擋 ICMP 重新導向封包", [("net.ipv4.conf.default.accept_redirects", "0"),
                                                     ("net.ipv6.conf.default.accept_redirects", "0")], 95),
    # 0096 所有網路介面阻擋安全之 ICMP 重新導向封包
    NetSysctl("所有網路介面阻擋安全之 ICMP 重新導向封包", [("net.ipv4.conf.all.secure_redirects", "0")], 96),
    # 0097 預設網路介面阻擋安全之 ICMP 重新導向封包
    NetSysctl("預設網路介面阻擋安全之 ICMP 重新導向封包", [("net.ipv4.conf.default.secure_redirects", "0")], 97),
    # 0098 所有網路介面記錄可疑封包
    NetSysctl("所有網路介面記錄可疑封包", [("net.ipv4.conf.all.log_martians", "1")], 98),
    # 0099 預設網路介面記錄可疑封包
    NetSysctl("預設網路介面記錄可疑封包", [("net.ipv4.conf.default.log_martians", "1")], 99),
    # 0100 不回應 ICMP 廣播要求
    NetSysctl("不回應 ICMP 廣播要求", [("net.ipv4.icmp_echo_ignore_broadcasts", "1")], 100),
    # 0101 忽略偽造之 ICMP 錯誤訊息
    NetSysctl("忽略偽造之 ICMP 錯誤訊息", [("net.ipv4.icmp_ignore_bogus_error_responses", "1")], 101),
    # 0102 所有網路介面啟用逆向路徑過濾功能
    RpFilterAll("所有網路介面啟用逆向路徑過濾功能", [("net.ipv4.conf.all.rp_filter", "1")], 102,
              risk="B", fix_note=RP_NOTE),
    # 0103 預設網路介面啟用逆向路徑過濾功能
    NetSysctl("預設網路介面啟用逆向路徑過濾功能", [("net.ipv4.conf.default.rp_filter", "1")], 103,
              risk="B", fix_note=RP_NOTE),
    # 0104 TCP SYN cookies
    NetSysctl("TCP SYN cookies", [("net.ipv4.tcp_syncookies", "1")], 104),
    # 0105 所有網路介面阻擋 IPv6 路由器公告訊息（IPv6 停用時不適用）
    NetSysctl("所有網路介面阻擋 IPv6 路由器公告訊息", [("net.ipv6.conf.all.accept_ra", "0")], 105,
              risk="B", fix_note=RA_NOTE),
    # 0106 預設網路介面阻擋 IPv6 路由器公告訊息（IPv6 停用時不適用）
    NetSysctl("預設網路介面阻擋 IPv6 路由器公告訊息", [("net.ipv6.conf.default.accept_ra", "0")], 106,
              risk="B", fix_note=RA_NOTE),
    # 0107 DCCP 協定
    NetModule("dccp", 107, "DCCP 協定"),
    # 0108 SCTP 協定
    NetModule("sctp", 108, "SCTP 協定"),
    # 0109 RDS 協定
    NetModule("rds", 109, "RDS 協定"),
    # 0110 TIPC 協定
    NetModule("tipc", 110, "TIPC 協定"),
    # 0111 無線網路介面
    Wireless(U(111)),
]
