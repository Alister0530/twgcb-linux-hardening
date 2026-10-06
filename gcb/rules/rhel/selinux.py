# -*- coding: utf-8 -*-
"""RHEL 8 / 9 SELinux、cron 設定、防火牆（firewalld / nftables / iptables）規則。

  SELinux、cron   RHEL 8 0185–0207 ↔ RHEL 9 0183–0205
  Firewalld       RHEL 8 0244–0248 ↔ RHEL 9 0242–0246
  Nftables        RHEL 8 0249–0255 ↔ RHEL 9 0247–0253
  Iptables        RHEL 8 0256–0261（RHEL 9 無此表格）

防火牆安全原則（docs/決策紀錄.md）：
  - 三套防火牆多選一，依 config.ini firewall_backend（auto 時依 fw_backend() 的判斷順序），其他兩套判不適用。
  - 啟用防火牆、預設拒絕「進入」為 B 類：修復前先以 sshd -T 取得 sshd 埠（取不到就停止），
    放行 sshd 埠、迴路介面與已建立連線，修復後立即確認 SSH 放行規則存在，否則還原。
  - 預設拒絕「外出」只檢測，不自動修改（標示部分修復並提供建議規則）。
  - 不自動安裝會與現有防火牆衝突的套件（iptables-services）。
  - 回滾：firewalld 備份 /etc/firewalld；nftables / iptables 先備份目前規則集並登記還原指令。
"""
import glob
import os
import re
import shlex
import socket
import tempfile
import time

from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, stamp, which, write_text_atomic
from ..base import ERROR, FAIL, PASS, Check, Rule
from ..common import VIRT_IFACES, VIRT_UNITS, PackageAbsent, ServiceEnabled
from ..generic import FilePerm, PackagePresent, installed
from .helpers import R

SEL = "SELinux"
CRON = "cron 設定"
FWD = "Firewalld 配置"
NFT = "Nftables 配置"
IPT = "Iptables 配置"

SELINUX_CONF = "/etc/selinux/config"
DEFAULT_GRUB = "/etc/default/grub"
BLS_ENTRIES = "/boot/loader/entries/*.conf"
GRUBENV = "/boot/grub2/grubenv"


# ====================================================================
# 共用小工具
# ====================================================================

def _getenforce():
    """回傳 Enforcing / Permissive / Disabled；無法執行時回傳 None。"""
    if not which("getenforce"):
        return None
    r = run(["getenforce"], timeout=10)
    return r.out.strip() if r.ok else None


def _write_backup(ctx, fx, name, text):
    """把備份內容（規則集）寫到本次執行的備份目錄，回傳路徑；預覽模式回傳 None。"""
    if fx.dry:
        fx.step("備份規則集", "[預覽] %s" % name, "預覽")
        return None
    d = ctx.journal.backup_dir
    if not os.path.isdir(d):
        os.makedirs(d, 0o700)
    path = os.path.join(d, "%s_%s_%s" % (fx.rid[-4:], stamp(), name))
    write_text_atomic(path, text, 0o600)
    fx.step("備份規則集", path, "成功")
    return path


# ====================================================================
# SELinux
# ====================================================================

SELINUX_BAD_ARGS = ("selinux=0", "enforcing=0")
_GRUB_LINE = re.compile(r'^(\s*(GRUB_CMDLINE_LINUX|GRUB_CMDLINE_LINUX_DEFAULT)=)(["\']?)(.*?)\3\s*$')


def grub_default_bad_args(text, bad=SELINUX_BAD_ARGS):
    """/etc/default/grub 的 GRUB_CMDLINE_LINUX(_DEFAULT) 中出現的停用參數。"""
    found = []
    for line in (text or "").splitlines():
        if line.strip().startswith("#"):
            continue
        m = _GRUB_LINE.match(line)
        if m:
            found += [a for a in m.group(4).split() if a in bad and a not in found]
    return found


def grub_default_remove_args(text, bad=SELINUX_BAD_ARGS):
    """移除 GRUB_CMDLINE_LINUX 與 GRUB_CMDLINE_LINUX_DEFAULT 中的停用參數，保留其他參數。"""
    out = []
    for line in (text or "").splitlines():
        m = None if line.strip().startswith("#") else _GRUB_LINE.match(line)
        if m and any(a in bad for a in m.group(4).split()):
            args = [a for a in m.group(4).split() if a not in bad]
            line = '%s"%s"' % (m.group(1), " ".join(args))
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


def grubby_bad_entries(text, bad=SELINUX_BAD_ARGS):
    """解析 grubby --info=ALL：回傳 [(kernel, [停用參數])]。"""
    out, kernel = [], None
    for line in (text or "").splitlines():
        if line.startswith("kernel="):
            kernel = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("args=") and kernel:
            args = line.split("=", 1)[1].strip().strip('"').split()
            hit = [a for a in args if a in bad]
            if hit:
                out.append((kernel, hit))
    return out


def grubenv_kernelopts(text):
    for line in (text or "").splitlines():
        if line.startswith("kernelopts="):
            return line.split("=", 1)[1].strip()
    return None


# [SelinuxBootloader] RHEL8 0186 / RHEL9 0184 開機載入程式啟用 SELinux
class SelinuxBootloader(Rule):
    category = SEL
    risk = "B"
    needs_reboot = True
    title = "開機載入程式啟用 SELinux"
    expected = "啟用（開機參數不含 selinux=0、enforcing=0）"

    def __init__(self, ids):
        self.ids = ids

    def _status(self, ctx):
        """回傳 (問題清單, 錯誤訊息)。"""
        if not which("grubby"):
            return None, "找不到 grubby"
        r = run(["grubby", "--info=ALL"], timeout=60)
        if not r.ok:
            return None, "grubby 執行失敗"
        bad = ["%s：%s" % (k, " ".join(a)) for k, a in grubby_bad_entries(r.out)]
        d = grub_default_bad_args(read_text(DEFAULT_GRUB) or "")
        if d:
            bad.append("%s：%s" % (DEFAULT_GRUB, " ".join(d)))
        if ctx.osi.key == "rhel8" and which("grub2-editenv"):
            ko = grubenv_kernelopts(run(["grub2-editenv", "list"], timeout=30).out)
            hit = [a for a in (ko or "").split() if a in SELINUX_BAD_ARGS]
            if hit:
                bad.append("grubenv kernelopts：%s" % " ".join(hit))
        return bad, ""

    def check(self, ctx):
        bad, err = self._status(ctx)
        if bad is None:
            return Check(ERROR, err)
        running = [a for a in (read_text("/proc/cmdline") or "").split() if a in SELINUX_BAD_ARGS]
        rt = "；目前核心仍帶 %s（需重開機生效）" % " ".join(running) if running else ""
        if bad:
            return Check(FAIL, "含停用參數：" + "；".join(bad) + rt)
        return Check(PASS, "所有開機項目與 /etc/default/grub 皆未停用 SELinux" + rt)

    def fix(self, ctx, fx):
        bad, err = self._status(ctx)
        if bad is None:
            raise FixError(err)
        had_selinux0 = "selinux=0" in " ".join(bad) or "selinux=0" in (read_text("/proc/cmdline") or "").split()
        fx.edit_file(DEFAULT_GRUB, grub_default_remove_args)
        # grubby 會改寫 BLS 開機項目與 grubenv，先備份，回滾時還原檔案
        for f in sorted(glob.glob(BLS_ENTRIES)):
            fx.backup_only(f)
        fx.backup_only(GRUBENV)
        fx.run(["grubby", "--update-kernel=ALL", "--remove-args=%s" % " ".join(SELINUX_BAD_ARGS)],
               "以 grubby 移除所有開機項目的 selinux=0、enforcing=0")
        if ctx.osi.key == "rhel8" and which("grub2-editenv") and not fx.dry:
            ko = grubenv_kernelopts(run(["grub2-editenv", "list"], timeout=30).out)
            if ko and any(a in SELINUX_BAD_ARGS for a in ko.split()):
                new = " ".join(a for a in ko.split() if a not in SELINUX_BAD_ARGS)
                fx.run(["grub2-editenv", "-", "set", "kernelopts=%s" % new], "更新 grubenv kernelopts")
        if had_selinux0 and (_getenforce() or "Disabled") == "Disabled":
            # 原本以 selinux=0 完全停用：重開機後 SELinux 會啟用，檔案需重新標記，先以 permissive 開機
            fx.write_file("/.autorelabel", "")
            if (te.get_kv(read_text(SELINUX_CONF) or "", "SELINUX") or "").lower() == "enforcing":
                fx.edit_file(SELINUX_CONF, lambda t: te.set_kv(t, "SELINUX", "permissive", sep="="))
                fx.note("SELinux 原以 selinux=0 停用，已暫設 SELINUX=permissive 並建立 /.autorelabel；"
                        "重開機完成重新標記、確認無異常 AVC 後，再處理「SELinux 啟用狀態」項目切換為 enforcing")
            else:
                fx.note("SELinux 原以 selinux=0 停用，已建立 /.autorelabel，重開機時會重新標記檔案系統（耗時較長）")
        fx.note("開機參數已更新，重開機後生效")


# [SelinuxPolicy] RHEL8 0187 / RHEL9 0185 SELinux 政策
class SelinuxPolicy(Rule):
    category = SEL
    risk = "B"
    needs_reboot = True
    title = "SELinux 政策"
    expected = "targeted 或更嚴格之政策（SELINUXTYPE=targeted 或 mls）"
    OK_TYPES = ("targeted", "mls")

    def __init__(self, ids):
        self.ids = ids

    @staticmethod
    def _loaded():
        if not which("sestatus"):
            return None
        for line in run(["sestatus"], timeout=15).out.splitlines():
            if line.lower().startswith("loaded policy name:"):
                return line.split(":", 1)[1].strip()
        return None

    def check(self, ctx):
        v = te.get_kv(read_text(SELINUX_CONF) or "", "SELINUXTYPE")
        if v is None:
            return Check(FAIL, "SELINUXTYPE 未設定" + ("" if os.path.exists(SELINUX_CONF) else "（%s 不存在）" % SELINUX_CONF))
        cur = "SELINUXTYPE=%s" % v
        loaded = self._loaded()
        if loaded and loaded != v:
            cur += "；目前載入政策為 %s（需重開機生效）" % loaded
        if v.lower() == "minimum":
            cur += "（minimum 比 targeted 寬鬆）"
        return Check(PASS if v.lower() in self.OK_TYPES else FAIL, cur)

    def fix(self, ctx, fx):
        old = te.get_kv(read_text(SELINUX_CONF) or "", "SELINUXTYPE")
        if old and old.lower() in self.OK_TYPES:
            return
        if not os.path.exists(SELINUX_CONF):
            # 系統完全沒有 SELinux 政策：安裝政策並啟用需重新標記整個檔案系統，且套件回滾可能牽動 dnf 等受保護套件
            raise ManualRequired("%s 不存在（未安裝 SELinux 政策），請人工安裝 selinux-policy-targeted、"
                                 "建立 /.autorelabel 並重開機後再執行本工具" % SELINUX_CONF)
        if not pkgsvc.pkg_installed(ctx.osi, "selinux-policy-targeted"):
            fx.pkg_install("selinux-policy-targeted")
        fx.edit_file(SELINUX_CONF, lambda t: te.set_kv(t, "SELINUXTYPE", "targeted", sep="="))
        if old and (_getenforce() or "Disabled") != "Disabled":
            fx.write_file("/.autorelabel", "")
            fx.note("政策由 %s 改為 targeted，已建立 /.autorelabel，重開機時會重新標記檔案系統（耗時較長）；"
                    "目前為 enforcing 時建議先切換為 permissive 再重開機" % old)
        fx.note("SELinux 政策變更需重開機生效")


# [Unconfined] RHEL8 0189 / RHEL9 0187 未受限程序（C 類）
class Unconfined(Rule):
    category = SEL
    risk = "C"
    title = "未受限程序"
    expected = "無未受限程序（unconfined_service_t）"
    manual_hint = ("以 ls -Z 檢查清單中程序的執行檔標籤（常見為 /opt、/usr/local 下標為 bin_t 的第三方服務），"
                   "為其選擇正確類型後以 semanage fcontext -a -t <類型> '<路徑>' 與 restorecon -v <路徑> 永久設定"
                   "（GCB 範例的 chcon 為暫時性標籤，重新標記後會被還原），再重新啟動該服務")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        st = _getenforce()
        if st is None:
            return Check(FAIL, "找不到 getenforce（SELinux 未安裝）")
        if st == "Disabled":
            return Check(FAIL, "SELinux 未啟用，無法限制程序")
        found = []
        for d in glob.glob("/proc/[0-9]*"):
            label = (read_text(d + "/attr/current") or "").strip("\0\n ")
            if ":unconfined_service_t:" not in label:
                continue
            try:
                exe = os.readlink(d + "/exe")
            except OSError:
                exe = (read_text(d + "/comm") or "?").strip()
            found.append("%s(%s)" % (exe, os.path.basename(d)))
        if found:
            return Check(FAIL, "未受限程序 %d 個：%s" % (len(found), "、".join(sorted(found)[:10])))
        return Check(PASS, "無未受限程序（%s）" % st)


# [SetroubleshootAbsent] RHEL8 0190 / RHEL9 0188 setroubleshoot 套件
class SetroubleshootAbsent(PackageAbsent):
    def check(self, ctx):
        c = PackageAbsent.check(self, ctx)
        if pkgsvc.pkg_installed(ctx.osi, "setroubleshoot-server"):
            c.current += "；另安裝了 setroubleshoot-server（含 setroubleshootd，GCB 未要求，請人工評估）"
        return c


def _pkg_absent(cls, title, pkg, ids):
    r = cls(title, pkg, ids)
    r.category = SEL
    return r


# ====================================================================
# cron 設定
# ====================================================================

def cron_perm(title, ids, path, owner=False, max_mode=None):
    """cron 檔案／目錄的擁有者或權限（未安裝 cronie 不適用；不存在判不合格）。"""
    return FilePerm(title, CRON, ids, path, owner="root" if owner else None,
                    groups=["root"] if owner else None, max_mode=max_mode, missing="fail",
                    when=installed("cronie"))


# [CronAllow] RHEL8 0205 / RHEL9 0203 at.allow 與 cron.allow 檔案所有權、RHEL8 0206 / RHEL9 0204 檔案權限
class CronAllow(Rule):
    category = CRON
    risk = "B"
    PAIRS = (("/etc/cron.allow", "/etc/cron.deny"), ("/etc/at.allow", "/etc/at.deny"))
    NOTE = ("已移除 cron.deny/at.deny 並建立 cron.allow/at.allow：除 root 外，未列在 allow 檔中的使用者"
            "將無法再以 crontab/at 建立或修改排程（既有排程仍會執行）。需開放的使用者請由管理者逐一加入 allow 檔")

    def __init__(self, title, ids, mode):
        self.title = title
        self.ids = ids
        self.mode = mode  # "owner" 或 "perm"
        self.expected = ("root:root" if mode == "owner" else "600 或更低權限") + \
            "（移除 cron.deny/at.deny，建立 cron.allow/at.allow）"
        self.when = installed("cronie")

    def _bad_attr(self, path):
        st = os.stat(path)
        if self.mode == "owner":
            return None if st.st_uid == 0 and st.st_gid == 0 else "uid=%d gid=%d" % (st.st_uid, st.st_gid)
        mode = st.st_mode & 0o7777
        return None if not mode & ~0o600 else "權限 %03o" % mode

    def check(self, ctx):
        bad, ok = [], []
        for allow, deny in self.PAIRS:
            if os.path.exists(deny):
                bad.append("%s 存在" % deny)
            if not os.path.exists(allow):
                bad.append("%s 不存在" % allow)
                continue
            why = self._bad_attr(allow)
            (bad if why else ok).append("%s %s" % (allow, why or "符合"))
        return Check(FAIL if bad else PASS, "；".join(bad + ok))

    @staticmethod
    def _schedulers():
        """目前有排程的非 root 使用者與 deny 檔中的使用者（提示用）。"""
        users = sorted(u for u in (os.listdir("/var/spool/cron") if os.path.isdir("/var/spool/cron") else [])
                       if u != "root")
        out = []
        if users:
            out.append("有 crontab 的非 root 使用者：" + "、".join(users))
        for _, deny in CronAllow.PAIRS:
            names = [l.strip() for l in (read_text(deny) or "").splitlines() if l.strip() and not l.startswith("#")]
            if names:
                out.append("%s 原內容：%s" % (deny, "、".join(names[:20])))
        return out

    def fix(self, ctx, fx):
        for info in self._schedulers():
            fx.note(info)
        for allow, deny in self.PAIRS:
            if os.path.exists(deny):
                fx.backup_only(deny)
                fx.run(["rm", "-f", deny], "刪除 %s" % deny)
            if not os.path.exists(allow):
                fx.write_file(allow, "", mode=0o600)
            if not os.path.exists(allow):  # 預覽模式
                continue
            st = os.stat(allow)
            if st.st_uid != 0 or st.st_gid != 0:
                fx.chown(allow, 0, 0, "root:root")
            if st.st_mode & 0o7777 & ~0o600:
                fx.chmod(allow, st.st_mode & 0o600)
        fx.note(self.NOTE)


CRON_DROPIN = "/etc/rsyslog.d/50-gcb-cron.conf"


def rsyslog_cron_lines(text):
    """回傳把 cron.* 記錄到 /var/log/cron 的有效設定行。"""
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) != 2:
            continue
        sel, action = parts[0], parts[1].split("#", 1)[0].strip()
        if action.lstrip("-") != "/var/log/cron":
            continue
        for item in sel.split(";"):
            if "." not in item:
                continue
            facs, prio = item.rsplit(".", 1)
            if "cron" in facs.split(",") and prio == "*":
                out.append(s)
                break
    return out


# [CronLogging] RHEL8 0207 / RHEL9 0205 cron 日誌記錄功能
class CronLogging(Rule):
    category = CRON
    title = "cron 日誌記錄功能"
    expected = "啟用（rsyslog 設定 cron.* /var/log/cron）"
    MAIN = "/etc/rsyslog.conf"

    def __init__(self, ids):
        self.ids = ids

    def _files(self):
        return [self.MAIN] + sorted(glob.glob("/etc/rsyslog.d/*.conf"))

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "rsyslog"):
            return Check(FAIL, "未安裝 rsyslog（請先完成「rsyslog 服務」項目）")
        hits = ["%s：%s" % (f, l) for f in self._files() for l in rsyslog_cron_lines(read_text(f))]
        act = pkgsvc.svc_state("rsyslog")[1]
        svc = "；rsyslog 服務 %s" % act
        if hits:
            return Check(PASS, hits[0] + svc)
        return Check(FAIL, "未設定 cron.* /var/log/cron" + svc)

    def fix(self, ctx, fx):
        if not which("rsyslogd"):
            raise ManualRequired("未安裝 rsyslog，請先完成「rsyslog 服務」項目")
        fx.add_undo("if systemctl is-active -q rsyslog; then systemctl restart rsyslog; fi", "重新啟動 rsyslog（若執行中）")
        fx.write_file(CRON_DROPIN, "# gcb-checker：GCB cron 日誌記錄功能\ncron.*    /var/log/cron\n")
        r = fx.run(["rsyslogd", "-N1"], "檢查 rsyslog 設定語法", check=False)
        if r is not None and not r.ok:
            raise FixError("rsyslog 設定檢查失敗：%s" % r.text()[-200:])
        fx.run(["systemctl", "restart", "rsyslog"], "重新啟動 rsyslog")


# ====================================================================
# 防火牆：共用
# ====================================================================

NFT_CONF = "/etc/sysconfig/nftables.conf"
FW_RELOAD_GUARD = "if firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --reload; fi"


def nft_conf_includes(text):
    """nftables.conf 中有效的 include 路徑。"""
    out = []
    for line in (text or "").splitlines():
        m = re.match(r'^\s*include\s+"([^"]+)"', line)
        if m:
            inc = m.group(1)
            out.append(inc if inc.startswith("/") else os.path.join("/etc", inc))  # nft 相對路徑以 /etc 為基準
    return out


def fw_backend(ctx):
    """回傳 (防火牆種類, 判斷依據)。種類：firewalld / nftables / iptables（或設定檔中的其他值）。"""
    b = (ctx.cfg.firewall_backend or "auto").lower()
    if b != "auto":
        return b, "config.ini 指定 firewall_backend=%s" % b
    en, act = pkgsvc.svc_state("firewalld.service")
    if en in ("enabled", "enabled-runtime") or act == "active":
        return "firewalld", "firewalld 服務已啟用"
    en, act = pkgsvc.svc_state("nftables.service")
    if (en in ("enabled", "enabled-runtime") or act == "active") and nft_conf_includes(read_text(NFT_CONF)):
        return "nftables", "nftables 服務已啟用且 nftables.conf 有 include"
    if ctx.osi.key == "rhel8" and pkgsvc.pkg_installed(ctx.osi, "iptables-services"):
        en, act = pkgsvc.svc_state("iptables.service")
        if en in ("enabled", "enabled-runtime") or act == "active":
            return "iptables", "iptables 服務已啟用"
    return "firewalld", "未啟用其他防火牆，依 RHEL 預設採用 firewalld"


def backend_is(name):
    def _when(ctx):
        b, how = fw_backend(ctx)
        if b == name:
            return None
        return ("GCB 防火牆規則 firewalld／nftables／iptables 三選一；本機採用 %s（依據：%s），"
                "本項目屬 %s，不需設定" % (b, how, name))
    return _when


def sshd_ports():
    """sshd 使用的埠：sshd -T 的 port（多個時全部），加上 ss 中 sshd 實際監聽的埠；都取不到回傳 []。"""
    ports = set()
    sshd = which("sshd")
    if sshd:
        r = run([sshd, "-T"], timeout=30)
        if r.ok:
            ports.update(te.sshd_listen_ports(te.parse_sshd_T(r.out)))
    r = run(["ss", "-Htlnp"], timeout=15)
    for line in r.out.splitlines():
        parts = line.split()
        if '"sshd"' in line and len(parts) >= 4:
            p = parts[3].rsplit(":", 1)[-1]
            if p.isdigit():
                ports.add(p)
    return sorted(ports, key=int)


def ssh_ports_all():
    """sshd_ports() 再加上目前 SSH 連線的本機埠（SSH_CONNECTION）；取不到 sshd 埠時回傳 []。"""
    ports = sshd_ports()
    if not ports:
        return []
    conn = os.environ.get("SSH_CONNECTION", "").split()
    if len(conn) == 4 and conn[3].isdigit():
        ports = sorted(set(ports) | {conn[3]}, key=int)
    return ports


def need_ssh_ports():
    ports = ssh_ports_all()
    if not ports:
        raise ManualRequired("無法取得 sshd 監聽埠（sshd -T 與 ss 皆失敗），為避免修改防火牆後中斷遠端連線，停止修復")
    return ports


def other_listening(ssh_ports):
    """對外監聽（非迴路位址）的其他連接埠，如 ["tcp/80", "udp/123"]。"""
    out = set()
    r = run(["ss", "-Htlnu"], timeout=15)
    for line in r.out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        host, _, port = local.rpartition(":")
        host = host.strip("[]").split("%")[0]
        if host.startswith("127.") or host == "::1" or not port.isdigit():
            continue
        if proto == "tcp" and port in ssh_ports:
            continue
        out.add("%s/%s" % (proto, port))
    return sorted(out, key=lambda s: (s.split("/")[0], int(s.split("/")[1])))


def forwarding_in_use():
    """主機使用 IP 轉送或容器/虛擬化時回傳說明，否則 None（此時 forward 鏈不自動設為 drop）。"""
    why = []
    if (read_text("/proc/sys/net/ipv4/ip_forward") or "0").strip() == "1":
        why.append("net.ipv4.ip_forward=1")
    why += [u for u in VIRT_UNITS if pkgsvc.svc_state(u)[1] == "active"]
    ifaces = os.listdir("/sys/class/net") if os.path.isdir("/sys/class/net") else []
    why += [i for i in ifaces if i.startswith(VIRT_IFACES)]
    return "、".join(why) or None


def unmask_if_masked(fx, unit):
    """服務被遮蔽時先解除（回滾時再遮蔽回去）。"""
    if pkgsvc.svc_state(unit)[0] == "masked":
        fx.add_undo(["systemctl", "mask", unit], "還原遮蔽 %s" % unit)
        fx.run(["systemctl", "unmask", unit], "解除 %s 遮蔽" % unit)


def mask_unit(ctx, fx, unit, stop_first):
    """記錄服務狀態後遮蔽；stop_first 時先 stop 再 mask（不用 --now）。"""
    en, act = fx._record_service(unit)
    ctx.intended_stops.add(unit)
    if stop_first and act == "active":
        fx.run(["systemctl", "stop", unit], "停止服務 %s" % unit)
    fx.run(["systemctl", "mask", unit], "遮蔽服務 %s（原 %s/%s）" % (unit, en, act))
    return act == "active"


class Guard(object):
    """修改防火牆期間的自動還原保險：systemd-run 在數分鐘後執行還原指令，修改完成並確認後取消。"""

    def __init__(self, fx, restore_cmd, seconds=300):
        self.fx = fx
        self.unit = None
        if fx.dry or not restore_cmd or not which("systemd-run"):
            return
        unit = "gcb-fw-guard-%s-%d" % (fx.rid[-4:], int(time.time()))
        r = fx.run(["systemd-run", "--unit", unit, "--on-active=%d" % seconds] + restore_cmd,
                   "設定自動還原保險（%d 秒後還原防火牆規則；本工具中斷時生效）" % seconds, check=False)
        if r is not None and r.ok:
            self.unit = unit

    def cancel(self):
        if self.unit:
            self.fx.run(["systemctl", "stop", self.unit + ".timer"], "取消自動還原保險", check=False)
            self.unit = None


def fw_guard(fx, tar, was_running):
    """firewalld 修改期間的自動還原保險：數分鐘後以備份還原 /etc/firewalld，並恢復 firewalld 原本的執行狀態。"""
    if not tar:
        return Guard(fx, None)
    after = "firewall-cmd --reload" if was_running else "systemctl stop firewalld"
    script = "find /etc/firewalld -mindepth 1 -delete; tar -xf %s -C /etc && %s" % (tar, after)
    return Guard(fx, ["sh", "-c", script])


# ====================================================================
# nftables 解析
# ====================================================================

def _norm_rule(rule):
    r = re.sub(r"counter packets \d+ bytes \d+", "counter", rule)
    r = r.replace('"', "")
    r = re.sub(r"\s+", " ", r).strip()
    return r


def nft_parse(text):
    """解析 nft list ruleset 或設定檔，回傳 chains：[{family, table, name, hook, policy, rules}]。

    支援區塊格式（table … { chain … { … } }）與指令格式（add chain / add rule）。
    """
    chains = {}
    order = []

    def chain(fam, table, name):
        key = (fam, table, name)
        if key not in chains:
            chains[key] = {"family": fam, "table": table, "name": name, "hook": None, "policy": None, "rules": []}
            order.append(key)
        return chains[key]

    def base(c, body):
        m = re.search(r"\bhook\s+(\w+)", body)
        if m and re.search(r"\btype\s+filter\b", body):
            c["hook"] = m.group(1)
        m = re.search(r"\bpolicy\s+(\w+)", body)
        if m:
            c["policy"] = m.group(1)

    stack = []  # ("table", fam, name) / ("chain", dict) / ("other",)
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("#") else ""
        if not line:
            continue
        m = re.match(r"^(?:add|create)\s+chain\s+(\w+)\s+(\S+)\s+(\S+)\s*(\{.*\})?\s*$", line)
        if m:
            c = chain(m.group(1), m.group(2), m.group(3))
            base(c, m.group(4) or "")
            continue
        m = re.match(r"^(?:add|insert)\s+rule\s+(\w+)\s+(\S+)\s+(\S+)\s+(.*)$", line)
        if m:
            c = chain(m.group(1), m.group(2), m.group(3))
            if m.group(4).startswith("position") or m.group(4).startswith("index"):
                body = m.group(4).split(None, 2)[2] if len(m.group(4).split(None, 2)) > 2 else ""
            else:
                body = m.group(4)
            (c["rules"].insert(0, _norm_rule(body)) if line.startswith("insert") else c["rules"].append(_norm_rule(body)))
            continue
        opens = line.endswith("{")
        closes = line == "}" or (line.endswith("}") and line.count("}") > line.count("{"))
        if opens:
            m = re.match(r"^(?:add\s+|create\s+)?table\s+(\w+)\s+(\S+)\s*\{$", line)
            if m:
                stack.append(("table", m.group(1), m.group(2)))
                continue
            m = re.match(r"^chain\s+(\S+)\s*\{$", line)
            tables = [s for s in stack if s[0] == "table"]
            if m and tables:
                stack.append(("chain", chain(tables[-1][1], tables[-1][2], m.group(1))))
                continue
            stack.append(("other",))
            continue
        if closes:
            if stack:
                stack.pop()
            continue
        cur = stack[-1] if stack else None
        if cur and cur[0] == "chain":
            c = cur[1]
            if re.match(r"^type\s", line) or re.match(r"^policy\s", line):
                base(c, line)
            else:
                c["rules"].append(_norm_rule(line.rstrip(";")))
    return [chains[k] for k in order]


def nft_tables(text):
    """nft list tables 或設定檔中的 (family, table) 清單。"""
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(?:add\s+|create\s+)?table\s+(\w+)\s+([^\s{]+)", line.split("#", 1)[0])
        if m and (m.group(1), m.group(2)) not in out:
            out.append((m.group(1), m.group(2)))
    return out


def nft_hooks(chains):
    """回傳已存在的 filter 基本鏈 hook 集合（inet，或 ip 與 ip6 皆有）。"""
    fams = {}
    for c in chains:
        if c["hook"]:
            fams.setdefault(c["hook"], set()).add(c["family"])
    return set(h for h, f in fams.items() if "inet" in f or {"ip", "ip6"} <= f)


LOOP_RX = (re.compile(r"^(iif|iifname) lo( counter)? accept$"),
           re.compile(r"^ip saddr 127\.0\.0\.0/8\b.*\bdrop$"),
           re.compile(r"^ip6 saddr ::1(/128)?\b.*\bdrop$"))


def nft_loopback_ok(chains):
    """input 基本鏈中有 lo accept，且位於 127.0.0.0/8 與 ::1 drop 之前。"""
    for c in chains:
        if c["hook"] != "input":
            continue
        idx = []
        for rx in LOOP_RX:
            hit = [i for i, r in enumerate(c["rules"]) if rx.match(r.replace(" counter ", " "))
                   or rx.match(r)]
            idx.append(hit[0] if hit else None)
        if None not in idx and idx[0] < idx[1] and idx[0] < idx[2]:
            return True
    return False


def nft_policies(chains):
    """各 hook 是否有 policy drop 的基本鏈：{hook: True/False}（無基本鏈不列出）。"""
    out = {}
    for c in chains:
        if c["hook"]:
            out[c["hook"]] = out.get(c["hook"], False) or c["policy"] == "drop"
    return out


def _port_tokens(rule):
    m = re.search(r"\btcp dport (\{[^}]*\}|\S+)", rule)
    if not m:
        return set()
    out = set()
    for tok in re.split(r"[\s,{}]+", m.group(1)):
        if not tok:
            continue
        if tok.isdigit():
            out.add(tok)
        elif re.match(r"^\d+-\d+$", tok):
            lo, hi = tok.split("-")
            out.update(str(p) for p in range(int(lo), int(hi) + 1) if int(hi) - int(lo) < 70000)
        else:
            try:
                out.add(str(socket.getservbyname(tok, "tcp")))
            except (socket.error, OverflowError):
                pass
    return out


def nft_ssh_problems(chains, ports):
    """會阻擋連入的 input 基本鏈（policy drop 或無條件 drop/reject）若缺少 SSH 放行，回傳問題清單。

    firewalld 自己的表（table … firewalld）以區域管理，不在此檢查。
    """
    problems = []
    for c in chains:
        if c["hook"] != "input" or c["table"] == "firewalld":
            continue
        rules = c["rules"]
        blocking = c["policy"] == "drop" or any(
            re.match(r"^(counter )?(drop|reject)\b", r) for r in rules)
        if not blocking:
            continue
        name = "%s %s %s" % (c["family"], c["table"], c["name"])
        if not any("ct state" in r and "established" in r and r.endswith("accept") for r in rules):
            problems.append("%s 未放行已建立連線" % name)
        if not any(LOOP_RX[0].match(r) for r in rules):
            problems.append("%s 未放行迴路介面 lo" % name)
        allowed = set()
        for r in rules:
            if r.endswith("accept"):
                allowed |= _port_tokens(r)
        miss = [p for p in ports if p not in allowed]
        if miss:
            problems.append("%s 未放行 SSH 埠 %s" % (name, ",".join(miss)))
    return problems


def nft_runtime():
    r = run(["nft", "list", "ruleset"], timeout=30)
    return r.out if r.ok else None


def _expand_includes(path, depth=0):
    text = read_text(path) or ""
    if depth > 3:
        return text
    parts = [text]
    for inc in nft_conf_includes(text):  # 已是絕對路徑
        for f in sorted(glob.glob(inc)) or [inc]:
            parts.append(_expand_includes(f, depth + 1))
    return "\n".join(parts)


def nft_persistent():
    """開機時 nftables.service 會載入的設定（展開 include）。"""
    return _expand_includes(NFT_CONF)


# ---------------- nftables 管理檔案 ----------------

MANAGED_NFT = "/etc/nftables/gcb-filter.nft"
NFT_FLAGS = ("chains", "loopback", "input_drop", "forward_drop")


def nft_managed_state(text):
    """讀取管理檔案的旗標與 SSH 埠：(flags set, ports list)；檔案不存在回傳 (None, None)。"""
    if text is None:
        return None, None
    flags, ports = set(), []
    for line in text.splitlines():
        if line.startswith("# gcb-flags:"):
            flags = set(f for f in line.split(":", 1)[1].strip().split(",") if f)
        elif line.startswith("# gcb-ssh-ports:"):
            ports = [p for p in line.split(":", 1)[1].strip().split(",") if p.isdigit()]
    return flags, ports


def nft_render(flags, ports):
    """產生 table inet filter 的完整定義（開頭先建立再刪除，可重複載入）。"""
    flags = set(flags)
    if flags - {"chains"}:
        flags.add("chains")
    drop_in = "input_drop" in flags
    lines = ["# gcb-checker 管理的 nftables 規則（GCB Nftables 配置），請勿手動編輯；",
             "# 修改請另建檔案並在 /etc/sysconfig/nftables.conf include",
             "# gcb-flags: %s" % ",".join(sorted(flags)),
             "# gcb-ssh-ports: %s" % ",".join(ports),
             "table inet filter {}",
             "delete table inet filter",
             "table inet filter {"]
    if "chains" in flags:
        lines += ["\tchain input {",
                  "\t\ttype filter hook input priority 0; policy %s;" % ("drop" if drop_in else "accept")]
        if drop_in:
            lines.append("\t\tct state established,related accept")
        if drop_in or "loopback" in flags:
            lines.append('\t\tiif "lo" accept')
        if "loopback" in flags:
            lines += ["\t\tip saddr 127.0.0.0/8 counter drop", "\t\tip6 saddr ::1 counter drop"]
        if drop_in:
            lines += ["\t\ticmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept",
                      "\t\ticmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, "
                      "parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
                      "\t\ttcp dport { %s } accept" % ", ".join(ports)]
        lines += ["\t}",
                  "\tchain forward {",
                  "\t\ttype filter hook forward priority 0; policy %s;" % (
                      "drop" if "forward_drop" in flags else "accept"),
                  "\t}",
                  "\tchain output {",
                  "\t\ttype filter hook output priority 0; policy accept;",
                  "\t}"]
    lines.append("}")
    return "\n".join(lines) + "\n"


def nft_conf_add_include(text, path=MANAGED_NFT):
    if path in nft_conf_includes(text):
        return text
    t = text or ""
    if t and not t.endswith("\n"):
        t += "\n"
    return t + '# gcb-checker：GCB 載入 nftables 規則\ninclude "%s"\n' % path


def nft_user_config():
    """nftables.conf 已載入使用者自訂且非空的設定，或目前已有非本工具建立的 table inet filter 時回傳說明。"""
    found = []
    for inc in nft_conf_includes(read_text(NFT_CONF)):
        for f in sorted(glob.glob(inc)) or [inc]:
            if os.path.realpath(f) == os.path.realpath(MANAGED_NFT):
                continue
            body = [l for l in (read_text(f) or "").splitlines() if l.strip() and not l.strip().startswith("#")]
            if body:
                found.append(f)
    rt = nft_runtime()
    if rt and ("inet", "filter") in nft_tables(rt) and not os.path.exists(MANAGED_NFT):
        found.append("目前規則集已有非本工具建立的 table inet filter")
    return found


IPT_BUILTIN = ("INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING")


def nft_foreign_tables(text):
    """iptables-nft（含 podman/docker）建立的表：無法以 nft -f 原樣還原。"""
    out = []
    for c in nft_parse(text):
        name = "%s %s" % (c["family"], c["table"])
        if (c["name"] in IPT_BUILTIN or c["name"].startswith("DOCKER")) and name not in out:
            out.append(name)
    for m in re.finditer(r"table (\w+ \S+) is managed by iptables-nft", text or ""):
        if m.group(1) not in out:
            out.append(m.group(1))
    return out


def nft_snapshot(ctx, fx, strict=True):
    """備份目前整個規則集，登記還原指令（nft -f 原子性還原），回傳還原指令（list）。

    規則集含 iptables-nft 建立的表時無法原樣還原：strict 時停止修復，否則只備註不備份。
    """
    rt = nft_runtime()
    if rt is None:
        return None
    foreign = nft_foreign_tables(rt)
    if foreign:
        if strict:
            raise ManualRequired("目前規則集含 iptables-nft（或容器）建立的表：%s，無法安全備份還原，請人工處理"
                                 % "、".join(foreign))
        fx.note("規則集含 iptables-nft 建立的表（%s），未備份整個規則集；回滾時以 firewall-cmd --reload 重建"
                % "、".join(foreign))
        return None
    path = _write_backup(ctx, fx, "nft-ruleset.nft", "flush ruleset\n" + rt)
    if not path:
        return None
    cmd = [which("nft") or "nft", "-f", path]
    fx.add_undo(cmd, "還原 nftables 規則集")
    return cmd


def nft_apply(ctx, fx, add_flags, ports=None):
    """更新 gcb 管理檔案（table inet filter），驗證語法後載入，並確保 nftables.conf include 該檔。"""
    if not which("nft"):
        raise ManualRequired("未安裝 nftables，請先完成「nftables 服務」項目")
    user = nft_user_config()
    if user:
        raise ManualRequired("系統已有使用者自訂的 nftables 設定（%s），為避免覆寫不自動修改，"
                             "請依 GCB 在既有規則中人工設定" % "、".join(user))
    flags, old_ports = nft_managed_state(read_text(MANAGED_NFT))
    flags = set(flags or ()) | set(add_flags)
    ports = sorted(set(old_ports or []) | set(ports or []), key=int)
    if "input_drop" in flags and not ports:
        raise ManualRequired("無法取得 sshd 監聽埠，停止修復")
    text = nft_render(flags, ports)
    if not fx.dry:
        fd, tmp = tempfile.mkstemp(prefix="gcb-nft-", suffix=".nft")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(text.encode("utf-8"))
            r = run(["nft", "-c", "-f", tmp], timeout=30)
        finally:
            os.unlink(tmp)
        if not r.ok:
            raise FixError("nftables 規則語法驗證失敗：%s" % r.text()[-300:])
    restore = nft_snapshot(ctx, fx)
    guard = Guard(fx, restore) if "input_drop" in flags or "forward_drop" in flags else None
    try:
        fx.write_file(MANAGED_NFT, text, mode=0o600)
        fx.run(["nft", "-f", MANAGED_NFT], "載入 nftables 規則（table inet filter）")
        fx.edit_file(NFT_CONF, nft_conf_add_include, mode=0o600)
        r = fx.run(["nft", "-c", "-f", NFT_CONF], "驗證 nftables.conf 語法", check=False)
        if r is not None and not r.ok:
            raise FixError("nftables.conf 驗證失敗：%s" % r.text()[-300:])
        if not fx.dry and "input_drop" in flags:
            probs = nft_ssh_problems(nft_parse(nft_runtime()), ports)
            if probs:
                raise FixError("套用後 SSH 放行規則檢查失敗：%s" % "；".join(probs))
            fx.step("確認 SSH 放行", "input 鏈已放行 lo、已建立連線與 SSH 埠 %s" % ",".join(ports), "成功")
    finally:
        if guard:
            guard.cancel()


# ---------------- iptables ----------------

class IptFamily(object):
    def __init__(self, v6):
        self.v6 = v6
        self.cmd = "ip6tables" if v6 else "iptables"
        self.save = self.cmd + "-save"
        self.restore = self.cmd + "-restore"
        self.file = "/etc/sysconfig/%s" % self.cmd
        self.loop_src = "::1/128" if v6 else "127.0.0.0/8"

    def available(self):
        return bool(which(self.cmd) and which(self.save))

    def runtime(self):
        """iptables -S（filter 表）輸出；失敗回傳 None。"""
        r = run([self.cmd, "-S"], timeout=30)
        return r.out if r.ok else None


def ipt_parse(text, saved=False):
    """解析 iptables -S 或 iptables-save 檔（只取 *filter）：({鏈: 政策}, [規則])。"""
    pol, rules, in_filter = {}, [], not saved
    for line in (text or "").splitlines():
        s = re.sub(r"\s+", " ", line.strip())
        if saved:
            if s.startswith("*"):
                in_filter = s == "*filter"
                continue
            if not in_filter:
                continue
            m = re.match(r"^:(\S+) (\S+)", s)
            if m:
                pol[m.group(1)] = m.group(2)
                continue
        else:
            m = re.match(r"^-P (\S+) (\S+)", s)
            if m:
                pol[m.group(1)] = m.group(2)
                continue
        if s.startswith("-A "):
            rules.append(s)
    return pol, rules


def ipt_loop_rules(v6):
    src = "::1/128" if v6 else "127.0.0.0/8"
    return ["-A INPUT -i lo -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT", "-A INPUT -s %s -j DROP" % src]


def _ipt_rule_eq(a, b):
    return a.replace(" -s ::1 ", " -s ::1/128 ") == b.replace(" -s ::1 ", " -s ::1/128 ")


def ipt_loopback_missing(rules, v6):
    """回傳缺少的回送規則；lo ACCEPT 必須在迴路位址 DROP 之前。"""
    want = ipt_loop_rules(v6)
    idx = []
    for w in want:
        hit = [i for i, r in enumerate(rules) if _ipt_rule_eq(r, w)]
        idx.append(hit[0] if hit else None)
    miss = [w for w, i in zip(want, idx) if i is None]
    if idx[0] is not None and idx[2] is not None and idx[0] > idx[2]:
        miss.append("（%s 位於 %s 之後）" % (want[0], want[2]))
    return miss


def ipt_ssh_problems(pol, rules, ports):
    """INPUT 會阻擋連入（政策 DROP/REJECT 或無條件 DROP/REJECT）時，檢查 lo、已建立連線與 SSH 放行。"""
    inp = [r for r in rules if r.startswith("-A INPUT ")]
    blocking = pol.get("INPUT", "ACCEPT") != "ACCEPT" or any(
        re.match(r"^-A INPUT( -m comment --comment \S+)? -j (DROP|REJECT)", r) for r in inp)
    if not blocking:
        return []
    probs = []
    if not any("-i lo" in r and r.endswith("-j ACCEPT") for r in inp):
        probs.append("INPUT 未放行迴路介面 lo")
    if not any(re.search(r"--(ct)?state \S*ESTABLISHED", r) and "-j ACCEPT" in r for r in inp):
        probs.append("INPUT 未放行已建立連線")
    allowed = set()
    for r in inp:
        if "-j ACCEPT" in r and "-p tcp" in r:
            m = re.search(r"--dports? (\S+)", r)
            if m:
                for tok in m.group(1).split(","):
                    if ":" in tok:
                        lo, hi = tok.split(":")
                        allowed.update(str(p) for p in range(int(lo or 0), int(hi or 65535) + 1))
                    else:
                        allowed.add(tok)
    miss = [p for p in ports if p not in allowed]
    if miss:
        probs.append("INPUT 未放行 SSH 埠 %s" % ",".join(miss))
    return probs


def ipt_file_add_allows(text, lines):
    """在 iptables-save 檔的 *filter 區段第一條 -A 規則前插入放行規則（沒有 *filter 時新增）。"""
    out = (text or "").splitlines()
    start = [i for i, l in enumerate(out) if l.strip() == "*filter"]
    if not start:
        out += ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"] + lines + ["COMMIT"]
        return "\n".join(out) + "\n"
    i = start[0] + 1
    while i < len(out) and not out[i].startswith("-A ") and out[i].strip() != "COMMIT":
        i += 1
    out[i:i] = lines
    return "\n".join(out) + "\n"


def ipt_snapshot(ctx, fx, fam):
    r = run([fam.save], timeout=30)
    if not r.ok:
        raise FixError("無法讀取目前規則（%s）：%s" % (fam.save, r.text()[-200:]))
    text = r.out
    if "*filter" not in text:
        # filter 表尚未載入時 *-save 沒有輸出；補上空的 ACCEPT 表，回滾時才能清掉新增的規則
        text += "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
    path = _write_backup(ctx, fx, "%s.rules" % fam.save, text)
    if not path:
        return None
    cmd = [which(fam.restore) or fam.restore, path]
    fx.add_undo(cmd, "還原 %s 規則" % fam.cmd)
    return cmd


def ipt_persist(fx, fam):
    """以 iptables-save 寫入 /etc/sysconfig/iptables（先備份、記錄差異）。"""
    fx.backup_only(fam.file)
    fx.run_tracked(["sh", "-c", "%s > %s" % (fam.save, shlex.quote(fam.file))], "保存規則到 %s" % fam.file,
                   [fam.file])


def _ipt_exists(fam, rule_args):
    return run([fam.cmd, "-C"] + rule_args, timeout=15).ok


def _v6_disabled():
    return not os.path.exists("/proc/net/if_inet6")


# ====================================================================
# Firewalld
# ====================================================================

def fw_running():
    r = run(["firewall-cmd", "--state"], timeout=30)
    return r.ok and r.out.strip() == "running"


def _fw_base(running, permanent):
    if not running:
        return ["firewall-offline-cmd"]
    return ["firewall-cmd", "--permanent"] if permanent else ["firewall-cmd"]


def fw_default_zone(running):
    r = run((["firewall-cmd"] if running else ["firewall-offline-cmd"]) + ["--get-default-zone"], timeout=30)
    return r.out.strip() if r.ok and r.out.strip() else None


def fw_parse_zones(text):
    """解析 --list-all-zones：{zone: {"interfaces": [...], "sources": [...], ...}}。"""
    zones, cur = {}, None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            cur = line.split()[0]
            zones[cur] = {}
        elif cur and ":" in line:
            k, v = line.strip().split(":", 1)
            zones[cur][k.strip()] = v.split()
    return zones


def fw_zones_to_cover(running):
    """需要放行 SSH 的區域：預設區域、有綁定介面或來源的區域、執行中時的作用中區域。"""
    zones = set()
    d = fw_default_zone(running)
    if d:
        zones.add(d)
    r = run(_fw_base(running, True) + ["--list-all-zones"], timeout=60)
    for z, info in fw_parse_zones(r.out).items():
        if info.get("interfaces") or info.get("sources"):
            zones.add(z)
    if running:
        r = run(["firewall-cmd", "--get-active-zones"], timeout=30)
        for line in r.out.splitlines():
            if line.strip() and not line[0].isspace():
                zones.add(line.split()[0])
    return sorted(zones)


def fw_zone_open_ports(base, zone):
    """區域放行的 TCP 埠集合；目標為 ACCEPT 時回傳 None（全部放行）。"""
    r = run(base + ["--zone=%s" % zone, "--list-all"], timeout=30)
    data = {}
    for line in r.out.splitlines():
        if ":" in line and line[:1].isspace():
            k, v = line.strip().split(":", 1)
            data[k.strip()] = v.split()
    if (data.get("target") or [""])[0] == "ACCEPT":
        return None
    ports = set()

    def add(spec):
        p, _, proto = spec.partition("/")
        if proto != "tcp":
            return
        if "-" in p:
            lo, hi = p.split("-", 1)
            if lo.isdigit() and hi.isdigit():
                ports.update(str(x) for x in range(int(lo), int(hi) + 1))
        elif p.isdigit():
            ports.add(p)
    for spec in data.get("ports", []):
        add(spec)
    for svc in data.get("services", []):
        si = run(base + ["--info-service=%s" % svc], timeout=30)
        for line in si.out.splitlines():
            if line.strip().startswith("ports:"):
                for spec in line.split(":", 1)[1].split():
                    add(spec)
    return ports


def fw_ssh_missing(running, ports, permanent=True, zones=None):
    """回傳 {zone: [未放行的 SSH 埠]}。"""
    base = _fw_base(running, permanent)
    out = {}
    for z in zones or fw_zones_to_cover(running):
        opened = fw_zone_open_ports(base, z)
        if opened is None:
            continue
        miss = [p for p in ports if p not in opened]
        if miss:
            out[z] = miss
    return out


def fw_allow_ssh(fx, running, ports, zones=None):
    """在需要的區域放行 SSH 埠（永久設定；執行中時同時加入目前設定）。"""
    for perm in ([True, False] if running else [True]):
        base = _fw_base(running, perm)
        for z, miss in fw_ssh_missing(running, ports, perm, zones).items():
            for p in miss:
                arg = "--add-service=ssh" if p == "22" else "--add-port=%s/tcp" % p
                fx.run(base + ["--zone=%s" % z, arg], "firewalld 區域 %s 放行 SSH 埠 %s（%s）" % (
                    z, p, "永久" if perm else "目前"))


def _fw_installed(ctx):
    return pkgsvc.pkg_installed(ctx.osi, "firewalld")


def _fw_when(ctx):
    return backend_is("firewalld")(ctx)


# [FirewalldEnabled] RHEL8 0245 / RHEL9 0243 firewalld 服務（啟用）
class FirewalldEnabled(Rule):
    category = FWD
    risk = "B"
    title = "firewalld 服務"
    expected = "啟用"
    UNIT = "firewalld.service"

    def __init__(self, ids):
        self.ids = ids
        self.when = _fw_when

    def check(self, ctx):
        if not _fw_installed(ctx):
            return Check(FAIL, "未安裝 firewalld")
        en, _ = pkgsvc.svc_state(self.UNIT)
        st = "running" if fw_running() else "not running"
        return Check(PASS if en == "enabled" and st == "running" else FAIL, "%s / %s" % (en, st))

    def fix(self, ctx, fx):
        ports = need_ssh_ports()
        if not _fw_installed(ctx):
            raise ManualRequired("未安裝 firewalld，請先完成「firewalld 防火牆套件」項目")
        running = fw_running()
        fx.add_undo(FW_RELOAD_GUARD, "重新載入 firewalld（若執行中）")
        tar = fx.backup_dir("/etc/firewalld")
        guard = fw_guard(fx, tar, running)
        try:
            self._enable(fx, running, ports)
        finally:
            guard.cancel()

    def _enable(self, fx, running, ports):
        # 啟用前先在永久設定放行 SSH 埠（firewalld 預設已放行 lo 與已建立連線）
        fw_allow_ssh(fx, running, ports)
        others = other_listening(ports)
        if others:
            fx.note("啟用 firewalld 後，下列對外監聽的連接埠若未在區域中放行將被阻擋（未自動放行，請人工確認）："
                    + "、".join(others))
        virt = [u for u in VIRT_UNITS if pkgsvc.svc_state(u)[1] == "active"]
        if virt:
            fx.note("偵測到容器/虛擬化服務（%s），啟用 firewalld 可能影響其網路，請確認" % "、".join(virt))
        unmask_if_masked(fx, self.UNIT)
        fx.service_enable(self.UNIT)
        if fx.dry:
            return
        if not fw_running():
            raise FixError("firewalld 未能啟動")
        # 啟用後立即確認：作用中區域都放行 SSH（NetworkManager 指定的區域只在執行時出現）
        fw_allow_ssh(fx, True, ports)
        miss = fw_ssh_missing(True, ports, permanent=False)
        if miss:
            raise FixError("啟用後 SSH 埠未放行：%s" % "；".join("%s:%s" % (z, ",".join(p)) for z, p in miss.items()))
        fx.step("確認 SSH 放行", "firewalld 作用中區域皆已放行 SSH 埠 %s" % ",".join(ports), "成功")


# [UnitsMasked] RHEL8 0246 / RHEL9 0244 iptables 服務、RHEL8 0247 / RHEL9 0245 nftables 服務（firewalld 模式下停用）
class UnitsMasked(Rule):
    category = FWD
    risk = "B"
    expected = "停用（systemctl --now mask）"

    def __init__(self, title, units, ids, kind):
        self.title = title
        self.units = units
        self.ids = ids
        self.kind = kind  # "iptables" / "nftables"
        self.when = _fw_when

    def _states(self):
        return [(u,) + pkgsvc.svc_state(u) for u in self.units]

    def check(self, ctx):
        present = [s for s in self._states() if s[1] != "not-found"]
        if not present:
            return Check(PASS, "未安裝（單元不存在）")
        bad = [s for s in present if s[1] != "masked" or s[2] in ("active", "activating")]
        return Check(FAIL if bad else PASS, "、".join("%s=%s/%s" % s for s in present))

    def fix(self, ctx, fx):
        todo = [s for s in self._states() if s[1] != "not-found" and (s[1] != "masked" or s[2] == "active")]
        if not todo:
            return
        was_active = any(s[2] == "active" for s in todo)
        fx.add_undo(FW_RELOAD_GUARD, "重新載入 firewalld（若執行中）")
        restore = None
        if was_active:
            if self.kind == "nftables" and which("nft"):
                restore = nft_snapshot(ctx, fx, strict=False)
            elif self.kind == "iptables":
                for fam in (IptFamily(False), IptFamily(True)):
                    if fam.available():
                        ipt_snapshot(ctx, fx, fam)
        guard = Guard(fx, restore)
        try:
            self._mask(ctx, fx, todo, was_active)
        finally:
            guard.cancel()

    def _mask(self, ctx, fx, todo, was_active):
        for unit, en, act in todo:
            # stop 時 ExecStop 會清空規則（nftables 為 flush ruleset，連 firewalld 的規則一併清除），先 stop 再 mask
            mask_unit(ctx, fx, unit, stop_first=True)
        if was_active and fw_running():
            fx.run(["firewall-cmd", "--reload"], "重新載入 firewalld 以重建規則")
            if not fx.dry:
                ports = sshd_ports()
                miss = fw_ssh_missing(True, ports, permanent=False) if ports else {}
                if miss:
                    raise FixError("重新載入後 SSH 埠未放行：%s" % miss)


# [FirewalldZone] RHEL8 0248 / RHEL9 0246 firewalld 防火牆預設區域
class FirewalldZone(Rule):
    category = FWD
    risk = "B"
    title = "firewalld 防火牆預設區域"
    expected = "須設定預設區域"
    CONF = "/etc/firewalld/firewalld.conf"

    def __init__(self, ids):
        self.ids = ids
        self.when = _fw_when

    def _state(self):
        running = fw_running()
        zone = fw_default_zone(running)
        r = run((["firewall-cmd"] if running else ["firewall-offline-cmd"]) + ["--get-zones"], timeout=30)
        zones = r.out.split()
        conf = te.get_kv(read_text(self.CONF) or "", "DefaultZone")
        return running, zone, zones, conf

    def check(self, ctx):
        if not _fw_installed(ctx):
            return Check(FAIL, "未安裝 firewalld")
        running, zone, zones, conf = self._state()
        ok = bool(zone) and zone in zones and bool(conf)
        cur = "預設區域=%s、firewalld.conf DefaultZone=%s" % (zone or "無法取得", conf or "未設定")
        if zone and zone not in zones:
            cur += "（區域不存在）"
        if zone == "trusted":
            cur += "；注意：trusted 區域等同全部放行"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if not _fw_installed(ctx):
            raise ManualRequired("未安裝 firewalld，請先完成「firewalld 防火牆套件」項目")
        running, zone, zones, conf = self._state()
        if zone and zone in zones and conf:
            return
        ports = need_ssh_ports()
        fx.add_undo(FW_RELOAD_GUARD, "重新載入 firewalld（若執行中）")
        tar = fx.backup_dir("/etc/firewalld")
        guard = fw_guard(fx, tar, running)
        try:
            self._set_zone(fx, running, zone, zones, ports)
        finally:
            guard.cancel()

    def _set_zone(self, fx, running, zone, zones, ports):
        target = zone if zone and zone in zones else "public"  # 目前區域有效時只把它寫入設定檔，不改成 public
        fw_allow_ssh(fx, running, ports, zones=[target])
        cmd = (["firewall-cmd"] if running else ["firewall-offline-cmd"]) + ["--set-default-zone=" + target]
        fx.run(cmd, "設定 firewalld 預設區域為 %s" % target)
        if running and not fx.dry:
            miss = fw_ssh_missing(True, ports, permanent=False)
            if miss:
                raise FixError("設定後 SSH 埠未放行：%s" % miss)


# ====================================================================
# Nftables
# ====================================================================

def _nft_when(ctx):
    return backend_is("nftables")(ctx)


# [NftEnabled] RHEL8 0249 / RHEL9 0247 nftables 服務（啟用）
class NftEnabled(Rule):
    category = NFT
    risk = "B"
    title = "nftables 服務"
    expected = "啟用"
    UNIT = "nftables.service"

    def __init__(self, ids):
        self.ids = ids
        self.when = _nft_when

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "nftables"):
            return Check(FAIL, "未安裝 nftables")
        en, act = pkgsvc.svc_state(self.UNIT)
        return Check(PASS if en == "enabled" and act == "active" else FAIL, "%s / %s" % (en, act))

    def fix(self, ctx, fx):
        ports = need_ssh_ports()
        if not pkgsvc.pkg_installed(ctx.osi, "nftables"):
            fx.pkg_install("nftables")
        if fx.dry and not which("nft"):
            return
        r = run(["nft", "-c", "-f", NFT_CONF], timeout=30)
        if not r.ok:
            raise ManualRequired("%s 語法驗證失敗，啟用服務會載入失敗，請人工修正：%s" % (NFT_CONF, r.text()[-200:]))
        probs = nft_ssh_problems(nft_parse(nft_persistent()), ports)
        if probs:
            raise ManualRequired("開機規則集會阻擋連入但缺少必要放行（%s），請先補上 lo、已建立連線與 SSH 埠放行" %
                                 "；".join(probs))
        fx.add_undo(FW_RELOAD_GUARD, "重新載入 firewalld（若執行中）")
        restore = nft_snapshot(ctx, fx)
        guard = Guard(fx, restore)
        try:
            unmask_if_masked(fx, self.UNIT)
            fx.service_enable(self.UNIT)
            if not fx.dry:
                probs = nft_ssh_problems(nft_parse(nft_runtime()), ports)
                if probs:
                    raise FixError("啟用後 SSH 放行規則檢查失敗：%s" % "；".join(probs))
        finally:
            guard.cancel()


# [NftFirewalldMasked] RHEL8 0250 / RHEL9 0248 firewalld 服務（nftables 模式下停用）
# [IptFirewalldMasked] RHEL8 0257 firewalld 服務（iptables 模式下停用）
class FirewalldMasked(Rule):
    risk = "B"
    title = "firewalld 服務"
    expected = "停用（systemctl --now mask）"
    UNIT = "firewalld.service"

    def __init__(self, ids, backend):
        self.ids = ids
        self.backend = backend
        self.category = NFT if backend == "nftables" else IPT
        self.when = backend_is(backend)

    def check(self, ctx):
        en, act = pkgsvc.svc_state(self.UNIT)
        if en == "not-found":
            return Check(PASS, "未安裝")
        ok = en == "masked" and act not in ("active", "activating")
        return Check(PASS if ok else FAIL, "%s / %s" % (en, act))

    def fix(self, ctx, fx):
        en, act = pkgsvc.svc_state(self.UNIT)
        if en == "not-found":
            return
        ports = need_ssh_ports()
        # 停用 firewalld 後由 nftables / iptables 規則接手，先確認其規則不會擋掉 SSH
        if self.backend == "nftables":
            rt = nft_runtime() if which("nft") else ""
            probs = nft_ssh_problems(nft_parse(rt), ports)
        else:
            fam = IptFamily(False)
            probs = ipt_ssh_problems(*(ipt_parse(fam.runtime()) + (ports,))) if fam.available() else []
            # 停用後會 restart iptables / ip6tables 服務，載入的是保存檔，保存檔也要放行 SSH
            for f6 in (IptFamily(False), IptFamily(True)):
                saved = read_text(f6.file)
                if saved and pkgsvc.svc_state(f6.cmd + ".service")[1] == "active":
                    probs += ["%s：%s" % (f6.file, p) for p in ipt_ssh_problems(*(ipt_parse(saved, saved=True) + (ports,)))]
        if probs:
            raise ManualRequired("%s 規則尚未就緒（%s），停用 firewalld 前請先補上放行規則" % (self.backend, "；".join(probs)))
        # 回滾順序（反向）：恢復 firewalld → 還原規則集快照 → 最後讓 firewalld 重新載入自己的規則
        fx.add_undo(FW_RELOAD_GUARD, "重新載入 firewalld（若執行中）")
        if self.backend == "nftables":
            if which("nft"):
                nft_snapshot(ctx, fx)
        else:
            for fam in (IptFamily(False), IptFamily(True)):
                if fam.available():
                    ipt_snapshot(ctx, fx, fam)
        fx.service_mask(self.UNIT)
        if self.backend == "iptables":
            # firewalld 停止時可能清除 iptables 鏈，重新載入已保存的 iptables 規則
            for unit in ("iptables.service", "ip6tables.service"):
                if pkgsvc.svc_state(unit)[1] == "active":
                    fx.run(["systemctl", "restart", unit], "重新載入 %s 規則" % unit)


# [NftTable] RHEL8 0251 / RHEL9 0249 在 nftables 中建立表
class NftTable(Rule):
    category = NFT
    title = "在 nftables 中建立表"
    expected = "1 個以上（目前生效與開機載入皆需有）"

    def __init__(self, ids):
        self.ids = ids
        self.when = _nft_when

    def check(self, ctx):
        if not which("nft"):
            return Check(FAIL, "未安裝 nftables")
        rt = nft_runtime()
        if rt is None:
            return Check(ERROR, "nft list ruleset 執行失敗")
        cur = nft_tables(rt)
        per = nft_tables(nft_persistent())
        ok = bool(cur) and bool(per)
        return Check(PASS if ok else FAIL, "目前：%s；開機載入：%s" % (
            "、".join("%s %s" % t for t in cur) or "無", "、".join("%s %s" % t for t in per) or "無"))

    def fix(self, ctx, fx):
        nft_apply(ctx, fx, set())


# [NftChains] RHEL8 0252 / RHEL9 0250 在 nftables 建立基本鏈
class NftChains(Rule):
    category = NFT
    title = "在 nftables 建立基本鏈"
    expected = "1 個以上（input、forward、output 基本鏈）"
    HOOKS = ("input", "forward", "output")

    def __init__(self, ids):
        self.ids = ids
        self.when = _nft_when

    def check(self, ctx):
        if not which("nft"):
            return Check(FAIL, "未安裝 nftables")
        rt = nft_runtime()
        if rt is None:
            return Check(ERROR, "nft list ruleset 執行失敗")
        cur, per = nft_hooks(nft_parse(rt)), nft_hooks(nft_parse(nft_persistent()))
        miss_c = [h for h in self.HOOKS if h not in cur]
        miss_p = [h for h in self.HOOKS if h not in per]
        if not miss_c and not miss_p:
            return Check(PASS, "input、forward、output 基本鏈皆存在（目前與開機載入）")
        return Check(FAIL, "目前缺少：%s；開機載入缺少：%s" % ("、".join(miss_c) or "無", "、".join(miss_p) or "無"))

    def fix(self, ctx, fx):
        nft_apply(ctx, fx, {"chains"})


# [NftLoopback] RHEL8 0253 / RHEL9 0251 在 nftables 設定回送流量規則
class NftLoopback(Rule):
    category = NFT
    title = "在 nftables 設定回送流量規則"
    expected = "建立回送流量規則（iif lo accept；127.0.0.0/8、::1 drop）"

    def __init__(self, ids):
        self.ids = ids
        self.when = _nft_when

    def check(self, ctx):
        if not which("nft"):
            return Check(FAIL, "未安裝 nftables")
        rt = nft_runtime()
        if rt is None:
            return Check(ERROR, "nft list ruleset 執行失敗")
        c, p = nft_loopback_ok(nft_parse(rt)), nft_loopback_ok(nft_parse(nft_persistent()))
        return Check(PASS if c and p else FAIL, "目前：%s；開機載入：%s" % (
            "已設定" if c else "未設定", "已設定" if p else "未設定"))

    def fix(self, ctx, fx):
        nft_apply(ctx, fx, {"loopback"})


OUTPUT_SUGGEST = ("lo、已建立連線（established,related）、DNS（53）、NTP（123）、套件庫（80/443）、"
                  "日誌伺服器、LDAP/AD 等本機必要的對外連線")


# [NftDefaultDrop] RHEL8 0254 / RHEL9 0252 在 nftables 建立預設拒絕規則（input/forward B 類，output 只檢測）
class NftDefaultDrop(Rule):
    category = NFT
    risk = "B"
    title = "在 nftables 建立預設拒絕規則"
    expected = "Drop（input、forward、output 基本鏈 policy drop）"
    HOOKS = ("input", "forward", "output")
    manual_hint = "output 鏈預設拒絕需先放行 " + OUTPUT_SUGGEST + "，請管理者確認後自行設定"

    def __init__(self, ids):
        self.ids = ids
        self.when = _nft_when

    def check(self, ctx):
        if not which("nft"):
            return Check(FAIL, "未安裝 nftables")
        rt = nft_runtime()
        if rt is None:
            return Check(ERROR, "nft list ruleset 執行失敗")
        cur, per = nft_policies(nft_parse(rt)), nft_policies(nft_parse(nft_persistent()))
        parts, ok = [], True
        for h in self.HOOKS:
            good = cur.get(h) is True and per.get(h) is True
            ok = ok and good
            parts.append("%s:%s/%s" % (h, {True: "drop", False: "accept"}.get(cur.get(h), "無鏈"),
                                       {True: "drop", False: "accept"}.get(per.get(h), "無鏈")))
        return Check(PASS if ok else FAIL, "目前/開機 " + "、".join(parts))

    def fix(self, ctx, fx):
        ports = need_ssh_ports()
        flags = {"loopback", "input_drop"}
        fwd = forwarding_in_use()
        if fwd:
            fx.note("偵測到 IP 轉送或容器/虛擬化（%s），forward 鏈未設為 drop，請人工評估" % fwd)
        else:
            flags.add("forward_drop")
        others = other_listening(ports)
        if others:
            fx.note("input 預設拒絕後只放行 SSH 埠 %s；下列對外監聽的連接埠將被阻擋，需要時請人工新增放行規則：%s"
                    % (",".join(ports), "、".join(others)))
        nft_apply(ctx, fx, flags, ports)
        fx.partial = True
        fx.note("output 鏈預設拒絕未自動設定（GCB 決策：預設拒絕外出只檢測）；建議先放行 " + OUTPUT_SUGGEST
                + "，確認後再設定 policy drop")


# [NftPersist] RHEL8 0255 / RHEL9 0253 載入 nftables 規則
class NftPersist(Rule):
    category = NFT
    risk = "B"
    title = "載入 nftables 規則"
    expected = "開機時自動載入 nftables 規則集（nftables.conf 有效 include 且服務已啟用）"
    UNIT = "nftables.service"

    def __init__(self, ids):
        self.ids = ids
        self.when = _nft_when

    def check(self, ctx):
        incs = nft_conf_includes(read_text(NFT_CONF))
        if not incs:
            return Check(FAIL, "%s 沒有有效的 include" % NFT_CONF)
        missing = [i for i in incs if not glob.glob(i)]
        valid = which("nft") and run(["nft", "-c", "-f", NFT_CONF], timeout=30).ok
        en = pkgsvc.svc_state(self.UNIT)[0]
        ok = not missing and valid and en == "enabled"
        cur = "include：%s；語法：%s；服務：%s" % ("、".join(incs), "正確" if valid else "驗證失敗", en)
        if missing:
            cur += "；檔案不存在：" + "、".join(missing)
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        ports = need_ssh_ports()
        probs = nft_ssh_problems(nft_parse(nft_persistent()), ports)
        if probs:
            raise ManualRequired("開機規則集會阻擋連入但缺少必要放行（%s），請先人工修正" % "；".join(probs))
        incs = nft_conf_includes(read_text(NFT_CONF))
        valid = incs and all(glob.glob(i) for i in incs) and which("nft") \
            and run(["nft", "-c", "-f", NFT_CONF], timeout=30).ok
        if MANAGED_NFT not in incs and not valid:
            # 只有在沒有可用的 include 時才建立本工具管理的規則檔；使用者規則已就緒時只需啟用服務
            nft_apply(ctx, fx, set())
        en = pkgsvc.svc_state(self.UNIT)[0]
        if en != "enabled":
            unmask_if_masked(fx, self.UNIT)
            fx._record_service(self.UNIT)
            fx.run(["systemctl", "enable", self.UNIT], "設定 nftables 服務開機啟動（原 %s）" % en)


# ====================================================================
# Iptables（僅 RHEL 8）
# ====================================================================

def _ipt_when(ctx):
    return backend_is("iptables")(ctx)


def _ipt_v6_when(ctx):
    r = _ipt_when(ctx)
    if r:
        return r
    return "核心已停用 IPv6，沒有 IPv6 流量需要以 ip6tables 管制" if _v6_disabled() else None


# [IptEnabled] RHEL8 0256 iptables 服務（啟用）
class IptEnabled(Rule):
    category = IPT
    risk = "B"
    title = "iptables 服務"
    expected = "啟用"
    UNIT = "iptables.service"

    def __init__(self, ids):
        self.ids = ids
        self.when = _ipt_when

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "iptables-services"):
            return Check(FAIL, "未安裝 iptables-services")
        en, act = pkgsvc.svc_state(self.UNIT)
        return Check(PASS if en == "enabled" and act == "active" else FAIL, "%s / %s" % (en, act))

    def fix(self, ctx, fx):
        ports = need_ssh_ports()
        if not pkgsvc.pkg_installed(ctx.osi, "iptables-services"):
            raise ManualRequired("未安裝 iptables-services；為避免與 firewalld 衝突不自動安裝，請人工評估後安裝")
        fam = IptFamily(False)
        pol, rules = ipt_parse(read_text(fam.file), saved=True)
        if ipt_ssh_problems(pol, rules, ports):
            # 開機規則檔會阻擋連入：補上 lo、已建立連線與 SSH 埠放行（插入在既有規則之前）
            add = ["-A INPUT -i lo -j ACCEPT",
                   "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]
            add += ["-A INPUT -p tcp -m tcp --dport %s -j ACCEPT" % p for p in ports]
            fx.edit_file(fam.file, lambda t: ipt_file_add_allows(t, add), mode=0o600)
        others = other_listening(ports)
        if others:
            fx.note("iptables 規則檔若有預設拒絕，下列對外監聽的連接埠可能被阻擋（未自動放行）：" + "、".join(others))
        fx.add_undo(FW_RELOAD_GUARD, "重新載入 firewalld（若執行中）")
        restore = ipt_snapshot(ctx, fx, fam) if fam.available() else None
        guard = Guard(fx, restore)
        try:
            unmask_if_masked(fx, self.UNIT)
            fx.service_enable(self.UNIT)
            if not fx.dry:
                probs = ipt_ssh_problems(*(ipt_parse(fam.runtime()) + (ports,)))
                if probs:
                    raise FixError("啟用後 SSH 放行規則檢查失敗：%s" % "；".join(probs))
        finally:
            guard.cancel()


# [IptDefaultDrop] RHEL8 0258 在 iptables 建立預設拒絕規則、RHEL8 0260 在 ip6tables 建立預設拒絕規則
class IptDefaultDrop(Rule):
    category = IPT
    risk = "B"
    CHAINS = ("INPUT", "FORWARD", "OUTPUT")
    ICMP6 = ("133", "134", "135", "136", "2")  # 路由器/鄰居探索、Packet Too Big

    def __init__(self, ids, v6):
        self.ids = ids
        self.fam = IptFamily(v6)
        self.title = "在 %s 建立預設拒絕規則" % self.fam.cmd
        self.expected = "Drop（INPUT、FORWARD、OUTPUT 預設政策 DROP）"
        self.manual_hint = "OUTPUT 預設拒絕需先放行 " + OUTPUT_SUGGEST + "，請管理者確認後自行設定"
        self.when = _ipt_v6_when if v6 else _ipt_when

    def check(self, ctx):
        if not self.fam.available():
            return Check(FAIL, "找不到 %s" % self.fam.cmd)
        rt = self.fam.runtime()
        if rt is None:
            return Check(ERROR, "%s -S 執行失敗" % self.fam.cmd)
        cur, _ = ipt_parse(rt)
        per, _ = ipt_parse(read_text(self.fam.file), saved=True)
        ok = all(cur.get(c) == "DROP" and per.get(c) == "DROP" for c in self.CHAINS)
        return Check(PASS if ok else FAIL, "目前/開機 " + "、".join(
            "%s:%s/%s" % (c, cur.get(c, "?"), per.get(c, "未設定")) for c in self.CHAINS))

    def fix(self, ctx, fx):
        ports = need_ssh_ports()
        fam = self.fam
        if not fam.available():
            raise ManualRequired("找不到 %s / %s" % (fam.cmd, fam.save))
        allow = [["INPUT", "-i", "lo", "-j", "ACCEPT"],
                 ["INPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]]
        allow += [["INPUT", "-p", "tcp", "--dport", p, "-j", "ACCEPT"] for p in ports]
        if fam.v6:
            allow += [["INPUT", "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "ACCEPT"] for t in self.ICMP6]
        fwd = forwarding_in_use()
        others = other_listening(ports)
        restore = ipt_snapshot(ctx, fx, fam)
        guard = Guard(fx, restore)
        try:
            pos = 1
            for a in allow:
                if not _ipt_exists(fam, a):
                    fx.run([fam.cmd, "-I", a[0], str(pos)] + a[1:], "%s 放行：%s" % (fam.cmd, " ".join(a)))
                    pos += 1
            fx.run([fam.cmd, "-P", "INPUT", "DROP"], "%s INPUT 預設政策 DROP" % fam.cmd)
            if fwd:
                fx.note("偵測到 IP 轉送或容器/虛擬化（%s），FORWARD 未設為 DROP，請人工評估" % fwd)
            else:
                fx.run([fam.cmd, "-P", "FORWARD", "DROP"], "%s FORWARD 預設政策 DROP" % fam.cmd)
            if not fx.dry:
                probs = ipt_ssh_problems(*(ipt_parse(fam.runtime()) + (ports,)))
                if probs:
                    raise FixError("套用後 SSH 放行規則檢查失敗：%s" % "；".join(probs))
                fx.step("確認 SSH 放行", "INPUT 已放行 lo、已建立連線與 SSH 埠 %s" % ",".join(ports), "成功")
            ipt_persist(fx, fam)
        finally:
            guard.cancel()
        if others:
            fx.note("INPUT 預設拒絕後只放行 SSH 埠 %s；下列對外監聽的連接埠將被阻擋，需要時請人工新增放行規則：%s"
                    % (",".join(ports), "、".join(others)))
        fx.partial = True
        fx.note("OUTPUT 預設拒絕未自動設定（GCB 決策：預設拒絕外出只檢測）；建議先放行 " + OUTPUT_SUGGEST
                + "，確認後再設定 -P OUTPUT DROP")


# [IptLoopback] RHEL8 0259 在 iptables 設定回送流量規則、RHEL8 0261 在 ip6tables 設定回送流量規則
class IptLoopback(Rule):
    category = IPT

    def __init__(self, ids, v6):
        self.ids = ids
        self.fam = IptFamily(v6)
        self.title = "在 %s 設定回送流量規則" % self.fam.cmd
        self.expected = "建立回送流量規則（INPUT/OUTPUT 放行 lo、INPUT 拒絕 %s）" % self.fam.loop_src
        self.when = _ipt_v6_when if v6 else _ipt_when

    def check(self, ctx):
        if not self.fam.available():
            return Check(FAIL, "找不到 %s" % self.fam.cmd)
        rt = self.fam.runtime()
        if rt is None:
            return Check(ERROR, "%s -S 執行失敗" % self.fam.cmd)
        mc = ipt_loopback_missing(ipt_parse(rt)[1], self.fam.v6)
        mp = ipt_loopback_missing(ipt_parse(read_text(self.fam.file), saved=True)[1], self.fam.v6)
        if not mc and not mp:
            return Check(PASS, "回送流量規則已設定（目前與 %s）" % self.fam.file)
        return Check(FAIL, "目前缺少：%s；%s 缺少：%s" % ("、".join(mc) or "無", self.fam.file, "、".join(mp) or "無"))

    def fix(self, ctx, fx):
        fam = self.fam
        if not fam.available():
            raise ManualRequired("找不到 %s / %s" % (fam.cmd, fam.save))
        ipt_snapshot(ctx, fx, fam)
        rules = ipt_parse(fam.runtime())[1]
        lo_in = ["INPUT", "-i", "lo", "-j", "ACCEPT"]
        lo_out = ["OUTPUT", "-o", "lo", "-j", "ACCEPT"]
        drop = ["INPUT", "-s", fam.loop_src, "-j", "DROP"]
        miss = ipt_loopback_missing(rules, fam.v6)
        if any(m.startswith("（") for m in miss) or not _ipt_exists(fam, lo_in):
            fx.run([fam.cmd, "-I", "INPUT", "1"] + lo_in[1:], "%s INPUT 放行 lo（置於鏈開頭）" % fam.cmd)
        if not _ipt_exists(fam, lo_out):
            fx.run([fam.cmd, "-I", "OUTPUT", "1"] + lo_out[1:], "%s OUTPUT 放行 lo（置於鏈開頭）" % fam.cmd)
        if not _ipt_exists(fam, drop):
            # 插在第一條 lo 放行規則之後
            pos = 2
            if not fx.dry:
                inp = [r for r in ipt_parse(fam.runtime())[1] if r.startswith("-A INPUT ")]
                lo = [i for i, r in enumerate(inp) if _ipt_rule_eq(r, ipt_loop_rules(fam.v6)[0])]
                pos = lo[0] + 2 if lo else 1
            fx.run([fam.cmd, "-I", "INPUT", str(pos)] + drop[1:], "%s INPUT 拒絕迴路位址 %s（lo 放行之後）" % (
                fam.cmd, fam.loop_src))
        ipt_persist(fx, fam)


# ====================================================================
# 規則清單
# ====================================================================

def _pkg_present(title, pkg, ids, category, when=None):
    r = PackagePresent(title, pkg, ids, category)
    r.expected = "安裝（%s）" % pkg
    r.when = when
    return r


RULES = [
    # ---------------- SELinux ----------------
    # RHEL8 0185 / RHEL9 0183 SELinux 套件
    _pkg_present("SELinux 套件", "libselinux", R(r8=185, r9=183), SEL),
    # RHEL8 0186 / RHEL9 0184 開機載入程式啟用 SELinux
    SelinuxBootloader(R(r8=186, r9=184)),
    # RHEL8 0187 / RHEL9 0185 SELinux 政策
    SelinuxPolicy(R(r8=187, r9=185)),
    # RHEL8 0188 / RHEL9 0186 SELinux 啟用狀態 → common.py
    # RHEL8 0189 / RHEL9 0187 未受限程序
    Unconfined(R(r8=189, r9=187)),
    # RHEL8 0190 / RHEL9 0188 setroubleshoot 套件
    _pkg_absent(SetroubleshootAbsent, "setroubleshoot 套件", "setroubleshoot", R(r8=190, r9=188)),
    # RHEL8 0191 / RHEL9 0189 mcstrans 套件
    _pkg_absent(PackageAbsent, "mcstrans 套件", "mcstrans", R(r8=191, r9=189)),

    # ---------------- cron 設定 ----------------
    # RHEL8 0192 / RHEL9 0190 cron 守護程序
    ServiceEnabled("cron 守護程序", CRON, "crond", {"rhel": "cronie"}, R(r8=192, r9=190)),
    # RHEL8 0193 / RHEL9 0191 /etc/crontab 檔案所有權
    cron_perm("/etc/crontab 檔案所有權", R(r8=193, r9=191), "/etc/crontab", owner=True),
    # RHEL8 0194 / RHEL9 0192 /etc/crontab 檔案權限
    cron_perm("/etc/crontab 檔案權限", R(r8=194, r9=192), "/etc/crontab", max_mode=0o600),
    # RHEL8 0195 / RHEL9 0193 /etc/cron.hourly 目錄所有權
    cron_perm("/etc/cron.hourly 目錄所有權", R(r8=195, r9=193), "/etc/cron.hourly", owner=True),
    # RHEL8 0196 / RHEL9 0194 /etc/cron.hourly 目錄權限
    cron_perm("/etc/cron.hourly 目錄權限", R(r8=196, r9=194), "/etc/cron.hourly", max_mode=0o700),
    # RHEL8 0197 / RHEL9 0195 /etc/cron.daily 目錄所有權
    cron_perm("/etc/cron.daily 目錄所有權", R(r8=197, r9=195), "/etc/cron.daily", owner=True),
    # RHEL8 0198 / RHEL9 0196 /etc/cron.daily 目錄權限
    cron_perm("/etc/cron.daily 目錄權限", R(r8=198, r9=196), "/etc/cron.daily", max_mode=0o700),
    # RHEL8 0199 / RHEL9 0197 /etc/cron.weekly 目錄所有權
    cron_perm("/etc/cron.weekly 目錄所有權", R(r8=199, r9=197), "/etc/cron.weekly", owner=True),
    # RHEL8 0200 / RHEL9 0198 /etc/cron.weekly 目錄權限
    cron_perm("/etc/cron.weekly 目錄權限", R(r8=200, r9=198), "/etc/cron.weekly", max_mode=0o700),
    # RHEL8 0201 / RHEL9 0199 /etc/cron.monthly 目錄所有權
    cron_perm("/etc/cron.monthly 目錄所有權", R(r8=201, r9=199), "/etc/cron.monthly", owner=True),
    # RHEL8 0202 / RHEL9 0200 /etc/cron.monthly 目錄權限
    cron_perm("/etc/cron.monthly 目錄權限", R(r8=202, r9=200), "/etc/cron.monthly", max_mode=0o700),
    # RHEL8 0203 / RHEL9 0201 /etc/cron.d 目錄所有權
    cron_perm("/etc/cron.d 目錄所有權", R(r8=203, r9=201), "/etc/cron.d", owner=True),
    # RHEL8 0204 / RHEL9 0202 /etc/cron.d 目錄權限
    cron_perm("/etc/cron.d 目錄權限", R(r8=204, r9=202), "/etc/cron.d", max_mode=0o700),
    # RHEL8 0205 / RHEL9 0203 at.allow 與 cron.allow 檔案所有權
    CronAllow("at.allow 與 cron.allow 檔案所有權", R(r8=205, r9=203), "owner"),
    # RHEL8 0206 / RHEL9 0204 at.allow 與 cron.allow 檔案權限
    CronAllow("at.allow 與 cron.allow 檔案權限", R(r8=206, r9=204), "perm"),
    # RHEL8 0207 / RHEL9 0205 cron 日誌記錄功能
    CronLogging(R(r8=207, r9=205)),

    # ---------------- Firewalld 配置 ----------------
    # RHEL8 0244 / RHEL9 0242 firewalld 防火牆套件
    _pkg_present("firewalld 防火牆套件", "firewalld", R(r8=244, r9=242), FWD, when=_fw_when),
    # RHEL8 0245 / RHEL9 0243 firewalld 服務
    FirewalldEnabled(R(r8=245, r9=243)),
    # RHEL8 0246 / RHEL9 0244 iptables 服務
    UnitsMasked("iptables 服務", ["iptables.service", "ip6tables.service"], R(r8=246, r9=244), "iptables"),
    # RHEL8 0247 / RHEL9 0245 nftables 服務
    UnitsMasked("nftables 服務", ["nftables.service"], R(r8=247, r9=245), "nftables"),
    # RHEL8 0248 / RHEL9 0246 firewalld 防火牆預設區域
    FirewalldZone(R(r8=248, r9=246)),

    # ---------------- Nftables 配置 ----------------
    # RHEL8 0249 / RHEL9 0247 nftables 服務
    NftEnabled(R(r8=249, r9=247)),
    # RHEL8 0250 / RHEL9 0248 firewalld 服務
    FirewalldMasked(R(r8=250, r9=248), "nftables"),
    # RHEL8 0251 / RHEL9 0249 在 nftables 中建立表
    NftTable(R(r8=251, r9=249)),
    # RHEL8 0252 / RHEL9 0250 在 nftables 建立基本鏈
    NftChains(R(r8=252, r9=250)),
    # RHEL8 0253 / RHEL9 0251 在 nftables 設定回送流量規則
    NftLoopback(R(r8=253, r9=251)),
    # RHEL8 0254 / RHEL9 0252 在 nftables 建立預設拒絕規則
    NftDefaultDrop(R(r8=254, r9=252)),
    # RHEL8 0255 / RHEL9 0253 載入 nftables 規則
    NftPersist(R(r8=255, r9=253)),

    # ---------------- Iptables 配置（僅 RHEL 8） ----------------
    # RHEL8 0256 iptables 服務
    IptEnabled(R(r8=256)),
    # RHEL8 0257 firewalld 服務
    FirewalldMasked(R(r8=257), "iptables"),
    # RHEL8 0258 在 iptables 建立預設拒絕規則
    IptDefaultDrop(R(r8=258), v6=False),
    # RHEL8 0259 在 iptables 設定回送流量規則
    IptLoopback(R(r8=259), v6=False),
    # RHEL8 0260 在 ip6tables 建立預設拒絕規則
    IptDefaultDrop(R(r8=260), v6=True),
    # RHEL8 0261 在 ip6tables 設定回送流量規則
    IptLoopback(R(r8=261), v6=True),
]
