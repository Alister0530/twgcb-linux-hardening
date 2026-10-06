# -*- coding: utf-8 -*-
"""RHEL selinux.py 涵蓋率測試（一）：SELinux、cron、共用工具、nftables。

所有指令、檔案、服務狀態皆以假物件取代，不修改系統。
防火牆修復著重驗證：SSH／lo／已建立連線放行先於預設拒絕，回滾與自動還原保險先於修改登記。
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402
from fakes import FakeCtx, FakeRunner, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS  # noqa: E402
from gcb.rules.rhel import selinux as s  # noqa: E402

# 以假資料模擬的系統路徑前綴；其他路徑（暫存目錄）使用真實 os
VIRTUAL = ("/etc/", "/proc/", "/var/", "/boot/", "/sys/", "/.autorelabel")
ALL_CMDS = {"getenforce", "grubby", "grub2-editenv", "sestatus", "rsyslogd", "sshd", "nft", "systemd-run",
            "iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save", "ip6tables-restore",
            "firewall-cmd"}
GUARD_UNIT = "gcb-fw-guard-TEST-1000"


# ---------------- 假系統 ----------------

class St(object):
    def __init__(self, uid=0, gid=0, mode=0o100600):
        self.st_uid, self.st_gid, self.st_mode = uid, gid, mode


class FakePath(object):
    def __init__(self, env):
        self.env = env

    def __getattr__(self, name):
        return getattr(os.path, name)

    def exists(self, p):
        if self.env.virtual(p):
            return p in self.env.exists or p in self.env.fs
        return os.path.exists(p)

    def isdir(self, p):
        if self.env.virtual(p):
            return p in self.env.dirs
        return os.path.isdir(p)

    def realpath(self, p):
        return p if self.env.virtual(p) else os.path.realpath(p)


class FakeOs(object):
    def __init__(self, env):
        self.env = env
        self.path = FakePath(env)
        self.environ = env.environ

    def __getattr__(self, name):
        return getattr(os, name)

    def stat(self, p):
        if self.env.virtual(p):
            return self.env.stats.get(p) or St()
        return os.stat(p)

    def listdir(self, p):
        return list(self.env.dirs.get(p, []))

    def readlink(self, p):
        if p in self.env.links:
            return self.env.links[p]
        raise OSError("no link")


class FakeGlob(object):
    def __init__(self, env):
        self.env = env

    def glob(self, pattern):
        return list(self.env.globs.get(pattern, []))


class FakeTime(object):
    @staticmethod
    def time():
        return 1000


class Journal(object):
    def __init__(self, d):
        self.backup_dir = d


class Fx(fakes.FakeFx):
    """補上 mask_unit／NftPersist 會用到的 _record_service。"""

    def _record_service(self, unit):
        self.events.append(("record", unit))
        return s.pkgsvc.svc_state(unit)


class FakeFirewalld(object):
    """firewall-cmd / firewall-offline-cmd 的簡易模型：區域分永久（perm）與目前（rt）設定。"""
    SERVICES = {"ssh": "22/tcp", "http": "80/tcp", "dhcpv6-client": "546/udp"}

    def __init__(self, running=False, default="public", zones=None):
        self.running = running
        self.default = default
        # zone -> {"target", "ifaces", "perm": set, "rt": set}
        self.zones = zones or {}
        self.nm_zone = None          # 只在執行時出現的作用中區域（NetworkManager 指定）
        self.ignore_rt_adds = False  # 模擬目前設定加入失效
        self.start_ok = True

    def zone(self, name, ifaces=(), perm=(), target="default"):
        self.zones[name] = {"target": target, "ifaces": list(ifaces), "perm": set(perm), "rt": set(perm)}

    def start(self):
        if self.start_ok:
            self.running = True
            self.reload()

    def reload(self):
        for z in self.zones.values():
            z["rt"] = set(z["perm"])

    def __call__(self, c):
        t = c.split()
        offline = t[0] == "firewall-offline-cmd"
        perm = offline or "--permanent" in t
        if "--state" in t:
            return res(0, "running\n") if self.running else res(252, "not running\n")
        if not offline and not self.running:
            return res(252, "", "FirewallD is not running")
        zone = [a.split("=", 1)[1] for a in t if a.startswith("--zone=")]
        key = "perm" if perm else "rt"
        if "--get-default-zone" in t:
            return res(0, self.default + "\n")
        if "--get-zones" in t:
            return res(0, " ".join(sorted(self.zones)) + "\n")
        if "--list-all-zones" in t:
            out = ""
            for n in sorted(self.zones):
                z = self.zones[n]
                out += "%s\n  target: %s\n  interfaces: %s\n  sources: \n\n" % (n, z["target"], " ".join(z["ifaces"]))
            return res(0, out)
        if "--get-active-zones" in t:
            act = [n for n in sorted(self.zones) if self.zones[n]["ifaces"]]
            if self.nm_zone:
                act.append(self.nm_zone)
            return res(0, "".join("%s\n  interfaces: eth0\n" % n for n in act))
        if "--list-all" in t:
            z = self.zones[zone[0]]
            items = z[key]
            return res(0, "%s\n  target: %s\n  services: %s\n  ports: %s\n" % (
                zone[0], z["target"], " ".join(sorted(i for i in items if "/" not in i)),
                " ".join(sorted(i for i in items if "/" in i))))
        for a in t:
            if a.startswith("--info-service="):
                return res(0, "%s\n  ports: %s\n" % (a.split("=")[1], self.SERVICES.get(a.split("=")[1], "")))
            if a.startswith("--add-service=") or a.startswith("--add-port="):
                if not (key == "rt" and self.ignore_rt_adds):
                    self.zones[zone[0]][key].add(a.split("=", 1)[1])
                return res(0, "success\n")
            if a.startswith("--set-default-zone="):
                self.default = a.split("=", 1)[1]
                return res(0, "success\n")
        if "--reload" in t:
            self.reload()
            return res(0, "success\n")
        return res(1, "", "unknown")


class FakeIpt(object):
    """iptables / ip6tables 的簡易模型（只有 filter 表）。"""

    def __init__(self, cmd="iptables", pol=None, rules=None):
        self.cmd = cmd
        self.pol = {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"}
        self.pol.update(pol or {})
        self.rules = list(rules or [])
        self.frozen = False  # True：-I 不生效（模擬放行規則沒有載入）
        self.save_rc = 0
        self.s_rc = 0

    def load_saved(self, text):
        pol, rules = s.ipt_parse(text, saved=True)
        self.pol.update(pol)
        self.rules = rules

    def dump_s(self):
        return "".join("-P %s %s\n" % (c, self.pol[c]) for c in ("INPUT", "FORWARD", "OUTPUT")) + \
            "".join(r + "\n" for r in self.rules)

    def dump_save(self):
        return "*filter\n" + "".join(":%s %s [0:0]\n" % (c, self.pol[c]) for c in ("INPUT", "FORWARD", "OUTPUT")) + \
            "".join(r + "\n" for r in self.rules) + "COMMIT\n"

    def __call__(self, c):
        t = c.split()
        if t[0] in (self.cmd + "-save", "sh"):
            return res(self.save_rc, self.dump_save() if self.save_rc == 0 else "", "save error")
        op = t[1]
        if op == "-S":
            return res(self.s_rc, self.dump_s() if self.s_rc == 0 else "")
        if op == "-C":
            return res(0) if "-A " + " ".join(t[2:]) in self.rules else res(1)
        if op == "-I":
            if self.frozen:
                return res(0)
            chain, pos = t[2], int(t[3])
            idx = [i for i, r in enumerate(self.rules) if r.split()[1] == chain]
            at = idx[pos - 1] if pos - 1 < len(idx) else (idx[-1] + 1 if idx else len(self.rules))
            self.rules.insert(at, "-A %s %s" % (chain, " ".join(t[4:])))
            return res(0)
        if op == "-P":
            self.pol[t[2]] = t[3]
            return res(0)
        return res(1)


class Env(unittest.TestCase):
    """共用的假系統環境：patch selinux 模組使用的 run/which/read_text/os/glob/time 與 pkgsvc。"""

    def setUp(self):
        self.fs, self.exists, self.dirs, self.stats, self.links = {}, set(), {}, {}, {}
        self.environ, self.states, self.pkgs, self.globs = {}, {}, set(), {}
        self.cmds = set(ALL_CMDS)
        self.backups = {}
        self.runner = FakeRunner()
        # 自動還原保險要比 firewall-cmd／iptables 的規則先對應（其指令內含還原指令文字）
        self.runner.rules.append(("systemd-run", res(0)))
        self.runner.rules.append(("sshd -T", res(0, "port 22\nport 2222\n")))
        self.tmp = tempfile.mkdtemp(prefix="gcb-cov-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patches = [
            mock.patch.object(s, "run", self.runner),
            mock.patch.object(s, "which", lambda n: "/usr/sbin/" + n if n in self.cmds else None),
            mock.patch.object(s, "read_text", lambda p, *a, **k: self.fs.get(p)),
            mock.patch.object(s, "write_text_atomic", self._write_atomic),
            mock.patch.object(s, "stamp", lambda: "20260101-000000"),
            mock.patch.object(s, "os", FakeOs(self)),
            mock.patch.object(s, "glob", FakeGlob(self)),
            mock.patch.object(s, "time", FakeTime),
            mock.patch.object(s.pkgsvc, "svc_state", lambda u: self.states.get(u, ("not-found", "inactive"))),
            mock.patch.object(s.pkgsvc, "pkg_installed", lambda osi, p: p in self.pkgs),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def virtual(self, p):
        return p.startswith(VIRTUAL) and not p.startswith(self.tmp)

    def _write_atomic(self, path, text, mode=0o644):
        self.backups[path] = text

    def ctx(self, key="rhel9", dry=False):
        c = FakeCtx(key, dry_run=dry)
        c.journal = Journal(os.path.join(self.tmp, "bk"))
        return c

    def fx(self, key="rhel9", dry=False):
        return Fx(self.ctx(key, dry), fs=self.fs, runner=self.runner)

    def on(self, pattern, result):
        """新增（優先）的指令對應。"""
        self.runner.add(pattern, result)

    @staticmethod
    def pos(fx, kind, sub):
        """第一個符合（種類、子字串）的事件索引；找不到時 fail。"""
        for i, e in enumerate(fx.events):
            if e[0] == kind and sub in str(e[1]):
                return i
        raise AssertionError("找不到事件 %s %s：%s" % (kind, sub, fx.events))


# ---------------- 共用小工具 ----------------

class Helpers(Env):
    def test_getenforce(self):
        self.on("getenforce", res(0, "Enforcing\n"))
        self.assertEqual(s._getenforce(), "Enforcing")
        self.on("getenforce", res(1))
        self.assertIsNone(s._getenforce())
        self.cmds.discard("getenforce")
        self.assertIsNone(s._getenforce())

    def test_write_backup(self):
        fx = self.fx(dry=True)
        self.assertIsNone(s._write_backup(fx.ctx, fx, "x.rules", "data"))
        self.assertEqual(fx.steps[-1][2], "預覽")
        fx = self.fx()
        p = s._write_backup(fx.ctx, fx, "x.rules", "data")
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "bk")))  # 目錄不存在時建立
        self.assertTrue(p.endswith("TEST_20260101-000000_x.rules"))
        self.assertEqual(self.backups[p], "data")
        # 目錄已存在
        self.assertEqual(s._write_backup(fx.ctx, fx, "x.rules", "d2"), p)

    def test_grubenv_no_kernelopts(self):
        self.assertIsNone(s.grubenv_kernelopts("saved_entry=x\n"))

    def test_sshd_ports(self):
        self.on("sshd -T", res(0, "port 22\nlistenaddress 0.0.0.0:2222\n"))
        self.on("ss -Htlnp", res(0, 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                                    'LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("httpd",pid=2,fd=3))\n'
                                    '"sshd" short\n'))
        self.assertEqual(s.sshd_ports(), ["22", "2200", "2222"])
        # 無 sshd 指令：只看 ss
        self.cmds.discard("sshd")
        self.assertEqual(s.sshd_ports(), ["2200"])

    def test_ssh_ports_all_and_need(self):
        self.environ["SSH_CONNECTION"] = "10.0.0.9 51000 10.0.0.1 22022"
        self.assertEqual(s.ssh_ports_all(), ["22", "2222", "22022"])
        self.on("sshd -T", res(255))
        self.assertEqual(s.ssh_ports_all(), [])
        with self.assertRaises(ManualRequired):
            s.need_ssh_ports()

    def test_other_listening(self):
        self.on("ss -Htlnu", res(0, "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
                                    "tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*\n"
                                    "tcp LISTEN 0 128 [::1]:25 [::]:*\n"
                                    "udp UNCONN 0 0 0.0.0.0:123 0.0.0.0:*\n"
                                    "tcp LISTEN 0 128 [fe80::1%eth0]:80 [::]:*\n"
                                    "tcp LISTEN 0 128 0.0.0.0:* 0.0.0.0:*\n"
                                    "short line\n"))
        self.assertEqual(s.other_listening(["22"]), ["tcp/80", "udp/123"])

    def test_forwarding_in_use(self):
        self.assertIsNone(s.forwarding_in_use())
        self.fs["/proc/sys/net/ipv4/ip_forward"] = "1\n"
        self.states["docker"] = ("enabled", "active")
        self.dirs["/sys/class/net"] = ["eth0", "docker0"]
        self.assertEqual(s.forwarding_in_use(), "net.ipv4.ip_forward=1、docker、docker0")

    def test_backend_when(self):
        # firewalld／nftables 規則的適用條件依 config.ini firewall_backend
        c = self.ctx()
        c.cfg.firewall_backend = "nftables"
        self.assertIsNone(s._nft_when(c))
        self.assertEqual(s._fw_when(c), "GCB 防火牆規則 firewalld／nftables／iptables 三選一；本機採用 nftables"
                                        "（依據：config.ini 指定 firewall_backend=nftables），本項目屬 firewalld，不需設定")
        c.cfg.firewall_backend = "firewalld"
        self.assertIsNone(s._fw_when(c))
        self.assertIn("本項目屬 nftables", s._nft_when(c))

    def test_unmask_if_masked(self):
        fx = self.fx()
        s.unmask_if_masked(fx, "nftables.service")
        self.assertEqual(fx.events, [])
        self.states["nftables.service"] = ("masked", "inactive")
        s.unmask_if_masked(fx, "nftables.service")
        # 先登記回滾（遮蔽回去）再解除遮蔽
        self.assertEqual(fx.events, [("undo", "systemctl mask nftables.service"),
                                     ("run", "systemctl unmask nftables.service")])

    def test_mask_unit(self):
        fx = self.fx()
        self.states["nftables.service"] = ("enabled", "active")
        self.assertTrue(s.mask_unit(fx.ctx, fx, "nftables.service", stop_first=True))
        self.assertEqual(fx.events, [("record", "nftables.service"), ("run", "systemctl stop nftables.service"),
                                     ("run", "systemctl mask nftables.service")])
        self.assertIn("nftables.service", fx.ctx.intended_stops)
        fx = self.fx()
        self.states["nftables.service"] = ("enabled", "inactive")
        self.assertFalse(s.mask_unit(fx.ctx, fx, "nftables.service", stop_first=True))
        self.assertEqual(fx.kinds("run"), ["systemctl mask nftables.service"])

    def test_guard(self):
        fx = self.fx()
        g = s.Guard(fx, ["nft", "-f", "/bk/r.nft"], seconds=120)
        self.assertEqual(g.unit, GUARD_UNIT)
        self.assertEqual(fx.kinds("run"), ["systemd-run --unit %s --on-active=120 nft -f /bk/r.nft" % GUARD_UNIT])
        g.cancel()
        g.cancel()  # 第二次不再執行
        self.assertEqual(fx.kinds("run")[1:], ["systemctl stop %s.timer" % GUARD_UNIT])
        # systemd-run 失敗：沒有保險可取消
        self.on("systemd-run", res(1))
        fx = self.fx()
        g = s.Guard(fx, ["nft"])
        self.assertIsNone(g.unit)
        g.cancel()
        self.assertEqual(len(fx.kinds("run")), 1)
        # 沒有 systemd-run、預覽、沒有還原指令：不設定
        self.cmds.discard("systemd-run")
        for f, cmd in ((self.fx(), ["nft"]), (self.fx(dry=True), ["nft"]), (self.fx(), None)):
            self.assertIsNone(s.Guard(f, cmd).unit)
            self.assertEqual(f.events, [])

    def test_fw_guard(self):
        fx = self.fx()
        self.assertIsNone(s.fw_guard(fx, None, True).unit)
        self.assertEqual(fx.events, [])
        s.fw_guard(fx, "/bk/fw.tar", True)
        self.assertIn("tar -xf /bk/fw.tar -C /etc && firewall-cmd --reload", fx.events[-1][1])
        s.fw_guard(fx, "/bk/fw.tar", False)
        self.assertIn("&& systemctl stop firewalld", fx.events[-1][1])
        self.assertTrue(fx.events[-1][1].startswith("systemd-run --unit %s --on-active=300 sh -c" % GUARD_UNIT))


# ---------------- SELinux ----------------

GRUBBY_BAD = 'index=0\nkernel="/boot/vmlinuz-4.18"\nargs="ro selinux=0"\n'
GRUBBY_OK = 'index=0\nkernel="/boot/vmlinuz-4.18"\nargs="ro quiet"\n'


# RHEL8 0186 / RHEL9 0184 開機載入程式啟用 SELinux
class SelinuxBootloaderTest(Env):
    def setUp(self):
        Env.setUp(self)
        self.rule = s.SelinuxBootloader({"rhel8": "TWGCB-01-008-0186", "rhel9": "TWGCB-01-012-0184"})

    def test_check_errors(self):
        self.cmds.discard("grubby")
        self.assertEqual(self.rule.check(self.ctx()).status, ERROR)
        self.cmds.add("grubby")
        self.on("grubby --info=ALL", res(1))
        c = self.rule.check(self.ctx())
        self.assertEqual((c.status, c.current), (ERROR, "grubby 執行失敗"))
        with self.assertRaises(FixError):
            self.rule.fix(self.ctx(), self.fx())

    def test_check_fail_rhel8(self):
        self.on("grubby --info=ALL", res(0, GRUBBY_BAD))
        self.on("grub2-editenv list", res(0, "kernelopts=root=/dev/sda ro enforcing=0\n"))
        self.fs[s.DEFAULT_GRUB] = 'GRUB_CMDLINE_LINUX="rhgb selinux=0"\n'
        self.fs["/proc/cmdline"] = "ro selinux=0"
        c = self.rule.check(self.ctx("rhel8"))
        self.assertEqual(c.status, FAIL)
        for part in ("/boot/vmlinuz-4.18：selinux=0", "/etc/default/grub：selinux=0",
                     "grubenv kernelopts：enforcing=0", "目前核心仍帶 selinux=0"):
            self.assertIn(part, c.current)

    def test_check_pass_but_running(self):
        self.on("grubby --info=ALL", res(0, GRUBBY_OK))
        self.fs["/proc/cmdline"] = "ro enforcing=0"
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, PASS)
        self.assertIn("目前核心仍帶 enforcing=0（需重開機生效）", c.current)
        self.assertEqual(self.runner.ran("grub2-editenv"), [])  # RHEL 9 不看 grubenv

    def _bad_rhel8(self, selinux_conf):
        self.on("grubby --info=ALL", res(0, GRUBBY_BAD))
        self.on("grub2-editenv list", res(0, "kernelopts=root=/dev/sda ro selinux=0 enforcing=0\n"))
        self.on("getenforce", res(0, "Disabled\n"))
        self.fs[s.DEFAULT_GRUB] = 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="rhgb selinux=0"\n'
        self.fs[s.SELINUX_CONF] = selinux_conf
        self.globs[s.BLS_ENTRIES] = ["/boot/loader/entries/b.conf", "/boot/loader/entries/a.conf"]

    def test_fix_rhel8_selinux0_enforcing(self):
        self._bad_rhel8("SELINUX=enforcing\nSELINUXTYPE=targeted\n")
        fx = self.fx("rhel8")
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(self.fs[s.DEFAULT_GRUB], 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="rhgb"\n')
        # grubby 改寫前先備份 BLS 開機項目與 grubenv
        grubby = self.pos(fx, "run", "grubby --update-kernel=ALL")
        self.assertLess(self.pos(fx, "backup", "a.conf"), self.pos(fx, "backup", "b.conf"))
        self.assertLess(self.pos(fx, "backup", "b.conf"), grubby)
        self.assertLess(self.pos(fx, "backup", s.GRUBENV), grubby)
        self.assertIn("'--remove-args=selinux=0 enforcing=0'", fx.events[grubby][1])
        self.assertIn("grub2-editenv - set 'kernelopts=root=/dev/sda ro'", fx.kinds("run"))
        # 原以 selinux=0 停用：建立 /.autorelabel 並暫設 permissive
        self.assertEqual(self.fs["/.autorelabel"], "")
        self.assertIn("SELINUX=permissive", self.fs[s.SELINUX_CONF])
        self.assertIn("暫設 SELINUX=permissive", fx.notes[0])
        self.assertEqual(fx.notes[-1], "開機參數已更新，重開機後生效")

    def test_fix_rhel8_selinux0_permissive(self):
        self._bad_rhel8("SELINUX=permissive\n")
        fx = self.fx("rhel8")
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(self.fs[s.SELINUX_CONF], "SELINUX=permissive\n")
        self.assertIn("已建立 /.autorelabel", fx.notes[0])

    def test_fix_dry_run(self):
        self._bad_rhel8("SELINUX=enforcing\n")
        before = dict(self.fs)
        fx = self.fx("rhel8", dry=True)
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(self.fs, before)
        self.assertEqual(self.runner.ran("--update-kernel"), [])
        self.assertEqual(self.runner.ran("grub2-editenv - set"), [])

    def test_fix_enforcing_without_selinux0(self):
        self.on("grubby --info=ALL", res(0, GRUBBY_OK.replace("quiet", "enforcing=0")))
        self.on("getenforce", res(0, "Permissive\n"))
        fx = self.fx("rhel9")
        self.rule.fix(fx.ctx, fx)
        self.assertNotIn("/.autorelabel", self.fs)
        self.assertEqual(fx.notes, ["開機參數已更新，重開機後生效"])


# RHEL8 0187 / RHEL9 0185 SELinux 政策
class SelinuxPolicyTest(Env):
    def setUp(self):
        Env.setUp(self)
        self.rule = s.SelinuxPolicy({"rhel9": "TWGCB-01-012-0185"})

    def test_loaded(self):
        self.on("sestatus", res(0, "SELinux status: enabled\nLoaded policy name:             mls\n"))
        self.assertEqual(self.rule._loaded(), "mls")
        self.on("sestatus", res(0, "SELinux status: disabled\n"))
        self.assertIsNone(self.rule._loaded())
        self.cmds.discard("sestatus")
        self.assertIsNone(self.rule._loaded())

    def test_check(self):
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("不存在", c.current)
        self.fs[s.SELINUX_CONF] = "SELINUX=enforcing\n"
        self.assertEqual(self.rule.check(self.ctx()).current, "SELINUXTYPE 未設定")
        self.fs[s.SELINUX_CONF] = "SELINUXTYPE=targeted\n"
        self.on("sestatus", res(0, "Loaded policy name: mls\n"))
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, PASS)
        self.assertIn("目前載入政策為 mls", c.current)
        self.fs[s.SELINUX_CONF] = "SELINUXTYPE=minimum\n"
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("比 targeted 寬鬆", c.current)

    def test_fix_already_ok(self):
        self.fs[s.SELINUX_CONF] = "SELINUXTYPE=mls\n"
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_missing_conf(self):
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_minimum_enforcing(self):
        self.fs[s.SELINUX_CONF] = "SELINUX=enforcing\nSELINUXTYPE=minimum\n"
        self.on("getenforce", res(0, "Enforcing\n"))
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        # 先安裝政策套件再改設定
        self.assertLess(self.pos(fx, "pkg_install", "selinux-policy-targeted"), self.pos(fx, "write", s.SELINUX_CONF))
        self.assertEqual(self.fs[s.SELINUX_CONF], "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
        self.assertEqual(self.fs["/.autorelabel"], "")
        self.assertIn("由 minimum 改為 targeted", fx.notes[0])

    def test_fix_unset_type(self):
        self.fs[s.SELINUX_CONF] = "SELINUX=enforcing\n"
        self.pkgs.add("selinux-policy-targeted")
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("pkg_install"), [])
        self.assertIn("SELINUXTYPE=targeted", self.fs[s.SELINUX_CONF])
        self.assertNotIn("/.autorelabel", self.fs)  # 原本沒有設定政策：不需重新標記
        self.assertEqual(fx.notes, ["SELinux 政策變更需重開機生效"])


# RHEL8 0189 / RHEL9 0187 未受限程序
class UnconfinedTest(Env):
    def setUp(self):
        Env.setUp(self)
        self.rule = s.Unconfined({"rhel9": "TWGCB-01-012-0187"})

    def test_no_selinux(self):
        self.cmds.discard("getenforce")
        self.assertIn("找不到 getenforce", self.rule.check(self.ctx()).current)
        self.cmds.add("getenforce")
        self.on("getenforce", res(0, "Disabled\n"))
        self.assertEqual(self.rule.check(self.ctx()).status, FAIL)

    def test_processes(self):
        self.on("getenforce", res(0, "Enforcing\n"))
        self.globs["/proc/[0-9]*"] = ["/proc/1", "/proc/20", "/proc/30"]
        self.fs["/proc/1/attr/current"] = "system_u:system_r:init_t:s0\0"
        self.fs["/proc/20/attr/current"] = "system_u:system_r:unconfined_service_t:s0\0"
        self.fs["/proc/30/attr/current"] = "system_u:system_r:unconfined_service_t:s0\n"
        self.links["/proc/20/exe"] = "/opt/app/bin/app"
        self.fs["/proc/30/comm"] = "kworker\n"  # 無法讀取 exe 時用 comm
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "未受限程序 2 個：/opt/app/bin/app(20)、kworker(30)")
        del self.fs["/proc/20/attr/current"], self.fs["/proc/30/attr/current"]
        c = self.rule.check(self.ctx())
        self.assertEqual((c.status, c.current), (PASS, "無未受限程序（Enforcing）"))


# RHEL8 0190 / RHEL9 0188 setroubleshoot 套件
class SetroubleshootTest(Env):
    def test_server_note(self):
        rule = s.RULES[4]
        self.assertIsInstance(rule, s.SetroubleshootAbsent)
        self.assertEqual(rule.category, s.SEL)
        self.pkgs.update(["setroubleshoot", "setroubleshoot-server"])
        c = rule.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("另安裝了 setroubleshoot-server", c.current)
        self.pkgs.discard("setroubleshoot")
        c = rule.check(self.ctx())
        self.assertEqual(c.status, PASS)  # 只裝 server 不判不合格，只提示
        self.assertIn("請人工評估", c.current)


# ---------------- cron ----------------

# RHEL8 0205 / RHEL9 0203 at.allow 與 cron.allow 檔案所有權、RHEL8 0206 / RHEL9 0204 檔案權限
class CronAllowTest(Env):
    def setUp(self):
        Env.setUp(self)
        self.owner = s.CronAllow("所有權", {"rhel9": "TWGCB-01-012-0203"}, "owner")
        self.perm = s.CronAllow("權限", {"rhel9": "TWGCB-01-012-0204"}, "perm")

    def test_check(self):
        self.fs["/etc/cron.deny"] = "alice\n"
        self.exists.add("/etc/at.allow")
        self.stats["/etc/at.allow"] = St(1000, 0, 0o100644)
        c = self.owner.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "/etc/cron.deny 存在；/etc/cron.allow 不存在；/etc/at.allow uid=1000 gid=0")
        self.assertEqual(self.perm.check(self.ctx()).current,
                         "/etc/cron.deny 存在；/etc/cron.allow 不存在；/etc/at.allow 權限 644")
        # 合格：無 deny、allow 為 root:root 600
        del self.fs["/etc/cron.deny"]
        self.exists.add("/etc/cron.allow")
        self.stats["/etc/at.allow"] = St(0, 0, 0o100400)
        for rule in (self.owner, self.perm):
            self.assertEqual(rule.check(self.ctx()).status, PASS)

    def test_fix(self):
        self.dirs["/var/spool/cron"] = ["root", "alice"]
        self.fs["/etc/cron.deny"] = "# 註解\nbob\n\ncarol\n"
        self.exists.add("/etc/at.allow")
        self.stats["/etc/at.allow"] = St(1000, 1000, 0o100644)
        fx = self.fx()
        self.perm.fix(fx.ctx, fx)
        # deny 先備份再刪除
        self.assertLess(self.pos(fx, "backup", "/etc/cron.deny"), self.pos(fx, "run", "rm -f /etc/cron.deny"))
        self.assertEqual(self.fs["/etc/cron.allow"], "")
        self.assertEqual(fx.modes["/etc/cron.allow"], 0o600)
        self.assertNotIn(("chown", "/etc/cron.allow", "root:root"), fx.events)  # 新建的已是 root 600
        self.assertIn(("chown", "/etc/at.allow", "root:root"), fx.events)
        self.assertIn(("chmod", "/etc/at.allow", 0o600), fx.events)
        self.assertEqual(fx.notes[:2], ["有 crontab 的非 root 使用者：alice", "/etc/cron.deny 原內容：bob、carol"])
        self.assertEqual(fx.notes[-1], s.CronAllow.NOTE)

    def test_fix_dry_run(self):
        self.fs["/etc/cron.deny"] = "bob\n"
        fx = self.fx(dry=True)
        self.owner.fix(fx.ctx, fx)
        self.assertEqual(self.runner.ran("rm -f"), [])
        self.assertNotIn("/etc/cron.allow", self.fs)
        self.assertEqual(fx.kinds("chown"), [])  # 預覽時 allow 尚未建立，略過權限檢查


# RHEL8 0207 / RHEL9 0205 cron 日誌記錄功能
class CronLoggingTest(Env):
    def setUp(self):
        Env.setUp(self)
        self.rule = s.CronLogging({"rhel9": "TWGCB-01-012-0205"})

    def test_lines_selector_without_dot(self):
        self.assertEqual(s.rsyslog_cron_lines("cron /var/log/cron\n$IncludeConfig\nkern,cron.* /var/log/cron # x\n"),
                         ["kern,cron.* /var/log/cron # x"])  # 單一欄位的指令行略過

    def test_check(self):
        self.assertIn("未安裝 rsyslog", self.rule.check(self.ctx()).current)
        self.pkgs.add("rsyslog")
        self.states["rsyslog"] = ("enabled", "active")
        self.fs["/etc/rsyslog.conf"] = "*.info /var/log/messages\n"
        self.assertEqual(self.rule.check(self.ctx()).current, "未設定 cron.* /var/log/cron；rsyslog 服務 active")
        self.globs["/etc/rsyslog.d/*.conf"] = ["/etc/rsyslog.d/a.conf"]
        self.fs["/etc/rsyslog.d/a.conf"] = "cron.* -/var/log/cron\n"
        c = self.rule.check(self.ctx())
        self.assertEqual((c.status, c.current), (PASS, "/etc/rsyslog.d/a.conf：cron.* -/var/log/cron；rsyslog 服務 active"))

    def test_fix(self):
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual([e[0] for e in fx.events], ["undo", "write", "run", "run"])
        self.assertIn("cron.*    /var/log/cron", self.fs[s.CRON_DROPIN])
        self.assertEqual(fx.kinds("run"), ["rsyslogd -N1", "systemctl restart rsyslog"])

    def test_fix_syntax_error(self):
        self.on("rsyslogd -N1", res(1, "", "error during parsing"))
        fx = self.fx()
        with self.assertRaises(FixError):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events[0][0], "undo")  # 回滾已登記，失敗時可還原 drop-in
        self.assertEqual(self.runner.ran("systemctl restart"), [])

    def test_fix_no_rsyslog(self):
        self.cmds.discard("rsyslogd")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# ---------------- nftables 解析 ----------------

class NftParseExtra(Env):
    def test_command_position_insert_and_other_blocks(self):
        t = ("add chain inet t input { type filter hook input priority 0 ; policy drop ; }\n"
             "add rule inet t input tcp dport 22 accept\n"
             "add rule inet t input position 5 tcp dport 2222 accept\n"
             "add rule inet t input index 3\n"
             "insert rule inet t input iif lo accept\n"
             "table inet u {\n"
             "\tset allowed {\n\t\ttype ipv4_addr\n\t}\n"
             "\tchain output {\n\t\ttype filter hook output priority 0;\n\t}\n"
             "\tchain input {\n\t\ttype filter hook input priority 0;\n"
             "\t\tiif lo accept\n\t\tip saddr 127.0.0.0/8 drop\n\t\tip6 saddr ::1 drop\n\t}\n"
             "}\n")
        chains = s.nft_parse(t)
        self.assertEqual(chains[0]["rules"], ["iif lo accept", "tcp dport 22 accept", "tcp dport 2222 accept", ""])
        self.assertEqual([c["name"] for c in chains], ["input", "output", "input"])  # set 區塊不當成鏈
        self.assertTrue(s.nft_loopback_ok(chains[1:]))  # 先略過 output 鏈

    def test_port_tokens(self):
        t = ("table inet t {\n chain i {\n  type filter hook input priority 0; policy drop;\n"
             "  ct state established accept\n  iif lo accept\n  tcp dport 20-23 accept\n"
             "  tcp dport no-such-service-zz accept\n }\n}\n")
        chains = s.nft_parse(t)
        self.assertEqual(s.nft_ssh_problems(chains, ["22"]), [])
        self.assertEqual(s.nft_ssh_problems(chains, ["2222"]), ["inet t i 未放行 SSH 埠 2222"])

    def test_add_include_no_newline(self):
        self.assertEqual(s.nft_conf_add_include('include "/etc/a.nft"'),
                         'include "/etc/a.nft"\n# gcb-checker：GCB 載入 nftables 規則\ninclude "%s"\n' % s.MANAGED_NFT)

    def test_runtime_and_persistent(self):
        self.on("nft list ruleset", res(1))
        self.assertIsNone(s.nft_runtime())
        self.fs[s.NFT_CONF] = 'include "/etc/nftables/*.nft"\n'
        self.globs["/etc/nftables/*.nft"] = ["/etc/nftables/b.nft", "/etc/nftables/a.nft"]
        self.fs["/etc/nftables/a.nft"] = "table inet a {}\n"
        self.fs["/etc/nftables/b.nft"] = "table inet b {}\n"
        self.assertEqual(s.nft_tables(s.nft_persistent()), [("inet", "a"), ("inet", "b")])

    def test_include_depth_limit(self):
        self.fs[s.NFT_CONF] = 'include "/etc/sysconfig/nftables.conf"\n'  # 自我 include
        self.assertEqual(s.nft_persistent().count("include"), 5)

    def test_user_config(self):
        self.fs[s.NFT_CONF] = 'include "%s"\ninclude "/etc/nftables/empty.nft"\ninclude "/etc/nftables/u.nft"\n' \
            % s.MANAGED_NFT
        self.fs[s.MANAGED_NFT] = "table inet filter {}\n"
        self.fs["/etc/nftables/empty.nft"] = "# 只有註解\n\n"
        self.fs["/etc/nftables/u.nft"] = "table inet mine {}\n"
        self.assertEqual(s.nft_user_config(), ["/etc/nftables/u.nft"])
        # 規則集已有非本工具建立的 table inet filter
        del self.fs[s.MANAGED_NFT], self.fs["/etc/nftables/u.nft"]
        self.on("nft list ruleset", res(0, "table inet filter {\n}\n"))
        self.assertEqual(s.nft_user_config(), ["目前規則集已有非本工具建立的 table inet filter"])


class NftSnapshotTest(Env):
    def test_runtime_fail(self):
        self.on("nft list ruleset", res(1))
        fx = self.fx()
        self.assertIsNone(s.nft_snapshot(fx.ctx, fx))
        self.assertEqual(fx.events, [])

    def test_foreign(self):
        from test_rhel_selinux import IPT_NFT
        self.on("nft list ruleset", res(0, IPT_NFT))
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            s.nft_snapshot(fx.ctx, fx)
        self.assertIsNone(s.nft_snapshot(fx.ctx, fx, strict=False))
        self.assertIn("ip filter", fx.notes[0])
        self.assertEqual(fx.kinds("undo"), [])

    def test_backup_and_undo(self):
        self.on("nft list ruleset", res(0, "table inet x {\n}\n"))
        fx = self.fx()
        cmd = s.nft_snapshot(fx.ctx, fx)
        self.assertEqual(cmd[:2], ["/usr/sbin/nft", "-f"])
        self.assertEqual(self.backups[cmd[2]], "flush ruleset\ntable inet x {\n}\n")
        self.assertEqual(fx.kinds("undo"), [" ".join(cmd)])
        fx = self.fx(dry=True)
        self.assertIsNone(s.nft_snapshot(fx.ctx, fx))


# ---------------- nftables 規則 ----------------

GOOD_NFT = s.nft_render({"loopback", "input_drop", "forward_drop"}, ["22"]).replace(
    "hook output priority 0; policy accept", "hook output priority 0; policy drop")
BLOCKING_NFT = "table inet t {\n chain i {\n  type filter hook input priority 0; policy drop;\n }\n}\n"


class NftEnv(Env):
    """nft list ruleset 依「是否已載入管理檔」回傳不同規則集。"""

    def setUp(self):
        Env.setUp(self)
        self.loaded = None  # 載入後的目前規則集（None：載入前為空）
        self.after_load = None
        self.on("nft list ruleset", lambda c: res(0, self.loaded or ""))

        def load(c):
            self.loaded = self.after_load if self.after_load is not None else self.fs.get(s.MANAGED_NFT)
            return res(0)
        self.on("nft -f %s" % s.MANAGED_NFT, load)
        self.on("ss -Htlnu", res(0, "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"))
        self.fs["/proc/sys/net/ipv4/ip_forward"] = "0\n"
        self.dirs["/sys/class/net"] = ["lo", "eth0"]

    def persistent(self, text):
        self.fs[s.NFT_CONF] = 'include "/etc/nftables/main.nft"\n'
        self.globs["/etc/nftables/main.nft"] = ["/etc/nftables/main.nft"]
        self.fs["/etc/nftables/main.nft"] = text


# RHEL8 0251 / RHEL9 0249 在 nftables 中建立表、0252/0250 基本鏈、0253/0251 回送流量、0254/0252 預設拒絕（檢測）
class NftChecks(NftEnv):
    RULES = (s.NftTable({}), s.NftChains({}), s.NftLoopback({}), s.NftDefaultDrop({}))

    def test_no_nft_and_error(self):
        for rule in self.RULES:
            self.cmds.discard("nft")
            self.assertEqual(rule.check(self.ctx()).current, "未安裝 nftables")
            self.cmds.add("nft")
            self.on("nft list ruleset", res(1))
            self.assertEqual(rule.check(self.ctx()).status, ERROR)
            self.runner.rules.pop(0)

    def test_pass(self):
        self.loaded = GOOD_NFT
        self.persistent(GOOD_NFT)
        for rule in self.RULES:
            self.assertEqual(rule.check(self.ctx()).status, PASS, rule.title)
        self.assertEqual(self.RULES[3].check(self.ctx()).current,
                         "目前/開機 input:drop/drop、forward:drop/drop、output:drop/drop")

    def test_fail(self):
        self.loaded = "table inet t {\n chain i {\n  type filter hook input priority 0; policy accept;\n }\n}\n"
        self.assertEqual(self.RULES[0].check(self.ctx()).current, "目前：inet t；開機載入：無")
        self.assertEqual(self.RULES[1].check(self.ctx()).current,
                         "目前缺少：forward、output；開機載入缺少：input、forward、output")
        self.assertEqual(self.RULES[2].check(self.ctx()).current, "目前：未設定；開機載入：未設定")
        self.assertEqual(self.RULES[3].check(self.ctx()).current,
                         "目前/開機 input:accept/無鏈、forward:無鏈/無鏈、output:無鏈/無鏈")
        for rule in self.RULES:
            self.assertEqual(rule.check(self.ctx()).status, FAIL)


# RHEL8 0254 / RHEL9 0252 nftables 預設拒絕
class NftDefaultDropFix(NftEnv):
    def setUp(self):
        NftEnv.setUp(self)
        self.rule = s.NftDefaultDrop({"rhel9": "TWGCB-01-012-0252"})

    def test_fix_order_and_content(self):
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        text = self.fs[s.MANAGED_NFT]
        # 載入前已做語法驗證
        check_idx = [i for i, c in enumerate(self.runner.calls) if "nft -c -f" in c and "gcb-nft-" in c]
        load_idx = self.runner.calls.index("nft -f %s" % s.MANAGED_NFT)
        self.assertTrue(check_idx and check_idx[0] < load_idx)
        # 回滾還原指令與自動還原保險先於任何修改
        undo = self.pos(fx, "undo", "/usr/sbin/nft -f ")
        guard = self.pos(fx, "run", "systemd-run --unit " + GUARD_UNIT)
        write = self.pos(fx, "write", s.MANAGED_NFT)
        self.assertLess(undo, guard)
        self.assertLess(guard, write)
        self.assertLess(write, self.pos(fx, "run", "nft -f " + s.MANAGED_NFT))
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))
        self.assertIn(GUARD_UNIT + " --on-active=300 /usr/sbin/nft -f", fx.events[guard][1])
        # 規則檔：input policy drop 與 SSH、lo、已建立連線、ICMPv6 鄰居探索同一份原子載入
        self.assertIn("hook input priority 0; policy drop;", text)
        for rule in ("ct state established,related accept", 'iif "lo" accept', "tcp dport { 22, 2222 } accept",
                     "nd-neighbor-solicit", "nd-neighbor-advert"):
            self.assertIn(rule, text)
        chains = s.nft_parse(text)
        self.assertEqual(s.nft_ssh_problems(chains, ["22", "2222"]), [])
        self.assertTrue(s.nft_loopback_ok(chains))
        self.assertEqual(s.nft_policies(chains), {"input": True, "forward": True, "output": False})
        self.assertEqual(fx.modes[s.MANAGED_NFT], 0o600)
        self.assertEqual(s.nft_conf_includes(self.fs[s.NFT_CONF]), [s.MANAGED_NFT])
        self.assertTrue(self.backups[fx.events[undo][1].split()[-1]].startswith("flush ruleset\n"))
        self.assertIn(("確認 SSH 放行", "input 鏈已放行 lo、已建立連線與 SSH 埠 22,2222", "成功"), fx.steps)
        self.assertTrue(fx.partial)
        self.assertIn("tcp/80", fx.notes[0])
        self.assertIn("output 鏈預設拒絕未自動設定", fx.notes[-1])

    def test_forwarding_keeps_forward_accept(self):
        self.fs["/proc/sys/net/ipv4/ip_forward"] = "1\n"
        self.on("ss -Htlnu", res(0, ""))
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(s.nft_policies(s.nft_parse(self.fs[s.MANAGED_NFT])),
                         {"input": True, "forward": False, "output": False})
        self.assertIn("forward 鏈未設為 drop", fx.notes[0])
        self.assertEqual(len(fx.notes), 2)

    def test_post_check_fail_cancels_guard(self):
        self.after_load = BLOCKING_NFT  # 載入後 SSH 未放行
        fx = self.fx()
        with self.assertRaises(FixError) as cm:
            self.rule.fix(fx.ctx, fx)
        self.assertIn("未放行 SSH 埠 22,2222", str(cm.exception))
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))
        self.assertFalse(fx.partial)

    def test_conf_validate_fail(self):
        self.on("nft -c -f " + s.NFT_CONF, res(1, "", "syntax error"))
        fx = self.fx()
        with self.assertRaises(FixError):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))

    def test_syntax_fail_before_any_change(self):
        self.on("gcb-nft-", res(1, "", "Error: syntax"))
        fx = self.fx()
        with self.assertRaises(FixError):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_dry_run(self):
        fx = self.fx(dry=True)
        self.rule.fix(fx.ctx, fx)
        self.assertNotIn(s.MANAGED_NFT, self.fs)
        self.assertEqual(self.runner.ran("gcb-nft-"), [])
        self.assertEqual(self.runner.ran("nft -f"), [])
        self.assertEqual(self.runner.ran("systemd-run"), [])
        self.assertEqual(fx.kinds("undo"), [])

    def test_no_ports(self):
        self.on("sshd -T", res(255))
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


class NftApplyGuards(NftEnv):
    def test_no_nft(self):
        self.cmds.discard("nft")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            s.nft_apply(fx.ctx, fx, set())

    def test_user_config(self):
        self.persistent("table inet mine {}\n")
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            s.nft_apply(fx.ctx, fx, {"input_drop"}, ["22"])
        self.assertIn("/etc/nftables/main.nft", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_input_drop_without_ports(self):
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            s.nft_apply(fx.ctx, fx, {"input_drop"}, [])

    def test_keeps_existing_flags_and_ports(self):
        self.fs[s.MANAGED_NFT] = s.nft_render({"loopback", "input_drop"}, ["2200"])
        fx = self.fx()
        s.nft_apply(fx.ctx, fx, {"chains"}, ["22"])
        flags, ports = s.nft_managed_state(self.fs[s.MANAGED_NFT])
        self.assertEqual(flags, {"chains", "loopback", "input_drop"})
        self.assertEqual(ports, ["22", "2200"])


# RHEL8 0251 / RHEL9 0249 在 nftables 中建立表、0252/0250 基本鏈、0253/0251 回送流量（修復）
class NftSimpleFixes(NftEnv):
    def test_table(self):
        fx = self.fx()
        s.NftTable({}).fix(fx.ctx, fx)
        text = self.fs[s.MANAGED_NFT]
        self.assertEqual(s.nft_tables(text), [("inet", "filter")])
        self.assertNotIn("chain", text)
        self.assertEqual(self.runner.ran("systemd-run"), [])  # 不改變放行行為，不需保險

    def test_chains(self):
        fx = self.fx()
        s.NftChains({}).fix(fx.ctx, fx)
        chains = s.nft_parse(self.fs[s.MANAGED_NFT])
        self.assertEqual(s.nft_hooks(chains), {"input", "forward", "output"})
        self.assertEqual(s.nft_policies(chains), {"input": False, "forward": False, "output": False})

    def test_loopback(self):
        fx = self.fx()
        s.NftLoopback({}).fix(fx.ctx, fx)
        chains = s.nft_parse(self.fs[s.MANAGED_NFT])
        self.assertTrue(s.nft_loopback_ok(chains))
        self.assertEqual(s.nft_policies(chains)["input"], False)


# RHEL8 0249 / RHEL9 0247 nftables 服務（啟用）
class NftEnabledTest(NftEnv):
    def setUp(self):
        NftEnv.setUp(self)
        self.rule = s.NftEnabled({"rhel9": "TWGCB-01-012-0247"})
        self.pkgs.add("nftables")
        self.persistent(GOOD_NFT.replace("{ 22 }", "{ 22, 2222 }"))

        def enable(c):
            self.loaded = self.fs["/etc/nftables/main.nft"] if self.after_load is None else self.after_load
            return res(0)
        self.on("systemctl --now enable nftables.service", enable)

    def test_check(self):
        self.assertEqual(self.rule.check(self.ctx()).current, "not-found / inactive")
        self.states["nftables.service"] = ("enabled", "active")
        self.assertEqual(self.rule.check(self.ctx()).status, PASS)
        self.pkgs.discard("nftables")
        self.assertEqual(self.rule.check(self.ctx()).current, "未安裝 nftables")

    def test_fix(self):
        self.states["nftables.service"] = ("masked", "inactive")
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        kinds = [e[0] for e in fx.events]
        self.assertEqual(fx.events[0], ("undo", s.FW_RELOAD_GUARD))
        undo_nft = self.pos(fx, "undo", "/usr/sbin/nft -f")
        guard = self.pos(fx, "run", "systemd-run")
        self.assertLess(undo_nft, guard)
        self.assertLess(guard, self.pos(fx, "undo", "systemctl mask nftables.service"))
        self.assertLess(self.pos(fx, "run", "systemctl unmask"), kinds.index("enable"))
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))
        # 啟用前先驗證開機設定語法
        self.assertLess(self.runner.calls.index("nft -c -f " + s.NFT_CONF),
                        self.runner.calls.index("systemctl --now enable nftables.service"))

    def test_post_check_fail(self):
        self.after_load = BLOCKING_NFT
        fx = self.fx()
        with self.assertRaises(FixError):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))

    def test_conf_invalid(self):
        self.on("nft -c -f " + s.NFT_CONF, res(1, "", "bad"))
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_persistent_blocks_ssh(self):
        self.persistent(BLOCKING_NFT)
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            self.rule.fix(fx.ctx, fx)
        self.assertIn("未放行迴路介面 lo", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_install_then_dry_without_nft(self):
        self.pkgs.discard("nftables")
        self.cmds.discard("nft")
        fx = self.fx(dry=True)
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("pkg_install", "nftables")])


# RHEL8 0255 / RHEL9 0253 載入 nftables 規則
class NftPersistTest(NftEnv):
    def setUp(self):
        NftEnv.setUp(self)
        self.rule = s.NftPersist({"rhel9": "TWGCB-01-012-0253"})

    def test_check(self):
        self.assertIn("沒有有效的 include", self.rule.check(self.ctx()).current)
        self.fs[s.NFT_CONF] = 'include "%s"\n' % s.MANAGED_NFT
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("檔案不存在：%s" % s.MANAGED_NFT, c.current)
        self.globs[s.MANAGED_NFT] = [s.MANAGED_NFT]
        self.states["nftables.service"] = ("enabled", "inactive")
        self.assertEqual(self.rule.check(self.ctx()).status, PASS)
        self.on("nft -c -f", res(1))
        self.assertIn("驗證失敗", self.rule.check(self.ctx()).current)

    def test_fix_creates_managed_and_enables(self):
        self.states["nftables.service"] = ("masked", "inactive")
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(s.nft_conf_includes(self.fs[s.NFT_CONF]), [s.MANAGED_NFT])
        self.assertIn(s.MANAGED_NFT, self.fs)
        en = self.pos(fx, "run", "systemctl enable nftables.service")
        self.assertLess(self.pos(fx, "write", s.NFT_CONF), en)
        self.assertLess(self.pos(fx, "undo", "systemctl mask nftables.service"), self.pos(fx, "run", "unmask"))
        self.assertLess(self.pos(fx, "record", "nftables.service"), en)

    def test_fix_user_rules_ready(self):
        self.persistent(GOOD_NFT.replace("{ 22 }", "{ 22, 2222 }"))
        self.states["nftables.service"] = ("enabled", "active")
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_persistent_blocks_ssh(self):
        self.persistent(BLOCKING_NFT)
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


if __name__ == "__main__":
    unittest.main()
