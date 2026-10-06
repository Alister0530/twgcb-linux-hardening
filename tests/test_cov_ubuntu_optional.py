# -*- coding: utf-8 -*-
"""gcb/rules/ubuntu/optional.py 的涵蓋率測試（一）：共用環境、輔助函式、校時、UFW。

以 Env 取代模組內的 read_text、run、which、os、glob、pkgsvc、write_text_atomic，
所有檔案存在記憶體 dict，所有指令由 FakeRunner 回應，不碰真實系統。
"""
import fnmatch
import os
import posixpath
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import fakes  # noqa: E402
from fakes import FakeCtx, FakeFx, FakeRunner, res  # noqa: E402
from gcb import textedit as te  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS  # noqa: E402
from gcb.rules.ubuntu import optional as o  # noqa: E402

BINS = ("sshd", "nft", "ufw", "systemd-run", "dconf", "iptables", "ip6tables",
        "iptables-restore", "ip6tables-restore")


def R(n):
    """依編號取出 RULES 中的規則。"""
    rid = "TWGCB-01-014-%04d" % n
    return [r for r in o.RULES if r.ids.get("ubuntu2204") == rid][0]


# ---------- 假環境 ----------

class FakeJournal(object):
    def __init__(self, fs):
        self.fs = fs
        self.backed = []

    def backup_file(self, rid, path):
        self.backed.append(path)
        return {"data": {"existed": path in self.fs, "backup": "/bk" + path}}


class _Path(object):
    join = staticmethod(posixpath.join)
    basename = staticmethod(posixpath.basename)

    def __init__(self, env):
        self.env = env

    def isfile(self, p):
        return p in self.env.fs

    def isdir(self, p):
        p = p.rstrip("/")
        return p in self.env.dirs or any(f.startswith(p + "/") for f in self.env.fs)

    def exists(self, p):
        return self.isfile(p) or self.isdir(p)

    def getmtime(self, p):
        return self.env.mtime.get(p, 0)


class _Os(object):
    def __init__(self, env):
        self.path = _Path(env)
        self.environ = env.environ


class _Glob(object):
    def __init__(self, env):
        self.env = env

    def glob(self, pat):
        cand = set(self.env.fs) | set(self.env.dirs)
        return [p for p in cand if fnmatch.fnmatchcase(p, pat) and p.count("/") == pat.count("/")]


class _Pkgsvc(object):
    def __init__(self, env):
        self.env = env

    def pkg_installed(self, osi, pkg):
        return pkg in self.env.pkgs

    def svc_state(self, unit):
        return self.env.svc.get(unit, ("disabled", "inactive"))


class Env(object):
    """with Env(...) as e: 在 e.fx / e.ctx 上執行規則；e.fs 為假檔案系統。"""

    def __init__(self, fs=None, dirs=(), pkgs=(), svc=None, bins=BINS, runner=None, environ=None,
                 mtime=None, rid="TWGCB-01-014-0216", dry_run=False, **cfg):
        self.fs = dict(fs or {})
        self.dirs = set(dirs)
        self.pkgs = set(pkgs)
        self.svc = dict(svc or {})
        self.bins = set(bins)
        self.runner = runner or FakeRunner()
        self.environ = environ or {}
        self.mtime = dict(mtime or {})
        self.ctx = FakeCtx("ubuntu2204", dry_run=dry_run, **cfg)
        self.ctx.journal = FakeJournal(self.fs)
        self.ctx.run_dir = "/run/gcb"
        self.fx = FakeFx(self.ctx, fs=self.fs, runner=self.runner, rid=rid)
        self._p = [
            mock.patch.object(o, "read_text", lambda p, *a, **k: self.fs.get(p)),
            mock.patch.object(o, "run", self.runner),
            mock.patch.object(o, "which", lambda n: "/usr/bin/" + n if n in self.bins else None),
            mock.patch.object(o, "write_text_atomic", self._write),
            mock.patch.object(o, "os", _Os(self)),
            mock.patch.object(o, "glob", _Glob(self)),
            mock.patch.object(o, "pkgsvc", _Pkgsvc(self)),
        ]

    def _write(self, path, text, mode=0o644):
        # 規則集備份檔：記錄在 events，方便確認順序
        self.fs[path] = text
        self.fx.events.append(("snapshot", path))

    def __enter__(self):
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *a):
        for p in reversed(self._p):
            p.stop()

    # ---- 查詢 ----
    def runs(self, sub=""):
        return [e[1] for e in self.fx.events if e[0] == "run" and sub in e[1]]

    def idx(self, kind, sub=""):
        """第一個符合事件的位置（找不到時 AssertionError）。"""
        for i, e in enumerate(self.fx.events):
            if e[0] == kind and sub in str(e[1]):
                return i
        raise AssertionError("找不到事件 %s %s：%s" % (kind, sub, self.fx.events))


def seq(*results):
    """依序回傳結果，用完後重複最後一個。"""
    lst = list(results)

    def _f(_cmd):
        return lst.pop(0) if len(lst) > 1 else lst[0]
    return _f


# ====================================================================
# 共用輔助函式
# ====================================================================

class UptimeTest(unittest.TestCase):
    def test_uptime_boot(self):
        with Env(fs={"/proc/uptime": "100.5 50.0\n"}):
            self.assertAlmostEqual(o._uptime_boot(), time.time() - 100.5, delta=5)
        with Env(fs={"/proc/uptime": "abc"}):
            self.assertEqual(o._uptime_boot(), 0)
        with Env(fs={"/proc/uptime": "   "}):
            self.assertEqual(o._uptime_boot(), 0)


class Ipv6ForwardTest(unittest.TestCase):
    def test_ipv6_enabled(self):
        with Env(fs={"/proc/net/if_inet6": "x"}) as e:
            self.assertIsNone(o.ipv6_enabled(e.ctx))
        with Env() as e:
            self.assertIn("IPv6", o.ipv6_enabled(e.ctx))

    def test_forwarding(self):
        with Env(fs={"/proc/sys/net/ipv4/ip_forward": "1\n", "/proc/sys/net/ipv6/conf/all/forwarding": "0"}):
            self.assertTrue(o._forwarding())
            self.assertFalse(o._forwarding(True))
        with Env():
            self.assertFalse(o._forwarding())

    def test_ipv6_active(self):
        with Env(dirs={"/proc/sys/net/ipv6"}):
            self.assertTrue(o.ipv6_active())
        with Env(dirs={"/proc/sys/net/ipv6"}, fs={"/proc/sys/net/ipv6/conf/all/disable_ipv6": "1"}):
            self.assertFalse(o.ipv6_active())


class SshPortsTest(unittest.TestCase):
    def test_all_sources(self):
        ss = ('LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
              'LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=2,fd=3))\n')
        run = FakeRunner({"sshd -T": res(0, "port 2222\nlistenaddress 0.0.0.0:2200\n"), "ss -Htlnp": res(0, ss)})
        with Env(runner=run, environ={"SSH_CONNECTION": "10.0.0.9 5555 10.0.0.1 2022"}):
            self.assertEqual(o.ssh_ports(), ["22", "2022", "2200", "2222"])

    def test_default_22(self):
        # 沒有 sshd、ss 無輸出、非 SSH 連線 → 22
        with Env(bins=()):
            self.assertEqual(o.ssh_ports(), ["22"])
        run = FakeRunner({"sshd -T": res(1, "", "bad config")})
        with Env(runner=run, environ={"SSH_CONNECTION": "x y"}):
            self.assertEqual(o.ssh_ports(), ["22"])


# 防火牆自動還原保險（systemd-run 計時器）
class GuardTest(unittest.TestCase):
    def test_schedule_and_cancel(self):
        with Env(rid="TWGCB-01-014-0216") as e:
            g = o._Guard(e.fx, ["/usr/bin/nft", "-f", "/x"])
            self.assertTrue(g.unit.startswith("gcb-fw-guard-0216-"))
            cmd = e.runs("systemd-run")[0]
            self.assertIn("--on-active=300", cmd)
            self.assertTrue(cmd.endswith("/usr/bin/nft -f /x"))
            unit = g.unit
            g.cancel()
            self.assertEqual(e.runs("systemctl stop"), ["systemctl stop %s.timer" % unit])
            self.assertIsNone(g.unit)
            g.cancel()  # 再次取消不重複執行
            self.assertEqual(len(e.runs("systemctl stop")), 1)

    def test_no_guard(self):
        # 預覽、沒有 systemd-run、排程失敗 → 不建立保險，cancel 不做事
        with Env(dry_run=True) as e:
            g = o._Guard(e.fx, ["x"])
            self.assertIsNone(g.unit)
            self.assertEqual(e.runs(), [])
        with Env(bins=("nft",)) as e:
            self.assertIsNone(o._Guard(e.fx, ["x"]).unit)
            self.assertEqual(e.runs(), [])
        with Env(runner=FakeRunner({"systemd-run": res(1)})) as e:
            g = o._Guard(e.fx, ["x"])
            self.assertIsNone(g.unit)
            g.cancel()
            self.assertEqual(e.runs("systemctl stop"), [])


# 規則集備份與回滾登記
class SnapshotTest(unittest.TestCase):
    RS = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"

    def test_dry_run(self):
        with Env(dry_run=True) as e:
            self.assertIsNone(o._snapshot(e.ctx, e.fx, "nft"))
            self.assertEqual(e.fx.events, [])
            self.assertEqual(e.runner.calls, [])
            self.assertIn("[預覽]", e.fx.steps[0][1])

    def test_nft(self):
        with Env(runner=FakeRunner({"nft list ruleset": res(0, self.RS)})) as e:
            path = o._snapshot(e.ctx, e.fx, "nft")
            self.assertTrue(path.startswith("/run/gcb/fw-0216-nft-"))
            self.assertEqual(e.fs[path], "flush ruleset\n" + self.RS)
            # 先寫備份檔，再登記回滾
            self.assertEqual(e.fx.events, [("snapshot", path), ("undo", "/usr/bin/nft -f " + path)])

    def test_nft_foreign_and_fail(self):
        foreign = "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority 0;\n\t}\n}\n"
        with Env(runner=FakeRunner({"nft list ruleset": res(0, foreign)})) as e:
            with self.assertRaises(ManualRequired):
                o._snapshot(e.ctx, e.fx, "nft")
            self.assertEqual(e.fx.events, [])
        with Env(runner=FakeRunner({"iptables-save": res(1, "", "denied")})) as e:
            with self.assertRaises(FixError):
                o._snapshot(e.ctx, e.fx, "v4")
            self.assertEqual(e.fx.events, [])

    def test_ipt(self):
        # filter 表未載入時補上空的 ACCEPT 表
        with Env(runner=FakeRunner({"iptables-save": res(0, "*nat\nCOMMIT\n")})) as e:
            path = o._snapshot(e.ctx, e.fx, "v4")
            self.assertIn("*filter\n:INPUT ACCEPT [0:0]", e.fs[path])
            self.assertEqual(e.fx.events[-1], ("undo", "/usr/bin/iptables-restore " + path))
        with Env(bins=(), runner=FakeRunner({"ip6tables-save": res(0, "*filter\n:INPUT DROP [0:0]\nCOMMIT\n")})) as e:
            path = o._snapshot(e.ctx, e.fx, "v6")
            self.assertEqual(e.fs[path], "*filter\n:INPUT DROP [0:0]\nCOMMIT\n")
            self.assertEqual(e.fx.events[-1], ("undo", "ip6tables-restore " + path))

    def test_restore_cmd(self):
        with Env():
            self.assertEqual(o._restore_cmd("nft", "/p"), ["/usr/bin/nft", "-f", "/p"])
            self.assertEqual(o._restore_cmd("v4", "/p"), ["/usr/bin/iptables-restore", "/p"])
            self.assertEqual(o._restore_cmd("v6", "/p"), ["/usr/bin/ip6tables-restore", "/p"])
        with Env(bins=()):
            self.assertEqual(o._restore_cmd("nft", "/p"), ["nft", "-f", "/p"])
            self.assertEqual(o._restore_cmd("v4", "/p"), ["iptables-restore", "/p"])


class ParseMiscTest(unittest.TestCase):
    def test_ufw_tuples_and_ports(self):
        self.assertEqual(o.ufw_tuples("### tuple ### allow tcp 22\nfoo\n"), [])
        self.assertTrue(o._port_in("any", "22"))
        self.assertFalse(o._port_in("x:y", "22"))
        t6 = o.ufw_tuples("### tuple ### deny any any ::/0 any ::1 in\n"
                          "### tuple ### allow any any ::/0 any ::/0 in_lo\n")
        miss = o.ufw_loopback_status(o.ufw_tuples(UFW_USER4_OK), t6)
        self.assertEqual(miss, ["deny ::1 排在 allow in on lo 之前"])

    def test_policies_and_ipv6(self):
        text = 'IPV6=no\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n'
        with Env(fs={o.UFW_DEFAULT: text}):
            self.assertFalse(o.ufw_ipv6())
            self.assertEqual(o.ufw_policies(), {"incoming": "DROP", "outgoing": "ACCEPT", "routed": "未設定"})
        with Env():
            self.assertTrue(o.ufw_ipv6())


# ====================================================================
# 校時
# ====================================================================

TSD = "systemd-timesyncd.service"


class TimeChoiceTest(unittest.TestCase):
    def test_time_is(self):
        with Env(pkgs={"chrony", "systemd-timesyncd"}, svc={"chrony.service": ("enabled", "active")}) as e:
            self.assertEqual(o.time_choice(e.ctx)[0], "chrony")
            self.assertIsNone(R(194).when(e.ctx))
            self.assertIn("Chrony", R(198).when(e.ctx))

    def test_firewall_auto(self):
        with Env(pkgs={"ufw"}, fs={o.UFW_CONF: "ENABLED=yes\n"}) as e:
            self.assertEqual(o.firewall_choice(e.ctx)[0], "ufw")
            self.assertIsNone(o.fw_is("ufw")(e.ctx))
            self.assertIn("UFW", o.fw_is("nftables")(e.ctx))
        with Env(pkgs={"nftables"}, svc={"nftables.service": ("enabled", "active")}) as e:
            self.assertEqual(o.firewall_choice(e.ctx)[0], "nftables")


# TWGCB-01-014-0194 chrony 校時套件、0198 systemd-timesyncd 校時套件、0201 ntp 校時套件
class TimePackageTest(unittest.TestCase):
    def test_check(self):
        with Env(pkgs={"ntp"}, svc={TSD: ("enabled", "active")}) as e:
            c = R(194).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            for s in ("未安裝 chrony", "仍安裝 ntp", "未遮蔽"):
                self.assertIn(s, c.current)
        with Env(pkgs={"chrony"}, svc={TSD: ("masked", "inactive")}) as e:
            c = R(194).check(e.ctx)
            self.assertEqual(c.status, PASS)
            self.assertIn("已安裝 chrony", c.current)
        with Env(pkgs={"systemd-timesyncd"}, svc={TSD: ("masked", "inactive")}) as e:
            c = R(198).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("被遮蔽", c.current)

    def test_fix_chrony(self):
        # 先備份並移除 ntp，再安裝 chrony，最後遮蔽 timesyncd
        with Env(pkgs={"ntp"}, fs={"/etc/ntp.conf": "server x\n"}, svc={TSD: ("enabled", "active")}) as e:
            R(194).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events[:3], [("backup", "/etc/ntp.conf"), ("pkg_remove", "ntp"),
                                               ("pkg_install", "chrony")])
            self.assertIn(("mask", TSD), e.fx.events)
            self.assertNotIn(("backup", "/etc/default/ntp"), e.fx.events)

    def test_fix_timesyncd(self):
        # 移除 chrony（先備份 /etc/chrony），timesyncd 被遮蔽時先登記回滾再解除遮蔽
        with Env(pkgs={"chrony", "systemd-timesyncd"}, dirs={"/etc/chrony"},
                 svc={TSD: ("masked", "inactive")}) as e:
            R(198).fix(e.ctx, e.fx)
            ev = e.fx.events
            self.assertLess(ev.index(("backup_dir", "/etc/chrony")), ev.index(("pkg_remove", "chrony")))
            self.assertNotIn(("pkg_install", "systemd-timesyncd"), ev)
            u = ev.index(("undo", "systemctl mask " + TSD))
            self.assertLess(u, ev.index(("run", "systemctl unmask " + TSD)))
        # 已是理想狀態 → 不做任何事
        with Env(pkgs={"systemd-timesyncd"}, svc={TSD: ("enabled", "active")}) as e:
            R(198).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])


# TWGCB-01-014-0197 chrony 校時服務、0200 systemd-timesyncd 校時服務、0204 ntp 校時服務
class TimeServiceTest(unittest.TestCase):
    def test_check(self):
        with Env() as e:
            self.assertEqual(R(197).check(e.ctx).status, FAIL)
        with Env(pkgs={"chrony"}, svc={"chrony.service": ("enabled", "active")}) as e:
            self.assertEqual(R(197).check(e.ctx).status, PASS)

    def test_fix(self):
        with Env() as e:
            with self.assertRaises(ManualRequired) as cm:
                R(197).fix(e.ctx, e.fx)
            self.assertIn("0194", str(cm.exception))
        with Env(pkgs={"ntp"}, svc={"ntp.service": ("masked", "inactive")}) as e:
            R(204).fix(e.ctx, e.fx)
            ev = e.fx.events
            self.assertEqual(ev[0], ("undo", "systemctl mask ntp.service"))
            self.assertEqual(ev[1], ("run", "systemctl unmask ntp.service"))
            self.assertIn(("enable", "ntp.service"), ev)
        with Env(pkgs={"ntp"}) as e:
            R(204).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events[0], ("enable", "ntp.service"))


# TWGCB-01-014-0195 chrony 校時設定、0199 systemd-timesyncd 校時設定、0202 ntp 校時設定
class TimeSourcesTest(unittest.TestCase):
    def test_chrony(self):
        fs = {o.CHRONY_CONF: "pool ntp.ubuntu.com iburst\n",
              "/etc/chrony/conf.d/a.conf": "server 10.0.0.1 iburst\n",
              "/etc/chrony/sources.d/x.sources": "server 10.0.0.2\n"}
        with Env(fs=fs) as e:
            c = R(195).check(e.ctx)
            self.assertEqual(c.status, PASS)
            self.assertEqual(c.current, "校時來源：pool ntp.ubuntu.com、server 10.0.0.1、server 10.0.0.2")
        with Env() as e:
            c = R(195).check(e.ctx)
            self.assertEqual((c.status, c.current), (FAIL, "未設定校時來源"))

    def test_ntp(self):
        with Env(fs={"/etc/ntp.conf": "# server a\nserver time.stdtime.gov.tw iburst\n"}) as e:
            self.assertEqual(R(202).check(e.ctx).current, "校時來源：server time.stdtime.gov.tw")

    def test_timesyncd(self):
        with Env(fs={"/etc/systemd/timesyncd.conf": "[Time]\nFallbackNTP=a\n"}) as e:
            c = R(199).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("FallbackNTP", c.current)
        # 同名 drop-in 以 /etc 優先，後讀者覆蓋前者
        fs = {"/usr/lib/systemd/timesyncd.conf.d/a.conf": "[Time]\nNTP=x\n",
              "/etc/systemd/timesyncd.conf.d/a.conf": "[Time]\nNTP=y z\n",
              "/run/systemd/timesyncd.conf.d/0.conf": "[Time]\nNTP=w\n"}
        with Env(fs=fs) as e:
            self.assertEqual(o.timesyncd_files(), ["/etc/systemd/timesyncd.conf",
                                                   "/run/systemd/timesyncd.conf.d/0.conf",
                                                   "/etc/systemd/timesyncd.conf.d/a.conf"])
            self.assertEqual(o.timesyncd_ntp(), ["y", "z"])
            self.assertEqual(R(199).check(e.ctx).status, PASS)


# TWGCB-01-014-0196 chrony 校時使用者設定
class ChronyUserTest(unittest.TestCase):
    def test_check_unset(self):
        with Env(runner=FakeRunner({"ps -o user=": res(0, "_chrony\n")})) as e:
            c = R(196).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("執行身分：_chrony", c.current)
        with Env() as e:
            self.assertIn("未執行", R(196).check(e.ctx).current)

    def test_check_values(self):
        with Env(fs={o.CHRONY_CONF: "user _chrony\n", "/etc/chrony/conf.d/a.conf": "user root\n"}) as e:
            self.assertEqual(R(196).check(e.ctx).status, FAIL)
        with Env(fs={o.CHRONY_CONF: "user _chrony\n"}) as e:
            self.assertEqual(R(196).check(e.ctx).status, PASS)

    def test_fix(self):
        fs = {o.CHRONY_CONF: "pool x\nuser root\n", "/etc/chrony/conf.d/a.conf": "user root\n",
              "/etc/chrony/conf.d/b.conf": "user _chrony\n"}
        with Env(fs=fs) as e:
            R(196).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [("undo", "systemctl try-restart chrony.service"),
                                           ("write", "/etc/chrony/conf.d/a.conf"),
                                           ("write", o.CHRONY_CONF),
                                           ("run", "systemctl try-restart chrony.service")])
            self.assertEqual(e.fs["/etc/chrony/conf.d/a.conf"], te.MARK + "user root\n")
            self.assertEqual(e.fs[o.CHRONY_CONF], "pool x\nuser _chrony\n")
            self.assertEqual(e.fs["/etc/chrony/conf.d/b.conf"], "user _chrony\n")


# TWGCB-01-014-0203 ntp 校時使用者設定
class NtpUserTest(unittest.TestCase):
    W = "/usr/lib/ntp/ntp-systemd-wrapper"

    def test_check(self):
        with Env() as e:
            c = R(203).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("找不到", c.current)
        with Env(fs={"/etc/init.d/ntp": "RUNASUSER=ntp\n", self.W: "#!/bin/sh\n"}) as e:
            c = R(203).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("RUNASUSER=未設定", c.current)
        with Env(fs={"/etc/init.d/ntp": "RUNASUSER=ntp\n"}) as e:
            self.assertEqual(R(203).check(e.ctx).status, PASS)

    def test_fix(self):
        fs = {"/etc/init.d/ntp": "#!/bin/sh\nRUNASUSER=root\n", self.W: "#!/bin/sh\necho hi\n"}
        with Env(fs=fs) as e:
            R(203).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events[0], ("undo", "systemctl try-restart ntp.service"))
            self.assertEqual(e.fx.events[-1], ("run", "systemctl try-restart ntp.service"))
            self.assertEqual(e.fs["/etc/init.d/ntp"], "#!/bin/sh\nRUNASUSER=ntp\n")
            # 原本沒有 RUNASUSER：加在 shebang 之後
            self.assertEqual(e.fs[self.W], "#!/bin/sh\nRUNASUSER=ntp\necho hi\n")


# ====================================================================
# 防火牆共用
# ====================================================================

# TWGCB-01-014-0206 iptables-persistent 套件、0211 ufw 套件、0219 nftables 套件（移除）
class FwPkgAbsentTest(unittest.TestCase):
    def test_check(self):
        with Env(pkgs={"ufw"}) as e:
            self.assertEqual(R(211).check(e.ctx).status, FAIL)
            self.assertEqual(R(219).check(e.ctx).status, PASS)

    def test_in_use_refused(self):
        with Env(fs={o.UFW_CONF: "ENABLED=yes\n"}) as e:
            with self.assertRaises(ManualRequired):
                R(211).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])
        with Env(svc={"netfilter-persistent.service": ("enabled", "active")}) as e:
            with self.assertRaises(ManualRequired):
                R(206).fix(e.ctx, e.fx)
        with Env(svc={"nftables.service": ("disabled", "active")}) as e:
            with self.assertRaises(ManualRequired):
                R(219).fix(e.ctx, e.fx)

    def test_backup_then_remove(self):
        with Env(fs={o.UFW_CONF: "ENABLED=no\n"}) as e:
            R(211).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [("backup_dir", "/etc/ufw"), ("backup", o.UFW_DEFAULT),
                                           ("pkg_remove", "ufw")])
        with Env() as e:
            R(219).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [("backup", o.NFT_CONF), ("pkg_remove", "nftables")])
        with Env() as e:
            R(206).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [("backup", o.RULES_V4), ("backup", o.RULES_V6),
                                           ("pkg_remove", "iptables-persistent")])


# ====================================================================
# UFW
# ====================================================================

UFW_BEFORE_OK = "*filter\n-A ufw-before-input -i lo -j ACCEPT\n-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
UFW_USER4_OK = ("### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo\n"
                "### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 out_lo\n"
                "### tuple ### deny any any 0.0.0.0/0 any 127.0.0.0/8 in\n")
SSH22 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"


def ufw_allow_effect(env):
    """模擬 ufw allow in <port>/tcp：寫入 user.rules tuple。"""
    def _f(cmd):
        port = cmd.split()[-1].split("/")[0]
        env.fs[o.UFW_USER4] = (env.fs.get(o.UFW_USER4) or "") + \
            "### tuple ### allow tcp %s 0.0.0.0/0 any 0.0.0.0/0 in\n" % port
        return res(0)
    return _f


class UfwPrepareTest(unittest.TestCase):
    def test_missing_established(self):
        with Env(fs={o.UFW_BEFORE: "*filter\n"}) as e:
            with self.assertRaises(ManualRequired):
                o._ufw_prepare(e.fx, ["22"])
            self.assertEqual(e.fx.events, [])

    def test_allow_lo_and_ports(self):
        with Env(fs={o.UFW_BEFORE: "-A x --ctstate RELATED,ESTABLISHED -j ACCEPT\n", o.UFW_USER4: SSH22}) as e:
            o._ufw_prepare(e.fx, ["22", "2222"])
            self.assertEqual(e.runs(), ["ufw allow in on lo", "ufw allow in 2222/tcp"])
        with Env(fs={o.UFW_BEFORE: UFW_BEFORE_OK, o.UFW_USER4: SSH22}) as e:
            o._ufw_prepare(e.fx, ["22"])
            self.assertEqual(e.runs(), [])

    def test_verify(self):
        with Env(dry_run=True) as e:
            o._ufw_verify_ssh(e.fx, ["22"])
            self.assertEqual(e.fx.events, [])
        with Env(fs={o.UFW_USER4: SSH22}) as e:
            with self.assertRaises(FixError):
                o._ufw_verify_ssh(e.fx, ["22", "2222"])
            self.assertEqual(e.runs(), ["ufw --force disable"])
        with Env(fs={o.UFW_USER4: SSH22}) as e:
            o._ufw_verify_ssh(e.fx, ["22"])
            self.assertEqual(e.fx.steps[-1][2], "成功")


# TWGCB-01-014-0207 ufw 服務
class UfwServiceTest(unittest.TestCase):
    def env(self, conf="ENABLED=no\n", svc=("disabled", "inactive"), user4=""):
        e = Env(fs={o.UFW_CONF: conf, o.UFW_BEFORE: UFW_BEFORE_OK, o.UFW_USER4: user4},
                svc={"ufw.service": svc}, pkgs={"ufw"}, rid="TWGCB-01-014-0207")
        e.runner.add("ufw allow in", ufw_allow_effect(e))
        return e

    def test_check(self):
        with self.env(conf="ENABLED=yes\n", svc=("enabled", "active")) as e:
            self.assertEqual(R(207).check(e.ctx).status, PASS)
        with self.env() as e:
            c = R(207).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("ENABLED=no", c.current)
        with Env() as e:
            self.assertEqual(R(207).check(e.ctx).current, "未安裝 ufw")

    def test_no_ufw(self):
        with Env(bins=()) as e:
            with self.assertRaises(ManualRequired):
                R(207).fix(e.ctx, e.fx)

    def test_enable_safely(self):
        with self.env() as e:
            R(207).fix(e.ctx, e.fx)
            ev = e.fx.events
            # 回滾登記最先；SSH 放行與保險都在啟用 ufw 之前，完成後取消保險
            self.assertEqual(ev[0], ("undo", "ufw --force disable"))
            ssh = e.idx("run", "ufw allow in 22/tcp")
            guard = e.idx("run", "systemd-run")
            enable = e.idx("run", "ufw --force enable")
            self.assertLess(e.idx("backup_dir", "/etc/ufw"), ssh)
            self.assertLess(ssh, guard)
            self.assertLess(guard, e.idx("enable", "ufw.service"))
            self.assertLess(e.idx("enable", "ufw.service"), enable)
            self.assertIn("/usr/bin/ufw --force disable", ev[guard][1])
            self.assertLess(enable, e.idx("run", "systemctl stop gcb-fw-guard-0207"))

    def test_already_on(self):
        with self.env(conf="ENABLED=yes\n", svc=("enabled", "active"), user4=SSH22) as e:
            R(207).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events[0], ("undo", "ufw reload"))
            self.assertEqual(e.runs("--force enable"), [])
            self.assertNotIn(("enable", "ufw.service"), e.fx.events)

    def test_verify_fail_disables_and_cancels(self):
        with self.env() as e:
            e.runner.add("ufw allow in", res(0))  # 規則沒有真正寫入
            with self.assertRaises(FixError):
                R(207).fix(e.ctx, e.fx)
            self.assertTrue(e.runs("ufw --force disable"))
            self.assertTrue(e.runs("systemctl stop gcb-fw-guard"))


# TWGCB-01-014-0208 在 ufw 設定回送流量規則
class UfwLoopbackTest(unittest.TestCase):
    def test_check(self):
        with Env() as e:
            self.assertEqual(R(208).check(e.ctx).current, "未安裝 ufw")
        with Env(pkgs={"ufw"}, fs={o.UFW_USER4: UFW_USER4_OK, o.UFW_DEFAULT: "IPV6=no\n"}) as e:
            self.assertEqual(R(208).check(e.ctx).status, PASS)
        with Env(pkgs={"ufw"}, fs={o.UFW_USER4: UFW_USER4_OK}) as e:
            c = R(208).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("deny in from ::1", c.current)

    def test_fix(self):
        with Env(bins=()) as e:
            with self.assertRaises(ManualRequired):
                R(208).fix(e.ctx, e.fx)
        bad = ("### tuple ### deny any any 0.0.0.0/0 any 127.0.0.0/8 in\n"
               "### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo\n")
        with Env(fs={o.UFW_USER4: bad}) as e:
            with self.assertRaises(ManualRequired) as cm:
                R(208).fix(e.ctx, e.fx)
            self.assertIn("順序", str(cm.exception))
            self.assertEqual(e.fx.events, [])
        with Env() as e:
            R(208).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events[:3], [("undo", "ufw reload"), ("backup", o.UFW_USER4),
                                               ("backup", o.UFW_USER6)])
            self.assertEqual(e.runs(), ["ufw allow in on lo", "ufw allow out on lo",
                                        "ufw deny in from 127.0.0.0/8", "ufw deny in from ::1"])


# TWGCB-01-014-0209 在 ufw 建立預設拒絕規則
class UfwDefaultDenyTest(unittest.TestCase):
    def env(self, inp="ACCEPT", out="ACCEPT", fwd="ACCEPT", enabled="yes", forwarding="0"):
        e = Env(pkgs={"ufw"}, rid="TWGCB-01-014-0209", fs={
            o.UFW_CONF: "ENABLED=%s\n" % enabled, o.UFW_BEFORE: UFW_BEFORE_OK, o.UFW_USER4: "",
            o.UFW_DEFAULT: 'DEFAULT_INPUT_POLICY="%s"\nDEFAULT_OUTPUT_POLICY="%s"\nDEFAULT_FORWARD_POLICY="%s"\n'
                           % (inp, out, fwd),
            "/proc/sys/net/ipv4/ip_forward": forwarding})
        e.runner.add("ufw allow in", ufw_allow_effect(e))
        return e

    def test_check(self):
        with Env() as e:
            self.assertEqual(R(209).check(e.ctx).status, FAIL)
        with self.env("DROP", "DROP", "DROP") as e:
            c = R(209).check(e.ctx)
            self.assertEqual(c.status, PASS)
            self.assertEqual(c.current, "incoming=deny、outgoing=deny、routed=deny"
                                        "（核心未開啟 IP 轉送，ufw status 的 routed 顯示為 disabled）")
        with self.env("DROP", "ACCEPT", "DROP", forwarding="1") as e:
            c = R(209).check(e.ctx)
            self.assertEqual((c.status, c.current), (FAIL, "incoming=deny、outgoing=allow、routed=deny"))

    def test_nothing_to_do(self):
        with Env(bins=()) as e:
            with self.assertRaises(ManualRequired):
                R(209).fix(e.ctx, e.fx)
        with self.env("DROP", "ACCEPT", "DROP") as e:
            with self.assertRaises(ManualRequired):
                R(209).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])
        # IP 轉送開啟時不設定 deny routed
        with self.env("DROP", "ACCEPT", "ACCEPT", forwarding="1") as e:
            with self.assertRaises(ManualRequired):
                R(209).fix(e.ctx, e.fx)
            self.assertTrue(any("IP 轉送" in n for n in e.fx.notes))

    def test_deny_incoming_safely(self):
        with self.env() as e:
            R(209).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events[0], ("undo", "ufw reload"))
            ssh = e.idx("run", "ufw allow in 22/tcp")
            guard = e.idx("run", "systemd-run")
            deny = e.idx("run", "ufw default deny incoming")
            self.assertLess(ssh, guard)
            self.assertLess(guard, deny)
            self.assertIn("/usr/bin/ufw default allow incoming", e.fx.events[guard][1])
            self.assertLess(deny, e.idx("run", "ufw default deny routed"))
            self.assertLess(deny, e.idx("run", "systemctl stop gcb-fw-guard-0209"))
            self.assertEqual(e.runs("deny outgoing"), [])
            self.assertTrue(e.fx.partial)

    def test_disabled_no_guard_and_forwarding(self):
        with self.env(enabled="no", forwarding="1") as e:
            R(209).fix(e.ctx, e.fx)
            self.assertEqual(e.runs("systemd-run"), [])
            self.assertEqual(e.runs("ufw default deny"), ["ufw default deny incoming"])
            self.assertTrue(e.fx.partial)

    def test_routed_only(self):
        # 只需 deny routed：不需放行 SSH 也不排保險
        with self.env("DROP", "DROP", "ACCEPT", forwarding="0") as e:
            e.fs[o.UFW_USER4] = SSH22
            R(209).fix(e.ctx, e.fx)
            self.assertEqual(e.runs(), ["ufw default deny routed"])
            self.assertFalse(e.fx.partial)

    def test_failure_cancels_guard(self):
        with self.env() as e:
            e.runner.add("ufw default deny", res(1, "", "boom"))
            with self.assertRaises(FixError):
                R(209).fix(e.ctx, e.fx)
            self.assertTrue(e.runs("systemctl stop gcb-fw-guard"))


class MiscTest(unittest.TestCase):
    def test_w_risk(self):
        class X(object):
            risk = "A"
        r = o._w(X(), None, risk="C")
        self.assertEqual(r.risk, "C")
        self.assertIsNone(r.when)


# ip6tables 備份還原指令：找不到 ip6tables-restore 時仍用 ip6tables-restore（不可退回 iptables-restore）
class RestoreCmdRegression(unittest.TestCase):
    def test_v6_fallback(self):
        with mock.patch.object(o, "which", lambda n: None):
            self.assertEqual(o._restore_cmd("v6", "/x"), ["ip6tables-restore", "/x"])
            self.assertEqual(o._restore_cmd("v4", "/x"), ["iptables-restore", "/x"])


if __name__ == "__main__":
    unittest.main()
