# -*- coding: utf-8 -*-
"""RHEL selinux.py 涵蓋率測試（二）：firewalld 與 iptables。

以 FakeFirewalld／FakeIpt 模擬防火牆狀態，驗證 SSH、lo、已建立連線（與 ICMPv6 鄰居探索）
在預設拒絕前放行，且回滾與自動還原保險先於修改登記；不修改系統。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS  # noqa: E402
from gcb.rules.rhel import selinux as s  # noqa: E402
from test_cov_rhel_selinux import GUARD_UNIT, Env, FakeFirewalld, FakeIpt  # noqa: E402

STOP_GUARD = ("run", "systemctl stop %s.timer" % GUARD_UNIT)


class FwEnv(Env):
    def setUp(self):
        Env.setUp(self)
        self.fw = FakeFirewalld()
        # 附加在 systemd-run 之後：自動還原保險指令內含 firewall-cmd 文字
        self.runner.rules.append(("firewall-cmd", self.fw))
        self.runner.rules.append(("firewall-offline-cmd", self.fw))
        self.on("systemctl --now enable firewalld.service", lambda c: (self.fw.start(), res(0))[1])
        self.pkgs.add("firewalld")


# RHEL8 0245 / RHEL9 0243 firewalld 服務（啟用）
class FirewalldEnabledTest(FwEnv):
    def setUp(self):
        FwEnv.setUp(self)
        self.rule = s.FirewalldEnabled({"rhel9": "TWGCB-01-012-0243"})
        self.fw.zone("public", ifaces=["eth0"], perm=["dhcpv6-client"])
        self.fw.zone("work", ifaces=["eth2"], perm=["2000-2300/tcp", "53/udp", "http"])
        self.fw.zone("trusted", ifaces=["lo1"], target="ACCEPT")
        self.fw.zone("internal")
        self.fw.nm_zone = "internal"  # 執行後才出現的作用中區域
        self.states["firewalld.service"] = ("masked", "inactive")

    def test_check(self):
        self.assertEqual(self.rule.check(self.ctx()).current, "masked / not running")
        self.fw.running = True
        self.states["firewalld.service"] = ("enabled", "active")
        self.assertEqual(self.rule.check(self.ctx()).status, PASS)
        self.pkgs.discard("firewalld")
        self.assertEqual(self.rule.check(self.ctx()).current, "未安裝 firewalld")

    def test_fix(self):
        self.on("ss -Htlnu", res(0, "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"))
        self.states["docker"] = ("enabled", "active")
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events[0], ("undo", s.FW_RELOAD_GUARD))
        self.assertEqual(fx.events[1], ("backup_dir", "/etc/firewalld"))
        guard = self.pos(fx, "run", "systemd-run")
        self.assertIn("tar -xf /tmp/backup.tar -C /etc && systemctl stop firewalld", fx.events[guard][1])
        enable = fx.events.index(("enable", "firewalld.service"))
        # 啟用前先在永久設定放行 SSH（離線指令）
        pre = [e[1] for e in fx.events[:enable] if e[0] == "run" and "--add-" in e[1]]
        self.assertEqual(pre, ["firewall-offline-cmd --zone=public --add-service=ssh",
                               "firewall-offline-cmd --zone=public --add-port=2222/tcp",
                               "firewall-offline-cmd --zone=work --add-service=ssh"])  # 2222 已在 2000-2300 範圍
        self.assertLess(guard, self.pos(fx, "run", "--add-service=ssh"))
        self.assertLess(self.pos(fx, "undo", "systemctl mask firewalld.service"), enable)
        # 啟用後補上 NetworkManager 指定的作用中區域（永久與目前）
        post = [e[1] for e in fx.events[enable:] if e[0] == "run" and "--add-" in e[1]]
        self.assertIn("firewall-cmd --permanent --zone=internal --add-service=ssh", post)
        self.assertIn("firewall-cmd --zone=internal --add-port=2222/tcp", post)
        self.assertEqual(fx.events[-1], STOP_GUARD)
        self.assertTrue({"ssh", "2222/tcp"} <= self.fw.zones["internal"]["rt"])
        self.assertIn("tcp/80", fx.notes[0])
        self.assertIn("docker", fx.notes[1])
        self.assertEqual(fx.steps[-2][0], "確認 SSH 放行")

    def test_fix_not_started(self):
        self.fw.start_ok = False
        fx = self.fx()
        with self.assertRaises(FixError) as cm:
            self.rule.fix(fx.ctx, fx)
        self.assertIn("未能啟動", str(cm.exception))
        self.assertEqual(fx.events[-1], STOP_GUARD)

    def test_fix_runtime_still_missing(self):
        self.fw.ignore_rt_adds = True
        fx = self.fx()
        with self.assertRaises(FixError) as cm:
            self.rule.fix(fx.ctx, fx)
        self.assertIn("internal:22,2222", str(cm.exception))
        self.assertEqual(fx.events[-1], STOP_GUARD)

    def test_fix_dry_run(self):
        fx = self.fx(dry=True)
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(self.runner.ran("--add-"), [])
        self.assertEqual(self.runner.ran("systemctl --now enable"), [])
        self.assertEqual(self.runner.ran("systemd-run"), [])
        self.assertFalse(self.fw.running)

    def test_fix_guards(self):
        self.pkgs.discard("firewalld")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.on("sshd -T", res(255))
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# RHEL8 0248 / RHEL9 0246 firewalld 防火牆預設區域
class FirewalldZoneTest(FwEnv):
    def setUp(self):
        FwEnv.setUp(self)
        self.rule = s.FirewalldZone({"rhel9": "TWGCB-01-012-0246"})
        self.fw.zone("public", ifaces=["eth0"], perm=["ssh", "2222/tcp"])
        self.fw.zone("work")
        self.fw.zone("trusted", target="ACCEPT")

    def test_check(self):
        self.fw.running = True
        self.fs[s.FirewalldZone.CONF] = "DefaultZone=public\n"
        c = self.rule.check(self.ctx())
        self.assertEqual((c.status, c.current), (PASS, "預設區域=public、firewalld.conf DefaultZone=public"))
        self.fw.default = "trusted"
        del self.fs[s.FirewalldZone.CONF]
        c = self.rule.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("trusted 區域等同全部放行", c.current)
        self.fw.default = "nosuch"
        self.assertIn("（區域不存在）", self.rule.check(self.ctx()).current)
        self.pkgs.discard("firewalld")
        self.assertEqual(self.rule.check(self.ctx()).current, "未安裝 firewalld")
        with self.assertRaises(ManualRequired):
            self.rule.fix(self.ctx(), self.fx())

    def test_fix_already_ok(self):
        self.fs[s.FirewalldZone.CONF] = "DefaultZone=public\n"
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_offline_invalid_zone(self):
        self.fw.default = "nosuch"
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        guard = self.pos(fx, "run", "systemd-run")
        self.assertIn("systemctl stop firewalld", fx.events[guard][1])
        self.assertEqual(self.fw.default, "public")
        # public 已放行，不需再加；設定預設區域在保險之後
        self.assertEqual(self.runner.ran("--add-"), [])
        self.assertLess(guard, self.pos(fx, "run", "firewall-offline-cmd --set-default-zone=public"))
        self.assertEqual(fx.events[-1], STOP_GUARD)

    def test_fix_running_keeps_valid_zone(self):
        self.fw.running = True
        self.fw.default = "work"
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertIn("firewall-cmd --reload", fx.events[self.pos(fx, "run", "systemd-run")][1])
        setdef = self.pos(fx, "run", "--set-default-zone=work")
        # 先在目標區域放行 SSH（永久與目前），再設定預設區域
        for cmd in ("firewall-cmd --permanent --zone=work --add-service=ssh",
                    "firewall-cmd --permanent --zone=work --add-port=2222/tcp",
                    "firewall-cmd --zone=work --add-service=ssh", "firewall-cmd --zone=work --add-port=2222/tcp"):
            self.assertLess(fx.events.index(("run", cmd)), setdef)
        self.assertEqual(fx.events[-1], STOP_GUARD)

    def test_fix_running_post_check_fail(self):
        self.fw.running = True
        self.fw.default = "work"
        self.fw.ignore_rt_adds = True
        fx = self.fx()
        with self.assertRaises(FixError):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events[-1], STOP_GUARD)


# RHEL8 0246 / RHEL9 0244 iptables 服務、RHEL8 0247 / RHEL9 0245 nftables 服務（firewalld 模式下停用）
class UnitsMaskedTest(FwEnv):
    def setUp(self):
        FwEnv.setUp(self)
        self.nft = s.UnitsMasked("nftables 服務", ["nftables.service"], {"rhel9": "TWGCB-01-012-0245"}, "nftables")
        self.ipt = s.UnitsMasked("iptables 服務", ["iptables.service", "ip6tables.service"],
                                 {"rhel8": "TWGCB-01-008-0246"}, "iptables")
        self.fw.running = True
        self.fw.zone("public", ifaces=["eth0"], perm=["ssh", "2222/tcp"])
        self.on("nft list ruleset", res(0, "table inet x {\n}\n"))

    def test_check(self):
        self.assertEqual(self.nft.check(self.ctx()).current, "未安裝（單元不存在）")
        self.states["nftables.service"] = ("masked", "inactive")
        self.assertEqual(self.nft.check(self.ctx()).status, PASS)
        self.states["nftables.service"] = ("masked", "activating")
        self.assertEqual(self.nft.check(self.ctx()).status, FAIL)

    def test_nothing_to_do(self):
        self.states["nftables.service"] = ("masked", "inactive")
        fx = self.fx()
        self.nft.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_nftables_active(self):
        self.states["nftables.service"] = ("enabled", "active")
        fx = self.fx()
        self.nft.fix(fx.ctx, fx)
        kinds = [(e[0], e[1].split()[0]) for e in fx.events]
        self.assertEqual(kinds, [("undo", "if"), ("undo", "/usr/sbin/nft"), ("run", "systemd-run"),
                                 ("record", "nftables.service"), ("run", "systemctl"), ("run", "systemctl"),
                                 ("run", "firewall-cmd"), ("run", "systemctl")])
        self.assertEqual(fx.kinds("run")[1:4], ["systemctl stop nftables.service", "systemctl mask nftables.service",
                                                "firewall-cmd --reload"])
        self.assertEqual(fx.events[-1], STOP_GUARD)

    def test_fix_reload_loses_ssh(self):
        self.states["nftables.service"] = ("enabled", "active")
        self.fw.zones["public"]["perm"] = set()
        self.fw.zones["public"]["rt"] = set()
        fx = self.fx()
        with self.assertRaises(FixError) as cm:
            self.nft.fix(fx.ctx, fx)
        self.assertIn("重新載入後 SSH 埠未放行", str(cm.exception))
        self.assertEqual(fx.events[-1], STOP_GUARD)

    def test_fix_no_ssh_ports_skips_post_check(self):
        self.states["nftables.service"] = ("enabled", "active")
        self.fw.zones["public"]["rt"] = set()
        self.on("sshd -T", res(255))
        fx = self.fx()
        self.nft.fix(fx.ctx, fx)
        self.assertIn(("run", "firewall-cmd --reload"), fx.events)

    def test_fix_iptables(self):
        self.fw.running = False
        self.states["iptables.service"] = ("enabled", "active")
        self.states["ip6tables.service"] = ("disabled", "inactive")
        v4, v6 = FakeIpt("iptables"), FakeIpt("ip6tables")
        for pat, m in (("iptables-save", v4), ("ip6tables-save", v6)):
            self.runner.rules.append((pat, m))
        fx = self.fx("rhel8")
        self.ipt.fix(fx.ctx, fx)
        undos = fx.kinds("undo")
        self.assertEqual(undos[0], s.FW_RELOAD_GUARD)
        self.assertTrue(undos[1].startswith("/usr/sbin/iptables-restore "))
        self.assertTrue(undos[2].startswith("/usr/sbin/ip6tables-restore "))
        self.assertEqual(self.runner.ran("systemd-run"), [])  # iptables 快照不經 Guard
        self.assertEqual(fx.kinds("run"), ["systemctl stop iptables.service", "systemctl mask iptables.service",
                                           "systemctl mask ip6tables.service"])
        self.assertEqual(self.runner.ran("firewall-cmd --reload"), [])  # firewalld 未執行


# RHEL8 0250 / RHEL9 0248 firewalld 服務（nftables 模式下停用）、RHEL8 0257（iptables 模式下停用）
class FirewalldMaskedTest(FwEnv):
    def setUp(self):
        FwEnv.setUp(self)
        self.nft = s.FirewalldMasked({"rhel9": "TWGCB-01-012-0248"}, "nftables")
        self.ipt = s.FirewalldMasked({"rhel8": "TWGCB-01-008-0257"}, "iptables")
        self.states["firewalld.service"] = ("enabled", "active")
        self.v4, self.v6 = FakeIpt("iptables"), FakeIpt("ip6tables")
        for pat, m in (("iptables -", self.v4), ("iptables-save", self.v4),
                       ("ip6tables -", self.v6), ("ip6tables-save", self.v6)):
            self.runner.rules.append((pat, m))

    def test_check(self):
        self.assertEqual(self.ipt.category, s.IPT)
        self.assertEqual(self.nft.check(self.ctx()).current, "enabled / active")
        self.states["firewalld.service"] = ("masked", "inactive")
        self.assertEqual(self.nft.check(self.ctx()).status, PASS)
        self.states["firewalld.service"] = ("not-found", "inactive")
        self.assertEqual(self.nft.check(self.ctx()).current, "未安裝")
        fx = self.fx()
        self.nft.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_nft_blocking_runtime(self):
        self.on("nft list ruleset", res(0, "table inet t {\n chain i {\n  type filter hook input priority 0; "
                                           "policy drop;\n }\n}\n"))
        fx = self.fx()
        with self.assertRaises(ManualRequired) as cm:
            self.nft.fix(fx.ctx, fx)
        self.assertIn("未放行 SSH 埠 22,2222", str(cm.exception))
        self.assertEqual(fx.events, [])

    def test_nft_ok(self):
        self.on("nft list ruleset", res(0, "table inet x {\n}\n"))
        fx = self.fx()
        self.nft.fix(fx.ctx, fx)
        # 回滾順序：reload 保底 → 規則集快照 → 遮蔽
        self.assertEqual([e[0] for e in fx.events], ["undo", "undo", "mask", "run"])
        self.assertEqual(fx.events[0], ("undo", s.FW_RELOAD_GUARD))
        self.assertTrue(fx.events[1][1].startswith("/usr/sbin/nft -f "))
        self.assertEqual(fx.events[2], ("mask", "firewalld.service"))

    def test_nft_not_installed(self):
        self.cmds.discard("nft")
        fx = self.fx()
        self.nft.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("undo"), [s.FW_RELOAD_GUARD])
        self.assertEqual(self.runner.ran("nft list"), [])

    def test_ipt_runtime_blocking(self):
        self.v4.pol["INPUT"] = "DROP"
        fx = self.fx("rhel8")
        with self.assertRaises(ManualRequired):
            self.ipt.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_ipt_saved_file_blocking(self):
        self.fs["/etc/sysconfig/iptables"] = "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
        self.states["iptables.service"] = ("enabled", "active")
        fx = self.fx("rhel8")
        with self.assertRaises(ManualRequired) as cm:
            self.ipt.fix(fx.ctx, fx)
        self.assertIn("/etc/sysconfig/iptables：INPUT 未放行迴路介面 lo", str(cm.exception))

    def test_ipt_ok(self):
        self.fs["/etc/sysconfig/iptables"] = ("*filter\n:INPUT DROP [0:0]\n-A INPUT -i lo -j ACCEPT\n"
                                              "-A INPUT -m state --state ESTABLISHED -j ACCEPT\n"
                                              "-A INPUT -p tcp -m multiport --dports 22,2000:2300 -j ACCEPT\nCOMMIT\n")
        self.states["iptables.service"] = ("enabled", "active")
        fx = self.fx("rhel8")
        self.ipt.fix(fx.ctx, fx)
        undos = fx.kinds("undo")
        self.assertEqual(undos[0], s.FW_RELOAD_GUARD)
        self.assertTrue(undos[1].startswith("/usr/sbin/iptables-restore "))
        self.assertTrue(undos[2].startswith("/usr/sbin/ip6tables-restore "))
        mask = fx.events.index(("mask", "firewalld.service"))
        self.assertLess(fx.events.index(("undo", undos[2])), mask)
        # 遮蔽 firewalld 後重新載入仍在執行的 iptables 規則
        self.assertEqual(fx.events[-1], ("run", "systemctl restart iptables.service"))
        self.assertEqual(self.runner.ran("restart ip6tables"), [])

    def test_ipt_unavailable(self):
        self.cmds.difference_update({"iptables", "ip6tables"})
        fx = self.fx("rhel8")
        self.ipt.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("undo"), [s.FW_RELOAD_GUARD])
        self.assertEqual(fx.kinds("mask"), ["firewalld.service"])


# ---------------- iptables ----------------

class IptEnv(Env):
    def setUp(self):
        Env.setUp(self)
        self.v4, self.v6 = FakeIpt("iptables"), FakeIpt("ip6tables")
        for pat, m in (("iptables -", self.v4), ("iptables-save", self.v4),
                       ("ip6tables -", self.v6), ("ip6tables-save", self.v6)):
            self.runner.rules.append((pat, m))
        self.fs["/proc/sys/net/ipv4/ip_forward"] = "0\n"
        self.dirs["/sys/class/net"] = ["lo", "eth0"]

    def ctx(self, key="rhel8", dry=False):
        c = Env.ctx(self, key, dry)
        c.cfg.firewall_backend = "iptables"
        return c

    def fx(self, key="rhel8", dry=False):
        return Env.fx(self, key, dry)


class IptHelpers(IptEnv):
    def test_snapshot(self):
        fx = self.fx()
        self.v4.save_rc = 1
        with self.assertRaises(FixError):
            s.ipt_snapshot(fx.ctx, fx, s.IptFamily(False))
        # filter 表未載入：補上空的 ACCEPT 表，回滾才能清掉新增規則
        self.on("ip6tables-save", res(0, "*nat\nCOMMIT\n"))
        cmd = s.ipt_snapshot(fx.ctx, fx, s.IptFamily(True))
        self.assertEqual(self.backups[cmd[1]], "*nat\nCOMMIT\n*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n"
                                               ":OUTPUT ACCEPT [0:0]\nCOMMIT\n")
        self.assertEqual(fx.kinds("undo"), ["/usr/sbin/ip6tables-restore " + cmd[1]])
        fx = self.fx(dry=True)
        self.assertIsNone(s.ipt_snapshot(fx.ctx, fx, s.IptFamily(True)))

    def test_ssh_problems_ranges(self):
        rules = ["-A INPUT -i lo -j ACCEPT", "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                 "-A INPUT -p tcp -m multiport --dports :30,2200:,8080 -j ACCEPT"]
        self.assertEqual(s.ipt_ssh_problems({"INPUT": "DROP"}, rules, ["22", "2222", "8080"]), [])
        self.assertEqual(s.ipt_ssh_problems({"INPUT": "ACCEPT"}, [], ["22"]), [])

    def test_v6_when(self):
        self.assertEqual(s._ipt_v6_when(self.ctx()), "核心已停用 IPv6，沒有 IPv6 流量需要以 ip6tables 管制")
        self.exists.add("/proc/net/if_inet6")
        self.assertIsNone(s._ipt_v6_when(self.ctx()))
        c = self.ctx()
        c.cfg.firewall_backend = "nftables"
        self.assertIn("本項目屬 iptables，不需設定", s._ipt_v6_when(c))

    def test_foreign_from_comment_only(self):
        self.assertEqual(s.nft_foreign_tables("# Warning: table ip nat is managed by iptables-nft, do not touch!\n"),
                         ["ip nat"])


# RHEL8 0256 iptables 服務（啟用）
class IptEnabledTest(IptEnv):
    FILE = "/etc/sysconfig/iptables"

    def setUp(self):
        IptEnv.setUp(self)
        self.rule = s.IptEnabled({"rhel8": "TWGCB-01-008-0256"})
        self.pkgs.add("iptables-services")
        self.on("systemctl --now enable iptables.service",
                lambda c: (self.v4.load_saved(self.fs.get(self.FILE, "")), res(0))[1])

    def test_check(self):
        self.states["iptables.service"] = ("enabled", "active")
        self.assertEqual(self.rule.check(self.ctx()).status, PASS)
        self.pkgs.discard("iptables-services")
        self.assertEqual(self.rule.check(self.ctx()).current, "未安裝 iptables-services")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_adds_allows_before_enable(self):
        from test_rhel_selinux import IPT_FILE
        self.fs[self.FILE] = IPT_FILE
        self.states["iptables.service"] = ("masked", "inactive")
        self.on("ss -Htlnu", res(0, "tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\n"))
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        text = self.fs[self.FILE]
        pol, rules = s.ipt_parse(text, saved=True)
        self.assertEqual(s.ipt_ssh_problems(pol, rules, ["22", "2222"]), [])
        self.assertLess(text.index("--dport 2222"), text.index("REJECT"))  # 放行插在拒絕之前
        self.assertEqual(fx.modes[self.FILE], 0o600)
        enable = fx.events.index(("enable", "iptables.service"))
        write = self.pos(fx, "write", self.FILE)
        restore = self.pos(fx, "undo", "/usr/sbin/iptables-restore")
        guard = self.pos(fx, "run", "systemd-run")
        self.assertLess(write, enable)
        self.assertLess(self.pos(fx, "undo", s.FW_RELOAD_GUARD), restore)
        self.assertLess(restore, guard)
        self.assertLess(guard, self.pos(fx, "undo", "systemctl mask iptables.service"))
        self.assertLess(self.pos(fx, "run", "systemctl unmask iptables.service"), enable)
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))
        self.assertIn("tcp/80", fx.notes[0])

    def test_fix_file_ok_no_edit(self):
        self.fs[self.FILE] = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
        fx = self.fx()
        self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), [])
        self.assertIn(("enable", "iptables.service"), fx.events)

    def test_fix_post_check_fail(self):
        self.on("systemctl --now enable iptables.service", res(0))
        self.v4.pol["INPUT"] = "DROP"
        fx = self.fx()
        with self.assertRaises(FixError):
            self.rule.fix(fx.ctx, fx)
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))


# RHEL8 0258 在 iptables 建立預設拒絕規則、RHEL8 0260 在 ip6tables 建立預設拒絕規則
class IptDefaultDropTest(IptEnv):
    def setUp(self):
        IptEnv.setUp(self)
        self.r4 = s.IptDefaultDrop({"rhel8": "TWGCB-01-008-0258"}, v6=False)
        self.r6 = s.IptDefaultDrop({"rhel8": "TWGCB-01-008-0260"}, v6=True)

    def test_check(self):
        self.cmds.discard("ip6tables-save")
        self.assertEqual(self.r6.check(self.ctx()).current, "找不到 ip6tables")
        self.v4.s_rc = 1
        self.assertEqual(self.r4.check(self.ctx()).status, ERROR)
        self.v4.s_rc = 0
        self.v4.pol.update({"INPUT": "DROP", "FORWARD": "DROP", "OUTPUT": "DROP"})
        self.assertEqual(self.r4.check(self.ctx()).current, "目前/開機 INPUT:DROP/未設定、FORWARD:DROP/未設定、OUTPUT:DROP/未設定")
        self.fs["/etc/sysconfig/iptables"] = self.v4.dump_save()
        self.assertEqual(self.r4.check(self.ctx()).status, PASS)

    def test_fix_v6_allows_before_drop(self):
        self.v6.rules = ["-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]
        fx = self.fx()
        self.r6.fix(fx.ctx, fx)
        runs = fx.kinds("run")
        inserts = [r for r in runs if " -I " in r]
        self.assertEqual(inserts, ["ip6tables -I INPUT 1 -i lo -j ACCEPT",  # 已建立連線規則已存在，不重複
                                   "ip6tables -I INPUT 2 -p tcp --dport 22 -j ACCEPT",
                                   "ip6tables -I INPUT 3 -p tcp --dport 2222 -j ACCEPT"] +
                         ["ip6tables -I INPUT %d -p ipv6-icmp --icmpv6-type %s -j ACCEPT" % (4 + i, t)
                          for i, t in enumerate(("133", "134", "135", "136", "2"))])
        drop = runs.index("ip6tables -P INPUT DROP")
        self.assertTrue(all(runs.index(i) < drop for i in inserts))
        self.assertIn("ip6tables -P FORWARD DROP", runs)
        self.assertNotIn("ip6tables -P OUTPUT DROP", runs)  # 外出只檢測
        # 快照還原指令與保險在任何修改之前；保存開機規則在確認 SSH 之後
        restore = self.pos(fx, "undo", "/usr/sbin/ip6tables-restore")
        guard = self.pos(fx, "run", "systemd-run")
        self.assertEqual((restore, guard), (0, 1))
        self.assertIn("/usr/sbin/ip6tables-restore", fx.events[guard][1])
        self.assertIn(("確認 SSH 放行", "INPUT 已放行 lo、已建立連線與 SSH 埠 22,2222", "成功"), fx.steps)
        self.assertLess(self.pos(fx, "run", "-P FORWARD DROP"), self.pos(fx, "backup", "/etc/sysconfig/ip6tables"))
        self.assertIn("ip6tables-save > /etc/sysconfig/ip6tables", fx.events[-2][1])
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))
        self.assertEqual(self.v6.pol["INPUT"], "DROP")
        self.assertTrue(fx.partial)
        self.assertIn("-P OUTPUT DROP", fx.notes[-1])

    def test_fix_v4_forwarding_and_others(self):
        self.dirs["/sys/class/net"] = ["eth0", "virbr0"]
        self.on("ss -Htlnu", res(0, "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"))
        fx = self.fx()
        self.r4.fix(fx.ctx, fx)
        runs = fx.kinds("run")
        self.assertNotIn("iptables -P FORWARD DROP", runs)
        self.assertEqual([r for r in runs if "icmpv6" in r], [])
        self.assertIn("FORWARD 未設為 DROP", fx.notes[0])
        self.assertIn("tcp/443", fx.notes[1])

    def test_fix_post_check_fail(self):
        self.v4.frozen = True  # 放行規則未生效
        fx = self.fx()
        with self.assertRaises(FixError):
            self.r4.fix(fx.ctx, fx)
        self.assertEqual(fx.events[-1], ("run", "systemctl stop %s.timer" % GUARD_UNIT))
        self.assertEqual(fx.kinds("backup"), [])  # 不保存有問題的規則

    def test_fix_guards(self):
        self.cmds.discard("iptables")
        fx = self.fx()
        with self.assertRaises(ManualRequired):
            self.r4.fix(fx.ctx, fx)
        self.on("sshd -T", res(255))
        with self.assertRaises(ManualRequired):
            self.r6.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_dry_run(self):
        fx = self.fx(dry=True)
        self.r4.fix(fx.ctx, fx)
        self.assertEqual(self.runner.ran(" -I "), [])
        self.assertEqual(self.runner.ran(" -P "), [])
        self.assertEqual(self.v4.pol["INPUT"], "ACCEPT")
        self.assertEqual(fx.kinds("undo"), [])


# RHEL8 0259 在 iptables 設定回送流量規則、RHEL8 0261 在 ip6tables 設定回送流量規則
class IptLoopbackTest(IptEnv):
    def setUp(self):
        IptEnv.setUp(self)
        self.r4 = s.IptLoopback({"rhel8": "TWGCB-01-008-0259"}, v6=False)
        self.r6 = s.IptLoopback({"rhel8": "TWGCB-01-008-0261"}, v6=True)

    def test_check(self):
        self.cmds.discard("iptables")
        self.assertEqual(self.r4.check(self.ctx()).current, "找不到 iptables")
        self.v6.s_rc = 1
        self.assertEqual(self.r6.check(self.ctx()).status, ERROR)
        self.v6.s_rc = 0
        self.v6.rules = s.ipt_loop_rules(True)
        c = self.r6.check(self.ctx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "目前缺少：無；/etc/sysconfig/ip6tables 缺少：" + "、".join(s.ipt_loop_rules(True)))
        self.fs["/etc/sysconfig/ip6tables"] = self.v6.dump_save()
        self.assertEqual(self.r6.check(self.ctx()).status, PASS)
        with self.assertRaises(ManualRequired):
            self.r4.fix(self.ctx(), self.fx())

    def test_fix_v4_wrong_order(self):
        # lo 放行在迴路位址 DROP 之後：即使 lo 規則已存在仍插到鏈開頭
        self.v4.rules = ["-A INPUT -s 127.0.0.0/8 -j DROP", "-A INPUT -i lo -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT"]
        fx = self.fx()
        self.r4.fix(fx.ctx, fx)
        self.assertEqual(fx.events[0][0], "undo")  # 先登記還原
        self.assertEqual([r for r in fx.kinds("run") if " -I " in r], ["iptables -I INPUT 1 -i lo -j ACCEPT"])
        self.assertEqual(s.ipt_loopback_missing(self.v4.rules, False), [])
        self.assertIn("iptables-save > /etc/sysconfig/iptables", fx.events[-1][1])

    def test_fix_wrong_order_and_missing_output(self):
        # DROP 在 lo 放行之前且缺 OUTPUT lo：一次修復同時插入 INPUT lo（第 1 條）與 OUTPUT lo
        self.v4.rules = ["-A INPUT -s 127.0.0.0/8 -j DROP", "-A INPUT -i lo -j ACCEPT"]
        fx = self.fx()
        self.r4.fix(fx.ctx, fx)
        self.assertEqual(fx.events[0][0], "undo")
        self.assertEqual([r for r in fx.kinds("run") if " -I " in r],
                         ["iptables -I INPUT 1 -i lo -j ACCEPT", "iptables -I OUTPUT 1 -o lo -j ACCEPT"])
        self.assertEqual(self.v4.rules[0], "-A INPUT -i lo -j ACCEPT")
        self.assertEqual(s.ipt_loopback_missing(self.v4.rules, False), [])
        self.assertIn("iptables-save > /etc/sysconfig/iptables", fx.events[-1][1])

    def test_fix_v6_from_empty(self):
        self.v6.rules = ["-A INPUT -p tcp --dport 22 -j ACCEPT"]
        fx = self.fx()
        self.r6.fix(fx.ctx, fx)
        self.assertEqual([r for r in fx.kinds("run") if " -I " in r],
                         ["ip6tables -I INPUT 1 -i lo -j ACCEPT", "ip6tables -I OUTPUT 1 -o lo -j ACCEPT",
                          "ip6tables -I INPUT 2 -s ::1/128 -j DROP"])
        self.assertEqual(self.v6.rules[:2], ["-A INPUT -i lo -j ACCEPT", "-A INPUT -s ::1/128 -j DROP"])
        self.assertEqual(s.ipt_loopback_missing(self.v6.rules, True), [])

    def test_fix_drop_without_lo_rule(self):
        # 理論上 lo 規則剛插入；若讀不到則插在第 1 條
        self.v4.frozen = True
        fx = self.fx()
        self.r4.fix(fx.ctx, fx)
        self.assertIn("iptables -I INPUT 1 -s 127.0.0.0/8 -j DROP", fx.kinds("run"))

    def test_fix_dry_run(self):
        fx = self.fx(dry=True)
        self.r6.fix(fx.ctx, fx)
        self.assertIn("ip6tables -I INPUT 2 -s ::1/128 -j DROP", fx.kinds("run"))
        self.assertEqual(self.runner.ran(" -I "), [])
        self.assertEqual(fx.kinds("undo"), [])


# RHEL8 0259 / 0261 iptables／ip6tables 回送流量規則：同時缺 OUTPUT lo 與順序錯誤時，一次回報兩者
class IptLoopbackOrderRegression(unittest.TestCase):
    def test_order_checked_when_other_rule_missing(self):
        rules = ["-A INPUT -s 127.0.0.0/8 -j DROP", "-A INPUT -i lo -j ACCEPT"]
        miss = s.ipt_loopback_missing(rules, False)
        self.assertIn("-A OUTPUT -o lo -j ACCEPT", miss)
        self.assertTrue(any(m.startswith("（") for m in miss))


if __name__ == "__main__":
    unittest.main()
