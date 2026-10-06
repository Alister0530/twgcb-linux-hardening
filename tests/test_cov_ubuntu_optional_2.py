# -*- coding: utf-8 -*-
"""gcb/rules/ubuntu/optional.py 的涵蓋率測試（二）：Nftables、Iptables、GNOME。

共用 test_cov_ubuntu_optional 的 Env（假檔案系統、假指令、假套件／服務狀態）。
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fakes import FakeRunner, res  # noqa: E402
from gcb import textedit as te  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, PASS  # noqa: E402
from gcb.rules.ubuntu import optional as o  # noqa: E402
from test_cov_ubuntu_optional import R, Env, seq  # noqa: E402


def chain(h, policy="accept", rules=(), fam="inet", table="filter"):
    body = "".join("\t\t%s\n" % r for r in rules)
    return "\tchain %s {\n\t\ttype filter hook %s priority filter; policy %s;\n%s\t}\n" % (h, h, policy, body)


def ruleset(chains, fam="inet", table="filter"):
    return "table %s %s {\n%s}\n" % (fam, table, "".join(chains))


SAFE_IN = ['iif "lo" accept', "ct state established,related accept", "tcp dport { 22 } accept"]
CONF_EMPTY = o.NFT_HEADER + o.NFT_CHAINS_BLOCK
RT_ACCEPT = ruleset([chain("input"), chain("forward"), chain("output")])


# ====================================================================
# nftables 解析與共用函式
# ====================================================================

class NftParseMoreTest(unittest.TestCase):
    def test_skip_block(self):
        text = "table inet f {\n\tset s {\n\t\ttype ipv4_addr\n\t}\n" + chain("input") + "}\n"
        tables, chains = o.nft_parse(text)
        self.assertEqual(tables, [("inet", "f")])
        self.assertEqual([c["chain"] for c in chains], ["input"])

    def test_accepts_port(self):
        self.assertTrue(o.nft_accepts_port("tcp dport 2000-3000 accept", "2222"))
        self.assertFalse(o.nft_accepts_port("tcp dport 2000-3000 accept", "22"))
        self.assertFalse(o.nft_accepts_port("tcp dport a-b accept", "22"))
        self.assertTrue(o.nft_accepts_port("tcp dport ssh accept", "22"))
        self.assertFalse(o.nft_accepts_port("tcp dport 22 drop", "22"))

    def test_ssh_safe_branches(self):
        self.assertEqual(o.nft_chain_ssh_safe({"policy": "accept", "hook": "input"}, ["22"]), (True, ""))
        c = {"policy": "drop", "hook": "input", "family": "ip", "rules": ["tcp dport 22 accept"]}
        with Env():
            self.assertEqual(o.nft_chain_ssh_safe(c, ["22"]), (False, "迴路介面、已建立連線"))

    def test_loopback_missing_all(self):
        self.assertEqual(o.nft_loopback_missing({"rules": []}), [o.NFT_LO, o.NFT_LO4, o.NFT_LO6])

    def test_conf_edit_none(self):
        self.assertIsNone(o.nft_conf_insert_rules(CONF_EMPTY, ("ip", "x", "input"), ["r"]))
        self.assertIsNone(o.nft_conf_set_policy(CONF_EMPTY, ("ip", "x", "input"), "drop"))
        one = "table inet f {\n chain input { type filter hook input priority 0; }\n}\n"
        self.assertIsNone(o.nft_conf_set_policy(one, ("inet", "f", "input"), "drop"))

    def test_allow_rules_nd(self):
        with Env(dirs={"/proc/sys/net/ipv6"}):
            out = o.NftDefaultDrop._allow_rules(None, ["22", "2222"])
            self.assertEqual([a[0] for a in out], [o.NFT_LO, "ct state established,related accept", o.NFT_ND,
                                                   "tcp dport { 22, 2222 } accept"])
            self.assertEqual(out[-1][1], ["tcp", "dport", "{ 22, 2222 }", "accept"])
        with Env():
            c = {"family": "inet", "rules": SAFE_IN}
            self.assertEqual(o.NftDefaultDrop._allow_rules(c, ["22"]), [])


class NftConfFilesTest(unittest.TestCase):
    def test_includes(self):
        main = 'include "/etc/nftables.d/*.nft"\ninclude "extra.nft"\n' + ruleset([chain("input")])
        fs = {o.NFT_CONF: main, "/etc/nftables.d/b.nft": ruleset([chain("output")], table="b"),
              "/etc/nftables.d/a.nft": "", "/etc/extra.nft": ruleset([], table="e")}
        with Env(fs=fs):
            self.assertEqual([p for p, _ in o._nft_conf_files()],
                             [o.NFT_CONF, "/etc/nftables.d/a.nft", "/etc/nftables.d/b.nft", "/etc/extra.nft"])
            tables, chains = o._nft_conf()
            self.assertEqual(tables, [("inet", "filter"), ("inet", "b"), ("inet", "e")])
            self.assertEqual([(c["chain"], c["file"]) for c in chains],
                             [("input", o.NFT_CONF), ("output", "/etc/nftables.d/b.nft")])
        with Env():
            self.assertEqual(o._nft_conf_files(), [])

    def test_runtime(self):
        with Env(bins=()):
            self.assertRaises(RuntimeError, o._nft_runtime)
        with Env(runner=FakeRunner({"nft list ruleset": res(1, "", "perm")})):
            self.assertRaises(RuntimeError, o._nft_runtime)
        foreign = ruleset([chain("INPUT")], fam="ip", table="filter")
        with Env(runner=FakeRunner({"nft list ruleset": res(0, RT_ACCEPT + foreign)})):
            tables, chains = o._nft_runtime()
            self.assertEqual(tables, [("inet", "filter")])
            self.assertEqual(len(chains), 3)

    def test_check_conf(self):
        with Env(runner=FakeRunner({"nft -c -f": res(1, "", "syntax error")})) as e:
            with self.assertRaises(FixError):
                o._nft_check_conf(e.fx)
        with Env(dry_run=True, runner=FakeRunner({"nft -c -f": res(1)})) as e:
            o._nft_check_conf(e.fx)
            self.assertEqual(e.runs(), ["nft -c -f /etc/nftables.conf"])

    def test_target(self):
        with Env(bins=(), fs={o.NFT_CONF: CONF_EMPTY}):
            self.assertRaises(ManualRequired, o._nft_target, "input")
        ip_conf = ruleset([chain("input")], fam="ip", table="t")
        run = FakeRunner({"nft list ruleset": res(0, ip_conf)})
        with Env(fs={o.NFT_CONF: ip_conf}, runner=run):
            self.assertRaises(ManualRequired, o._nft_target, "input")
            key, c = o._nft_target("input", need_inet=False)
            self.assertEqual(key, ("ip", "t", "input"))
            self.assertEqual(c["file"], o.NFT_CONF)

    def test_handles(self):
        out = ("table inet filter {\n\tchain input { # handle 1\n"
               "\t\ttype filter hook input priority filter; policy accept;\n"
               '\t\tiif "lo" accept # handle 5\n\t\tct state established accept # handle 7\n\t}\n}\n')
        with Env(runner=FakeRunner({"nft -a list chain": res(0, out)})) as e:
            self.assertEqual(o._nft_handles(("inet", "filter", "input")),
                             [('iif "lo" accept', "5"), ("ct state established accept", "7")])
            self.assertEqual(e.runner.calls, ["nft -a list chain inet filter input"])


# TWGCB-01-014-0212 nftables 服務
class NftServiceTest(unittest.TestCase):
    CONF = o.NFT_HEADER + ruleset([chain("input", "drop", SAFE_IN), chain("forward"), chain("output")])
    RT = ruleset([chain("input", "drop", SAFE_IN), chain("forward"), chain("output")])

    def env(self, rt=None, conf=None, **kw):
        run = FakeRunner({"nft list ruleset": rt or res(0, self.RT)})
        return Env(fs={o.NFT_CONF: conf or self.CONF}, runner=run, pkgs={"nftables"},
                   rid="TWGCB-01-014-0212", **kw)

    def test_check(self):
        with Env() as e:
            self.assertEqual(R(212).check(e.ctx).status, FAIL)
        with Env(pkgs={"nftables"}, svc={"nftables.service": ("enabled", "active")}) as e:
            self.assertEqual(R(212).check(e.ctx).status, PASS)

    def test_refusals(self):
        with Env(bins=()) as e:
            self.assertRaises(ManualRequired, R(212).fix, e.ctx, e.fx)
        with Env() as e:
            self.assertRaises(ManualRequired, R(212).fix, e.ctx, e.fx)
        # 設定檔 input policy drop 但未放行 SSH
        bad = ruleset([chain("input", "drop", SAFE_IN[:2])])
        with self.env(conf=bad) as e:
            with self.assertRaises(ManualRequired) as cm:
                R(212).fix(e.ctx, e.fx)
            self.assertIn("SSH 埠 22", str(cm.exception))
        with self.env(rt=res(1, "", "x")) as e:
            self.assertRaises(ManualRequired, R(212).fix, e.ctx, e.fx)
        # 執行中有設定檔沒有的表 → 啟動會被清除
        with self.env(rt=res(0, self.RT + ruleset([], table="extra"))) as e:
            with self.assertRaises(ManualRequired) as cm:
                R(212).fix(e.ctx, e.fx)
            self.assertIn("inet extra", str(cm.exception))
        for env in (e,):
            self.assertEqual(env.fx.events, [])

    def test_enable_safely(self):
        with self.env() as e:
            R(212).fix(e.ctx, e.fx)
            check = e.idx("run", "nft -c -f")
            undo = e.idx("undo", "/usr/bin/nft -f /run/gcb/fw-0212-nft-")
            guard = e.idx("run", "systemd-run")
            enable = e.idx("enable", "nftables.service")
            self.assertLess(check, e.idx("snapshot"))
            self.assertLess(e.idx("snapshot"), undo)
            self.assertLess(undo, guard)
            self.assertLess(guard, enable)
            self.assertLess(enable, e.idx("run", "systemctl stop gcb-fw-guard-0212"))
            self.assertIn("/usr/bin/nft -f /run/gcb/fw-0212-nft-", e.fx.events[guard][1])

    def test_post_check_fails(self):
        unsafe = ruleset([chain("input", "drop", SAFE_IN[:1])])
        with self.env(rt=seq(res(0, self.RT), res(0, self.RT), res(0, unsafe))) as e:
            with self.assertRaises(FixError):
                R(212).fix(e.ctx, e.fx)
            self.assertTrue(e.runs("systemctl stop gcb-fw-guard"))

    def test_dry_run(self):
        with self.env(dry_run=True) as e:
            R(212).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.kinds("undo"), [])
            self.assertEqual(e.runs("systemd-run"), [])
            self.assertEqual(e.fs, {o.NFT_CONF: self.CONF})


# TWGCB-01-014-0213 在 nftables 中建立表
class NftTableTest(unittest.TestCase):
    def test_check(self):
        with Env(bins=()) as e:
            self.assertEqual(R(213).check(e.ctx).status, ERROR)
        run = FakeRunner({"nft list ruleset": res(0, RT_ACCEPT)})
        with Env(runner=run, fs={o.NFT_CONF: CONF_EMPTY}) as e:
            c = R(213).check(e.ctx)
            self.assertEqual((c.status, c.current), (PASS, "設定檔：inet filter；執行中：inet filter"))
        with Env() as e:
            c = R(213).check(e.ctx)
            self.assertEqual((c.status, c.current), (FAIL, "設定檔：無；執行中：無"))

    def test_fix_create(self):
        with Env(rid="TWGCB-01-014-0213") as e:
            R(213).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[o.NFT_CONF], o.NFT_HEADER + "table inet filter {\n}\n")
            ev = e.fx.events
            self.assertEqual(ev[0], ("write", o.NFT_CONF))
            self.assertEqual(ev[1], ("run", "nft -c -f /etc/nftables.conf"))
            self.assertLess(e.idx("undo", "nft -f"), e.idx("run", "nft add table inet filter"))

    def test_fix_noop(self):
        run = FakeRunner({"nft list ruleset": res(0, RT_ACCEPT)})
        with Env(runner=run, fs={o.NFT_CONF: CONF_EMPTY}) as e:
            R(213).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])


# TWGCB-01-014-0214 在 nftables 建立基本鏈
class NftBaseChainTest(unittest.TestCase):
    def test_check(self):
        with Env(bins=()) as e:
            self.assertEqual(R(214).check(e.ctx).status, ERROR)
        run = FakeRunner({"nft list ruleset": res(0, ruleset([chain("input")]))})
        with Env(runner=run, fs={o.NFT_CONF: CONF_EMPTY}) as e:
            c = R(214).check(e.ctx)
            self.assertEqual(c.status, PASS)
            self.assertIn("建議 input、forward、output 三者齊全", c.current)
        with Env() as e:
            c = R(214).check(e.ctx)
            self.assertEqual((c.status, c.current), (FAIL, "設定檔：無；執行中：無"))

    def test_refusals(self):
        with Env(fs={o.NFT_CONF: CONF_EMPTY}) as e:
            with self.assertRaises(ManualRequired) as cm:
                R(214).fix(e.ctx, e.fx)
            self.assertIn("0212", str(cm.exception))
        regular = "table inet filter {\n\tchain input {\n\t}\n}\n"
        with Env(fs={o.NFT_CONF: regular}) as e:
            self.assertRaises(ManualRequired, R(214).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])

    def test_fix_create(self):
        with Env(rid="TWGCB-01-014-0214") as e:
            R(214).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[o.NFT_CONF], CONF_EMPTY)
            adds = e.runs("nft add")
            self.assertEqual(adds[0], "nft add table inet filter")
            self.assertEqual(len(adds), 4)
            self.assertTrue(all("policy accept" in a for a in adds[1:]))
            self.assertLess(e.idx("undo", "nft -f"), e.idx("run", "nft add"))

    def test_fix_conf_only(self):
        with Env(runner=FakeRunner({"nft list ruleset": res(0, RT_ACCEPT)})) as e:
            R(214).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[o.NFT_CONF], CONF_EMPTY)
            self.assertEqual(e.runs("nft add"), [])
            self.assertEqual(e.fx.kinds("undo"), [])


# TWGCB-01-014-0215 在 nftables 設定回送流量規則
class NftLoopbackTest(unittest.TestCase):
    LO_ALL = [o.NFT_LO, o.NFT_LO4, o.NFT_LO6]

    def env(self, conf_rules=(), rt_rules=(), conf=None, extra=None):
        rt = ruleset([chain("input", rules=rt_rules)])
        run = FakeRunner(dict({"nft list ruleset": res(0, rt)}, **(extra or {})))
        return Env(fs={o.NFT_CONF: conf or o.NFT_HEADER + ruleset([chain("input", rules=conf_rules)])},
                   runner=run, rid="TWGCB-01-014-0215")

    def test_check(self):
        with Env(bins=()) as e:
            self.assertEqual(R(215).check(e.ctx).status, ERROR)
        with Env(runner=FakeRunner({"nft list ruleset": res(0, ruleset([chain("output")]))})) as e:
            self.assertEqual(R(215).check(e.ctx).current, "執行中沒有 input 基本鏈")
        with self.env(self.LO_ALL, self.LO_ALL) as e:
            self.assertEqual(R(215).check(e.ctx).status, PASS)
        with self.env(self.LO_ALL[:1], self.LO_ALL) as e:
            c = R(215).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("執行中缺少：無；設定檔缺少：%s" % o.NFT_LO4, c.current)
        with self.env(conf=ruleset([chain("output")]), rt_rules=self.LO_ALL) as e:
            self.assertIn("設定檔無此鏈", R(215).check(e.ctx).current)

    def test_order_wrong(self):
        with self.env([o.NFT_LO4, o.NFT_LO, o.NFT_LO6], self.LO_ALL) as e:
            self.assertRaises(ManualRequired, R(215).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])

    def test_fix_all(self):
        with self.env() as e:
            R(215).fix(e.ctx, e.fx)
            ev = e.fx.events
            self.assertLess(e.idx("undo", "nft -f"), e.idx("write", o.NFT_CONF))
            # 設定檔：lo accept 在最前，drop 在其後
            c = o.nft_base(o.nft_parse(e.fs[o.NFT_CONF])[1], "input")[0]
            self.assertEqual(c["rules"], self.LO_ALL)
            self.assertLess(e.idx("write"), e.idx("run", "nft -c -f"))
            # 執行中：由後往前 insert，最後 lo 在最前
            ins = e.runs("nft insert rule inet filter input")
            self.assertEqual(len(ins), 3)
            self.assertTrue(ins[0].endswith("ip6 saddr ::1 counter drop"))
            self.assertTrue(ins[-1].endswith("iif lo accept"))
            self.assertEqual(ev[-1][0], "run")

    def test_fix_after_lo(self):
        handles = res(0, '\t\tiif "lo" accept # handle 9\n')
        with self.env([o.NFT_LO], [o.NFT_LO], extra={"nft -a list chain": handles}) as e:
            R(215).fix(e.ctx, e.fx)
            c = o.nft_base(o.nft_parse(e.fs[o.NFT_CONF])[1], "input")[0]
            self.assertEqual(c["rules"], self.LO_ALL)
            adds = e.runs("nft add rule")
            self.assertEqual(len(adds), 2)
            self.assertTrue(all("position 9" in a for a in adds))
        with self.env(self.LO_ALL, [o.NFT_LO]) as e:
            R(215).fix(e.ctx, e.fx)
            self.assertNotIn(("write", o.NFT_CONF), e.fx.events)
            self.assertEqual(len(e.runs("nft insert rule")), 2)

    def test_one_line_conf(self):
        one = "table inet filter {\n chain input { type filter hook input priority 0; policy accept; }\n}\n"
        with self.env(conf=one) as e:
            with self.assertRaises(ManualRequired) as cm:
                R(215).fix(e.ctx, e.fx)
            self.assertIn("單行", str(cm.exception))
            self.assertNotIn(("write", o.NFT_CONF), e.fx.events)


class _NftState(object):
    """模擬執行中規則集：執行 policy drop 後改回傳 after。"""

    def __init__(self, before, after):
        self.before, self.after, self.dropped = before, after, False

    def ruleset(self, _cmd):
        return res(0, self.after if self.dropped else self.before)

    def drop(self, _cmd):
        self.dropped = True
        return res(0)


# TWGCB-01-014-0216 在 nftables 建立預設拒絕規則
class NftDefaultDropTest(unittest.TestCase):
    ALL_DROP = ruleset([chain("input", "drop", SAFE_IN), chain("forward", "drop"), chain("output", "drop")])

    def env(self, before=RT_ACCEPT, after=None, conf=CONF_EMPTY, fwd="0", **kw):
        st = _NftState(before, after or ruleset([chain("input", "drop", SAFE_IN), chain("forward", "drop"),
                                                  chain("output")]))
        run = FakeRunner({"policy drop": st.drop, "nft list ruleset": st.ruleset,
                          "sshd -T": res(0, "port 22\n")})
        e = Env(fs={o.NFT_CONF: conf, "/proc/sys/net/ipv4/ip_forward": fwd}, runner=run,
                rid="TWGCB-01-014-0216", **kw)
        return e

    def test_check(self):
        with Env(bins=()) as e:
            self.assertEqual(R(216).check(e.ctx).status, ERROR)
        with self.env(before=self.ALL_DROP, conf=self.ALL_DROP) as e:
            self.assertEqual(R(216).check(e.ctx).status, PASS)
        with self.env(before=ruleset([chain("input")])) as e:
            c = R(216).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("執行中：input=accept forward=無基本鏈 output=無基本鏈", c.current)

    def test_nothing_to_do(self):
        with self.env(before=self.ALL_DROP, conf=self.ALL_DROP) as e:
            self.assertRaises(ManualRequired, R(216).fix, e.ctx, e.fx)
        drop_in = ruleset([chain("input", "drop", SAFE_IN), chain("forward"), chain("output")])
        with self.env(before=drop_in, conf=drop_in, fwd="1") as e:
            self.assertRaises(ManualRequired, R(216).fix, e.ctx, e.fx)
            self.assertTrue(any("IP 轉送" in n for n in e.fx.notes))
            self.assertEqual(e.fx.events, [])

    def test_drop_safely(self):
        with self.env() as e:
            R(216).fix(e.ctx, e.fx)
            # 設定檔：input 鏈已放行 lo、已建立連線、SSH，policy drop
            _, cch = o.nft_parse(e.fs[o.NFT_CONF])
            cin = o.nft_base(cch, "input")[0]
            self.assertEqual(cin["policy"], "drop")
            self.assertEqual(cin["rules"][:3], ['iif "lo" accept', "ct state established,related accept",
                                                "tcp dport { 22 } accept"])
            self.assertEqual(o.nft_base(cch, "forward")[0]["policy"], "drop")
            self.assertEqual(o.nft_base(cch, "output")[0]["policy"], "accept")
            # 順序：備份回滾 → 改檔 → 語法檢查 → 保險 → 放行規則 → policy drop → 取消保險
            undo = e.idx("undo", "nft -f")
            write = e.idx("write", o.NFT_CONF)
            check = e.idx("run", "nft -c -f")
            guard = e.idx("run", "systemd-run")
            allow = e.idx("run", "nft insert rule inet filter input")
            drop = e.idx("run", "policy drop")
            cancel = e.idx("run", "systemctl stop gcb-fw-guard-0216")
            self.assertEqual([undo, write, check, guard, allow, drop, cancel],
                             sorted([undo, write, check, guard, allow, drop, cancel]))
            ins = e.runs("nft insert rule")
            self.assertEqual(len(ins), 3)
            self.assertIn("tcp dport", ins[0])
            self.assertTrue(ins[-1].endswith("iif lo accept"))
            self.assertTrue(all(e.fx.events.index(("run", i)) < drop for i in ins))
            self.assertEqual(len(e.runs("policy drop")), 2)
            self.assertTrue(e.fx.partial)
            self.assertIn("確認 SSH 放行規則", [x[0] for x in e.fx.steps])

    def test_post_check_restores(self):
        bad_after = ruleset([chain("input", "drop", SAFE_IN[:1])])
        with self.env(after=bad_after) as e:
            with self.assertRaises(FixError):
                R(216).fix(e.ctx, e.fx)
            acc = e.idx("run", "policy accept")
            self.assertLess(e.idx("run", "policy drop"), acc)
            self.assertLess(acc, e.idx("run", "systemctl stop gcb-fw-guard"))

    def test_one_line_refusals(self):
        one_in = "table inet filter {\n chain input { type filter hook input priority 0; policy accept; }\n}\n"
        with self.env(before=ruleset([chain("input")]), conf=one_in, fwd="1") as e:
            with self.assertRaises(ManualRequired) as cm:
                R(216).fix(e.ctx, e.fx)
            self.assertIn("input 鏈為單行", str(cm.exception))
            self.assertEqual(e.runs("policy drop"), [])
        # 只需處理 forward，但 forward 為單行寫法
        conf = ("table inet filter {\n" + chain("input", "drop", SAFE_IN) +
                " chain forward { type filter hook forward priority 0; }\n}\n")
        rt = ruleset([chain("input", "drop", SAFE_IN), chain("forward")])
        with self.env(before=rt, conf=conf) as e:
            with self.assertRaises(ManualRequired) as cm:
                R(216).fix(e.ctx, e.fx)
            self.assertIn("forward 鏈為單行", str(cm.exception))

    def test_dry_run(self):
        with self.env(dry_run=True) as e:
            R(216).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[o.NFT_CONF], CONF_EMPTY)
            self.assertEqual(e.fx.kinds("undo"), [])
            self.assertEqual(e.runs("systemd-run"), [])
            self.assertEqual(e.runner.ran("policy drop"), [])


# TWGCB-01-014-0217 載入 nftables 規則
class NftBootTest(unittest.TestCase):
    ON = {"nftables.service": ("enabled", "active")}

    def test_problems(self):
        with Env() as e:
            c = R(217).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("開機未啟用", c.current)
            self.assertIn("找不到 /etc/nftables.conf", c.current)
        with Env(fs={o.NFT_CONF: "#!/usr/sbin/nft -f\n"}, svc=self.ON, bins=()) as e:
            c = R(217).check(e.ctx).current
            for s in ("設定檔未定義表", "缺少基本鏈：input、forward、output", "找不到 nft"):
                self.assertIn(s, c)
        with Env(fs={o.NFT_CONF: CONF_EMPTY}, svc=self.ON,
                 runner=FakeRunner({"nft -c -f": res(1, "", "Error: bad")})) as e:
            self.assertIn("語法檢查失敗：Error: bad", R(217).check(e.ctx).current)

    def test_pass(self):
        with Env(fs={o.NFT_CONF: CONF_EMPTY}, svc=self.ON) as e:
            self.assertEqual(R(217).check(e.ctx).status, PASS)

    def test_fix(self):
        with Env() as e:
            self.assertRaises(ManualRequired, R(217).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])
        with Env(fs={o.NFT_CONF: CONF_EMPTY}) as e:
            R(217).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [("undo", "systemctl disable nftables.service"),
                                           ("run", "systemctl enable nftables.service")])


# ====================================================================
# iptables
# ====================================================================

class IptHelpersTest(unittest.TestCase):
    def test_pure(self):
        self.assertIsNone(o.ipt_policy(["-A INPUT -j ACCEPT"], "INPUT"))
        self.assertFalse(o._ipt_port("-A INPUT -p tcp -j ACCEPT", "22"))
        ok, miss = o.ipt_input_safe(["-P INPUT DROP", "-A INPUT -p tcp --dport 22 -j ACCEPT"], ["22"])
        self.assertEqual((ok, miss), (False, "迴路介面、已建立連線"))
        self.assertEqual(o._norm_ipt("# c\n:INPUT DROP [1:2]\n\n-A INPUT -j ACCEPT\n"),
                         [":INPUT DROP", "-A INPUT -j ACCEPT"])

    def test_lines(self):
        with Env(bins=()):
            self.assertRaises(RuntimeError, o._ipt_lines, False)
        with Env(runner=FakeRunner({"ip6tables -S": res(1, "", "x")})):
            self.assertRaises(RuntimeError, o._ipt_lines, True)
        with Env(runner=FakeRunner({"iptables -S": res(0, "-P INPUT DROP\n-P OUTPUT ACCEPT\n")})):
            self.assertEqual(o._ipt_lines(False), ["-P INPUT DROP", "-P OUTPUT ACCEPT"])

    def test_persist_and_has(self):
        with Env(dry_run=True) as e:
            o._ipt_persist(e.fx, True)
            self.assertEqual(e.fx.events, [])
            self.assertIn("ip6tables-save > /etc/iptables/rules.v6", e.fx.steps[0][1])
        with Env(runner=FakeRunner({"iptables-save": res(1)})) as e:
            self.assertRaises(FixError, o._ipt_persist, e.fx, False)
        with Env(runner=FakeRunner({"iptables-save": res(0, "*filter\nCOMMIT\n")})) as e:
            o._ipt_persist(e.fx, False)
            self.assertEqual(e.fs[o.RULES_V4], "*filter\nCOMMIT\n")
            self.assertEqual(e.fx.modes[o.RULES_V4], 0o640)
        with Env(runner=FakeRunner({"iptables -C": res(1)})) as e:
            self.assertFalse(o._ipt_has(False, ["INPUT", "-i", "lo", "-j", "ACCEPT"]))
            self.assertEqual(e.runner.calls, ["iptables -C INPUT -i lo -j ACCEPT"])


# TWGCB-01-014-0218 iptables 防火牆套件
class IptPackagesTest(unittest.TestCase):
    def test(self):
        with Env(pkgs={"iptables"}) as e:
            c = R(218).check(e.ctx)
            self.assertEqual((c.status, c.current), (FAIL, "未安裝：iptables-persistent"))
            self.assertRaises(ManualRequired, R(218).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])
        with Env(pkgs={"iptables", "iptables-persistent"}) as e:
            self.assertEqual(R(218).check(e.ctx).status, PASS)
            R(218).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.events, [("pkg_install", "iptables")])


# TWGCB-01-014-0221 iptables 服務、0222 ip6tables 服務
class NetfilterServiceTest(unittest.TestCase):
    U = "netfilter-persistent.service"
    SAVE4 = "# x\n*filter\n:INPUT ACCEPT [10:20]\nCOMMIT\n"

    def env(self, fs=None, svc=("disabled", "inactive"), save=None, **kw):
        run = FakeRunner({"ip6tables-save": res(0, "*filter\nCOMMIT\n"), "iptables-save": save or res(0, self.SAVE4)})
        return Env(fs=fs, pkgs={"iptables-persistent"}, svc={self.U: svc}, runner=run,
                   rid="TWGCB-01-014-0221", **kw)

    def test_check(self):
        with Env() as e:
            self.assertEqual(R(221).check(e.ctx).status, FAIL)
        with self.env(fs={o.RULES_V4: "x"}, svc=("enabled", "active")) as e:
            self.assertEqual(R(221).check(e.ctx).status, PASS)
            c = R(222).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("rules.v6 不存在", c.current)

    def test_refusals(self):
        with Env() as e:
            self.assertRaises(ManualRequired, R(221).fix, e.ctx, e.fx)
        with self.env(save=res(1, "", "x")) as e:
            self.assertRaises(FixError, R(221).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])
        # 檔案與執行中規則不同且服務未運作 → 啟動會套用檔案規則
        with self.env(fs={o.RULES_V4: "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"}) as e:
            self.assertRaises(ManualRequired, R(221).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])

    def test_fix_new_file(self):
        with self.env() as e:
            R(221).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[o.RULES_V4], self.SAVE4)
            self.assertEqual(e.fx.modes[o.RULES_V4], 0o640)
            ev = e.fx.events
            self.assertEqual(ev[0], ("write", o.RULES_V4))
            undos = [i for i, x in enumerate(ev) if x[0] == "undo"]
            self.assertEqual(len(undos), 2)
            self.assertIn("iptables-restore", ev[undos[0]][1])
            self.assertIn("ip6tables-restore", ev[undos[1]][1])
            self.assertLess(undos[1], ev.index(("enable", self.U)))

    def test_fix_existing(self):
        # 檔案內容與執行中相同（僅計數器不同）→ 直接啟用
        with self.env(fs={o.RULES_V4: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"}) as e:
            R(221).fix(e.ctx, e.fx)
            self.assertNotIn(("write", o.RULES_V4), e.fx.events)
            self.assertIn(("enable", self.U), e.fx.events)
        # 服務運作中 → 不比對
        with self.env(fs={o.RULES_V4: "different"}, svc=("disabled", "active")) as e:
            R(221).fix(e.ctx, e.fx)
            self.assertIn(("enable", self.U), e.fx.events)


class _IptState(object):
    """模擬 iptables -S：執行 -P INPUT DROP 後改回傳 after。"""

    def __init__(self, before, after):
        self.before, self.after, self.dropped = before, after, False

    def lines(self, _cmd):
        return res(0, "\n".join(self.after if self.dropped else self.before) + "\n")

    def policy(self, _cmd):
        self.dropped = True
        return res(0)


# TWGCB-01-014-0223 在 iptables 建立預設拒絕規則、0225 在 ip6tables 建立預設拒絕規則
class IptDefaultDropTest(unittest.TestCase):
    ACC = ["-P INPUT ACCEPT", "-P FORWARD ACCEPT", "-P OUTPUT ACCEPT"]
    SAFE = ["-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT ACCEPT", "-A INPUT -i lo -j ACCEPT",
            "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT"]
    DROPF = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"

    def env(self, before=None, after=None, v6=False, fs=None, has=res(1), **kw):
        ipt = "ip6tables" if v6 else "iptables"
        st = _IptState(before or self.ACC, after or self.SAFE)
        run = FakeRunner({"%s -S" % ipt: st.lines, "%s -P INPUT DROP" % ipt: st.policy,
                          "%s -C" % ipt: has, "sshd -T": res(0, "port 22\n"),
                          "%s-save" % ipt: res(0, "*filter\n:INPUT DROP [0:0]\nCOMMIT\n")})
        return Env(fs=fs, runner=run, rid="TWGCB-01-014-0223", **kw)

    def test_check(self):
        with Env(bins=()) as e:
            self.assertEqual(R(223).check(e.ctx).status, ERROR)
        drop = ["-P INPUT DROP", "-P FORWARD DROP", "-P OUTPUT DROP"]
        with self.env(before=drop, fs={o.RULES_V4: self.DROPF}) as e:
            self.assertEqual(R(223).check(e.ctx).status, PASS)
        with self.env() as e:
            c = R(223).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("不存在或無 *filter", c.current)

    def test_when_v6(self):
        with Env(firewall_backend="iptables") as e:
            self.assertIn("IPv6", R(225).when(e.ctx))
            self.assertIn("IPv6", R(226).when(e.ctx))

    def test_nothing_to_do(self):
        with self.env(before=["-P INPUT DROP", "-P FORWARD DROP"],
                      fs={o.RULES_V4: self.DROPF}) as e:
            self.assertRaises(ManualRequired, R(223).fix, e.ctx, e.fx)
        with self.env(before=["-P INPUT DROP", "-P FORWARD ACCEPT"], fs={
                o.RULES_V4: self.DROPF, "/proc/sys/net/ipv4/ip_forward": "1"}) as e:
            self.assertRaises(ManualRequired, R(223).fix, e.ctx, e.fx)
            self.assertTrue(any("IP 轉送" in n for n in e.fx.notes))
            self.assertEqual(e.fx.events, [])

    def test_drop_safely(self):
        with self.env() as e:
            R(223).fix(e.ctx, e.fx)
            undo = e.idx("undo", "iptables-restore")
            guard = e.idx("run", "systemd-run")
            ins = e.runs("iptables -I INPUT 1")
            # 由下往上插入：最後順序為 lo、已建立連線、SSH
            self.assertEqual(ins, ["iptables -I INPUT 1 -p tcp -m tcp --dport 22 -j ACCEPT",
                                   "iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                                   "iptables -I INPUT 1 -i lo -j ACCEPT"])
            pin = e.idx("run", "iptables -P INPUT DROP")
            self.assertLess(undo, guard)
            self.assertLess(guard, e.idx("run", "iptables -I INPUT 1"))
            self.assertTrue(all(e.fx.events.index(("run", i)) < pin for i in ins))
            self.assertLess(pin, e.idx("run", "iptables -P FORWARD DROP"))
            self.assertLess(e.idx("write", o.RULES_V4), e.idx("run", "systemctl stop gcb-fw-guard-0223"))
            self.assertIn("/usr/bin/iptables-restore /run/gcb/fw-0223-v4-", e.fx.events[guard][1])
            self.assertTrue(e.fx.partial)

    def test_existing_rules_skipped_v6(self):
        with self.env(v6=True, has=res(0), before=self.ACC, fs={"/proc/net/if_inet6": "x"}) as e:
            R(225).fix(e.ctx, e.fx)
            self.assertEqual(e.runs("-I INPUT"), [])
            self.assertTrue(e.runner.ran("ip6tables -C INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136"))
            self.assertEqual(e.runs("ip6tables -P"), ["ip6tables -P INPUT DROP", "ip6tables -P FORWARD DROP"])
            self.assertIn(o.RULES_V6, e.fs)

    def test_post_check_restores(self):
        with self.env(after=["-P INPUT DROP"]) as e:
            with self.assertRaises(FixError):
                R(223).fix(e.ctx, e.fx)
            acc = e.idx("run", "iptables -P INPUT ACCEPT")
            self.assertLess(e.idx("run", "iptables -P INPUT DROP"), acc)
            self.assertLess(acc, e.idx("run", "systemctl stop gcb-fw-guard"))
            self.assertNotIn(o.RULES_V4, e.fs)

    def test_dry_run(self):
        with self.env(dry_run=True) as e:
            R(223).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.kinds("undo"), [])
            self.assertEqual(e.runs("systemd-run"), [])
            self.assertEqual(e.fs, {})
            self.assertEqual(e.runner.ran("-P INPUT DROP"), [])


# TWGCB-01-014-0224 在 iptables 設定回送流量規則、0226 在 ip6tables 設定回送流量規則
class IptLoopbackTest(unittest.TestCase):
    OK = ["-P INPUT ACCEPT", "-A INPUT -i lo -j ACCEPT", "-A INPUT -s 127.0.0.0/8 -j DROP",
          "-A OUTPUT -o lo -j ACCEPT"]

    def env(self, lines, fs=None, v6=False, lo_effect=True, **kw):
        state = list(lines)
        ipt = "ip6tables" if v6 else "iptables"

        def ins_lo(_cmd):
            if lo_effect:
                state.insert(0, "-A INPUT -i lo -j ACCEPT")
            return res(0)
        run = FakeRunner({"%s -S" % ipt: lambda c: res(0, "\n".join(state) + "\n"),
                          "-I INPUT 1 -i lo": ins_lo, "%s-save" % ipt: res(0, "*filter\nCOMMIT\n")})
        return Env(fs=fs, runner=run, rid="TWGCB-01-014-0224", **kw)

    def test_check(self):
        with Env(bins=()) as e:
            self.assertEqual(R(224).check(e.ctx).status, ERROR)
        with self.env(self.OK, fs={o.RULES_V4: "\n".join(self.OK)}) as e:
            self.assertEqual(R(224).check(e.ctx).status, PASS)
        with self.env(self.OK) as e:
            c = R(224).check(e.ctx)
            self.assertEqual(c.status, FAIL)
            self.assertIn("執行中缺少：無", c.current)

    def test_fix_missing_all(self):
        with self.env(["-P INPUT ACCEPT"]) as e:
            R(224).fix(e.ctx, e.fx)
            self.assertLess(e.idx("undo", "iptables-restore"), e.idx("run", "iptables -I"))
            self.assertEqual(e.runs("iptables -I"), [
                "iptables -I INPUT 1 -i lo -j ACCEPT", "iptables -I OUTPUT 1 -o lo -j ACCEPT",
                "iptables -I INPUT 2 -s 127.0.0.0/8 -j DROP"])
            self.assertEqual(e.fs[o.RULES_V4], "*filter\nCOMMIT\n")

    def test_fix_wrong_order(self):
        bad = ["-A INPUT -s 127.0.0.0/8 -j DROP", "-A INPUT -i lo -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT"]
        with self.env(bad) as e:
            R(224).fix(e.ctx, e.fx)
            d = e.idx("run", "iptables -D INPUT -s 127.0.0.0/8 -j DROP")
            i = e.idx("run", "iptables -I INPUT")
            self.assertLess(e.idx("undo"), d)
            self.assertLess(d, i)
            # 刪除假執行未真正移除，lo 在第 2 行 → 插在第 3
            self.assertEqual(e.runs("iptables -I"), ["iptables -I INPUT 3 -s 127.0.0.0/8 -j DROP"])

    def test_fix_v6_no_lo_after(self):
        with self.env(["-A OUTPUT -o lo -j ACCEPT"], v6=True, lo_effect=False) as e:
            R(226).fix(e.ctx, e.fx)
            self.assertIn("ip6tables -I INPUT 1 -s ::1/128 -j DROP", e.runs("ip6tables -I"))
            self.assertIn(o.RULES_V6, e.fs)

    def test_fix_complete_and_dry(self):
        with self.env(self.OK) as e:
            R(224).fix(e.ctx, e.fx)
            self.assertEqual(e.fx.kinds("undo"), [])
            self.assertEqual(e.runs(), [])
        with self.env(["-P INPUT ACCEPT"], dry_run=True) as e:
            R(224).fix(e.ctx, e.fx)
            self.assertIn("iptables -I INPUT 2 -s 127.0.0.0/8 -j DROP", e.runs())
            self.assertEqual(e.fs, {})


# ====================================================================
# GNOME
# ====================================================================

LOCAL_D = "/etc/dconf/db/local.d"
SS = LOCAL_D + "/00-screensaver"
USER_PROF = "/etc/dconf/profile/user"
SS_OK = "[org/gnome/desktop/session]\nidle-delay=uint32 900\n\n[org/gnome/desktop/screensaver]\nlock-delay=uint32 0\n"


class GnomeHelpersTest(unittest.TestCase):
    def test_when(self):
        with Env(pkgs={"gnome-shell"}) as e:
            self.assertIsNone(o.gnome_when(e.ctx))
            self.assertEqual(o.gdm_when(e.ctx), "未安裝 gdm3 圖形登入畫面，本項目是登入畫面設定，不需設定")
        with Env() as e:
            self.assertIn("GNOME", o.gnome_when(e.ctx))

    def test_dconf_reads(self):
        fs = {LOCAL_D + "/00-a": "[s]\nk=1\n", LOCAL_D + "/10-b": "[s]\nk=2\n", LOCAL_D + "/20-c": "[t]\nk=3\n",
              LOCAL_D + "/locks/x": "# c\n/a/b\n\n/c/d\n", "/etc/dconf/db/local": "bin"}
        with Env(fs=fs, mtime={"/etc/dconf/db/local": 100, LOCAL_D + "/10-b": 50}):
            self.assertEqual(o.dconf_values("local", "s", "k"), [(LOCAL_D + "/00-a", "1"), (LOCAL_D + "/10-b", "2")])
            self.assertEqual(o.dconf_locks("local"), {"/a/b", "/c/d"})
            self.assertTrue(o.dconf_compiled("local"))
            self.assertFalse(o.dconf_compiled("gdm"))
        with Env(fs=fs, mtime={"/etc/dconf/db/local": 10, LOCAL_D + "/locks/x": 50}):
            self.assertFalse(o.dconf_compiled("local"))

    def test_ini_and_profile_merge(self):
        # 重複的 key：取代第一個、註解其餘
        self.assertEqual(o.ini_set("[s]\nk=1\nk=2\n", "s", "k", "9"), "[s]\nk=9\n" + te.MARK + "k=2\n")
        # 區段內已有其他 key：加在最後一個非空行之後
        self.assertEqual(o.ini_set("[s]\na=1\n\n[t]\n", "s", "k", "9"), "[s]\na=1\nk=9\n\n[t]\n")
        self.assertEqual(o.profile_merge("user-db:user\nsystem-db:local\n", o.USER_PROFILE),
                         "user-db:user\nsystem-db:local\n")

    def test_profile(self):
        with Env(fs={"/usr/share/dconf/profile/user": "user-db:user\n"}):
            self.assertEqual(o._profile("user"), ("/usr/share/dconf/profile/user", "user-db:user\n"))
        with Env(fs={USER_PROF: "a\n", "/usr/share/dconf/profile/user": "b\n"}):
            self.assertEqual(o._profile("user"), (USER_PROF, "a\n"))
        with Env():
            self.assertEqual(o._profile("gdm"), (None, ""))


# TWGCB-01-014-0228 GNOME 使用者會談逾時時間、0229 鎖定、0231 卸除式儲存裝置鎖定、0233 Autorun 鎖定
class DconfRuleTest(unittest.TestCase):
    def test_check_pass(self):
        fs = {SS: SS_OK, USER_PROF: "user-db:user\nsystem-db:local\n", "/etc/dconf/db/local": "bin"}
        with Env(fs=fs, mtime={"/etc/dconf/db/local": 100}) as e:
            c = R(228).check(e.ctx)
            self.assertEqual((c.status, c.current), (PASS, "idle-delay=uint32 900、lock-delay=uint32 0"))
        fs[LOCAL_D + "/locks/screensaver"] = ("/org/gnome/desktop/session/idle-delay\n"
                                              "/org/gnome/desktop/screensaver/lock-delay\n")
        with Env(fs=fs, mtime={"/etc/dconf/db/local": 100}) as e:
            self.assertEqual(R(229).check(e.ctx).current, "已鎖定 2 項")

    def test_check_fail(self):
        with Env(fs={SS: SS_OK, USER_PROF: "user-db:user\nsystem-db:local\n"}) as e:
            self.assertEqual(R(228).check(e.ctx).current, "設定尚未以 dconf update 編譯生效")
        with Env(fs={SS: "[org/gnome/desktop/session]\nidle-delay=uint32 0\n"}) as e:
            c = R(228).check(e.ctx).current
            self.assertIn("idle-delay=uint32 0（00-screensaver）", c)
            self.assertIn("lock-delay 未設定", c)
            self.assertIn("dconf profile user 缺少 user-db:user、system-db:local", c)
        with Env() as e:
            self.assertIn("未鎖定 /org/gnome/desktop/session/idle-delay", R(229).check(e.ctx).current)

    def test_fix_no_dconf(self):
        with Env(bins=()) as e:
            self.assertRaises(ManualRequired, R(228).fix, e.ctx, e.fx)
            self.assertEqual(e.fx.events, [])

    def test_fix_keys(self):
        bad = LOCAL_D + "/10-site"
        fs = {bad: "[org/gnome/desktop/session]\nidle-delay=uint32 0\n", USER_PROF: "system-db:ibus\n"}
        with Env(fs=fs, rid="TWGCB-01-014-0228") as e:
            R(228).fix(e.ctx, e.fx)
            ev = e.fx.events
            self.assertEqual(ev[0], ("undo", "dconf update"))
            self.assertEqual(e.fs[USER_PROF], "user-db:user\nsystem-db:ibus\nsystem-db:local\n")
            self.assertEqual(e.ctx.journal.backed, ["/etc/dconf/db/local"])
            self.assertEqual(e.fs[bad], "[org/gnome/desktop/session]\n" + te.MARK + "idle-delay=uint32 0\n")
            self.assertEqual(e.fs[SS], SS_OK)
            self.assertLess(e.idx("run", "touch " + LOCAL_D), e.idx("run", "dconf update"))
            self.assertEqual(ev[-1], ("run", "dconf update"))

    def test_fix_locks_shared_file(self):
        mh = LOCAL_D + "/locks/media-handling"
        fs = {mh: "/org/gnome/desktop/media-handling/automount", USER_PROF: "user-db:user\nsystem-db:local\n",
              "/etc/dconf/db/local": "bin"}
        mt = {"/etc/dconf/db/local": 100}
        with Env(fs=fs, mtime=mt) as e:
            R(231).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[mh], "/org/gnome/desktop/media-handling/automount\n"
                                       "/org/gnome/desktop/media-handling/automount-open\n")
            self.assertEqual(e.runs("touch"), [])
            fs2 = dict(e.fs)
        with Env(fs=fs2, mtime=mt) as e:
            R(233).fix(e.ctx, e.fx)
            R(231).fix(e.ctx, e.fx)
            lines = e.fs[mh].splitlines()
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[-1], "/org/gnome/desktop/media-handling/autorun-never")

    def test_fix_dry(self):
        with Env(dry_run=True) as e:
            R(228).fix(e.ctx, e.fx)
            self.assertEqual(e.fs, {})
            self.assertEqual(e.ctx.journal.backed, [])
            self.assertEqual(e.fx.kinds("undo"), [])
            self.assertEqual(e.runs("touch"), [])
            self.assertEqual(e.runs(), ["dconf update"])


# TWGCB-01-014-0234 XDMCP 協定
class GdmXdmcpTest(unittest.TestCase):
    P = "/etc/gdm3/custom.conf"

    def test_check(self):
        with Env() as e:
            self.assertIn("未設定", R(234).check(e.ctx).current)
        with Env(fs={self.P: "[xdmcp]\nEnable=true\n"}) as e:
            self.assertEqual(R(234).check(e.ctx).current, "Enable=true")
        fs = {self.P: "[xdmcp]\nEnable=False\n", "/proc/uptime": "100 1"}
        with Env(fs=fs, mtime={self.P: 1e12}) as e:
            c = R(234).check(e.ctx)
            self.assertEqual(c.status, PASS)
            self.assertIn("需重新啟動", c.current)
        with Env(fs=fs, mtime={self.P: 1}) as e:
            self.assertEqual(R(234).check(e.ctx).current, "Enable=false")

    def test_fix(self):
        with Env(fs={self.P: "[daemon]\n\n[xdmcp]\n\n[chooser]\n"}) as e:
            R(234).fix(e.ctx, e.fx)
            self.assertEqual(e.fs[self.P], "[daemon]\n\n[xdmcp]\nEnable=false\n\n[chooser]\n")
            self.assertTrue(e.fx.notes)


if __name__ == "__main__":
    unittest.main()
