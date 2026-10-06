# -*- coding: utf-8 -*-
"""主流程（gcb/engine.py）與命令列入口（gcb.py）的補充測試：例外處理、互動確認、無修改時略過後測等分支。"""
import argparse
import importlib.util
import io
import os
import runpy
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_engine_flow import FileRule, health_items, make_args  # noqa: E402
from gcb import engine, health, osinfo  # noqa: E402
from gcb.config import Config  # noqa: E402
from gcb.fixer import ManualRequired  # noqa: E402
from gcb.rules.base import FAIL, PASS, Check, Rule  # noqa: E402
from gcb.util import read_text  # noqa: E402

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


class Custom(Rule):
    """以參數指定 check / fix / precondition 行為的假規則。"""
    category = "測試"

    def __init__(self, n, check=None, fix=None, pre=None, when=None, risk="A", needs_reboot=False):
        self.ids = {"ubuntu2204": "TWGCB-01-014-%04d" % n}
        self.title = "自訂規則 %d" % n
        self._check, self._fix, self._pre = check, fix, pre
        self.when = when
        self.risk = risk
        self.needs_reboot = needs_reboot

    def check(self, ctx):
        return self._check(ctx)

    def fix(self, ctx, fx):
        self._fix(ctx, fx)

    def precondition(self, ctx):
        return self._pre(ctx) if self._pre else None


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cfg = Config(None, self.tmp)
        self.cfg.report_dir = os.path.join(self.tmp, "reports")
        self.osi = osinfo.OSInfo("ubuntu2204", "debian", "Ubuntu 22.04 測試", "ubuntu", "22.04")
        self.rules = []
        self.answers = []
        self.health_seq = []
        for p in (mock.patch.object(engine, "rules_for", lambda osi: [(r.rule_id(osi), r) for r in self.rules]),
                  mock.patch.object(health, "run_all", lambda ctx: self.health_seq.pop(0) if self.health_seq
                                    else health_items()),
                  mock.patch.object(engine, "primary_ip", lambda: "127.0.0.1"),
                  mock.patch("sys.stdout", new_callable=io.StringIO)):
            p.start()
            self.addCleanup(p.stop)

    def ctx(self, **kw):
        return engine.new_context(self.cfg, self.osi, make_args(**kw))

    def file(self, name, text="bad\n"):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(text)
        return p

    def good_check(self, path):
        return lambda ctx: Check(PASS if (read_text(path) or "").strip() == "good" else FAIL, "x")


class TestDetectPlan(Base):
    def test_load_context_missing(self):
        with self.assertRaises(SystemExit):
            engine.load_context(self.cfg, self.osi, "nope", make_args())

    def test_detect_errors_and_na(self):
        def boom(ctx):
            raise OSError("Permission denied")
        self.rules = [Custom(1, check=boom), Custom(2, check=None, when=lambda ctx: "未安裝 x"),
                      Custom(3, check=lambda ctx: Check(PASS, "ok"))]
        out = engine.do_detect(self.ctx(), "檢測")
        self.assertEqual([c["status"] for c in out], ["檢測失敗", "不適用", "合格"])
        self.assertEqual(out[0]["current"], "檢測程式錯誤：Permission denied")
        self.assertTrue(out[0]["advice"])
        self.assertEqual(out[1]["current"], "未安裝 x")
        self.assertEqual(engine.summarize(out)["rate"], "50.0%")
        self.assertEqual(engine.summarize([])["rate"], "-")

    def test_plan_precondition(self):
        def boom(ctx):
            raise ValueError("壞掉")
        self.rules = [Custom(1, pre=boom), Custom(2, pre=lambda ctx: "有容器"), Custom(3)]
        checks = [{"id": r.rule_id(self.osi), "status": FAIL} for r in self.rules]
        plan = engine.plan_fixes(self.ctx(), checks, set())
        self.assertEqual([p[2] for p in plan], ["需人工處理（前置條件檢查錯誤：壞掉）", "已跳過（前置條件）：有容器", "修復"])


    def test_plan_status_branches(self):
        self.rules = [Custom(1), Custom(2), Custom(3), Custom(4)]
        rid = [r.rule_id(self.osi) for r in self.rules]
        checks = [{"id": rid[0], "status": PASS}, {"id": rid[1], "status": "不適用"},
                  {"id": rid[2], "status": "檢測失敗"}, {"id": rid[3], "status": FAIL}]
        plan = engine.plan_fixes(self.ctx(), checks, {rid[3]})
        self.assertEqual([p[2] for p in plan], ["無需修復", "不適用", "需人工處理（檢測失敗）", "已排除（設定檔/參數）"])

    def test_do_health_prints_advice(self):
        items = health_items(H04=health.BAD)
        items[3]["advice"] = ["原因：測試；建議：測試"]
        self.health_seq = [items]
        engine.do_health(self.ctx(), "前測")
        out = sys.stdout.getvalue()
        self.assertIn("! H04", out)
        self.assertIn("↳ 原因：測試；建議：測試", out)


class TestApplyRule(Base):
    def apply(self, rule, log=None, **kw):
        ctx = self.ctx(**kw)
        if log is not None:
            ctx.log = log
        out = engine.apply_rule(ctx, rule.rule_id(self.osi), rule, {"current": "bad"})
        return ctx, out

    def test_unexpected_exception_rolls_back_own_changes(self):
        p = self.file("a.conf")

        def fix(ctx, fx):
            fx.write_file(p, "good\n")
            raise KeyError("oops")
        log = mock.Mock()
        ctx, (outcome, notes, advice) = self.apply(Custom(1, check=self.good_check(p), fix=fix), log=log)
        self.assertEqual(outcome, "修復失敗（已還原本項變更）")
        self.assertIn("程式錯誤：'oops'", notes)
        self.assertEqual(read_text(p), "bad\n")
        self.assertIn("KeyError", log.error.call_args[0][0])     # 完整 traceback 寫入 log

    def test_manual_required_after_change(self):
        p = self.file("a.conf")

        def fix(ctx, fx):
            fx.write_file(p, "good\n")
            raise ManualRequired("請人工處理")
        ctx, (outcome, notes, advice) = self.apply(Custom(1, check=self.good_check(p), fix=fix))
        self.assertEqual(outcome, "需人工處理（已還原本項變更）")
        self.assertEqual(read_text(p), "bad\n")

    def test_manual_required_without_change(self):
        def fix(ctx, fx):
            raise ManualRequired("請人工處理")
        ctx, (outcome, notes, advice) = self.apply(Custom(1, check=lambda c: Check(FAIL, ""), fix=fix))
        self.assertEqual(outcome, "需人工處理")

    def test_partial_and_still_failing(self):
        def partial(ctx, fx):
            fx.partial = True
        ctx, (outcome, _, _) = self.apply(Custom(1, check=lambda c: Check(FAIL, "x"), fix=partial))
        self.assertEqual(outcome, "部分修復")
        ctx, (outcome, notes, _) = self.apply(Custom(1, check=lambda c: Check(FAIL, "仍是 x"), fix=lambda c, f: None))
        self.assertEqual(outcome, "修復失敗")
        self.assertEqual(notes, ["修復後檢測仍不合格：仍是 x"])

    def test_reboot_needed(self):
        ok = lambda c: Check(PASS, "")
        ctx, (outcome, _, _) = self.apply(Custom(1, check=ok, fix=lambda c, f: None, needs_reboot=True))
        self.assertEqual(outcome, "已修復（需重開機生效）")
        ctx, (outcome, _, _) = self.apply(Custom(1, check=ok, fix=lambda c, f: f.note("需重開機後生效")))
        self.assertEqual(outcome, "已修復（需重開機生效）")
        ctx, (outcome, _, _) = self.apply(Custom(1, check=ok, fix=lambda c, f: None), dry_run=True)
        self.assertEqual(outcome, "預覽")


class TestAsk(unittest.TestCase):
    def test_ask(self):
        with mock.patch.object(engine.sys, "stdin", mock.Mock(isatty=lambda: False)):
            self.assertIsNone(engine.ask("?"))
        with mock.patch.object(engine.sys, "stdin", mock.Mock(isatty=lambda: True)):
            with mock.patch("builtins.input", return_value=" Y "):
                self.assertEqual(engine.ask("?"), "y")
            with mock.patch("builtins.input", side_effect=EOFError):
                self.assertIsNone(engine.ask("?"))


class TestRunBranches(Base):
    def test_nothing_to_fix_skips_post_health(self):
        p = self.file("a.conf", "good\n")
        self.rules = [FileRule(1, p)]
        ctx = self.ctx()
        self.health_seq = [health_items(), health_items(H04=health.BAD)]   # 第二次不應被使用
        rc = engine.cmd_run(ctx, make_args(yes=False))
        self.assertEqual(rc, 0)
        self.assertNotIn("post_health", ctx.state)
        self.assertEqual(ctx.state["checks_after"], ctx.state["checks_before"])
        self.assertEqual(len(self.health_seq), 1)
        self.assertIn("沒有需要自動修復的項目", sys.stdout.getvalue())

    def test_fix_failed_restored_skips_post_health(self):
        # 修復失敗並還原後，日誌仍有紀錄（已回滾），會進入後測
        p = self.file("a.conf")
        self.rules = [FileRule(1, p, fail_after_write=True)]
        ctx = self.ctx()
        rc = engine.cmd_run(ctx, make_args())
        self.assertEqual(rc, 0)
        self.assertIn("post_health", ctx.state)

    def test_failure_advice_and_reboot_message(self):
        p1, p2 = self.file("a.conf"), self.file("b.conf")

        def fail(ctx, fx):
            from gcb.fixer import FixError
            raise FixError("Could not resolve host: mirror")

        def reboot(ctx, fx):
            fx.write_file(p2, "good\n")
        self.rules = [Custom(1, check=self.good_check(p1), fix=fail),
                      Custom(2, check=self.good_check(p2), fix=reboot, needs_reboot=True)]
        ctx = self.ctx()
        rc = engine.cmd_run(ctx, make_args())
        self.assertEqual(rc, 0)
        out = sys.stdout.getvalue()
        self.assertIn("— Could not resolve host", out)
        self.assertIn("↳ ", out)
        self.assertIn("./gcb.sh verify %s" % ctx.run_id, out)
        self.assertTrue(ctx.state["fixes"][1]["needs_reboot"])

    def test_manual_confirm_retry_and_noninteractive(self):
        ctx = self.ctx()
        answers = ["maybe", "yes"]
        with mock.patch.object(engine, "ask", lambda prompt: answers.pop(0)):
            self.assertEqual(engine.manual_login_confirm(ctx), "正常")
        self.assertIn("請輸入 y 或 n。", sys.stdout.getvalue())
        with mock.patch.object(engine, "ask", lambda prompt: None):
            self.assertEqual(engine.manual_login_confirm(ctx), "未執行")
        self.assertEqual(ctx.state["steps"][-1]["detail"], "未執行")

    def test_rollback_refused_on_later_conflict(self):
        p = self.file("shared.conf")

        class Writer(FileRule):
            def check(self, ctx):
                return Check(PASS if read_text(self.path).startswith("good") else FAIL, "")

            def fix(self, ctx, fx):
                fx.write_file(self.path, "good %s\n" % self.rule_id(ctx.osi))
        self.rules = [Writer(1, p), Writer(2, p)]
        ctx = self.ctx()
        engine.cmd_run(ctx, make_args())
        ctx2 = engine.load_context(self.cfg, self.osi, ctx.run_id, make_args())
        self.assertEqual(engine.cmd_rollback(ctx2, "TWGCB-01-014-0001"), 1)
        self.assertIn("之後的規則 TWGCB-01-014-0002", sys.stdout.getvalue())
        self.assertEqual(read_text(p), "good TWGCB-01-014-0002\n")     # 沒有被回滾


# ====================================================================
# 命令列入口 gcb.py
# ====================================================================

class U8(io.StringIO):
    """編碼為 UTF-8 的記憶體輸出（_utf8_stdio 不會重新包裝）。"""
    encoding = "utf-8"


def load_cli():
    spec = importlib.util.spec_from_file_location("gcb_cli_under_test", os.path.join(ROOT, "gcb.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCli(unittest.TestCase):
    def setUp(self):
        self.cli = load_cli()
        self.out = U8()
        for p in (mock.patch.object(self.cli, "_utf8_stdio", lambda: None), mock.patch("sys.stdout", self.out),
                  mock.patch("sys.stderr", U8()), mock.patch("sys.stdin", U8())):
            p.start()
            self.addCleanup(p.stop)
        self.osi = osinfo.OSInfo("rhel9", "rhel", "Rocky Linux 9.5", "rocky", "9.5")

    def main(self, *argv, **kw):
        with mock.patch.object(sys, "argv", ["gcb.py"] + list(argv)), \
                mock.patch.object(self.cli.osinfo, "detect", return_value=kw.get("detect", (self.osi, ""))), \
                mock.patch.object(self.cli.os, "geteuid", return_value=kw.get("euid", 0)):
            return self.cli.main()

    def test_no_command(self):
        self.assertEqual(self.main(), 1)
        self.assertIn("usage", self.out.getvalue())

    def test_unsupported_os(self):
        self.assertEqual(self.main("check", detect=(None, "不支援的作業系統：X")), 1)
        self.assertIn("不支援的作業系統：X", self.out.getvalue())

    def test_requires_root(self):
        self.assertEqual(self.main("check", euid=1000), 1)
        self.assertIn("請以 root 執行（sudo ./gcb.sh check）", self.out.getvalue())

    def test_dispatch(self):
        ctx = mock.Mock(run_id="r1", state={})
        with mock.patch.object(self.cli.engine, "new_context", return_value=ctx) as nc, \
                mock.patch.object(self.cli.engine, "cmd_check", return_value=0) as chk, \
                mock.patch.object(self.cli.engine, "cmd_run", return_value=2) as run_, \
                mock.patch.object(self.cli.engine, "do_health", return_value=["h"]):
            self.assertEqual(self.main("check"), 0)
            self.assertEqual(nc.call_args[0][3], "check_")
            chk.assert_called_once_with(ctx)
            self.assertEqual(self.main("run", "--include-risky", "--exclude", "A", "B"), 2)
            args = run_.call_args[0][1]
            self.assertTrue(args.include_risky)
            self.assertEqual(args.exclude, ["A", "B"])
            self.assertEqual(self.main("health"), 0)
            self.assertEqual(ctx.state["pre_health"], ["h"])
            ctx.save.assert_called_once_with()
        self.assertIn("注意：rocky 與 RHEL 相容", str(ctx.say.call_args_list))

    def test_rules_and_list(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "reports", "run_b"))
        os.makedirs(os.path.join(d, "reports", "run_a"))
        cfg = os.path.join(d, "config.ini")
        with open(cfg, "w") as f:
            f.write("[general]\nreport_dir = %s\n" % os.path.join(d, "reports"))
        self.assertEqual(self.main("-c", cfg, "list", euid=1000), 0)
        self.assertTrue(self.out.getvalue().endswith("run_a\nrun_b\n"))
        self.assertEqual(self.main("-c", os.path.join(d, "none.ini"), "rules", euid=1000), 0)
        lines = self.out.getvalue().splitlines()
        self.assertIn("Rocky Linux 9.5", lines)
        self.assertTrue(any(l.startswith("TWGCB-01-012-0001 ") for l in lines))

    def test_setup_dispatch(self):
        ctx = mock.Mock(run_id="r1", state={})
        with mock.patch.object(self.cli.engine, "new_context", return_value=ctx) as nc, \
                mock.patch("gcb.setup.cmd_setup", return_value=0) as cs:
            self.assertEqual(self.main("setup", "--user", "bob", "--services", ""), 0)
        self.assertEqual(nc.call_args[0][3], "setup_")
        args = cs.call_args[0][2]
        self.assertEqual((args.user, args.services), ("bob", ""))

    def test_verify_and_rollback(self):
        ctx = mock.Mock()
        with mock.patch.object(self.cli.engine, "load_context", return_value=ctx) as lc, \
                mock.patch.object(self.cli.engine, "cmd_verify", return_value=0) as v, \
                mock.patch.object(self.cli.engine, "cmd_rollback", return_value=0) as rb:
            self.main("verify", "run1")
            v.assert_called_once_with(ctx)
            self.main("rollback", "run1", "--rule", "TWGCB-01-012-0001")
            rb.assert_called_once_with(ctx, "TWGCB-01-012-0001")
            self.assertEqual(lc.call_args[0][2], "run1")

    def test_utf8_stdio_rewraps_ascii_streams(self):
        cli = load_cli()
        streams = {n: io.TextIOWrapper(io.BytesIO(), encoding="ascii") for n in ("stdout", "stderr", "stdin")}
        with mock.patch.object(sys, "stdout", streams["stdout"]), mock.patch.object(sys, "stderr", streams["stderr"]), \
                mock.patch.object(sys, "stdin", streams["stdin"]):
            cli._utf8_stdio()
            self.assertEqual((sys.stdout.encoding, sys.stderr.encoding, sys.stdin.encoding), ("utf-8",) * 3)
            self.assertIsNot(sys.stdout, streams["stdout"])

    def test_on_signal_raises_keyboard_interrupt(self):
        with self.assertRaises(KeyboardInterrupt):
            self.cli._on_signal(15, None)

    def test_main_entry_interrupted(self):
        # 以 __main__ 執行：登記訊號處理（模擬）並在中斷時以 130 結束
        with mock.patch("signal.signal") as sig, mock.patch.object(sys, "argv", ["gcb.py", "rules"]), \
                mock.patch("gcb.osinfo.detect", side_effect=KeyboardInterrupt):
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(os.path.join(ROOT, "gcb.py"), run_name="__main__")
        self.assertEqual(cm.exception.code, 130)
        self.assertEqual(sig.call_count, 2)
        self.assertIn("已中斷", self.out.getvalue())

    def test_main_entry_interrupt_output_fails(self):
        class Broken(U8):
            def write(self, s):
                raise OSError("terminal closed")
        with mock.patch("signal.signal"), mock.patch.object(sys, "argv", ["gcb.py", "rules"]), \
                mock.patch("gcb.osinfo.detect", side_effect=KeyboardInterrupt), \
                mock.patch("sys.stdout", Broken()):
            with self.assertRaises(SystemExit) as cm:
                runpy.run_path(os.path.join(ROOT, "gcb.py"), run_name="__main__")
        self.assertEqual(cm.exception.code, 130)


if __name__ == "__main__":
    unittest.main()
