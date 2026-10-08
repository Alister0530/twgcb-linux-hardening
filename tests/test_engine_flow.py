# -*- coding: utf-8 -*-
"""主流程情境測試：用假規則（只改暫存檔）與假健康檢查結果，驗證 run / verify / rollback 的流程分支。

不需要 root、不會修改系統，在任何平台都能執行。
"""
import argparse
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import engine, health, osinfo  # noqa: E402
from gcb.config import Config  # noqa: E402
from gcb.fixer import FixError  # noqa: E402
from gcb.rules.base import FAIL, PASS, Check, Rule  # noqa: E402
from gcb.util import read_text  # noqa: E402


class FileRule(Rule):
    """檢測暫存檔內容是否為 good；修復時寫入 good。"""
    category = "測試"

    def __init__(self, n, path, risk="A", fail_after_write=False, run_last=False, order_log=None):
        self.ids = {"ubuntu2204": "TWGCB-01-014-%04d" % n}
        self.path = path
        self.risk = risk
        self.title = "測試規則 %d" % n
        self.expected = "good"
        self.fail_after_write = fail_after_write
        self.run_last = run_last
        self.order_log = order_log
        if risk == "C":
            self.manual_hint = "請人工確認檔案用途後處理"

    def check(self, ctx):
        v = (read_text(self.path) or "").strip()
        return Check(PASS if v == "good" else FAIL, v or "空")

    def fix(self, ctx, fx):
        if self.order_log is not None:
            self.order_log.append(self.rule_id(ctx.osi))
        fx.write_file(self.path, "good\n")
        if self.fail_after_write:
            raise FixError("模擬修復失敗")


def health_items(**status):
    """產生健康檢查結果；H01–H06 為關鍵項目，預設通過。"""
    out = []
    for hid in ("H01", "H02", "H03", "H04", "H05", "H06", "H08", "H09"):
        out.append(health.item(hid, hid, hid in engine.LOGIN_CHECKS, status.get(hid, health.OK), "", []))
    for i in out:
        i["advice"] = []
    return out


def make_args(**kw):
    a = dict(exclude=None, force=False, skip_login_test=False, yes=True, no_manual_confirm=True,
             include_risky=False, dry_run=False)
    a.update(kw)
    return argparse.Namespace(**a)


class FlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.files = {n: os.path.join(self.tmp, "f%d.conf" % n) for n in (1, 2, 3, 4, 5)}
        for p in self.files.values():
            with open(p, "w") as f:
                f.write("bad\n")
        self.order = []
        self.rules = [
            FileRule(1, self.files[1]),                                   # A 類
            FileRule(2, self.files[2], risk="B"),                         # B 類
            FileRule(3, self.files[3], risk="C"),                         # C 類
            FileRule(4, self.files[4], fail_after_write=True),            # 修復失敗 → 只還原本項
            FileRule(5, self.files[5], run_last=True, order_log=self.order),  # 最後執行
        ]
        self.rules[0].order_log = self.order
        self.cfg = Config(None, self.tmp)
        self.cfg.report_dir = os.path.join(self.tmp, "reports")
        self.osi = osinfo.OSInfo("ubuntu2204", "debian", "Ubuntu 22.04 測試", "ubuntu", "22.04")
        self.health_seq = []
        self.answers = []
        patches = [
            mock.patch.object(engine, "rules_for", lambda osi: [(r.rule_id(osi), r) for r in self.rules]),
            mock.patch.object(health, "run_all", lambda ctx: self.health_seq.pop(0) if self.health_seq
                              else health_items()),
            mock.patch.object(engine, "ask", lambda prompt: self.answers.pop(0) if self.answers else None),
            mock.patch.object(engine, "primary_ip", lambda: "127.0.0.1"),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def content(self, n):
        return read_text(self.files[n]).strip()

    def run_engine(self, args, health_seq=None, answers=None, cfg=None):
        self.health_seq = list(health_seq or [])
        self.answers = list(answers or [])
        ctx = engine.new_context(cfg or self.cfg, self.osi, args)
        rc = engine.cmd_run(ctx, args)
        return ctx, rc

    def outcome(self, ctx, n):
        return next(f["outcome"] for f in ctx.state["fixes"] if f["id"].endswith("%04d" % n))

    # ---------------- 一般修復 ----------------

    def test_a_only(self):
        ctx, rc = self.run_engine(make_args())
        self.assertEqual(rc, 0)
        self.assertEqual(self.content(1), "good")
        self.assertEqual(self.content(2), "bad")            # B 類未加 --include-risky
        self.assertEqual(self.outcome(ctx, 2), "已跳過（風險項目）")
        self.assertEqual(self.outcome(ctx, 3), "需人工處理")
        notes = next(f["notes"] for f in ctx.state["fixes"] if f["id"].endswith("0003"))
        self.assertTrue(notes[0].startswith("無法自動修復的原因："))
        self.assertEqual(self.content(4), "bad")            # 修復失敗只還原本項
        self.assertEqual(self.outcome(ctx, 4), "修復失敗（已還原本項變更）")
        self.assertTrue(os.path.exists(os.path.join(ctx.run_dir, "GCB修復報告_%s.xlsx" % ctx.run_id)))
        self.assertTrue(os.path.exists(os.path.join(ctx.run_dir, "GCB不合格清單_%s.xlsx" % ctx.run_id)))

    def test_include_risky(self):
        ctx, rc = self.run_engine(make_args(include_risky=True))
        self.assertEqual(self.content(2), "good")
        self.assertEqual(self.outcome(ctx, 2), "已修復")

    def test_run_last_order(self):
        self.run_engine(make_args())
        self.assertEqual(self.order, ["TWGCB-01-014-0001", "TWGCB-01-014-0005"])

    def test_exclude(self):
        ctx, rc = self.run_engine(make_args(exclude=["TWGCB-01-014-0001"]))
        self.assertEqual(self.content(1), "bad")
        self.assertEqual(self.outcome(ctx, 1), "已排除（設定檔/參數）")

    def test_dry_run_changes_nothing(self):
        ctx, rc = self.run_engine(make_args(dry_run=True, include_risky=True))
        self.assertEqual(rc, 0)
        for n in (1, 2, 4, 5):
            self.assertEqual(self.content(n), "bad")
        self.assertEqual(self.outcome(ctx, 1), "預覽")
        self.assertEqual(ctx.journal.entries, [])
        self.assertTrue(os.path.exists(os.path.join(ctx.run_dir, "GCB修復報告_%s.xlsx" % ctx.run_id)))

    def test_confirm_cancel(self):
        ctx, rc = self.run_engine(make_args(yes=False), answers=["n"])
        self.assertEqual(rc, 1)
        self.assertEqual(self.content(1), "bad")

    # ---------------- 前測 ----------------

    def test_precheck_login_fail_stops(self):
        ctx, rc = self.run_engine(make_args(), health_seq=[health_items(H04=health.BAD)])
        self.assertEqual(rc, 1)
        self.assertEqual(self.content(1), "bad")

    def test_precheck_login_fail_force(self):
        ctx, rc = self.run_engine(make_args(force=True), health_seq=[health_items(H04=health.BAD)])
        self.assertEqual(self.content(1), "good")

    def test_no_test_user_stops(self):
        ctx, rc = self.run_engine(make_args(), health_seq=[health_items(H04=health.SKIP)])
        self.assertEqual(rc, 1)
        self.assertEqual(self.content(1), "bad")
        ctx, rc = self.run_engine(make_args(skip_login_test=True), health_seq=[health_items(H04=health.SKIP)])
        self.assertEqual(self.content(1), "good")

    # ---------------- 後測與回滾 ----------------

    def test_regression_auto_rollback(self):
        ctx, rc = self.run_engine(make_args(), health_seq=[health_items(), health_items(H04=health.BAD)])
        self.assertEqual(rc, 2)
        self.assertEqual(self.content(1), "bad")            # 已自動回滾
        self.assertEqual(self.outcome(ctx, 1), "已修復 → 已回滾")
        self.assertIn("後測關鍵項目退步", ctx.state["rollback"]["reason"])
        self.assertIn("rollback_health", ctx.state)

    def test_regression_without_auto_rollback(self):
        self.cfg.auto_rollback = False
        ctx, rc = self.run_engine(make_args(), health_seq=[health_items(), health_items(H04=health.BAD)])
        self.assertEqual(rc, 0)
        self.assertEqual(self.content(1), "good")
        self.assertNotIn("rollback", ctx.state)

    def test_noncritical_regression_no_rollback(self):
        ctx, rc = self.run_engine(make_args(), health_seq=[health_items(), health_items(H08=health.BAD)])
        self.assertEqual(rc, 0)
        self.assertEqual(self.content(1), "good")

    def test_manual_confirm_no_rolls_back(self):
        ctx, rc = self.run_engine(make_args(no_manual_confirm=False), answers=["n"])
        self.assertEqual(rc, 2)
        self.assertEqual(ctx.state["manual_confirm"], "異常")
        self.assertEqual(self.content(1), "bad")
        # 結尾明確說明已全部回滾、原因與結果，不再提示「如需回滾」
        out = sys.stdout.getvalue()
        tail = out[out.index("================ 完成"):]
        self.assertIn("完成：本次修改已全部回滾", tail)
        self.assertIn("回滾原因：人工登入確認異常", tail)
        self.assertIn("失敗 0 項，系統已回到修復前狀態", tail)
        self.assertIn("回滾後登入：正常", tail)
        self.assertIn("已回滾不保留", tail)
        self.assertNotIn("如需回滾", tail)

    def test_manual_confirm_yes_summary_offers_rollback(self):
        self.run_engine(make_args(no_manual_confirm=False), answers=["y"])
        tail = sys.stdout.getvalue().split("================ 完成 ================")[1]
        self.assertIn("如需回滾：", tail)
        self.assertNotIn("已全部回滾", tail)

    def test_rollback_result_failures_and_login(self):
        said = []
        ctx = mock.Mock(say=said.append)
        engine._say_rollback_result(ctx, 5, 2, [{"id": "H04", "name": "SSH 實際登入測試", "status": health.BAD},
                                                {"id": "H19", "name": "SSH 從主要網卡 IP 登入", "status": health.SKIP}])
        text = "\n".join(said)
        self.assertIn("! 成功 5 項、失敗 2 項，系統未完全回到修復前狀態", text)
        self.assertIn("還原 VM 快照", text)
        self.assertIn("回滾後登入：! 未通過：H04 SSH 實際登入測試", text)
        self.assertNotIn("H19", text)

    def test_manual_confirm_yes_keeps(self):
        ctx, rc = self.run_engine(make_args(no_manual_confirm=False), answers=["y"])
        self.assertEqual(rc, 0)
        self.assertEqual(ctx.state["manual_confirm"], "正常")
        self.assertEqual(self.content(1), "good")

    # ---------------- verify / rollback 指令 ----------------

    def test_verify_appends(self):
        ctx, rc = self.run_engine(make_args())
        ctx2 = engine.load_context(self.cfg, self.osi, ctx.run_id, make_args())
        self.health_seq = [health_items()]
        self.assertEqual(engine.cmd_verify(ctx2), 0)
        self.assertEqual(len(ctx2.state["verify"]), 1)

    def test_rollback_single_rule(self):
        ctx, rc = self.run_engine(make_args(include_risky=True))
        ctx2 = engine.load_context(self.cfg, self.osi, ctx.run_id, make_args())
        self.assertEqual(engine.cmd_rollback(ctx2, "TWGCB-01-014-0001"), 0)
        self.assertEqual(self.content(1), "bad")
        self.assertEqual(self.content(2), "good")            # 其他規則不受影響
        self.assertEqual(self.outcome(ctx2, 1), "已修復 → 已回滾")
        self.assertEqual(engine.cmd_rollback(ctx2, "TWGCB-01-014-0099"), 1)  # 沒有紀錄的規則

    def test_rollback_single_rule_audit_locked_note(self):
        ctx, rc = self.run_engine(make_args(include_risky=True))
        ctx2 = engine.load_context(self.cfg, self.osi, ctx.run_id, make_args())

        def rb(j, osi, say, rule_id=None):
            j.reboot_audit = True
            return 1, 0
        with mock.patch.object(engine.journal, "rollback", rb):
            engine.cmd_rollback(ctx2, "TWGCB-01-014-0001")
        self.assertIn("需重開機後稽核規則才會恢復", sys.stdout.getvalue())

    def test_rollback_all_twice_no_duplicate_mark(self):
        ctx, rc = self.run_engine(make_args())
        ctx2 = engine.load_context(self.cfg, self.osi, ctx.run_id, make_args())
        engine.cmd_rollback(ctx2)
        self.assertIn("================ 回滾完成 ================", sys.stdout.getvalue())
        self.assertIn("系統已回到修復前狀態", sys.stdout.getvalue())
        engine.cmd_rollback(ctx2)
        self.assertEqual(self.content(1), "bad")
        self.assertEqual(self.outcome(ctx2, 1), "已修復 → 已回滾")

    def test_check_command(self):
        ctx = engine.new_context(self.cfg, self.osi, make_args())
        self.assertEqual(engine.cmd_check(ctx), 0)
        self.assertEqual(self.content(1), "bad")
        self.assertEqual(len(ctx.state["checks_before"]), 5)


class CompareTest(unittest.TestCase):
    def item(self, hid, st, critical=True, data=None):
        return health.item(hid, hid, critical, st, "", data or [])

    def test_critical_regression(self):
        r = health.compare([self.item("H04", health.OK)], [self.item("H04", health.BAD)])
        self.assertEqual(r["H04"], ("退步（通過→失敗）", True))

    def test_improvement_and_unchanged(self):
        r = health.compare([self.item("H01", health.BAD), self.item("H02", health.OK)],
                           [self.item("H01", health.OK), self.item("H02", health.OK)])
        self.assertEqual(r["H01"][0], "改善（失敗→通過）")
        self.assertEqual(r["H02"], ("無變化", False))

    def test_noncritical_regression_not_critical(self):
        r = health.compare([self.item("H12", health.OK, False)], [self.item("H12", health.BAD, False)])
        self.assertEqual(r["H12"][1], False)

    def test_new_failed_units(self):
        r = health.compare([self.item("H08", health.OK, False, [])],
                           [self.item("H08", health.WARN, False, ["x.service"])])
        self.assertEqual(r["H08"][0], "新增失敗服務：x.service")

    def test_stopped_services_exclude_intended(self):
        pre = [self.item("H09", health.OK, False, ["a.service", "avahi-daemon.service", "b.service"])]
        post = [self.item("H09", health.OK, False, ["a.service"])]
        r = health.compare(pre, post, intended_stops={"avahi-daemon.service"})
        self.assertEqual(r["H09"][0], "修復後停止：b.service")


class HealthMetaTest(unittest.TestCase):
    def test_exception_keeps_id_and_critical(self):
        def boom(ctx):
            raise RuntimeError("x")
        boom.__name__ = "ssh_login_test"
        with mock.patch.object(health, "CHECKS", [boom]):
            items = health.run_all(None)
        self.assertEqual([(i["id"], i["critical"], i["status"]) for i in items],
                         [("H04", True, health.BAD), ("H19", True, health.BAD)])

    def test_new_fstab_error_is_regression(self):
        pre = [health.item("H15", "fstab", True, health.BAD, "err1")]
        post = [health.item("H15", "fstab", True, health.BAD, "err1\nerr2")]
        self.assertTrue(health.compare(pre, post)["H15"][1])


class LaterConflictTest(unittest.TestCase):
    def test_single_rule_rollback_refused_when_later_rule_touched_same_file(self):
        from gcb import journal
        d = tempfile.mkdtemp()
        f = os.path.join(d, "f.conf")
        with open(f, "w") as fh:
            fh.write("v0\n")
        j = journal.Journal(os.path.join(d, "run"))
        os.makedirs(j.run_dir)
        j.backup_file("A", f)
        j.backup_file("B", f)
        self.assertEqual(journal.later_conflicts(j, "A"), ["B"])
        self.assertEqual(journal.later_conflicts(j, "B"), [])
        shutil.rmtree(d, True)


class UndoRunsAfterRestoreTest(unittest.TestCase):
    """先登記的回滾指令，實際回滾時在檔案還原「之後」才執行（服務 reload 才會讀到原設定）。"""
    def test_reload_sees_restored_file(self):
        import tempfile
        from gcb import journal
        from gcb.util import write_text_atomic
        base = tempfile.mkdtemp()
        conf = os.path.join(base, "unit.conf")
        seen = os.path.join(base, "seen_by_reload")
        write_text_atomic(conf, "original\n")
        run_dir = os.path.join(base, "run")
        os.mkdir(run_dir)
        j = journal.Journal(run_dir)
        j.add("R1", "cmd", cmd=["sh", "-c", "cat %s > %s" % (conf, seen)], desc="模擬 reload")  # 先登記
        j.backup_file("R1", conf)                                                               # 再備份、修改
        write_text_atomic(conf, "modified\n")
        ok, fail = journal.rollback(j, None, lambda *a: None)
        self.assertEqual(fail, 0)
        with open(seen) as f:
            self.assertEqual(f.read(), "original\n")


class ProgressTest(unittest.TestCase):
    """指令執行過久時，畫面每隔一段時間顯示目前在做什麼與已執行時間。"""
    def test_context_prints_progress(self):
        from gcb import util
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        cfg = Config(None, tmp)
        cfg.report_dir = os.path.join(tmp, "reports")
        osi = osinfo.OSInfo("ubuntu2204", "debian", "Ubuntu 22.04 測試", "ubuntu", "22.04")
        ctx = engine.new_context(cfg, osi, make_args())
        self.addCleanup(util.set_progress, None)
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            util._progress("修復 TWGCB-01-014-0033 AIDE 套件", 754)
        self.assertEqual(out.getvalue(), "      … 仍在執行：修復 TWGCB-01-014-0033 AIDE 套件（已 12 分 34 秒）\n")


class AuditLockedRollbackTest(unittest.TestCase):
    """稽核規則已鎖定（-e 2）時，重新載入稽核規則的回滾步驟記為「需重開機」而非失敗。"""
    def setUp(self):
        from gcb import journal
        self.j = journal
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.jr = journal.Journal(self.tmp)
        self.jr.add("R0148", "cmd", cmd=["augenrules", "--load"], desc="重新載入稽核規則")
        self.jr.add("R0149", "cmd", cmd="service auditd reload", desc="重新載入")
        self.jr.add("R0150", "cmd", cmd=["true"], desc="其他還原")
        self.said = []

    def say(self, rid, action, msg, result):
        self.said.append((rid, action, result))

    def test_detect(self):
        e = self.jr.entries
        self.assertEqual([self.j.is_audit_reload(x) for x in e], [True, True, False])
        self.assertFalse(self.j.is_audit_reload({"type": "file", "data": {}}))
        with mock.patch.object(self.j, "run", return_value=mock.Mock(ok=True, out="enabled 2\nfailure 1\n")):
            self.assertTrue(self.j.audit_locked())
        with mock.patch.object(self.j, "run", return_value=mock.Mock(ok=True, out="enabled 1\n")):
            self.assertFalse(self.j.audit_locked())

    def test_locked_counts_as_reboot_needed(self):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return mock.Mock(ok=True, out="enabled 2\n", rc=0, cmd=str(cmd), text=lambda: "")
        with mock.patch.object(self.j, "run", fake_run):
            ok, fail = self.j.rollback(self.jr, None, self.say)
        self.assertEqual((ok, fail), (3, 0))
        self.assertTrue(self.jr.reboot_audit)
        self.assertEqual(calls.count(["auditctl", "-s"]), 1)      # 只查一次鎖定狀態
        self.assertNotIn(["augenrules", "--load"], calls)          # 不執行必定失敗的重新載入
        self.assertIn(("R0148", "略過重新載入稽核規則", "需重開機"), self.said)

    def test_not_locked_runs_reload(self):
        def fake_run(cmd, **kw):
            return mock.Mock(ok=cmd != ["augenrules", "--load"], out="enabled 1\n", rc=0, cmd=str(cmd), text=lambda: "x")
        with mock.patch.object(self.j, "run", fake_run):
            ok, fail = self.j.rollback(self.jr, None, self.say)
        self.assertEqual((ok, fail), (2, 1))
        self.assertFalse(self.jr.reboot_audit)

    def test_summary_mentions_reboot(self):
        said = []
        engine._say_rollback_result(mock.Mock(say=said.append), 220, 0, [], True)
        self.assertIn("稽核規則已鎖定（-e 2）：設定檔已還原，需重開機後稽核規則才會恢復（sudo reboot）", "\n".join(said))


if __name__ == "__main__":
    unittest.main()
