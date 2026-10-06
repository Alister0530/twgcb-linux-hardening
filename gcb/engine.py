# -*- coding: utf-8 -*-
"""主流程：前測 → 檢測 → 備份/修復 → 後測 → （必要時回滾）→ 報告。"""
import json
import logging
import os
import sys
import traceback

from . import health, hints, journal, report
from .fixer import FixError, Fx, ManualRequired
from .rules import ERROR, NA, PASS, rules_for
from .rules.base import manual_reason_for
from .util import activity, elapsed_str, hostname, now, primary_ip, set_progress, stamp

RISK_LABEL = {"A": "A 自動修復", "B": "B 風險項目（需 --include-risky）", "C": "C 需人工處理"}
LOGIN_CHECKS = ("H01", "H02", "H03", "H04", "H05", "H06")


class Context(object):
    def __init__(self, cfg, osi, run_dir, run_id, args):
        self.cfg = cfg
        self.osi = osi
        self.run_dir = run_dir
        self.run_id = run_id
        self.dry_run = getattr(args, "dry_run", False)
        self.include_risky = getattr(args, "include_risky", False)
        self.journal = journal.Journal(run_dir)
        self.intended_stops = set()
        self.pre_health_status = {}
        self.state_path = os.path.join(run_dir, "state.json")
        self.state = self._load_state()
        self.intended_stops.update(self.state.get("intended_stops", []))
        self.log = self._logger()
        set_progress(lambda what, sec: self.say("      … 仍在執行：%s（已 %s）" % (what, elapsed_str(sec))))

    def _load_state(self):
        if os.path.exists(self.state_path):
            with open(self.state_path, "rb") as f:
                return json.loads(f.read().decode("utf-8"))
        return {"run_id": self.run_id, "host": hostname(), "ip": primary_ip(),
                "os": {"key": self.osi.key, "pretty": self.osi.pretty, "doc": self.osi.gcb_doc,
                       "note": self.osi.compatible_note},
                "started": now(), "steps": [], "verify": []}

    def _logger(self):
        lg = logging.getLogger("gcb." + self.run_id)
        lg.setLevel(logging.INFO)
        lg.propagate = False
        if not lg.handlers:
            h = logging.FileHandler(os.path.join(self.run_dir, "remediation.log"), encoding="utf-8")
            h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-5s | %(message)s", "%Y-%m-%d %H:%M:%S"))
            lg.addHandler(h)
        return lg

    def save(self):
        self.state["intended_stops"] = sorted(self.intended_stops)
        tmp = self.state_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(self.state, ensure_ascii=False, indent=1).encode("utf-8"))
        os.replace(tmp, self.state_path)

    # ---- 紀錄 ----

    def say(self, msg):
        print(msg)
        sys.stdout.flush()
        self.log.info(msg.strip())

    def add_step(self, rec):
        self.state["steps"].append(rec)
        detail = rec["detail"].replace("\n", "\n" + " " * 30)
        self.log.info("[%s] %s | %s | %s", rec["rule"], rec["action"], rec["result"], detail)

    def log_event(self, rid, action, detail, result="資訊"):
        self.add_step({"time": now(), "rule": rid, "action": action, "detail": detail, "result": result})


def new_context(cfg, osi, args, prefix=""):
    run_id = "%s%s_%s" % (prefix, hostname().split(".")[0], stamp())
    run_dir = os.path.join(cfg.report_dir, run_id)
    os.makedirs(run_dir, exist_ok=True)
    os.chmod(run_dir, 0o700)  # 含備份檔（如 /etc/shadow），限 root 存取
    return Context(cfg, osi, run_dir, run_id, args)


def load_context(cfg, osi, run_id, args):
    run_dir = os.path.join(cfg.report_dir, run_id)
    if not os.path.exists(os.path.join(run_dir, "state.json")):
        raise SystemExit("找不到執行紀錄：%s" % run_dir)
    return Context(cfg, osi, run_dir, run_id, args)


# ====================================================================
# 各階段
# ====================================================================

def do_health(ctx, label):
    ctx.say("\n[%s] 系統健康檢查" % label)
    items = health.run_all(ctx)
    for i in items:
        mark = "!" if i["status"] == health.BAD and i["critical"] else " "
        ctx.say("  %s %-4s %-6s %s：%s" % (mark, i["id"], i["status"], i["name"], i["detail"].split("\n")[0][:100]))
        for a in i.get("advice", []):
            ctx.say("  %-12s ↳ %s" % ("", a))
    return items


def do_detect(ctx, label):
    ctx.say("\n[%s] GCB 規則檢測（%s）" % (label, ctx.osi.gcb_doc))
    out = []
    for rid, rule in rules_for(ctx.osi):
        try:
            reason = rule.not_applicable(ctx)
            if reason:
                status, cur = NA, reason
            else:
                with activity("檢測 %s %s" % (rid, rule.title_for(ctx.osi))):
                    c = rule.check(ctx)
                status, cur = c.status, c.current
        except Exception as e:
            status, cur = ERROR, "檢測程式錯誤：%s" % e
        out.append({"id": rid, "title": rule.title_for(ctx.osi), "category": rule.category, "risk": rule.risk,
                    "risk_label": RISK_LABEL[rule.risk], "expected": rule.expected_for(ctx.osi),
                    "status": status, "current": cur, "hint": rule.manual_hint,
                    "reason": manual_reason_for(rule) if rule.risk == "C" else "",
                    "advice": hints.explain(cur) if status == ERROR else []})
        ctx.say("  %-18s %-6s %s" % (rid, status, rule.title_for(ctx.osi)))
    s = summarize(out)
    ctx.say("  合格 %(pass)d / 不合格 %(fail)d / 不適用 %(na)d / 檢測失敗 %(err)d，合規率 %(rate)s" % s)
    return out


def summarize(checks):
    p = sum(1 for c in checks if c["status"] == PASS)
    na = sum(1 for c in checks if c["status"] == NA)
    err = sum(1 for c in checks if c["status"] == ERROR)
    f = len(checks) - p - na - err
    denom = p + f + err
    return {"total": len(checks), "pass": p, "fail": f, "na": na, "err": err,
            "rate": "%.1f%%" % (100.0 * p / denom) if denom else "-"}


def plan_fixes(ctx, checks, excluded):
    """決定每條規則的處理方式。回傳 [(rid, rule, 預定處理)]。"""
    rules = dict(rules_for(ctx.osi))
    plan = []
    for c in checks:
        rid, rule = c["id"], rules[c["id"]]
        if c["status"] == PASS:
            act = "無需修復"
        elif c["status"] == NA:
            act = "不適用"
        elif rid in excluded:
            act = "已排除（設定檔/參數）"
        elif c["status"] == ERROR:
            act = "需人工處理（檢測失敗）"
        elif rule.risk == "C":
            act = "需人工處理"
        elif rule.risk == "B" and not ctx.include_risky:
            act = "已跳過（風險項目）"
        else:
            try:
                reason = rule.precondition(ctx)
                act = "已跳過（前置條件）：" + reason if reason else "修復"
            except Exception as e:
                act = "需人工處理（前置條件檢查錯誤：%s）" % e
        plan.append((rid, rule, act))
    return plan


def apply_rule(ctx, rid, rule, check_before):
    fx = Fx(ctx, rid)
    fx.step("開始修復", "%s；修復前：%s" % (rule.title_for(ctx.osi), check_before["current"]))
    after = None
    try:
        with activity("修復 %s %s" % (rid, rule.title_for(ctx.osi))):
            rule.fix(ctx, fx)
        if ctx.dry_run:
            outcome = "預覽"
        else:
            with activity("修復後檢測 %s" % rid):
                after = rule.check(ctx)
            if after.status == PASS:
                outcome = "已修復"
                if rule.needs_reboot or any("重開機" in n for n in fx.notes):
                    outcome = "已修復（需重開機生效）"
            elif fx.partial:
                outcome = "部分修復"
            else:
                outcome = "修復失敗"
                fx.note("修復後檢測仍不合格：%s" % after.current)
    except ManualRequired as e:
        outcome = "需人工處理"
        fx.note(str(e))
    except FixError as e:
        outcome = "修復失敗"
        fx.note(str(e))
    except Exception as e:
        outcome = "修復失敗"
        fx.note("程式錯誤：%s" % e)
        ctx.log.error(traceback.format_exc())

    if outcome in ("修復失敗", "需人工處理") and not ctx.dry_run:
        if any(e["rule"] == rid and not e["rolled_back"] for e in ctx.journal.entries):
            _, bad = journal.rollback(ctx.journal, ctx.osi, _rb_say(ctx), rule_id=rid)
            outcome += "（已還原本項變更）" if not bad else "（還原未完全成功，請查看 log）"
    advice = []
    if not outcome.startswith(("已修復", "預覽")):
        # 依備註與失敗步驟的輸出比對常見錯誤
        text = "\n".join(fx.notes + [s["detail"] for s in fx.steps if "失敗" in s["result"]])
        advice = hints.explain(text)
        for a in advice:
            fx.step("可能原因與建議", a)
    fx.step("結束修復", outcome, outcome)
    return outcome, fx.notes, advice


def _rb_say(ctx):
    return lambda rid, action, msg, result: ctx.log_event(rid, action, msg, result)


def clear_scan_caches():
    """回滾或修復改變了檔案後，清除各規則的全檔案系統掃描快取，讓後續檢測重新掃描。"""
    import sys as _sys
    for name, mod in list(_sys.modules.items()):
        if name.startswith("gcb.rules.") and mod is not None:
            for attr in ("_FIND_CACHE", "_PRIV_CACHE", "_fs_cache", "_scan_cache", "_tree_cache"):
                c = getattr(mod, attr, None)
                if isinstance(c, dict):
                    c.clear()


def rollback_all(ctx, reason):
    ctx.say("\n[回滾] %s" % reason)
    ctx.log_event("-", "開始回滾", reason)
    ok, fail = journal.rollback(ctx.journal, ctx.osi, _rb_say(ctx))
    clear_scan_caches()
    ctx.say("  回滾完成：成功 %d 項，失敗 %d 項" % (ok, fail))
    mark = " → 已回滾" if fail == 0 else " → 回滾未完全成功"
    for f in ctx.state.get("fixes", []):
        if f["outcome"].startswith(("已修復", "部分修復")) and "回滾" not in f["outcome"]:
            f["outcome"] += mark
    ctx.state["rollback"] = {"time": now(), "reason": reason, "ok": ok, "fail": fail}
    ctx.save()
    return fail == 0


def ask(prompt):
    if not sys.stdin.isatty():
        return None
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return None


# ====================================================================
# 指令
# ====================================================================

def cmd_check(ctx):
    ctx.state["mode"] = "check"
    ctx.state["pre_health"] = do_health(ctx, "前測")
    ctx.state["checks_before"] = do_detect(ctx, "檢測")
    ctx.save()
    path = report.detection_report(ctx)
    ctx.say("\n不合格清單報告：%s\n執行紀錄目錄：%s" % (path, ctx.run_dir))
    return 0


def cmd_run(ctx, args):
    st = ctx.state
    st["mode"] = "dry-run" if ctx.dry_run else "run"
    st["args"] = {"include_risky": ctx.include_risky, "dry_run": ctx.dry_run}
    excluded = set(ctx.cfg.exclude_rules) | set(args.exclude or [])

    # 1. 前測
    pre = do_health(ctx, "1/5 前測")
    st["pre_health"] = pre
    ctx.pre_health_status = {i["id"]: i["status"] for i in pre}
    ctx.save()

    # 2. 檢測 + 不合格清單
    checks = do_detect(ctx, "2/5 檢測")
    st["checks_before"] = checks
    ctx.save()
    det = report.detection_report(ctx)
    ctx.say("  不合格清單報告：%s" % det)

    blocked = [i for i in pre if i["id"] in LOGIN_CHECKS and i["critical"] and i["status"] == health.BAD]
    no_login_test = ctx.pre_health_status.get("H04") == health.SKIP
    if blocked and not args.force:
        ctx.say("\n前測登入相關項目失敗（%s），為避免修復後無法確認登入，停止修復。"
                "\n請先排除問題，或確認風險後加 --force。" % "、".join(i["id"] for i in blocked))
        return 1
    if no_login_test and not args.skip_login_test:
        ctx.say("\n未設定 test_user，無法自動驗證修復後可登入。"
                "\n請在 config.ini 設定測試帳號，或加 --skip-login-test（改以人工確認）。")
        return 1

    # 3. 規劃
    plan = plan_fixes(ctx, checks, excluded)
    todo = [p for p in plan if p[2] == "修復"]
    ctx.say("\n[3/5 修復規劃] 將修復 %d 項：" % len(todo))
    for rid, rule, _ in todo:
        ctx.say("  - %s %s" % (rid, rule.title_for(ctx.osi)))
    for rid, rule, act in plan:
        if act not in ("修復", "無需修復", "不適用"):
            ctx.say("  · %s %s：%s" % (rid, rule.title_for(ctx.osi), act))
    if not todo:
        ctx.say("  沒有需要自動修復的項目。")
    elif not ctx.dry_run and not args.yes:
        ans = ask("\n確定開始修復？已建議先建立 VM 快照。[y/N] ")
        if ans != "y":
            ctx.say("已取消。")
            return 1

    # 4. 修復
    by_id = {c["id"]: c for c in checks}
    fixes = []
    st["fixes"] = fixes
    ctx.say("\n[4/5 %s]" % ("預覽修改內容（不會修改系統）" if ctx.dry_run else "修復"))
    order = sorted(plan, key=lambda x: (bool(getattr(x[1], "run_last", False)), x[0]))
    recs = {}
    for rid, rule, act in order:
        rec = {"id": rid, "title": rule.title_for(ctx.osi), "category": rule.category, "risk_label": RISK_LABEL[rule.risk],
               "before": by_id[rid]["status"], "before_current": by_id[rid]["current"],
               "outcome": act, "notes": [], "needs_reboot": False}
        if act.startswith("需人工處理") and rule.manual_hint:
            if rule.risk == "C":
                rec["notes"].append("無法自動修復的原因：" + manual_reason_for(rule))
            rec["notes"].append("人工處理方式：" + rule.manual_hint)
        if act == "修復":
            outcome, notes, advice = apply_rule(ctx, rid, rule, by_id[rid])
            rec.update(outcome=outcome, notes=notes, advice=advice, needs_reboot="重開機" in outcome)
            ctx.say("  %-18s %s %s" % (rid, outcome, ("— " + notes[-1].split("\n")[0][:120]) if notes and "失敗" in outcome else ""))
            for a in advice:
                ctx.say("  %-18s ↳ %s" % ("", a))
        recs[rid] = rec
        fixes[:] = [recs[p[0]] for p in plan if p[0] in recs]  # 報告依編號排列
        ctx.save()
    if ctx.dry_run:
        ctx.say("\n預覽完成，預計修改內容見 log：%s" % os.path.join(ctx.run_dir, "remediation.log"))
        path = report.remediation_report(ctx)
        ctx.say("預覽報告：%s" % path)
        return 0

    # 5. 後測（沒有任何修改時略過，系統狀態不變）
    if not ctx.journal.entries:
        st["checks_after"] = checks
        ctx.say("\n沒有修改任何設定，略過後測。")
        ctx.save()
        path = report.remediation_report(ctx)
        ctx.say("修復情況報告：%s" % path)
        return 0
    post = do_health(ctx, "5/5 後測")
    st["post_health"] = post
    st["checks_after"] = do_detect(ctx, "修復後檢測")
    cmp_ = health.compare(pre, post, ctx.intended_stops)
    st["compare"] = cmp_
    ctx.save()
    regress = [k for k, (desc, crit) in cmp_.items() if crit]
    rc = 0
    if regress:
        ctx.say("\n關鍵項目退步：%s" % "、".join(regress))
        if ctx.cfg.auto_rollback:
            rollback_all(ctx, "後測關鍵項目退步：" + "、".join(regress))
            st["rollback_health"] = do_health(ctx, "回滾後健康檢查")
            rc = 2
        else:
            ctx.say("auto_rollback=no，未自動回滾。可執行：./gcb.sh rollback %s" % ctx.run_id)
    elif ctx.cfg.manual_login_confirm and not args.no_manual_confirm:
        st["manual_confirm"] = manual_login_confirm(ctx)
        if st["manual_confirm"] == "異常":
            rollback_all(ctx, "人工登入確認異常")
            st["rollback_health"] = do_health(ctx, "回滾後健康檢查")
            rc = 2
    ctx.save()

    path = report.remediation_report(ctx)
    s0, s1 = summarize(checks), summarize(st["checks_after"])
    rb = st.get("rollback")
    if rb:
        _say_rolled_back(ctx, rb, st.get("rollback_health", []), s0, s1)
    else:
        ctx.say("\n================ 完成 ================")
        ctx.say("合規率：%s → %s" % (s0["rate"], s1["rate"]))
    ctx.say("不合格清單報告：%s" % det)
    ctx.say("修復情況報告：%s" % path)
    ctx.say("修復 log：%s" % os.path.join(ctx.run_dir, "remediation.log"))
    if not rb:
        if any(f["needs_reboot"] for f in fixes):
            ctx.say("\n部分項目需重開機生效。重開機後請執行：./gcb.sh verify %s" % ctx.run_id)
        ctx.say("如需回滾：./gcb.sh rollback %s" % ctx.run_id)
    return rc


def _say_rolled_back(ctx, rb, rb_health, s0, s1):
    """整次回滾後的結論：明確說明已回滾、原因、回滾結果與登入狀態。"""
    ctx.say("\n================ 完成：本次修改已全部回滾 ================")
    ctx.say("回滾原因：%s" % rb["reason"])
    _say_rollback_result(ctx, rb["ok"], rb["fail"], rb_health)
    ctx.say("合規率：修復前 %s；修復後曾達 %s，已回滾不保留" % (s0["rate"], s1["rate"]))


def _say_rollback_result(ctx, ok, fail, rb_health):
    if fail:
        ctx.say("回滾結果：! 成功 %d 項、失敗 %d 項，系統未完全回到修復前狀態" % (ok, fail))
        ctx.say("          請查看 log 中「回滾未完全成功」的項目人工處理，或還原 VM 快照")
    else:
        ctx.say("回滾結果：成功 %d 項、失敗 0 項，系統已回到修復前狀態" % ok)
    bad = [i for i in rb_health if i["id"] in LOGIN_CHECKS + ("H19",) and i["status"] not in (health.OK, health.SKIP)]
    if bad:
        ctx.say("回滾後登入：! 未通過：%s，請保留目前連線並立即確認可登入" % "、".join(
            "%s %s" % (i["id"], i["name"]) for i in bad))
    elif rb_health:
        ctx.say("回滾後登入：正常（SSH 登入、sudo 檢查通過）")


def manual_login_confirm(ctx):
    ctx.say("\n================ 人工登入確認 ================")
    ctx.say("請保持目前連線，另開一個終端機：")
    ctx.say("  1. 以一般帳號 SSH 登入本機（建議用通行碼登入一次，驗證 PAM 認證流程）")
    ctx.say("  2. 執行 sudo -v 確認可以提升權限")
    result = "未執行"
    while True:
        ans = ask("登入是否正常？[y=正常 / n=異常，將回滾] ")
        if ans is None:  # 非互動環境
            break
        if ans in ("y", "yes"):
            result = "正常"
            break
        if ans in ("n", "no"):
            result = "異常"
            break
        print("請輸入 y 或 n。")
    ctx.log_event("-", "人工登入確認", result)
    return result


def cmd_verify(ctx):
    """重開機後再驗證一次。"""
    st = ctx.state
    post = do_health(ctx, "重開機後驗證")
    checks = do_detect(ctx, "重開機後檢測")
    st["verify"].append({"time": now(), "health": post, "checks": checks,
                         "compare": health.compare(st.get("pre_health", []), post, ctx.intended_stops)})
    ctx.save()
    path = report.remediation_report(ctx)
    ctx.say("\n已更新修復情況報告：%s" % path)
    return 0


def cmd_rollback(ctx, rule_id=None):
    if rule_id:
        ctx.say("[回滾] 只回滾 %s（若其他規則也修改了同一檔案，會一併還原到該規則修改前的狀態）" % rule_id)
        if not any(e["rule"] == rule_id for e in ctx.journal.entries):
            ctx.say("  這次執行沒有 %s 的修改紀錄，不需要回滾。" % rule_id)
            return 1
        later = journal.later_conflicts(ctx.journal, rule_id)
        if later:
            ctx.say("  無法單獨回滾 %s：之後的規則 %s 也修改了同一個檔案，單獨回滾會在整次回滾時被蓋回。"
                    "\n  請先依序回滾這些規則，或執行整次回滾。" % (rule_id, "、".join(later)))
            return 1
        ok, fail = journal.rollback(ctx.journal, ctx.osi, _rb_say(ctx), rule_id=rule_id)
        clear_scan_caches()
        for f in ctx.state.get("fixes", []):
            if f["id"] == rule_id and "回滾" not in f["outcome"]:
                f["outcome"] += " → 已回滾" if fail == 0 else " → 回滾未完全成功"
        ctx.state.setdefault("manual_rollbacks", []).append({"time": now(), "rule": rule_id, "ok": ok, "fail": fail})
        ctx.say("  成功 %d 項，失敗 %d 項" % (ok, fail))
    else:
        rollback_all(ctx, "手動執行回滾")
    ctx.state["rollback_health"] = do_health(ctx, "回滾後健康檢查")
    ctx.save()
    path = report.remediation_report(ctx)
    if not rule_id:
        rb = ctx.state["rollback"]
        ctx.say("\n================ 回滾完成 ================")
        _say_rollback_result(ctx, rb["ok"], rb["fail"], ctx.state["rollback_health"])
    ctx.say("\n已更新修復情況報告：%s" % path)
    return 0
