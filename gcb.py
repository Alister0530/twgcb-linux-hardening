# -*- coding: utf-8 -*-
"""GCB 政府組態基準 檢測與修復工具。請以 ./gcb.sh 執行。"""
import argparse
import io
import os
import signal
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from gcb import __version__, engine, osinfo  # noqa: E402
from gcb.config import Config  # noqa: E402
from gcb.rules import rules_for  # noqa: E402


def _utf8_stdio():
    # RHEL 8 + Python 3.6 在 C locale 下預設 ASCII，中文輸出會出錯
    for name in ("stdout", "stderr"):
        s = getattr(sys, name)
        if (s.encoding or "").lower().replace("-", "") != "utf8":
            setattr(sys, name, io.TextIOWrapper(s.buffer, encoding="utf-8", errors="replace", line_buffering=True))
    if (sys.stdin.encoding or "").lower().replace("-", "") != "utf8":
        sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")


def build_parser():
    p = argparse.ArgumentParser(prog="gcb.sh", description="GCB 政府組態基準 檢測與修復工具 v" + __version__)
    p.add_argument("-c", "--config", default=os.path.join(BASE, "config.ini"), help="設定檔路徑")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("setup", help="設定精靈：建立測試帳號、選擇業務服務、寫入 config.ini")
    s.add_argument("--user", help="直接指定測試帳號")
    s.add_argument("--services", help="直接指定業務服務（逗號分隔，空字串代表沒有）")

    sub.add_parser("health", help="只執行系統健康檢查")
    sub.add_parser("check", help="健康檢查 + GCB 檢測，產出不合格清單（不修改系統）")
    sub.add_parser("rules", help="列出本機適用的規則")

    r = sub.add_parser("run", help="完整流程：前測 → 檢測 → 修復 → 後測 → 報告")
    r.add_argument("--include-risky", action="store_true", help="一併修復 B 類風險項目")
    r.add_argument("--dry-run", action="store_true", help="預覽修改內容（不會修改系統）：只列出會執行的修復步驟")
    r.add_argument("--exclude", nargs="*", metavar="TWGCB-ID", help="排除指定規則")
    r.add_argument("-y", "--yes", action="store_true", help="不詢問直接修復")
    r.add_argument("--no-manual-confirm", action="store_true", help="略過人工登入確認")
    r.add_argument("--skip-login-test", action="store_true", help="未設定 test_user 時仍繼續（不建議）")
    r.add_argument("--force", action="store_true", help="前測登入項目失敗時仍繼續（不建議）")

    v = sub.add_parser("verify", help="重開機後再次驗證並更新修復報告")
    v.add_argument("run_id")

    b = sub.add_parser("rollback", help="回滾某次執行的修改")
    b.add_argument("run_id")
    b.add_argument("--rule", metavar="TWGCB-ID", help="只回滾指定規則")

    sub.add_parser("list", help="列出歷次執行紀錄")
    return p


def main():
    _utf8_stdio()
    parser = build_parser()
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 1

    osi, err = osinfo.detect()
    if not osi:
        print(err)
        return 1
    cfg = Config(args.config, BASE)

    if args.cmd == "rules":
        print("%s\n%s\n" % (osi.pretty, osi.gcb_doc))
        for rid, rule in rules_for(osi):
            print("%-18s [%s] %-10s %s" % (rid, rule.risk, rule.category, rule.title_for(osi)))
        return 0
    if args.cmd == "list":
        if os.path.isdir(cfg.report_dir):
            for d in sorted(os.listdir(cfg.report_dir)):
                print(d)
        return 0

    if os.geteuid() != 0:
        print("請以 root 執行（sudo ./gcb.sh %s）" % args.cmd)
        return 1

    if args.cmd in ("verify", "rollback"):
        ctx = engine.load_context(cfg, osi, args.run_id, args)
        if args.cmd == "verify":
            return engine.cmd_verify(ctx)
        return engine.cmd_rollback(ctx, args.rule)

    prefix = {"health": "health_", "check": "check_", "setup": "setup_"}.get(args.cmd, "")
    ctx = engine.new_context(cfg, osi, args, prefix)
    ctx.say("GCB 檢測修復工具 v%s｜%s｜%s" % (__version__, osi.pretty, ctx.run_id))
    if osi.compatible_note:
        ctx.say("注意：" + osi.compatible_note)
    if args.cmd == "setup":
        from gcb.setup import cmd_setup
        return cmd_setup(ctx, args.config, args)
    if args.cmd == "health":
        ctx.state["pre_health"] = engine.do_health(ctx, "健康檢查")
        ctx.save()
        return 0
    if args.cmd == "check":
        return engine.cmd_check(ctx)
    return engine.cmd_run(ctx, args)


def _on_signal(signum, frame):
    # SSH 斷線（SIGHUP）或被 kill（SIGTERM）時比照 Ctrl+C 中斷，讓 finally 收尾（例如移除測試金鑰）
    raise KeyboardInterrupt


if __name__ == "__main__":
    for _sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, _on_signal)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        try:  # 斷線時終端機已關閉，輸出可能失敗
            print("\n已中斷。若修復已開始，可用 ./gcb.sh rollback <執行編號> 還原。")
        except Exception:
            pass
        sys.exit(130)
