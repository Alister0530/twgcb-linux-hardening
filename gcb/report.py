# -*- coding: utf-8 -*-
"""產生 Excel 報告：不合格清單報告、修復情況報告。"""
import os

from .xlsx import Workbook


def style_of(text):
    t = str(text or "")
    if t.startswith(("合格", "通過", "已修復", "無需修復", "改善", "正常", "成功")):
        return "pass"
    if t.startswith(("不合格", "失敗", "修復失敗", "退步", "異常", "檢測失敗")):
        return "fail"
    if t.startswith(("警告", "需人工", "部分", "已跳過", "預覽", "新增失敗", "修復後停止")) or "已回滾" in t:
        return "warn"
    if t.startswith(("不適用", "已排除", "略過", "資訊", "無變化", "未執行")):
        return "na"
    return "default"


def _s(text):
    return (text, style_of(text))


def _summarize(checks):
    from .engine import summarize
    return summarize(checks)


def _host_rows(ws, st):
    o = st["os"]
    ws.row(["主機名稱", st["host"]])
    ws.row(["IP 位址", st["ip"]])
    ws.row(["作業系統", o["pretty"] + ("（%s）" % o["note"] if o.get("note") else "")])
    ws.row(["適用 GCB 文件", o["doc"]])
    ws.row(["執行編號", st["run_id"]])
    ws.row(["開始時間", st["started"]])


def _check_sheet(wb, name, checks, only_bad=False):
    ws = wb.sheet(name, widths=[6, 20, 14, 30, 34, 50, 10, 24, 40, 50, 50])
    ws.header(["項次", "TWGCB-ID", "類別", "項目名稱", "GCB 設定值", "目前狀態", "檢測結果", "修復方式",
               "無法自動修復的原因", "人工處理方式", "檢測失敗的可能原因與建議"])
    n = 0
    for c in checks:
        if only_bad and c["status"] in ("合格", "不適用"):
            continue
        n += 1
        ws.row([n, c["id"], c["category"], c["title"], c["expected"], c["current"], _s(c["status"]),
                c["risk_label"], c.get("reason", ""), c.get("hint", ""), "\n".join(c.get("advice", []))])
    return ws


def _health_sheet(wb, name, items):
    ws = wb.sheet(name, widths=[8, 26, 8, 10, 70, 50])
    ws.header(["編號", "檢查項目", "關鍵", "結果", "說明", "可能原因與建議"])
    for i in items:
        ws.row([i["id"], i["name"], "是" if i["critical"] else "", _s(i["status"]), i["detail"],
                "\n".join(i.get("advice", []))])


def detection_report(ctx):
    st = ctx.state
    checks = st["checks_before"]
    s = _summarize(checks)
    wb = Workbook()
    ws = wb.sheet("摘要", widths=[22, 70])
    ws.row([("GCB 不合格清單報告", "title")])
    ws.blank()
    _host_rows(ws, st)
    ws.blank()
    ws.row([("檢測統計", "bold")])
    ws.row(["檢測項目數", s["total"]])
    ws.row(["合格", (s["pass"], "pass")])
    ws.row(["不合格", (s["fail"], "fail" if s["fail"] else "default")])
    ws.row(["不適用", s["na"]])
    ws.row(["檢測失敗", (s["err"], "warn" if s["err"] else "default")])
    ws.row(["合規率", s["rate"]])
    ws.row(["", "合規率 = 合格 ÷（合格 + 不合格 + 檢測失敗）"])
    pre = st.get("pre_health", [])
    if pre:
        ws.blank()
        bad = [i for i in pre if i["status"] == "失敗"]
        ws.row([("前測健康檢查", "bold")])
        ws.row(["失敗項目", (("、".join("%s %s" % (i["id"], i["name"]) for i in bad)) or "無",
                         "fail" if bad else "pass")])
    _check_sheet(wb, "不合格清單", checks, only_bad=True)
    _check_sheet(wb, "全部檢測結果", checks)
    if pre:
        _health_sheet(wb, "前測健康檢查", pre)
    path = os.path.join(ctx.run_dir, "GCB不合格清單_%s.xlsx" % st["run_id"])
    wb.save(path)
    return path


def remediation_report(ctx):
    st = ctx.state
    before = st.get("checks_before", [])
    after = st.get("checks_after", [])
    fixes = st.get("fixes", [])
    s0 = _summarize(before)
    s1 = _summarize(after) if after else None
    wb = Workbook()

    # ---- 摘要 ----
    ws = wb.sheet("摘要", widths=[24, 80])
    ws.row([("GCB 修復情況報告" + ("（預覽修改內容，未修改系統）" if st.get("mode") == "dry-run" else ""), "title")])
    ws.blank()
    _host_rows(ws, st)
    args = st.get("args", {})
    ws.row(["執行參數", "include-risky=%s、dry-run=%s" % (args.get("include_risky"), args.get("dry_run"))])
    ws.blank()
    ws.row([("合規率", "bold")])
    ws.row(["修復前", "%s（合格 %d / 不合格 %d）" % (s0["rate"], s0["pass"], s0["fail"])])
    rb = st.get("rollback")
    if s1:
        label = "修復後（回滾前）" if rb else "修復後"
        ws.row([label, ("%s（合格 %d / 不合格 %d）" % (s1["rate"], s1["pass"], s1["fail"]), "bold")])
    if rb:
        ws.row(["回滾後", _s("已回滾，系統設定回到修復前（合規率同「修復前」）")])
    if st.get("verify"):
        sv = _summarize(st["verify"][-1]["checks"])
        ws.row(["重開機後", "%s（%s 驗證）" % (sv["rate"], st["verify"][-1]["time"])])
    ws.blank()
    ws.row([("處理結果統計", "bold")])
    counts = {}
    for f in fixes:
        key = f["outcome"].split("：")[0]
        counts[key] = counts.get(key, 0) + 1
    for k in sorted(counts):
        ws.row([_s(k), counts[k]])
    ws.blank()
    ws.row([("系統正常性驗證", "bold")])
    cmp_ = st.get("compare", {})
    regress = ["%s %s" % (k, v[0]) for k, v in sorted(cmp_.items()) if v[0].startswith(("退步", "新增", "修復後停止"))]
    if "post_health" in st:
        ws.row(["後測退步項目", _s("、".join(regress) if regress else "無（正常）")])
    ws.row(["人工登入確認", _s(st.get("manual_confirm", "未執行"))])
    ws.row(["自動/手動回滾", _s("已回滾：%s（%s）" % (rb["reason"], rb["time"]) if rb else "無")])
    for m in st.get("manual_rollbacks", []):
        ws.row(["單一規則回滾", _s("已回滾 %s（%s；成功 %d 項、失敗 %d 項）" % (m["rule"], m["time"], m["ok"], m["fail"]))])
    reboot = [] if rb else [f["id"] for f in fixes if f.get("needs_reboot") and "回滾" not in f["outcome"]]
    ws.row(["需重開機生效", "、".join(reboot) if reboot else "無"])
    if reboot:
        ws.row(["", "重開機後請執行 ./gcb.sh verify %s 進行驗證" % st["run_id"]])
    ws.row(["修復 log", os.path.join(ctx.run_dir, "remediation.log")])
    ws.row(["備份與回滾紀錄", os.path.join(ctx.run_dir, "backup")
            + "、rollback.json（./gcb.sh rollback %s）" % st["run_id"]])

    # ---- 修復明細 ----
    after_map = {c["id"]: c for c in after}
    ws = wb.sheet("修復明細", widths=[6, 20, 14, 30, 22, 10, 40, 22, 10, 40, 50, 55])
    ws.header(["項次", "TWGCB-ID", "類別", "項目名稱", "修復方式", "修復前結果", "修復前狀態",
               "處理結果", "修復後結果", "修復後狀態", "備註", "可能原因與建議"])
    for n, f in enumerate(fixes, 1):
        a = after_map.get(f["id"], {})
        if "回滾" in f["outcome"]:
            a = {"status": "已回滾", "current": "已還原為修復前：" + f["before_current"]}
        ws.row([n, f["id"], f["category"], f["title"], f["risk_label"], _s(f["before"]), f["before_current"],
                _s(f["outcome"]), _s(a.get("status", "")), a.get("current", ""), "\n".join(f.get("notes", [])),
                "\n".join(f.get("advice", []))])

    # ---- 健康檢查對照 ----
    pre = st.get("pre_health", [])
    post = {i["id"]: i for i in st.get("post_health", [])}
    rbh = {i["id"]: i for i in st.get("rollback_health", [])}
    ws = wb.sheet("健康檢查對照", widths=[8, 24, 6, 10, 45, 10, 45, 22] + ([10] if rbh else []))
    hdr = ["編號", "檢查項目", "關鍵", "前測", "前測說明", "後測", "後測說明", "變化"]
    ws.header(hdr + (["回滾後"] if rbh else []))
    for i in pre:
        p = post.get(i["id"], {})
        chg = cmp_.get(i["id"], ["", False])[0]
        row = [i["id"], i["name"], "是" if i["critical"] else "", _s(i["status"]), i["detail"],
               _s(p.get("status", "")), "\n".join([p.get("detail", "")] + p.get("advice", [])), _s(chg)]
        if rbh:
            row.append(_s(rbh.get(i["id"], {}).get("status", "")))
        ws.row(row)

    # ---- 修復步驟紀錄 ----
    ws = wb.sheet("修復步驟紀錄", widths=[20, 20, 30, 14, 100])
    ws.header(["時間", "TWGCB-ID", "動作", "結果", "內容"])
    for s in st.get("steps", []):
        ws.row([s["time"], s["rule"], s["action"], _s(s["result"]), s["detail"]])

    # ---- 重開機後驗證 ----
    for idx, v in enumerate(st.get("verify", []), 1):
        ws = wb.sheet("重開機後驗證%d" % idx, widths=[20, 30, 10, 60, 22])
        ws.row([("驗證時間：%s" % v["time"], "bold")])
        ws.header(["編號/TWGCB-ID", "項目", "結果", "說明", "與前測比較"])
        for i in v["health"]:
            ws.row([i["id"], i["name"], _s(i["status"]), i["detail"], _s(v["compare"].get(i["id"], [""])[0])])
        ws.blank()
        for c in v["checks"]:
            ws.row([c["id"], c["title"], _s(c["status"]), c["current"], ""])

    path = os.path.join(ctx.run_dir, "GCB修復報告_%s.xlsx" % st["run_id"])
    wb.save(path)
    return path
