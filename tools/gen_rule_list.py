# -*- coding: utf-8 -*-
"""從程式碼產生規則清單文件 docs/規則清單.md（開發工具；新增或修改規則後執行一次）。

用法：python3 tools/gen_rule_list.py
"""
import os
import sys
from collections import Counter

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, BASE)

from gcb import osinfo, platforms  # noqa: E402
from gcb.rules import rules_for  # noqa: E402
from gcb.rules.base import manual_reason_for  # noqa: E402

RISK = {"A": "A 自動修復", "B": "B 風險項目", "C": "C 需人工"}


def main():
    out = ["# GCB 規則清單", "",
           "由 `tools/gen_rule_list.py` 依程式碼自動產生，請勿手動編輯。"
           "修復類型（A / B / C）的定義與執行方式見 [操作手冊.md](操作手冊.md#修復類型a--b--c)。", ""]
    summary = ["## 統計", "", "| 平台 | 文件 | 規則數 | A | B | C |", "|---|---|---|---|---|---|"]
    sections = []
    for p in platforms.PLATFORMS:
        osi = osinfo.OSInfo(p.key, p.family, p.key, p.os_ids[0], p.version)
        rules = rules_for(osi)
        c = Counter(r.risk for _, r in rules)
        summary.append("| %s | %s | %d | %d | %d | %d |" % (p.key, p.doc, len(rules), c["A"], c["B"], c["C"]))
        sec = ["## %s（%s）" % (p.key, p.doc), "",
               "| TWGCB-ID | 類別 | 項目名稱 | 修復類型 | 需重開機 | 說明（C 類為無法自動修復的原因） |",
               "|---|---|---|---|---|---|"]
        for rid, r in rules:
            reason = manual_reason_for(r) if r.risk == "C" else r.doc_note
            sec.append("| %s | %s | %s | %s | %s | %s |" % (rid, r.category, r.title_for(osi).replace("|", "／"),
                                                          RISK.get(r.risk, r.risk), "是" if r.needs_reboot else "",
                                                          reason))
        sections += sec + [""]
    path = os.path.join(BASE, "docs", "規則清單.md")
    with open(path, "w") as f:
        f.write("\n".join(out + summary + [""] + sections))
    print("已產生 %s" % path)
    print("\n".join(summary[4:]))


if __name__ == "__main__":
    main()
