# -*- coding: utf-8 -*-
"""把 GCB 官方 PDF 切成「一條規則一段文字」，供規格分析使用（開發工具，不部署到 VM）。

用法：
    python3 tools/gcb_pdf_split.py <PDF 檔> <輸出 chunks.json>

輸出 JSON：{"全文順序": {"seq", "table": 表格序號, "no": 表內項次, "id": "TWGCB-01-0xx-NNNN", "text": 原文}}
- 以表格「項次」（1, 2, 3…連號）切段，不依賴 TWGCB-ID 連號（RHEL 9 的編號不連續）。
- PDF 表格各欄的文字會交錯，分析時要人工重組。
需要 pypdf：pip3 install pypdf
"""
import json
import re
import sys

from pypdf import PdfReader

FOOTER = re.compile(r"本文件之智慧財產權屬數位發展部資通安全署擁有。\s*\n\d+\s*\n")
HEADER = re.compile(r"項\s*次\s*TWG\s*CB-ID\s*類別\s*原則設定\s*名稱\s*說明\s*設定方法\s*GCB\s*設定值")


def load_body(pdf):
    """取規範列表的本文（「2. … 政府組態基準列表」到「參考文獻」之間）。"""
    pages = [(p.extract_text() or "") for p in PdfReader(pdf).pages]
    text = FOOTER.sub("", "\n".join(pages))
    flat = re.sub(r"\s*\n\s*", " ", text)
    start = flat.find("政府組態基準列表(基本項目)")
    start = flat.find("TWG", start)
    end = flat.rfind("參考文獻")
    return HEADER.sub(" ", flat[start:end if end > start else len(flat)])


def split(body, doc_no):
    """以「項次 TWG CB-」切段（換頁時 01- 可能被擠到後面，所以只比對到 CB-）。

    基本項目表之後的附加表格（校時、防火牆、SSH…）項次會從 1 重新開始，
    因此依序處理多個表格，key 用全文順序編號，另記錄表格序號與表內項次。
    """
    row_rx = re.compile(r"(?<![\d.])(\d{1,3})\s+TWG\s*CB-")
    rows, pos, table = [], 0, 1
    while True:
        expect, found_any = 1, False
        while True:
            m = next((c for c in row_rx.finditer(body, pos) if int(c.group(1)) == expect), None)
            # 下一個表格的第 1 項如果比本表下一項更早出現，代表本表已結束
            if m and expect > 1:
                nxt = next((c for c in row_rx.finditer(body, pos) if int(c.group(1)) == 1), None)
                if nxt and nxt.start() < m.start():
                    m = None
            if not m:
                break
            rows.append((table, expect, m.start()))
            pos, expect, found_any = m.end(), expect + 1, True
        if not found_any:
            break
        table += 1
    out = {}
    id_rx = re.compile(r"%s-\s?(\d{4})" % doc_no)
    for i, (tb, no, start) in enumerate(rows):
        end = rows[i + 1][2] if i + 1 < len(rows) else len(body)
        text = body[start:end]
        m = id_rx.search(text)
        out[str(i + 1)] = {"seq": i + 1, "table": tb, "no": no,
                           "id": "TWGCB-01-%s-%s" % (doc_no, m.group(1)) if m else None, "text": text}
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    pdf, out = sys.argv[1], sys.argv[2]
    doc_no = re.search(r"TWGCB-01-(\d{3})", pdf).group(1)
    rows = split(load_body(pdf), doc_no)
    with open(out, "w") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)
    missing = [k for k, v in rows.items() if not v["id"]]
    ids = [v["id"] for v in rows.values() if v["id"]]
    dup = sorted(set(i for i in ids if ids.count(i) > 1))
    tables = {}
    for v in rows.values():
        tables[v["table"]] = tables.get(v["table"], 0) + 1
    print("%s：共 %d 條，各表格條數 %s，缺 TWGCB-ID：%s，重複 ID：%s" % (
        pdf.split("/")[-1][:12], len(rows), tables, "、".join(missing) or "無", "、".join(dup) or "無"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
