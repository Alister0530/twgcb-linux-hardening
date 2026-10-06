# -*- coding: utf-8 -*-
"""極簡 .xlsx 產生器（只用標準函式庫，目標主機不需安裝 openpyxl）。

用法：
    wb = Workbook()
    ws = wb.sheet("摘要", widths=[20, 60])
    ws.row(["項目", "值"], style="header")
    ws.row(["合格", ("5", "pass")])     # (值, 樣式) 可個別指定
    wb.save("out.xlsx")
"""
import re
import zipfile
from xml.sax.saxutils import escape

# 樣式名稱 -> cellXfs 索引（定義於 _styles_xml）
STYLES = {"default": 0, "header": 1, "pass": 2, "fail": 3, "warn": 4, "na": 5, "title": 6, "bold": 7}

_ILLEGAL = re.compile(u"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _col(n):
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _safe_sheet_name(name, used):
    name = re.sub(r"[\[\]:*?/\\]", "_", name)[:31] or "Sheet"
    base, i = name, 2
    while name in used:
        name = (base[:28] + "_%d" % i)
        i += 1
    used.add(name)
    return name


class Sheet(object):
    def __init__(self, name, widths=None, freeze=True):
        self.name = name
        self.widths = widths or []
        self.rows = []
        self.freeze = freeze
        self.filter_row = None

    def row(self, values, style="default"):
        self.rows.append([v if isinstance(v, tuple) else (v, style) for v in values])

    def header(self, values):
        """表頭列；同時啟用自動篩選。"""
        self.filter_row = len(self.rows)
        self.row(values, "header")

    def blank(self):
        self.rows.append([])

    def _xml(self):
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
        if self.freeze and self.filter_row is not None:
            r = self.filter_row + 2
            out.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="%d" topLeftCell="A%d" '
                       'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>' % (r - 1, r))
        if self.widths:
            out.append("<cols>")
            for i, w in enumerate(self.widths):
                out.append('<col min="%d" max="%d" width="%s" customWidth="1"/>' % (i + 1, i + 1, w))
            out.append("</cols>")
        out.append("<sheetData>")
        maxc = 0
        for ri, cells in enumerate(self.rows):
            out.append('<row r="%d">' % (ri + 1))
            for ci, (val, style) in enumerate(cells):
                maxc = max(maxc, ci + 1)
                ref = "%s%d" % (_col(ci), ri + 1)
                s = STYLES.get(style, 0)
                if val is None or val == "":
                    out.append('<c r="%s" s="%d"/>' % (ref, s))
                elif isinstance(val, (int, float)) and not isinstance(val, bool):
                    out.append('<c r="%s" s="%d"><v>%s</v></c>' % (ref, s, val))
                else:
                    txt = escape(_ILLEGAL.sub("", str(val))[:32000])  # 先截字再 escape，避免切斷 &lt; 等實體
                    out.append('<c r="%s" s="%d" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>'
                               % (ref, s, txt))
            out.append("</row>")
        out.append("</sheetData>")
        if self.filter_row is not None and maxc:
            out.append('<autoFilter ref="A%d:%s%d"/>' % (self.filter_row + 1, _col(maxc - 1), len(self.rows)))
        out.append('<pageMargins left="0.5" right="0.5" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>')
        out.append("</worksheet>")
        return "".join(out)


class Workbook(object):
    def __init__(self):
        self.sheets = []
        self._names = set()

    def sheet(self, name, widths=None):
        ws = Sheet(_safe_sheet_name(name, self._names), widths)
        self.sheets.append(ws)
        return ws

    def save(self, path):
        n = len(self.sheets)
        ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
              '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
              '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
              '<Default Extension="xml" ContentType="application/xml"/>',
              '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
              '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
        for i in range(n):
            ct.append('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % (i + 1))
        ct.append("</Types>")
        rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                '</Relationships>')
        wb = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
              '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
              'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>']
        wbr = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
        for i, ws in enumerate(self.sheets):
            wb.append('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (escape(ws.name, {'"': "&quot;"}), i + 1, i + 1))
            wbr.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i + 1, i + 1))
        wb.append("</sheets>")
        # 自動篩選需要定義名稱
        names = []
        for i, ws in enumerate(self.sheets):
            if ws.filter_row is not None and ws.rows:
                maxc = max(len(r) for r in ws.rows)
                names.append('<definedName name="_xlnm._FilterDatabase" localSheetId="%d" hidden="1">\'%s\'!$A$%d:$%s$%d</definedName>'
                             % (i, escape(ws.name).replace("'", "''"), ws.filter_row + 1, _col(maxc - 1), len(ws.rows)))
        if names:
            wb.append("<definedNames>" + "".join(names) + "</definedNames>")
        wb.append("</workbook>")
        wbr.append('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (n + 1))
        wbr.append("</Relationships>")

        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", "".join(ct))
            z.writestr("_rels/.rels", rels)
            z.writestr("xl/workbook.xml", "".join(wb))
            z.writestr("xl/_rels/workbook.xml.rels", "".join(wbr))
            z.writestr("xl/styles.xml", _styles_xml())
            for i, ws in enumerate(self.sheets):
                z.writestr("xl/worksheets/sheet%d.xml" % (i + 1), ws._xml())


def _styles_xml():
    # 字型：0 一般、1 粗體、2 白色粗體、3 標題
    fonts = ('<fonts count="4">'
             '<font><sz val="11"/><name val="Microsoft JhengHei"/></font>'
             '<font><b/><sz val="11"/><name val="Microsoft JhengHei"/></font>'
             '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Microsoft JhengHei"/></font>'
             '<font><b/><sz val="14"/><name val="Microsoft JhengHei"/></font></fonts>')

    def fill(rgb):
        return '<fill><patternFill patternType="solid"><fgColor rgb="%s"/><bgColor indexed="64"/></patternFill></fill>' % rgb
    # 填色：0 無、1 gray125（規格必要）、2 表頭藍、3 綠、4 紅、5 黃、6 灰
    fills = ('<fills count="7"><fill><patternFill patternType="none"/></fill>'
             '<fill><patternFill patternType="gray125"/></fill>'
             + fill("FF305496") + fill("FFC6EFCE") + fill("FFFFC7CE") + fill("FFFFEB9C") + fill("FFE7E6E6")
             + '</fills>')
    borders = ('<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>'
               '<border><left style="thin"><color rgb="FFBFBFBF"/></left><right style="thin"><color rgb="FFBFBFBF"/></right>'
               '<top style="thin"><color rgb="FFBFBFBF"/></top><bottom style="thin"><color rgb="FFBFBFBF"/></bottom><diagonal/></border></borders>')
    align = '<alignment vertical="top" wrapText="1"/>'

    def xf(font, fill_id, border=1):
        return ('<xf numFmtId="0" fontId="%d" fillId="%d" borderId="%d" applyFont="1" applyFill="1" '
                'applyBorder="1" applyAlignment="1">%s</xf>' % (font, fill_id, border, align))
    # 順序需與 STYLES 一致
    xfs = [xf(0, 0), xf(2, 2), xf(0, 3), xf(0, 4), xf(0, 5), xf(0, 6), xf(3, 0, 0), xf(1, 0)]
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            + fonts + fills + borders +
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="%d">%s</cellXfs>' % (len(xfs), "".join(xfs)) +
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
            '</styleSheet>')
