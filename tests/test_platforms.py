# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import osinfo, platforms  # noqa: E402
from gcb.rules import rules_for  # noqa: E402


def detect(text):
    f = tempfile.NamedTemporaryFile("w", delete=False)
    f.write(text)
    f.close()
    return osinfo.detect(f.name)


class PlatformTest(unittest.TestCase):
    def test_detect(self):
        cases = [('ID="rocky"\nVERSION_ID="9.3"\n', "rhel9"), ('ID="rhel"\nVERSION_ID="8.10"\n', "rhel8"),
                 ('ID=ubuntu\nVERSION_ID="22.04"\n', "ubuntu2204"), ('ID=almalinux\nVERSION_ID="8.9"\n', "rhel8")]
        for text, key in cases:
            self.assertEqual(detect(text)[0].key, key)

    def test_unsupported(self):
        osi, msg = detect('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04"\n')
        self.assertIsNone(osi)
        self.assertIn("Ubuntu 24.04", msg)

    def test_rule_ids(self):
        self.assertEqual(platforms.rule_ids(rhel8=1, rhel9=12),
                         {"rhel8": "TWGCB-01-008-0001", "rhel9": "TWGCB-01-012-0012"})

    def test_every_platform_has_rules_and_unique_ids(self):
        for p in platforms.PLATFORMS:
            osi = osinfo.OSInfo(p.key, p.family, p.key, p.os_ids[0], p.version)
            rules = rules_for(osi)  # 重複編號會丟出例外
            self.assertTrue(rules, p.key)
            for rid, _ in rules:
                self.assertTrue(rid.startswith("TWGCB-01-%s-" % p.doc_no), rid)


class DocumentMatchTest(unittest.TestCase):
    """程式中的規則與 GCB 原文（docs/gcb/<平台>/chunks.json）一一對應，且項目名稱與原文一致。"""

    def test_ids_and_titles_match_documents(self):
        import json
        import re
        base = os.path.join(os.path.dirname(__file__), "..", "docs", "gcb")
        for p in platforms.PLATFORMS:
            path = os.path.join(base, p.key, "chunks.json")
            if not os.path.exists(path):
                continue
            doc = dict((v["id"], re.sub(r"\s", "", v["text"])) for v in json.load(open(path)).values())
            osi = osinfo.OSInfo(p.key, p.family, p.key, p.os_ids[0], p.version)
            code = dict(rules_for(osi))
            self.assertEqual(sorted(doc), sorted(code), "%s 規則編號與文件不一致" % p.key)
            for rid, r in code.items():
                self.assertTrue(_title_in_doc(r.title_for(osi), doc[rid]),
                                "%s 項目名稱「%s」與原文不符" % (rid, r.title_for(osi)))


def _title_in_doc(title, text):
    """名稱完全出現在原文；或原文名稱在表格欄寬處被截斷（相同部分之後緊接「▪」）。"""
    import re
    t, d = re.sub(r"\s", "", title), text[:600]
    if t in d:
        return True
    i = d.find(t[:6])
    if i < 0:
        return False
    n = 0
    while n < len(t) and i + n < len(d) and t[n] == d[i + n]:
        n += 1
    return n >= 6 and i + n < len(d) and d[i + n] == "▪"


class ManualReasonTest(unittest.TestCase):
    def test_every_c_rule_has_reason_and_hint(self):
        from gcb.rules.base import manual_reason_for
        for p in platforms.PLATFORMS:
            osi = osinfo.OSInfo(p.key, p.family, p.key, p.os_ids[0], p.version)
            for rid, r in rules_for(osi):
                if r.risk == "C":
                    self.assertTrue((r.manual_hint or "").strip(), "%s 沒有人工處理方式" % rid)
                    self.assertFalse(manual_reason_for(r).startswith("自動修改可能影響系統運作"),
                                     "%s 沒有明確的無法自動修復原因" % rid)


if __name__ == "__main__":
    unittest.main()
