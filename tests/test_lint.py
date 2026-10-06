# -*- coding: utf-8 -*-
"""靜態檢查：
- 同一模組內不可重複定義同名的頂層函式或類別（後者會默默覆蓋前者）
- 「重新載入」類的回滾指令（daemon-reload、reload、restart、augenrules --load…）必須在修改檔案之前登記；
  回滾為反向執行，先登記的才會在還原檔案之後執行，服務才會讀到還原後的設定
"""
import ast
import os
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gcb")

MODIFY = {"write_file", "edit_file", "backup_only", "backup_dir"}
RELOAD_WORDS = ("reload", "restart", "--load", "flush", "apply")
RELOAD_HELPERS = {"_reload_undo", "undo_sshd"}  # 內部呼叫 fx.add_undo 登記重新載入的輔助函式


def _py_files():
    for d, _, files in os.walk(ROOT):
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(d, f)


def _name(call):
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)


def reload_undo_after_modify(source, filename="<src>"):
    """回傳 [(行號, 函式名稱)]：重新載入類回滾在同一函式中晚於檔案修改才登記。"""
    bad = []
    for fn in ast.walk(ast.parse(source, filename)):
        if not isinstance(fn, ast.FunctionDef):
            continue
        calls = sorted((n for n in ast.walk(fn) if isinstance(n, ast.Call)),
                       key=lambda n: (n.lineno, n.col_offset))
        first_mod = None
        for c in calls:
            name = _name(c)
            if name in MODIFY and first_mod is None:
                first_mod = c.lineno
            if name == "add_undo" and c.args:
                arg = ast.dump(c.args[0])
                is_reload = any(w in arg for w in RELOAD_WORDS)
            else:
                is_reload = name in RELOAD_HELPERS
            if is_reload and first_mod is not None and first_mod < c.lineno:
                bad.append((c.lineno, fn.name))
    return bad


class DuplicateDefTest(unittest.TestCase):
    def test_no_duplicate_top_level_defs(self):
        dups = []
        for path in _py_files():
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            seen = set()
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    if node.name in seen:
                        dups.append("%s:%d %s" % (os.path.relpath(path, ROOT), node.lineno, node.name))
                    seen.add(node.name)
        self.assertEqual(dups, [])


class UndoOrderTest(unittest.TestCase):
    def test_detects_wrong_order(self):
        bad = ('def fix(self, ctx, fx):\n'
               '    fx.write_file("/etc/systemd/system/x.d/a.conf", "x")\n'
               '    fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")\n')
        good = ('def fix(self, ctx, fx):\n'
                '    fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")\n'
                '    fx.write_file("/etc/systemd/system/x.d/a.conf", "x")\n')
        self.assertEqual(reload_undo_after_modify(bad), [(3, "fix")])
        self.assertEqual(reload_undo_after_modify(good), [])
        self.assertEqual(reload_undo_after_modify(bad.replace(
            'fx.add_undo(["systemctl", "daemon-reload"], "重新載入 systemd")', "_reload_undo(fx)")), [(3, "fix")])

    def test_all_rules_register_reload_before_modify(self):
        found = []
        for path in _py_files():
            with open(path, encoding="utf-8") as fh:
                for line, fn in reload_undo_after_modify(fh.read(), path):
                    found.append("%s:%d %s" % (os.path.relpath(path, ROOT), line, fn))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
