# -*- coding: utf-8 -*-
"""測試涵蓋率（只用標準函式庫，相容 Python 3.6）。

用法：
    # 單元測試 + 容器測試合併的涵蓋率
    COV_DIR=$PWD/tests/out/cov tests/docker_test.sh rockylinux:9      （可多個平台、也可用 docker_scenarios.sh）
    python3 tools/coverage.py report tests/out/cov

    # 只看單元測試
    python3 tools/coverage.py report

    # 列出某檔案未涵蓋的行號（可加容器測試資料目錄）
    python3 tools/coverage.py missing gcb/rules/rhel/ssh.py [tests/out/cov]

容器內由 gcb.sh 改呼叫 `coverage.py trace <gcb.py> 參數…`，每次執行把命中的行寫入 $COV_DIR/*.json。
"""
import ast
import json
import os
import sys
import trace

BASE = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def _rel(path, root):
    p = os.path.realpath(path)
    return os.path.relpath(p, root) if p.startswith(root + os.sep) else None


def _hits(tracer, root):
    out = set()
    for (fn, ln), c in tracer.results().counts.items():
        r = _rel(fn, root)
        if c and r and (r == "gcb.py" or r.startswith("gcb" + os.sep)):
            out.add((r, ln))
    return out


def cmd_trace(argv):
    """在容器內執行 gcb.py 並記錄命中的行。"""
    import runpy
    script = os.path.realpath(argv[0])
    root = os.path.dirname(script)
    sys.argv = [script] + argv[1:]
    sys.path.insert(0, root)
    tracer = trace.Trace(count=1, trace=0, ignoredirs=[sys.prefix, sys.exec_prefix])
    code = 0
    try:
        tracer.runfunc(runpy.run_path, script, run_name="__main__")
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    finally:
        out = os.environ.get("COV_OUT", "/cov")
        if os.path.isdir(out):
            name = "%s_%d.json" % (os.uname()[1], os.getpid())
            with open(os.path.join(out, name), "w") as f:
                json.dump(sorted(_hits(tracer, root)), f)
    sys.exit(code)


def _unit_hits():
    import unittest
    sys.path.insert(0, BASE)
    tracer = trace.Trace(count=1, trace=0, ignoredirs=[sys.prefix, sys.exec_prefix])

    def run():
        tests = os.path.join(BASE, "tests")
        sys.path.insert(0, tests)
        suite = unittest.defaultTestLoader.discover(tests, top_level_dir=tests)
        with open(os.devnull, "w") as null:
            res = unittest.TextTestRunner(stream=null).run(suite)
        if not res.wasSuccessful():
            print("注意：單元測試有失敗（%d 失敗、%d 錯誤）" % (len(res.failures), len(res.errors)))
    tracer.runfunc(run)
    return _hits(tracer, BASE)


def _exec_lines(path):
    """可執行的行：AST 中的敘述（排除 def / class / import / global 與 docstring）。"""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    lines = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.stmt) or isinstance(n, (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom,
                                                        ast.Global, ast.Nonlocal)):
            continue
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            continue
        lines.add(n.lineno)
    return lines


def _container_hits(dirs):
    cont = set()
    for d in dirs:
        for f in sorted(os.listdir(d)):
            if f.endswith(".json"):
                with open(os.path.join(d, f)) as fh:
                    cont |= set(tuple(x) for x in json.load(fh))
    return cont


def cmd_missing(argv):
    target = os.path.relpath(os.path.realpath(argv[0]), BASE)
    hits = {ln for f, ln in _unit_hits() | _container_hits(argv[1:]) if f == target}
    miss = sorted(_exec_lines(os.path.join(BASE, target)) - hits)
    # 連續行號合併成區間
    spans, start = [], None
    for i, ln in enumerate(miss):
        if start is None:
            start = ln
        if i + 1 == len(miss) or miss[i + 1] != ln + 1:
            spans.append(str(start) if start == ln else "%d-%d" % (start, ln))
            start = None
    total = len(_exec_lines(os.path.join(BASE, target)))
    print("%s：未涵蓋 %d / %d 行" % (target, len(miss), total))
    print(", ".join(spans))


def cmd_report(argv):
    unit = _unit_hits()
    cont = _container_hits(argv)
    files = ["gcb.py"] + sorted(os.path.relpath(os.path.join(dp, f), BASE)
                                for dp, _, fs in os.walk(os.path.join(BASE, "gcb")) for f in fs if f.endswith(".py"))
    rows, tot = [], [0, 0, 0]
    for r in files:
        el = _exec_lines(os.path.join(BASE, r))
        u = {ln for f, ln in unit if f == r} & el
        a = ({ln for f, ln in cont if f == r} & el) | u
        rows.append((r, len(el), len(u), len(a)))
        tot = [tot[0] + len(el), tot[1] + len(u), tot[2] + len(a)]

    def pct(n, d):
        return "%5.1f%%" % (n * 100.0 / d) if d else "    —"
    both = bool(argv)
    print("| 檔案 | 可執行行數 | 單元測試 |%s" % (" 合計（含容器測試） |" if both else ""))
    print("|---|---:|---:|%s" % ("---:|" if both else ""))
    for r, n, u, a in sorted(rows, key=lambda x: (x[3] if both else x[2]) * 1.0 / (x[1] or 1)):
        print("| %s | %d | %s |%s" % (r, n, pct(u, n), (" %s |" % pct(a, n)) if both else ""))
    print("| **整體** | %d | %s |%s" % (tot[0], pct(tot[1], tot[0]), (" %s |" % pct(tot[2], tot[0])) if both else ""))


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "trace":
        cmd_trace(sys.argv[2:])
    elif len(sys.argv) >= 3 and sys.argv[1] == "missing":
        cmd_missing(sys.argv[2:])
    elif len(sys.argv) >= 2 and sys.argv[1] == "report":
        cmd_report(sys.argv[2:])
    else:
        print(__doc__)
        sys.exit(2)
