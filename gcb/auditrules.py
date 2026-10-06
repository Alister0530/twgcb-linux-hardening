# -*- coding: utf-8 -*-
"""auditd 規則解析與比對（純函式，方便單元測試）。

用於「日誌與稽核」類的稽核規則項目（Ubuntu TWGCB-01-014-0115 起）。
設定檔寫法與 auditctl -l 的輸出格式不同（-k 與 -F key=、-w 與 -F path=、
auid!=-1 與 auid!=unset、系統呼叫順序與合併），比對前先轉成標準形式。
"""
import shlex

_UNSET = ("-1", "4294967295", "unset")


def _norm_field(f):
    for op in ("!=", ">=", "<=", "=", ">", "<", "&=", "&"):
        if op in f:
            k, v = f.split(op, 1)
            if k in ("auid", "uid", "euid", "loginuid") and v in _UNSET:
                v = "unset"
            return k + op + v
    return f


def parse(line):
    """回傳標準形式 dict；註解、空行、控制指令（-D/-b/-e…）回傳 None。"""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    try:
        tok = shlex.split(line)
    except ValueError:
        return None
    if not tok or tok[0] not in ("-w", "-a", "-A"):
        return None
    r = {"action": None, "arch": None, "syscalls": set(), "fields": set(),
         "key": None, "path": None, "perm": None}
    i = 0
    while i < len(tok):
        t = tok[i]
        v = tok[i + 1] if i + 1 < len(tok) else ""
        if t == "-w":
            r["path"] = v
        elif t == "-p":
            r["perm"] = "".join(sorted(v))
        elif t in ("-a", "-A"):
            r["action"] = ",".join(sorted(v.split(",")))
        elif t == "-S":
            r["syscalls"].update(s for s in v.split(",") if s)
        elif t == "-k":
            r["key"] = v
        elif t in ("-F", "-C"):
            f = _norm_field(v)
            if f.startswith("arch="):
                r["arch"] = f.split("=", 1)[1]
            elif f.startswith("key="):
                r["key"] = f.split("=", 1)[1]
            elif f.startswith(("path=", "dir=")) and not r["path"]:
                r["path"] = f.split("=", 1)[1]
            elif f.startswith("perm="):
                r["perm"] = "".join(sorted(f.split("=", 1)[1]))
            else:
                r["fields"].add(f)
        else:
            i += 1
            continue
        i += 2
    # auditctl -l 會把 -w 顯示成「-S all -F path=…」，且去掉目錄結尾的 /，都轉成同一形式
    if r["path"] and r["syscalls"] <= {"all"}:
        r["syscalls"] = set()
    if r["path"] and len(r["path"]) > 1:
        r["path"] = r["path"].rstrip("/")
    # 沒有系統呼叫的 path/dir 監控規則，視同 -w
    r["kind"] = "watch" if r["path"] and not r["syscalls"] else "syscall"
    r["fields"] = frozenset(r["fields"])
    return r


def _same_group(a, b):
    return (a["action"], a["arch"], a["fields"], a["key"]) == (b["action"], b["arch"], b["fields"], b["key"])


def satisfied(required_line, loaded):
    """required_line 是否已被 loaded（parse 後的清單）涵蓋。"""
    req = parse(required_line)
    if req is None:
        return True
    if req["kind"] == "watch":
        for r in loaded:
            if r["kind"] == "watch" and r["path"] == req["path"] \
                    and set(req["perm"] or "") <= set(r["perm"] or "") \
                    and (req["key"] is None or r["key"] == req["key"]):
                return True
        return False
    covered = set()
    for r in loaded:
        if r["kind"] == "syscall" and _same_group(req, r):
            covered |= r["syscalls"]
    return req["syscalls"] <= covered


def parse_all(text):
    return [r for r in (parse(l) for l in (text or "").splitlines()) if r]


def missing(required_lines, loaded_text):
    """回傳尚未生效的規則行。"""
    loaded = parse_all(loaded_text)
    return [l for l in required_lines if not satisfied(l, loaded)]
