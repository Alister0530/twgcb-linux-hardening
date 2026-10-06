# -*- coding: utf-8 -*-
"""RHEL 8 / 9 系統設定與維護（RHEL 8 0048–0091；RHEL 9 0048–0091、0301–0307）。"""
import glob
import grp
import os
import pwd
import re
import shlex
import stat
import time

from ... import pkgsvc
from ... import textedit as te
from ...fixer import ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from ..generic import FilePerm, installed
from .helpers import R

CAT = "系統設定與維護"
NOLOGIN = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")


def _show(items, n=10):
    s = "、".join(items[:n])
    return s + ("…等共 %d 個" % len(items) if len(items) > n else "")


def _uname(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


_gname_cache = {}


def _gname(gid):
    if gid not in _gname_cache:
        try:
            _gname_cache[gid] = grp.getgrgid(gid).gr_name
        except KeyError:
            _gname_cache[gid] = str(gid)
    return _gname_cache[gid]


# ====================================================================
# 全檔案系統掃描（0061–0065）：只掃本機檔案系統、設逾時、結果快取
# ====================================================================

LOCAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "vfat", "exfat", "f2fs", "jfs", "reiserfs",
            "ntfs", "ntfs3", "tmpfs")
SKIP_PREFIX = ("/proc", "/sys", "/dev", "/run")
SCAN_TIMEOUT = 1200
_fs_cache = {}


def _unoct(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def proc_mounts():
    """回傳 [(裝置, 掛載點, 類型, 選項清單)]。"""
    out = []
    for line in (read_text("/proc/self/mounts") or "").splitlines():
        p = line.split()
        if len(p) >= 4:
            out.append((_unoct(p[0]), _unoct(p[1]), p[2], p[3].split(",")))
    return out


def scan_roots(mounts=None):
    """本機檔案系統掛載點（白名單：排除網路、虛擬、唯讀映像），同一裝置只掃一次。"""
    roots, devs = [], set()
    for dev, mp, fstype, opts in sorted(mounts if mounts is not None else proc_mounts(), key=lambda m: len(m[1])):
        if mp != "/" and any(mp == p or mp.startswith(p + "/") for p in SKIP_PREFIX):
            continue
        if not (fstype in LOCAL_FS or (fstype == "overlay" and mp == "/")):
            continue  # nfs、cifs、fuse.*、squashfs 等不掃
        if not os.path.isdir(mp):
            continue
        try:
            d = os.stat(mp).st_dev
        except OSError:
            continue
        if d in devs:
            continue
        devs.add(d)
        roots.append(mp)
    return roots


def parse_fs_scan(out):
    """解析 find -printf 輸出（\\0 分隔）。"""
    res = {"ww": [], "nouser": [], "nogroup": [], "wwdir_uid": [], "wwdir_gid": []}
    keys = {"U": "nouser", "G": "nogroup", "D": "wwdir_uid", "E": "wwdir_gid"}
    for rec in out.split("\0"):
        p = rec.split("\t", 2)
        if p[0] == "W" and len(p) == 2:
            res["ww"].append(p[1])
        elif p[0] in keys and len(p) == 3:
            res[keys[p[0]]].append((p[1], p[2]))
    return res


def fs_scan():
    """一次 find 找出 0061–0065 所需項目（快取 2 分鐘）。回傳 dict 或錯誤字串。"""
    c = _fs_cache.get("r")
    if c and time.time() - c[0] < 120:
        return c[1]
    roots = scan_roots()
    if not roots:
        return "找不到可掃描的本機檔案系統"
    prune = []
    for p in SKIP_PREFIX:
        prune += ["-path", p, "-o"]
    ww_dir = ["-type", "d", "-perm", "-0002"]
    cmd = ["find"] + roots + ["-xdev", "("] + prune[:-1] + [
        ")", "-prune", "-o", "(",
        "(", "-type", "f", "-perm", "-0002", "-printf", "W\t%p\\0", ")", ",",
        "(", "-nouser", "-printf", "U\t%U\t%p\\0", ")", ",",
        "(", "-nogroup", "-printf", "G\t%G\t%p\\0", ")", ",",
        "("] + ww_dir + ["-uid", "+999", "-printf", "D\t%U\t%p\\0", ")", ",",
                        "("] + ww_dir + ["-gid", "+999", "-printf", "E\t%G\t%p\\0", ")", ")"]
    r = run(cmd, timeout=SCAN_TIMEOUT)
    if r.rc == 124:
        return "檔案系統掃描逾時（%d 秒），請於離峰時間人工執行 find (掛載點) -xdev 檢查" % SCAN_TIMEOUT
    if r.rc == 127:
        return "找不到 find 指令"
    res = parse_fs_scan(r.out)
    res["roots"] = roots
    _fs_cache["r"] = (time.time(), res)
    return res


# [FsScan] RHEL8 0061–0065 / RHEL9 0061–0065 全域可寫檔案、無擁有者/群組、全域可寫目錄之擁有者/群組（C 類）
class FsScan(Rule):
    category = CAT
    risk = "C"
    LABEL = {"nouser": "uid", "nogroup": "gid", "wwdir_uid": "擁有者", "wwdir_gid": "群組"}

    def __init__(self, title, ids, kind, expected, manual_hint):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.expected = expected
        self.manual_hint = manual_hint

    def check(self, ctx):
        res = fs_scan()
        if not isinstance(res, dict):
            return Check(ERROR, res)
        items = res[self.kind]
        scope = "掃描範圍：%s" % "、".join(res["roots"])
        if not items:
            return Check(PASS, "未發現；" + scope)
        if self.kind == "ww":
            shown = items
        else:
            lab = self.LABEL[self.kind]
            shown = []
            for i, p in items:
                if self.kind == "wwdir_uid":
                    i = _uname(int(i)) if i.isdigit() else i
                elif self.kind == "wwdir_gid":
                    i = _gname(int(i)) if i.isdigit() else i
                shown.append("%s（%s=%s）" % (p, lab, i))
        return Check(FAIL, "%d 個：%s；%s" % (len(items), _show(shown), scope))


# ====================================================================
# 系統命令與程式庫（0066–0071）
# ====================================================================

CMD_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin")
LIB_DIRS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64")
CMD_GROUPS = ("root", "tty", "slocate", "lock")
TREE_TIMEOUT = 900
_tree_cache = {}
_rpm_cache = {}


def tree_scan(dirs, deadline=None):
    """走訪目錄（等同 find -L：項目以目標屬性判斷；不跟隨目錄連結避免迴圈，壞掉的連結略過）。

    回傳 dict(mode=[], file_mode=[], owner=[], group=[], cmd_group=[]，roots=[...]) 或錯誤字串；
    每個項目為 (顯示路徑, 實際路徑, mode, uid, gid)，同一目標只列一次。
    """
    roots, seen = [], set()
    for d in dirs:
        if not os.path.isdir(d):
            continue
        real = os.path.realpath(d)
        if real not in roots:
            roots.append(real)
    res = {"mode": [], "file_mode": [], "owner": [], "group": [], "cmd_group": [], "roots": roots}

    def visit(path):
        try:
            st = os.stat(path)
        except OSError:
            return  # 壞掉的連結
        k = (st.st_dev, st.st_ino)
        if k in seen:
            return
        seen.add(k)
        real = os.path.realpath(path)
        item = (path if real == path else "%s → %s" % (path, real), real,
                st.st_mode & 0o7777, st.st_uid, st.st_gid)
        if st.st_mode & 0o022:
            res["mode"].append(item)
            if stat.S_ISREG(st.st_mode):
                res["file_mode"].append(item)
        if st.st_uid != 0:
            res["owner"].append(item)
        if st.st_gid != 0:
            res["group"].append(item)
            if _gname(st.st_gid) not in CMD_GROUPS:
                res["cmd_group"].append(item)

    n = 0
    for r in roots:
        for root, dnames, fnames in os.walk(r):
            visit(root)  # 一般子目錄會在下一輪以 root 身分檢查
            for name in dnames:
                p = os.path.join(root, name)
                if os.path.islink(p):
                    visit(p)
            for name in fnames:
                visit(os.path.join(root, name))
            n += 1
            if deadline and n % 200 == 0 and time.time() > deadline:
                return "掃描 %s 逾時（%d 秒）" % ("、".join(roots), TREE_TIMEOUT)
    return res


def tree_result(dirs):
    c = _tree_cache.get(dirs)
    if c and time.time() - c[0] < 120:
        return c[1]
    res = tree_scan(dirs, time.time() + TREE_TIMEOUT)
    if isinstance(res, dict):
        _tree_cache[dirs] = (time.time(), res)
    return res


def rpm_file_attrs():
    """{檔案路徑: (使用者, 群組)}：所有已安裝 RPM 套件定義的擁有者（快取 5 分鐘）。"""
    c = _rpm_cache.get("r")
    if c and time.time() - c[0] < 300:
        return c[1]
    out = {}
    if which("rpm"):
        r = run(["rpm", "-qa", "--qf", "[%{FILENAMES}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\n]"], timeout=600)
        for line in r.out.splitlines():
            p = line.split("\t")
            if len(p) == 3:
                out[p[0]] = (p[1], p[2])
    _rpm_cache["r"] = (time.time(), out)
    return out


def rpm_default(real, kind, attrs):
    """RPM 是否本來就把此檔案設為非 root 擁有者/群組；回傳說明或 None。"""
    a = attrs.get(real)
    if not a:
        return None
    if kind == "owner" and a[0] != "root":
        return "套件預設擁有者 %s" % a[0]
    if kind == "group" and a[1] != "root":
        return "套件預設群組 %s" % a[1]
    return None


# [TreePerm] RHEL8 0066–0071 / RHEL9 0066–0071 系統命令與程式庫檔案之權限、擁有者、擁有群組
class TreePerm(Rule):
    """kind：mode / file_mode（go-w）、owner、group（改為 root）、cmd_group（C 類，只檢測）。

    修復不照文件 chmod 755：只移除 go-w，保留 setuid/setgid；chown/chgrp 後還原原 mode
    （核心會在變更擁有者時清除 setuid/setgid）。RPM 本來就設為非 root 的項目列人工處理。
    """
    category = CAT

    def __init__(self, title, ids, dirs, kind, expected, risk, manual_hint=""):
        self.title = title
        self.ids = ids
        self.dirs = dirs
        self.kind = kind
        self.expected = expected
        self.risk = risk
        self.manual_hint = manual_hint

    def _desc(self, item):
        path, real, mode, uid, gid = item
        if self.kind in ("mode", "file_mode"):
            return "%s（%04o）" % (path, mode)
        if self.kind == "owner":
            return "%s（擁有者 %s）" % (path, _uname(uid))
        return "%s（群組 %s）" % (path, _gname(gid))

    def check(self, ctx):
        res = tree_result(self.dirs)
        if not isinstance(res, dict):
            return Check(ERROR, res)
        bad = res[self.kind]
        scope = "範圍：%s" % "、".join(res["roots"])
        if not bad:
            return Check(PASS, "皆符合；" + scope)
        shown = [self._desc(i) for i in bad[:10]]
        if self.kind in ("owner", "group", "cmd_group"):
            attrs = rpm_file_attrs()
            k = "owner" if self.kind == "owner" else "group"
            shown = [s + ("（%s）" % rpm_default(i[1], k, attrs) if rpm_default(i[1], k, attrs) else "")
                     for s, i in zip(shown, bad[:10])]
        more = "…等共 %d 個" % len(bad) if len(bad) > 10 else ""
        return Check(FAIL, "%s%s；%s" % ("、".join(shown), more, scope))

    def fix(self, ctx, fx):
        _tree_cache.clear()
        res = tree_scan(self.dirs, time.time() + TREE_TIMEOUT)
        if not isinstance(res, dict):
            raise ManualRequired(res)
        attrs = rpm_file_attrs() if self.kind in ("owner", "group") else {}
        keep = []
        for item in res[self.kind]:
            path, real, mode, uid, gid = item
            if self.kind in ("mode", "file_mode"):
                fx.chmod(real, mode & ~0o022)
                continue
            why = rpm_default(real, self.kind, attrs)
            if why:
                keep.append("%s（%s）" % (path, why))
                continue
            if self.kind == "owner":
                fx.chown(real, 0, gid, "root:%s" % _gname(gid))
            else:
                fx.chown(real, uid, 0, "%s:root" % _uname(uid))
            if not ctx.dry_run and os.stat(real).st_mode & 0o7777 != mode:
                fx.chmod(real, mode)  # 還原被清除的 setuid/setgid
        _tree_cache.clear()
        if keep:
            fx.partial = True
            fx.note("以下項目由 RPM 套件設定為非 root，變更會破壞功能，未修改，請人工確認是否列為例外：" + _show(keep))


# ====================================================================
# 帳號資料庫（0075–0078、0086–0091）
# ====================================================================

def parse_passwd(text=None):
    """回傳 [dict(name, pw, uid, gid, home, shell)]（欄位不足或 +/- 開頭的行略過）。"""
    out = []
    for line in (read_text("/etc/passwd") if text is None else text or "").splitlines():
        f = line.split(":")
        if len(f) < 7 or not f[0] or f[0].startswith(("+", "-")):
            continue
        out.append({"name": f[0], "pw": f[1], "uid": f[2], "gid": f[3], "home": f[5], "shell": f[6]})
    return out


def parse_group(text=None):
    """回傳 [dict(name, gid, members)]。"""
    out = []
    for line in (read_text("/etc/group") if text is None else text or "").splitlines():
        f = line.split(":")
        if len(f) < 4 or not f[0] or f[0].startswith(("+", "-")):
            continue
        out.append({"name": f[0], "gid": f[2], "members": [m for m in f[3].split(",") if m.strip()]})
    return out


def _names(path):
    return [l.split(":", 1)[0] for l in (read_text(path) or "").splitlines() if l.strip() and ":" in l]


def _dups(names):
    seen = {}
    for n in names:
        seen[n] = seen.get(n, 0) + 1
    return [n for n in sorted(seen) if seen[n] > 1]


def bad_uid0(pw, gr):
    return ["%s（UID 0）" % u["name"] for u in pw if u["uid"] == "0" and u["name"] != "root"]


def bad_passwd_gid(pw, gr):
    gids = set(g["gid"] for g in gr)
    return ["%s（GID %s 不存在於 /etc/group）" % (u["name"], u["gid"]) for u in pw if u["gid"] not in gids]


def bad_dup_uid(pw, gr):
    return ["UID %s：%s" % (i, ",".join(u["name"] for u in pw if u["uid"] == i)) for i in _dups([u["uid"] for u in pw])]


def bad_dup_gid(pw, gr):
    return ["GID %s：%s" % (i, ",".join(g["name"] for g in gr if g["gid"] == i)) for i in _dups([g["gid"] for g in gr])]


def bad_dup_user(pw, gr, shadow_names=None):
    out = ["帳號名稱重複：%s" % n for n in _dups([u["name"] for u in pw])]
    sn = _names("/etc/shadow") if shadow_names is None else shadow_names
    return out + ["/etc/shadow 帳號名稱重複：%s" % n for n in _dups(sn)]


def bad_dup_group(pw, gr, gshadow_names=None):
    out = ["群組名稱重複：%s" % n for n in _dups([g["name"] for g in gr])]
    gn = _names("/etc/gshadow") if gshadow_names is None else gshadow_names
    return out + ["/etc/gshadow 群組名稱重複：%s" % n for n in _dups(gn)]


# [AccountDb] RHEL8 0078、0086–0090 / RHEL9 0078、0086–0090 UID=0 之帳號與帳號/群組資料庫檢查（C 類）
class AccountDb(Rule):
    """func(passwd, group) 回傳不合格說明清單。"""
    category = CAT
    risk = "C"

    def __init__(self, title, ids, expected, func, manual_hint, ok_text):
        self.title = title
        self.ids = ids
        self.expected = expected
        self.func = func
        self.manual_hint = manual_hint
        self.ok_text = ok_text

    def check(self, ctx):
        if read_text("/etc/passwd") is None or read_text("/etc/group") is None:
            return Check(ERROR, "無法讀取 /etc/passwd 或 /etc/group")
        bad = self.func(parse_passwd(), parse_group())
        return Check(FAIL, _show(bad)) if bad else Check(PASS, self.ok_text)


def plus_lines(text):
    return [l for l in (text or "").splitlines() if l.startswith("+")]


def remove_plus_lines(text):
    lines = [l for l in (text or "").splitlines() if not l.startswith("+")]
    return "\n".join(lines) + "\n" if lines else ""


def nss_compat(text):
    """nsswitch.conf 中 passwd/group/shadow 使用 compat 的資料庫名稱。"""
    out = []
    for line in (text or "").splitlines():
        s = line.split("#", 1)[0]
        m = re.match(r"^\s*(passwd|group|shadow)\s*:(.*)$", s)
        if m and re.search(r"\bcompat\b", m.group(2)):
            out.append(m.group(1))
    return out


# [PlusLines] RHEL8 0075–0077 / RHEL9 0075–0077 /etc/passwd、/etc/shadow、/etc/group 檔案行首之「+」符號
class PlusLines(Rule):
    """文件 grep '^\\+:' 只抓「+:」；NIS compat 的「+帳號」「+@netgroup」同屬行首「+」，一併判定。"""
    category = CAT
    expected = "禁止"

    def __init__(self, path, ids):
        self.path = path
        self.ids = ids
        self.title = "%s 檔案行首之「+」符號" % path

    def check(self, ctx):
        text = read_text(self.path)
        if text is None:
            return Check(ERROR, "無法讀取 %s" % self.path)
        bad = plus_lines(text)
        if bad:
            return Check(FAIL, "行首為「+」：%s" % _show([l.split(":", 1)[0] for l in bad]))
        return Check(PASS, "無行首為「+」的行")

    def fix(self, ctx, fx):
        compat = nss_compat(read_text("/etc/nsswitch.conf"))
        if compat:
            raise ManualRequired("/etc/nsswitch.conf 的 %s 使用 compat，「+」行可能是 NIS 帳號來源，"
                                 "請確認後人工移除並改用 sss/nis 設定" % "、".join(compat))
        fx.edit_file(self.path, remove_plus_lines)


def shadow_group_problems(pw, gr):
    """回傳 (次要成員清單, 主要群組為 shadow 的帳號清單)；無 shadow 群組回傳 ([], [])。"""
    sg = [g for g in gr if g["name"] == "shadow"]
    if not sg:
        return [], []
    return sg[0]["members"], [u["name"] for u in pw if u["gid"] == sg[0]["gid"]]


# [ShadowGroup] RHEL8 0091 / RHEL9 0091 shadow 群組成員
class ShadowGroup(Rule):
    category = CAT
    title = "shadow 群組成員"
    expected = "shadow 群組不包含任何使用者"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        mem, prim = shadow_group_problems(parse_passwd(), parse_group())
        if not mem and not prim:
            return Check(PASS, "shadow 群組無成員" if any(g["name"] == "shadow" for g in parse_group())
                         else "無 shadow 群組")
        cur = []
        if mem:
            cur.append("成員：%s" % ",".join(mem))
        if prim:
            cur.append("主要群組為 shadow 的帳號：%s" % ",".join(prim))
        return Check(FAIL, "；".join(cur))

    def fix(self, ctx, fx):
        mem, prim = shadow_group_problems(parse_passwd(), parse_group())
        if mem:
            files = ["/etc/group", "/etc/gshadow"]
            for f in files:
                fx.backup_only(f)
            for u in mem:
                fx.run_tracked(["gpasswd", "-d", u, "shadow"], "將 %s 移出 shadow 群組" % u, files)
        if prim:
            fx.partial = True
            fx.note("帳號 %s 的主要群組為 shadow，請確認用途後以 usermod -g (群組) (帳號) 人工修改" % ",".join(prim))


# ====================================================================
# root 路徑變數（0073、0074）
# ====================================================================

def path_problems(path):
    bad = []
    for i, e in enumerate(path.split(":")):
        if e == "":
            bad.append("第 %d 個為空元素" % (i + 1))
        elif e in (".", ".."):
            bad.append("「%s」" % e)
        elif not e.startswith("/"):
            bad.append("「%s」開頭不是 /" % e)
    return bad


def root_login_path():
    """root 登入環境的 PATH（su - root 會載入 /etc/profile、/root/.bash_profile），回傳 (PATH, 錯誤)。"""
    mark = "__GCB_PATH__"
    r = run(["su", "-", "root", "-c", "printf '%s%%s%s' \"$PATH\"" % (mark, mark)], timeout=30)
    m = re.search(re.escape(mark) + "(.*?)" + re.escape(mark), r.out, re.S)
    if m:
        return m.group(1), ""
    return None, "無法取得 root 登入環境的 PATH：%s" % r.text()[-200:]


# [RootPath] RHEL8 0073 / RHEL9 0073 root 帳號之路徑變數（C 類）
class RootPath(Rule):
    category = CAT
    title = "root 帳號之路徑變數"
    expected = "不允許「.」、「..」、路徑開頭不是「/」及空元素"
    risk = "C"
    manual_hint = ("PATH 可能來自 /etc/profile、/etc/profile.d/*.sh、/root/.bash_profile、/root/.bashrc，"
                   "請找出來源並移除「.」、「..」、相對路徑與空元素（例如結尾的「:」）")

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        path, err = root_login_path()
        if path is None:
            return Check(ERROR, err)
        bad = path_problems(path)
        if bad:
            return Check(FAIL, "PATH=%s；不合格：%s" % (path, "、".join(bad)))
        return Check(PASS, "PATH=%s" % path)


SHARED_TMP = ("/tmp", "/var/tmp", "/dev/shm")


def writable_path_dirs(path):
    """回傳 ([(目錄, mode)], [不存在的目錄])：PATH 中 group/other 可寫的目錄。"""
    bad, missing, seen = [], [], set()
    for e in path.split(":"):
        if not e.startswith("/") or e in seen:
            continue
        seen.add(e)
        try:
            st = os.stat(e)
        except OSError:
            missing.append(e)
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_mode & 0o022:
            bad.append((e, st.st_mode & 0o7777))
    return bad, missing


# [RootPathWritable] RHEL8 0074 / RHEL9 0074 root 帳號之路徑變數不包含 world-writable 或 group-writable 目錄
class RootPathWritable(Rule):
    category = CAT
    title = "root 帳號之路徑變數不包含 world-writable 或 group-writable 目錄"
    expected = "不包含 world-writable 或 group-writable 目錄"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        path, err = root_login_path()
        if path is None:
            return Check(ERROR, err)
        bad, missing = writable_path_dirs(path)
        cur = "、".join("%s（%04o）" % b for b in bad) if bad else "PATH 目錄皆不可由群組或其他使用者寫入"
        if missing:
            cur += "；不存在（略過）：%s" % "、".join(missing)
        return Check(FAIL if bad else PASS, cur)

    def fix(self, ctx, fx):
        path, err = root_login_path()
        if path is None:
            raise ManualRequired(err)
        manual = []
        for d, mode in writable_path_dirs(path)[0]:
            real = os.path.realpath(d)
            if mode & 0o1000 or real in SHARED_TMP:
                manual.append(d)  # 刻意共用的暫存目錄，應從 PATH 移除而非改權限
                continue
            fx.chmod(real, mode & ~0o022)
        if manual:
            fx.partial = True
            fx.note("%s 為共用暫存目錄（黏滯位），不修改權限，請從 root 的 PATH 移除" % "、".join(manual))


# ====================================================================
# 使用者家目錄（0079–0085）
# ====================================================================

SHARED_PREFIX = ("/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", "/run", "/boot",
                 "/var", "/tmp", "/srv", "/opt", "/nonexistent")


def _uid_range():
    ld = read_text("/etc/login.defs") or ""
    try:
        lo = int(te.get_kv(ld, "UID_MIN") or 1000)
    except ValueError:
        lo = 1000
    try:
        hi = int(te.get_kv(ld, "UID_MAX") or 60000)
    except ValueError:
        hi = 60000
    return lo, hi


def login_users(include_root=True, passwd_text=None, uid_range=None):
    """依 GCB 腳本取具登入 shell 的帳號（排除 halt、sync、shutdown 與 nologin/false），
    再只保留 root 與一般使用者（UID_MIN–UID_MAX），略過系統或共用目錄及多帳號共用的家目錄。
    家目錄以 /etc/passwd 第 6 欄為準。回傳 (帳號清單, 略過說明清單)。
    """
    allu = parse_passwd(passwd_text)
    users = [u for u in allu if u["name"] not in ("halt", "sync", "shutdown") and u["shell"] not in NOLOGIN]
    if not include_root:
        users = [u for u in users if u["name"] != "root"]
    lo, hi = uid_range or _uid_range()
    homes = {}
    for u in users:  # 只計具登入 shell 的帳號（RHEL 的 operator 家目錄也是 /root，但為 nologin）
        homes.setdefault(os.path.normpath(u["home"] or "/"), []).append(u["name"])
    keep, skipped = [], []
    for u in users:
        try:
            uid = int(u["uid"])
        except ValueError:
            continue
        if uid != 0 and not lo <= uid <= hi:
            continue  # 系統帳號
        h = os.path.normpath(u["home"] or "/")
        if h == "/" or any(h == p or h.startswith(p + "/") for p in SHARED_PREFIX):
            skipped.append("%s（%s 為系統或共用目錄）" % (u["name"], h))
        elif len(homes.get(h, [])) > 1:
            skipped.append("%s（%s 與 %s 共用）" % (u["name"], h, ",".join(n for n in homes[h] if n != u["name"])))
        else:
            keep.append(u)
    return keep, skipped


# [HomeDirs] RHEL8 0079–0082 / RHEL9 0079–0082 使用者家目錄權限、擁有者、擁有群組、「.」檔案權限
class HomeDirs(Rule):
    """kind：mode（go-rwx，不照文件 chmod 700，/root 0550 修成 0500）/ owner / group / dotfiles（go-w）。"""
    category = CAT

    def __init__(self, title, ids, kind, expected, risk, manual_hint=""):
        self.title = title
        self.ids = ids
        self.kind = kind
        self.expected = expected
        self.risk = risk
        self.manual_hint = manual_hint

    def _problems(self):
        """回傳 ([(路徑, 說明)], 附註清單)。家目錄不存在只註明，不判不合格。"""
        users, notes = login_users()
        out = []
        for u in users:
            d = u["home"]
            if not os.path.isdir(d):
                notes.append("%s（家目錄 %s 不存在）" % (u["name"], d))
                continue
            st = os.stat(d)
            if self.kind == "mode" and st.st_mode & 0o077:
                out.append((d, "%s 權限 %03o" % (d, st.st_mode & 0o777)))
            elif self.kind == "owner" and str(st.st_uid) != u["uid"]:
                out.append((d, "%s 擁有者 %s（應為 %s）" % (d, _uname(st.st_uid), u["name"])))
            elif self.kind == "group" and str(st.st_gid) != u["gid"]:
                out.append((d, "%s 群組 %s（應為 GID %s）" % (d, _gname(st.st_gid), u["gid"])))
            elif self.kind == "dotfiles":
                for p in sorted(glob.glob(os.path.join(glob.escape(d), ".[A-Za-z0-9]*"))):
                    try:
                        lst = os.lstat(p)
                    except OSError:
                        continue
                    if stat.S_ISREG(lst.st_mode) and lst.st_mode & 0o022:
                        out.append((p, "%s 權限 %03o" % (p, lst.st_mode & 0o777)))
        return out, notes

    def check(self, ctx):
        bad, notes = self._problems()
        cur = _show([b[1] for b in bad]) if bad else "皆符合"
        if notes:
            cur += "；略過：" + _show(notes, 5)
        return Check(FAIL if bad else PASS, cur)

    def fix(self, ctx, fx):
        for path, desc in self._problems()[0]:
            mode = os.lstat(path).st_mode & 0o7777
            fx.chmod(path, mode & (~0o077 if self.kind == "mode" else ~0o022) & 0o7777)
        fx.note("已變更使用者家目錄相關權限，請通知使用者")


# [HomeFile] RHEL8 0083–0085 / RHEL9 0083–0085 使用者家目錄之「.forward」「.netrc」「.rhosts」檔案（C 類）
class HomeFile(Rule):
    category = CAT
    risk = "C"
    expected = "移除"

    def __init__(self, name, ids):
        self.name = name
        self.ids = ids
        self.title = "使用者家目錄之「%s」檔案" % name
        self.manual_hint = "屬使用者資料，請先通知使用者，確認不再需要後移除（建議先備份）：rm (家目錄)/%s" % name

    def check(self, ctx):
        users, _ = login_users(include_root=False)  # 文件腳本排除 root
        found = []
        for u in users:
            p = os.path.join(u["home"], self.name)
            try:
                if stat.S_ISREG(os.lstat(p).st_mode):
                    found.append(p)
            except OSError:
                pass
        cur = ("存在：" + _show(found)) if found else "未發現"
        rp = os.path.join("/root", self.name)
        if os.path.isfile(rp) and not os.path.islink(rp):
            cur += "；另有 %s（文件不檢查 root，供參考）" % rp
        return Check(FAIL if found else PASS, cur)


# ====================================================================
# RHEL 9 新增：/etc/shells、chrony、ptrace（0301–0307）
# ====================================================================

SHELLS = "/etc/shells"
_NOLOGIN_RX = re.compile(r"^[^#]*/nologin$")


def nologin_lines(text):
    return [l.rstrip() for l in (text or "").splitlines() if _NOLOGIN_RX.match(l.rstrip())]


def remove_nologin(text):
    lines = [l for l in (text or "").splitlines() if not _NOLOGIN_RX.match(l.rstrip())]
    return "\n".join(lines) + "\n" if lines else ""


# [ShellsNologin] RHEL9 0305 /etc/shells 中不應存在 nologin
class ShellsNologin(Rule):
    category = CAT
    title = "/etc/shells 中不應存在 nologin"
    expected = "移除含有 nologin 的行"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        text = read_text(SHELLS)
        if text is None:
            return Check(NA, "%s 不存在，沒有可檢查的 shell 清單" % SHELLS)
        bad = nologin_lines(text)
        return Check(FAIL, "含有：%s" % "、".join(bad)) if bad else Check(PASS, "不含 nologin")

    def fix(self, ctx, fx):
        fx.edit_file(SHELLS, remove_nologin)


CHRONY_SYSCONFIG = "/etc/sysconfig/chronyd"


def chrony_tokens(text):
    """OPTIONS 參數清單；未設定回傳 []，引號錯誤回傳 None。"""
    v = te.get_kv(text or "", "OPTIONS")
    if v is None:
        return []
    try:
        # 先依 shell 規則去掉引號，再依 systemd $OPTIONS 的方式以空白切開
        return " ".join(shlex.split(v)).split()
    except ValueError:
        return None


def chrony_eval(tokens):
    """回傳 (含 -u root, -F 的值或 None)。"""
    u_root, f = False, None
    for i, t in enumerate(tokens):
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if (t == "-u" and nxt == "root") or t == "-uroot":
            u_root = True
        elif t == "-F":
            f = nxt
        elif t.startswith("-F") and len(t) > 2:
            f = t[2:]
    return u_root, f


def chrony_fixed(tokens):
    """移除 -u root、把 -F 設為 2（保留其他參數）。"""
    out, i, has_f = [], 0, False
    while i < len(tokens):
        t = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if t == "-u" and nxt == "root":
            i += 2
            continue
        if t == "-uroot":
            i += 1
            continue
        if t == "-F":
            out += ["-F", "2"]
            has_f = True
            i += 2
            continue
        if t.startswith("-F") and len(t) > 2:
            out += ["-F", "2"]
            has_f = True
            i += 1
            continue
        out.append(t)
        i += 1
    if not has_f:
        out += ["-F", "2"]
    return out


def chronyd_users():
    r = run(["ps", "-o", "user=", "-C", "chronyd"], timeout=15)
    return sorted(set(r.out.split()))


# [ChronyNotRoot] RHEL9 0306 禁止 chrony 以 root 權限執行
class ChronyNotRoot(Rule):
    """以 OPTIONS 含 -F 2 且無 -u root 判定（保留 -4 等其他參數），並確認執行中的 chronyd 不是 root。"""
    category = CAT
    title = "禁止 chrony 以 root 權限執行"
    expected = 'OPTIONS="-F 2"'

    def __init__(self, ids):
        self.ids = ids
        self.when = installed("chrony")

    def check(self, ctx):
        text = read_text(CHRONY_SYSCONFIG)
        toks = chrony_tokens(text)
        if toks is None:
            return Check(FAIL, "%s 的 OPTIONS 引號不成對" % CHRONY_SYSCONFIG)
        u_root, f = chrony_eval(toks)
        users = chronyd_users()
        ok = not u_root and f == "2" and "root" not in users
        cur = "OPTIONS=%s" % (te.get_kv(text or "", "OPTIONS") or "未設定") if text is not None else \
            "%s 不存在" % CHRONY_SYSCONFIG
        cur += "；chronyd 執行身分：%s" % (",".join(users) or "未執行")
        if "root" in users and not u_root and f == "2":
            cur += "（設定已正確，需重新啟動 chronyd）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        text = read_text(CHRONY_SYSCONFIG)
        toks = chrony_tokens(text)
        if toks is None:
            raise ManualRequired("%s 的 OPTIONS 引號不成對，請人工修正為 OPTIONS=\"-F 2\"" % CHRONY_SYSCONFIG)
        new = '"%s"' % " ".join(chrony_fixed(toks))
        fx.add_undo(["systemctl", "try-restart", "chronyd.service"], "重新啟動 chronyd")
        fx.edit_file(CHRONY_SYSCONFIG, lambda t: te.set_kv(t, "OPTIONS", new, sep="="))
        fx.run(["systemctl", "try-restart", "chronyd.service"], "重新啟動 chronyd（僅在執行中時）", check=False)


PTRACE_KEY = "kernel.yama.ptrace_scope"
PTRACE_OWN = "/etc/sysctl.d/60-gcb-ptrace.conf"


# [PtraceScope] RHEL9 0307 ptrace 限制模式
class PtraceScope(Rule):
    """照字面要求 1；2、3 更嚴格，判不合格但不自動調降（部分修復）。

    不修改 /usr/lib/sysctl.d 的套件檔：只處理排序在本工具設定檔之後的衝突設定，
    非 /etc 的檔案以 /etc/sysctl.d 同名檔覆蓋。
    """
    category = CAT
    title = "ptrace 限制模式"
    expected = "啟用（kernel.yama.ptrace_scope=1）"
    WANT = "1"

    def __init__(self, ids):
        self.ids = ids

    def check(self, ctx):
        rt = pkgsvc.sysctl_runtime(PTRACE_KEY)
        if rt is None:
            return Check(NA, "核心未啟用 Yama 安全模組（沒有 %s），無法也不需設定" % PTRACE_KEY)
        pv, src, _ = pkgsvc.sysctl_persistent(PTRACE_KEY)
        ok = rt == self.WANT and pv == self.WANT
        cur = "%s 目前=%s 開機=%s%s" % (PTRACE_KEY, rt, pv if pv is not None else "未設定",
                                     "（%s）" % src if src else "")
        if not ok and (rt in ("2", "3") or pv in ("2", "3")):
            cur += "；值 2、3 比 GCB 要求更嚴格，照字面判定不合格"
        return Check(PASS if ok else FAIL, cur)

    @staticmethod
    def _after_own(f):
        """f 是否排在本工具設定檔之後（會覆蓋本檔）。"""
        return f == "/etc/sysctl.conf" or os.path.basename(f) > os.path.basename(PTRACE_OWN)

    def fix(self, ctx, fx):
        rt = pkgsvc.sysctl_runtime(PTRACE_KEY)
        pv = pkgsvc.sysctl_persistent(PTRACE_KEY)[0]
        if rt in ("2", "3") or pv in ("2", "3"):
            fx.partial = True
            fx.note("ptrace_scope 目前為更嚴格的設定（目前=%s 開機=%s），改為 1 會降低安全性，不自動修改" % (rt, pv))
            return
        for f, v in pkgsvc.sysctl_persistent(PTRACE_KEY)[2]:
            if v == self.WANT or f == PTRACE_OWN or not self._after_own(f):
                continue
            real = os.path.realpath(f)
            if real.startswith("/etc/"):
                fx.edit_file(real, lambda t: te.comment_sysctl(t, PTRACE_KEY, self.WANT))
            else:
                fx.write_file(os.path.join("/etc/sysctl.d", os.path.basename(f)),
                              te.comment_sysctl(read_text(f) or "", PTRACE_KEY, self.WANT))
        fx.edit_file(PTRACE_OWN, lambda t: te.set_kv(t, PTRACE_KEY, self.WANT))
        if rt != self.WANT:
            fx.sysctl_set(PTRACE_KEY, self.WANT)


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

ROOT_ROOT = "root:root"
ROOT_SHADOW = "root:root 或 root:shadow"


def _own(title, ids, paths, groups, expected, missing="na"):
    return FilePerm(title, CAT, ids, paths, owner="root", groups=groups, missing=missing, expected=expected)


def _mode(title, ids, paths, mode, missing="na"):
    exp = "000" if mode == 0 else "%03o 或更低權限" % mode
    return FilePerm(title, CAT, ids, paths, max_mode=mode, missing=missing, expected=exp)


RULES = [
    # RHEL8 0048 / RHEL9 0048 /etc/shadow 檔案權限 → common.py
    # RHEL8 0049 / RHEL9 0049 /etc/group 檔案所有權
    _own("/etc/group 檔案所有權", R(r8=49, r9=49), "/etc/group", ["root"], ROOT_ROOT, missing="fail"),
    # RHEL8 0050 / RHEL9 0050 /etc/group 檔案權限
    _mode("/etc/group 檔案權限", R(r8=50, r9=50), "/etc/group", 0o644, missing="fail"),
    # RHEL8 0051 / RHEL9 0051 /etc/gshadow 檔案所有權
    _own("/etc/gshadow 檔案所有權", R(r8=51, r9=51), "/etc/gshadow", ["root", "shadow"], ROOT_SHADOW, missing="fail"),
    # RHEL8 0052 / RHEL9 0052 /etc/gshadow 檔案權限
    _mode("/etc/gshadow 檔案權限", R(r8=52, r9=52), "/etc/gshadow", 0o000, missing="fail"),
    # RHEL8 0053 / RHEL9 0053 /etc/passwd- 檔案所有權
    _own("/etc/passwd- 檔案所有權", R(r8=53, r9=53), "/etc/passwd-", ["root"], ROOT_ROOT),
    # RHEL8 0054 /etc/passwd- 檔案權限（RHEL 8 要求 600）
    _mode("/etc/passwd- 檔案權限", R(r8=54), "/etc/passwd-", 0o600),
    # RHEL9 0054 /etc/passwd- 檔案權限（RHEL 9 要求 644）
    _mode("/etc/passwd- 檔案權限", R(r9=54), "/etc/passwd-", 0o644),
    # RHEL8 0055 / RHEL9 0055 /etc/shadow- 檔案所有權
    _own("/etc/shadow- 檔案所有權", R(r8=55, r9=55), "/etc/shadow-", ["root", "shadow"], ROOT_SHADOW),
    # RHEL8 0056 / RHEL9 0056 /etc/shadow- 檔案權限
    _mode("/etc/shadow- 檔案權限", R(r8=56, r9=56), "/etc/shadow-", 0o000),
    # RHEL8 0057 / RHEL9 0057 /etc/group- 檔案所有權
    _own("/etc/group- 檔案所有權", R(r8=57, r9=57), "/etc/group-", ["root"], ROOT_ROOT),
    # RHEL8 0058 / RHEL9 0058 /etc/group- 檔案權限
    _mode("/etc/group- 檔案權限", R(r8=58, r9=58), "/etc/group-", 0o644),
    # RHEL8 0059 / RHEL9 0059 /etc/gshadow- 檔案所有權
    _own("/etc/gshadow- 檔案所有權", R(r8=59, r9=59), "/etc/gshadow-", ["root", "shadow"], ROOT_SHADOW),
    # RHEL8 0060 / RHEL9 0060 /etc/gshadow- 檔案權限
    _mode("/etc/gshadow- 檔案權限", R(r8=60, r9=60), "/etc/gshadow-", 0o000),
    # RHEL8 0061 / RHEL9 0061 其他使用者寫入具有全域寫入權限之檔案
    FsScan("其他使用者寫入具有全域寫入權限之檔案", R(r8=61, r9=61), "ww", "禁止寫入",
           "請確認檔案用途後以 chmod o-w (檔案名稱) 移除其他使用者寫入權限（應用程式可能依賴，需人工判斷）"),
    # RHEL8 0062 / RHEL9 0062 檢查所有檔案與目錄之擁有者
    FsScan("檢查所有檔案與目錄之擁有者", R(r8=62, r9=62), "nouser", "所有檔案與目錄擁有者皆為合法使用者",
           "請確認檔案用途後以 chown (使用者) (檔案) 指定擁有者，或確認不需要後刪除"),
    # RHEL8 0063 / RHEL9 0063 檢查所有檔案與目錄之擁有群組
    FsScan("檢查所有檔案與目錄之擁有群組", R(r8=63, r9=63), "nogroup", "所有檔案與目錄擁有群組皆為合法群組",
           "請確認檔案用途後以 chgrp (群組) (檔案) 指定群組，或確認不需要後刪除"),
    # RHEL8 0064 / RHEL9 0064 所有具有全域寫入權限目錄之擁有者
    FsScan("所有具有全域寫入權限目錄之擁有者", R(r8=64, r9=64), "wwdir_uid", "root 或其他系統帳號",
           "請確認目錄用途（常為使用者自建的共享目錄）後以 chown root (目錄名稱) 修改，並考慮加上黏滯位（chmod +t）"),
    # RHEL8 0065 / RHEL9 0065 所有具有全域寫入權限目錄之擁有群組
    FsScan("所有具有全域寫入權限目錄之擁有群組", R(r8=65, r9=65), "wwdir_gid", "root 或其他系統群組",
           "請確認目錄用途後以 chgrp root (目錄名稱) 修改（或改為 sys、bin 或應用程式群組）"),
    # RHEL8 0066 / RHEL9 0066 系統命令檔案權限
    TreePerm("系統命令檔案權限", R(r8=66, r9=66), CMD_DIRS, "mode", "755 或更低權限", "A"),
    # RHEL8 0067 / RHEL9 0067 系統命令檔案擁有者
    TreePerm("系統命令檔案擁有者", R(r8=67, r9=67), CMD_DIRS, "owner", "root", "B"),
    # RHEL8 0068 / RHEL9 0068 系統命令檔案擁有群組
    TreePerm("系統命令檔案擁有群組", R(r8=68, r9=68), CMD_DIRS, "cmd_group", "root", "C",
             "請逐一確認：若檔案屬於 RPM 套件且套件本來就設定該群組（rpm -qf (檔案)、rpm -V (套件) 無異常，"
             "例如 postfix 的 postdrop、postqueue），改群組會破壞功能，應保留並記錄例外；其餘以 chgrp root (檔案) 修改，"
             "注意 chgrp 會清除 setuid/setgid，修改後需以原權限 chmod 還原"),
    # RHEL8 0069 / RHEL9 0069 程式庫檔案權限
    TreePerm("程式庫檔案權限", R(r8=69, r9=69), LIB_DIRS, "file_mode", "755 或更低權限", "A"),
    # RHEL8 0070 / RHEL9 0070 程式庫檔案擁有者
    TreePerm("程式庫檔案擁有者", R(r8=70, r9=70), LIB_DIRS, "owner", "root", "B"),
    # RHEL8 0071 / RHEL9 0071 程式庫檔案擁有群組
    TreePerm("程式庫檔案擁有群組", R(r8=71, r9=71), LIB_DIRS, "group", "root", "B"),
    # RHEL8 0072 / RHEL9 0072 帳號不使用空白通行碼 → common.py
    # RHEL8 0073 / RHEL9 0073 root 帳號之路徑變數
    RootPath(R(r8=73, r9=73)),
    # RHEL8 0074 / RHEL9 0074 root 帳號之路徑變數不包含 world-writable 或 group-writable 目錄
    RootPathWritable(R(r8=74, r9=74)),
    # RHEL8 0075 / RHEL9 0075 /etc/passwd 檔案行首之「+」符號
    PlusLines("/etc/passwd", R(r8=75, r9=75)),
    # RHEL8 0076 / RHEL9 0076 /etc/shadow 檔案行首之「+」符號
    PlusLines("/etc/shadow", R(r8=76, r9=76)),
    # RHEL8 0077 / RHEL9 0077 /etc/group 檔案行首之「+」符號
    PlusLines("/etc/group", R(r8=77, r9=77)),
    # RHEL8 0078 / RHEL9 0078 UID=0 之帳號
    AccountDb("UID=0 之帳號", R(r8=78, r9=78), "僅 root 帳號之 UID 為 0", bad_uid0,
              "請確認帳號用途後以 userdel (帳號) 刪除或 usermod -u (UID) (帳號) 變更 UID，並調整其檔案擁有權",
              "僅 root 之 UID 為 0"),
    # RHEL8 0079 / RHEL9 0079 使用者家目錄權限
    HomeDirs("使用者家目錄權限", R(r8=79, r9=79), "mode", "700 或更低權限", "B"),
    # RHEL8 0080 / RHEL9 0080 使用者家目錄擁有者
    HomeDirs("使用者家目錄擁有者", R(r8=80, r9=80), "owner", "使用者擁有", "C",
             "請先通知使用者，確認家目錄非共用或系統目錄後以 chown (帳號) (家目錄) 修改（家目錄以 /etc/passwd 第 6 欄為準）"),
    # RHEL8 0081 / RHEL9 0081 使用者家目錄擁有群組
    HomeDirs("使用者家目錄擁有群組", R(r8=81, r9=81), "group", "使用者群組擁有", "C",
             "請確認家目錄群組是否為刻意設定的共用群組後，以 chgrp (主要群組) (家目錄) 修改"),
    # RHEL8 0082 / RHEL9 0082 使用者家目錄之「.」檔案權限
    HomeDirs("使用者家目錄之「.」檔案權限", R(r8=82, r9=82), "dotfiles", "go-w 或更低權限", "B"),
    # RHEL8 0083 / RHEL9 0083 使用者家目錄之「.forward」檔案
    HomeFile(".forward", R(r8=83, r9=83)),
    # RHEL8 0084 / RHEL9 0084 使用者家目錄之「.netrc」檔案
    HomeFile(".netrc", R(r8=84, r9=84)),
    # RHEL8 0085 / RHEL9 0085 使用者家目錄之「.rhosts」檔案
    HomeFile(".rhosts", R(r8=85, r9=85)),
    # RHEL8 0086 / RHEL9 0086 檢查 /etc/passwd 檔案設定之群組
    AccountDb("檢查 /etc/passwd 檔案設定之群組", R(r8=86, r9=86),
              "/etc/passwd 檔案中帳號之群組皆須存在於 /etc/group 檔案中", bad_passwd_gid,
              "請以 groupadd -g (GID) (群組) 建立群組，或以 usermod -g (群組) (帳號) 修改主要群組", "所有帳號的群組皆存在"),
    # RHEL8 0087 / RHEL9 0087 唯一之 UID
    AccountDb("唯一之 UID", R(r8=87, r9=87), "為每個帳號設定唯一之 UID", bad_dup_uid,
              "請以 usermod -u (UID) (帳號) 指定唯一 UID，並以 find / -uid (舊 UID) 修正檔案擁有權", "無重複 UID"),
    # RHEL8 0088 / RHEL9 0088 唯一之 GID
    AccountDb("唯一之 GID", R(r8=88, r9=88), "為每個群組設定唯一之 GID", bad_dup_gid,
              "請以 groupmod -g (GID) (群組) 指定唯一 GID，並修正相關檔案的群組", "無重複 GID"),
    # RHEL8 0089 / RHEL9 0089 唯一之使用者帳號名稱
    AccountDb("唯一之使用者帳號名稱", R(r8=89, r9=89), "為每個使用者帳號設定唯一之名稱", bad_dup_user,
              "請以 vipw 人工編輯 /etc/passwd（及 vipw -s 編輯 /etc/shadow），為帳號設定唯一名稱", "無重複帳號名稱"),
    # RHEL8 0090 / RHEL9 0090 唯一之群組名稱
    AccountDb("唯一之群組名稱", R(r8=90, r9=90), "為每個群組設定唯一之群組名稱", bad_dup_group,
              "請以 vigr 人工編輯 /etc/group（及 vigr -s 編輯 /etc/gshadow），為群組設定唯一名稱", "無重複群組名稱"),
    # RHEL8 0091 / RHEL9 0091 shadow 群組成員
    ShadowGroup(R(r8=91, r9=91)),
    # RHEL9 0301 /etc/shells 檔案所有權
    _own("/etc/shells 檔案所有權", R(r9=301), "/etc/shells", ["root"], ROOT_ROOT),
    # RHEL9 0302 /etc/shells 檔案權限
    _mode("/etc/shells 檔案權限", R(r9=302), "/etc/shells", 0o644),
    # RHEL9 0303 /etc/security/opasswd 與 /etc/security/opasswd.old 檔案所有權
    _own("/etc/security/opasswd 與 /etc/security/opasswd.old 檔案所有權", R(r9=303),
         ["/etc/security/opasswd", "/etc/security/opasswd.old"], ["root"], ROOT_ROOT),
    # RHEL9 0304 /etc/security/opasswd 與 /etc/security/opasswd.old 檔案權限（只移除多餘位元，0600 維持不變）
    _mode("/etc/security/opasswd 與 /etc/security/opasswd.old 檔案權限", R(r9=304),
          ["/etc/security/opasswd", "/etc/security/opasswd.old"], 0o644),
    # RHEL9 0305 /etc/shells 中不應存在 nologin
    ShellsNologin(R(r9=305)),
    # RHEL9 0306 禁止 chrony 以 root 權限執行
    ChronyNotRoot(R(r9=306)),
    # RHEL9 0307 ptrace 限制模式
    PtraceScope(R(r9=307)),
]
