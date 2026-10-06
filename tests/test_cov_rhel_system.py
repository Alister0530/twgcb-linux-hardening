# -*- coding: utf-8 -*-
"""RHEL 8 / 9 系統設定與維護（rhel/system.py）規則 check／fix 的模擬測試（不碰真實系統）。"""
import glob as real_glob
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402  (fakes 會把專案根目錄加入 sys.path)
from fakes import FakeCtx, FakeFx, FakeRunner, mock, res  # noqa: E402
from gcb.fixer import ManualRequired  # noqa: E402
from gcb.rules.base import ERROR, FAIL, NA, PASS  # noqa: E402
from gcb.rules.rhel import system as s  # noqa: E402


# ---- 模擬環境 ----

def st(mode=0o100644, uid=0, gid=0, dev=1):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid, st_dev=dev, st_ino=0)


class FakeOs(object):
    """os 替身：stats 為 {路徑: st(...)}，不在其中的路徑 stat 拋出 OSError。"""

    def __init__(self, stats=None, real=None, files=()):
        self.stats = stats or {}
        real = real or {}
        self.path = SimpleNamespace(
            isdir=lambda p: p in self.stats and stat.S_ISDIR(self.stats[p].st_mode),
            isfile=lambda p: p in files or (p in self.stats and stat.S_ISREG(self.stats[p].st_mode)),
            islink=lambda p: False, realpath=lambda p: real.get(p, p),
            join=os.path.join, basename=os.path.basename, normpath=os.path.normpath)

    def stat(self, p):
        if p not in self.stats:
            raise OSError(2, "No such file")
        return self.stats[p]

    lstat = stat


DIR = 0o040000


def env(fs=None, runner=None, os_=None, users=None, groups=None, globs=None):
    """patch system 模組讀檔、指令、os、pwd/grp、glob；回傳 ExitStack。"""
    stack = ExitStack()
    stack.enter_context(mock.patch.object(s, "read_text", fakes.fs_reader(fs or {})))
    stack.enter_context(mock.patch.object(s, "run", runner or FakeRunner()))
    stack.enter_context(mock.patch.object(s, "which", lambda n: "/usr/bin/" + n))
    if os_ is not None:
        stack.enter_context(mock.patch.object(s, "os", os_))
    users, groups = users or {}, groups or {}

    def getpwuid(uid):
        if uid not in users:
            raise KeyError(uid)
        return SimpleNamespace(pw_name=users[uid])

    def getgrgid(gid):
        if gid not in groups:
            raise KeyError(gid)
        return SimpleNamespace(gr_name=groups[gid])
    stack.enter_context(mock.patch.object(s, "pwd", SimpleNamespace(getpwuid=getpwuid)))
    stack.enter_context(mock.patch.object(s, "grp", SimpleNamespace(getgrgid=getgrgid)))
    if globs is not None:
        stack.enter_context(mock.patch.object(s, "glob", SimpleNamespace(
            glob=lambda p: globs.get(p, []), escape=real_glob.escape)))
    s._gname_cache.clear()
    stack.callback(s._gname_cache.clear)
    return stack


def rule(cls, **attrs):
    for r in s.RULES:
        if isinstance(r, cls) and all(getattr(r, k) == v for k, v in attrs.items()):
            return r
    raise LookupError(cls)


class Base(unittest.TestCase):
    def setUp(self):
        for c in (s._fs_cache, s._tree_cache, s._rpm_cache, s._gname_cache):
            c.clear()

    tearDown = setUp


# ---- 名稱查詢與掛載點 ----

# 共用：UID/GID 名稱、本機掛載點
class TestHelpers(Base):
    def test_names_fallback(self):
        with env(users={0: "root"}, groups={0: "root"}):
            self.assertEqual((s._uname(0), s._uname(4321)), ("root", "4321"))
            self.assertEqual((s._gname(0), s._gname(4321)), ("root", "4321"))

    def test_scan_roots_stat_error_and_same_device(self):
        fos = FakeOs({"/": st(DIR, dev=1), "/home": st(DIR, dev=2), "/srv": st(DIR, dev=2)})
        orig_isdir = fos.path.isdir
        fos.path.isdir = lambda p: p == "/gone" or orig_isdir(p)  # 存在但 stat 失敗
        m = [("/dev/a", "/", "xfs", []), ("/dev/b", "/home", "xfs", []), ("/dev/b", "/srv", "xfs", []),
             ("/dev/c", "/gone", "ext4", [])]
        with env(os_=fos):
            self.assertEqual(s.scan_roots(m), ["/", "/srv"])  # 依掛載點長度排序，同裝置只取第一個


# ---- 全檔案系統掃描 ----

# RHEL8 0061–0065 / RHEL9 0061–0065 全域可寫檔案、無擁有者/群組、全域可寫目錄之擁有者/群組
class TestFsScan(Base):
    def test_fs_scan_errors(self):
        with env(), mock.patch.object(s, "scan_roots", lambda: []):
            self.assertEqual(s.fs_scan(), "找不到可掃描的本機檔案系統")
        with env(runner=FakeRunner({"find": res(124)})), mock.patch.object(s, "scan_roots", lambda: ["/"]):
            self.assertIn("逾時", s.fs_scan())
        with env(runner=FakeRunner({"find": res(127)})), mock.patch.object(s, "scan_roots", lambda: ["/"]):
            self.assertEqual(s.fs_scan(), "找不到 find 指令")
        self.assertEqual(s._fs_cache, {})  # 失敗不快取

    def test_fs_scan_ok_and_cached(self):
        runner = FakeRunner({"find": res(0, "W\t/a\0U\t1234\t/x\0")})
        with env(runner=runner), mock.patch.object(s, "scan_roots", lambda: ["/", "/home"]):
            r1 = s.fs_scan()
            r2 = s.fs_scan()
        self.assertIs(r1, r2)
        self.assertEqual(len(runner.calls), 1)
        self.assertTrue(runner.calls[0].startswith("find / /home -xdev"))
        self.assertEqual(r1["ww"], ["/a"])

    def _check(self, kind, scan):
        r = rule(s.FsScan, kind=kind)
        with env(users={1000: "alice"}, groups={1001: "devs"}), mock.patch.object(s, "fs_scan", lambda: scan):
            return r.check(FakeCtx())

    def test_check(self):
        scan = {"ww": ["/srv/w"], "nouser": [("1234", "/x")], "nogroup": [],
                "wwdir_uid": [("1000", "/d"), ("x", "/d2")], "wwdir_gid": [("1001", "/e")], "roots": ["/"]}
        self.assertEqual(self._check("ww", "掃描逾時").status, ERROR)
        c = self._check("nogroup", scan)
        self.assertEqual((c.status, c.current), (PASS, "未發現；掃描範圍：/"))
        self.assertEqual(self._check("ww", scan).current, "1 個：/srv/w；掃描範圍：/")
        self.assertIn("/x（uid=1234）", self._check("nouser", scan).current)
        self.assertIn("/d（擁有者=alice）、/d2（擁有者=x）", self._check("wwdir_uid", scan).current)
        self.assertIn("/e（群組=devs）", self._check("wwdir_gid", scan).current)


# ---- 系統命令與程式庫 ----

# RHEL8 0066–0071 / RHEL9 0066–0071 系統命令與程式庫檔案之權限、擁有者、擁有群組
class TestTree(Base):
    def setUp(self):
        Base.setUp(self)
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        Base.tearDown(self)
        shutil.rmtree(self.d)

    def test_scan_skips_missing_and_deadline(self):
        for i in range(200):
            os.mkdir(os.path.join(self.d, "d%03d" % i))
        r = s.tree_scan((os.path.join(self.d, "missing"), self.d))
        self.assertEqual(r["roots"], [os.path.realpath(self.d)])
        self.assertIn("逾時", s.tree_scan((self.d,), deadline=1))

    def test_rpm_default(self):
        attrs = {"/usr/bin/x": ("root", "mail"), "/usr/bin/y": ("nobody", "root")}
        self.assertIsNone(s.rpm_default("/nope", "owner", attrs))
        self.assertEqual(s.rpm_default("/usr/bin/y", "owner", attrs), "套件預設擁有者 nobody")
        self.assertEqual(s.rpm_default("/usr/bin/x", "group", attrs), "套件預設群組 mail")
        self.assertIsNone(s.rpm_default("/usr/bin/x", "owner", attrs))

    def _tree(self, **kw):
        res_ = {"mode": [], "file_mode": [], "owner": [], "group": [], "cmd_group": [], "roots": ["/usr/bin"]}
        res_.update(kw)
        return res_

    def test_check(self):
        item = ("/usr/bin/a", "/usr/bin/a", 0o4777, 1000, 0)
        ctx = FakeCtx()
        with env(users={1000: "alice"}):
            with mock.patch.object(s, "tree_result", lambda d: "掃描逾時"):
                self.assertEqual(rule(s.TreePerm, kind="mode").check(ctx).status, ERROR)
            with mock.patch.object(s, "tree_result", lambda d: self._tree(mode=[item] * 11, owner=[item])), \
                    mock.patch.object(s, "rpm_file_attrs", lambda: {"/usr/bin/a": ("alice", "root")}):
                c = rule(s.TreePerm, kind="mode").check(ctx)
                self.assertIn("/usr/bin/a（4777）", c.current)
                self.assertIn("…等共 11 個", c.current)
                c = rule(s.TreePerm, kind="owner", dirs=s.CMD_DIRS).check(ctx)
        self.assertEqual(c.current, "/usr/bin/a（擁有者 alice）（套件預設擁有者 alice）；範圍：/usr/bin")

    def test_fix_error(self):
        fx = FakeFx(FakeCtx())
        with mock.patch.object(s, "tree_scan", lambda d, dl: "掃描逾時"):
            with self.assertRaises(ManualRequired):
                rule(s.TreePerm, kind="mode").fix(fx.ctx, fx)

    def test_fix_mode_keeps_setuid(self):
        item = ("/usr/bin/l → /usr/bin/a", "/usr/bin/a", 0o4777, 0, 0)
        fx = FakeFx(FakeCtx())
        with mock.patch.object(s, "tree_scan", lambda d, dl: self._tree(mode=[item])):
            rule(s.TreePerm, kind="mode").fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chmod", "/usr/bin/a", 0o4755)])

    def test_fix_owner_group(self):
        own = [("/usr/bin/a", "/usr/bin/a", 0o4755, 1000, 50), ("/usr/bin/p", "/usr/bin/p", 0o2755, 1000, 0)]
        grp_ = [("/usr/lib/b", "/usr/lib/b", 0o644, 0, 1001)]
        attrs = {"/usr/bin/p": ("postfix", "root")}
        # chown 後核心清除 setuid：以 stat 回報的新 mode 判定需要還原
        fos = FakeOs({"/usr/bin/a": st(0o100755), "/usr/lib/b": st(0o100644)})
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        with env(os_=fos, users={0: "root"}, groups={50: "staff"}), \
                mock.patch.object(s, "rpm_file_attrs", lambda: attrs), \
                mock.patch.object(s, "tree_scan", lambda d, dl: self._tree(owner=own, group=grp_)):
            rule(s.TreePerm, kind="owner", dirs=s.CMD_DIRS).fix(ctx, fx)
            rule(s.TreePerm, kind="group", dirs=s.LIB_DIRS).fix(ctx, fx)
        self.assertEqual(fx.events, [("chown", "/usr/bin/a", "root:staff"), ("chmod", "/usr/bin/a", 0o4755),
                                     ("chown", "/usr/lib/b", "root:root")])
        self.assertTrue(fx.partial)
        self.assertIn("/usr/bin/p（套件預設擁有者 postfix）", fx.notes[0])


# ---- 帳號資料庫 ----

PASSWD = "root:x:0:0::/root:/bin/bash\n+::::::\nshort:x\nalice:x:1000:42::/home/alice:/bin/bash\n"
GROUP = "root:x:0:\n-grp:x:9:\nshadow:x:42:bob\n"


# RHEL8 0075–0078、0086–0091 / RHEL9 同編號 帳號與群組資料庫
class TestAccountDb(Base):
    def test_parse_skips(self):
        self.assertEqual([u["name"] for u in s.parse_passwd(PASSWD)], ["root", "alice"])
        self.assertEqual([g["name"] for g in s.parse_group(GROUP)], ["root", "shadow"])

    def test_account_db_unreadable(self):
        with env({"/etc/passwd": PASSWD}):
            self.assertEqual(rule(s.AccountDb).check(FakeCtx()).status, ERROR)

    def test_plus_lines(self):
        r = rule(s.PlusLines, path="/etc/passwd")
        with env({}):
            self.assertEqual(r.check(FakeCtx()).status, ERROR)
        fs = {"/etc/passwd": PASSWD, "/etc/nsswitch.conf": "passwd: files compat\n"}
        fx = FakeFx(FakeCtx(), fs=fs)
        with env(fs):
            self.assertEqual(r.check(fx.ctx).current, "行首為「+」：+")
            with self.assertRaises(ManualRequired):
                r.fix(fx.ctx, fx)
            self.assertEqual(fx.events, [])
            fs["/etc/nsswitch.conf"] = "passwd: files sss\n"
            r.fix(fx.ctx, fx)
        self.assertNotIn("+", fs["/etc/passwd"])


# RHEL8 0091 / RHEL9 0091 shadow 群組成員
class TestShadowGroup(Base):
    r = rule(s.ShadowGroup)

    def test_check(self):
        with env({"/etc/passwd": PASSWD, "/etc/group": "root:x:0:\n"}):
            self.assertEqual(self.r.check(FakeCtx()).current, "無 shadow 群組")
        with env({"/etc/passwd": PASSWD, "/etc/group": GROUP}):
            c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "成員：bob；主要群組為 shadow 的帳號：alice"))

    def test_fix(self):
        fx = FakeFx(FakeCtx())
        with env({"/etc/passwd": PASSWD, "/etc/group": GROUP}):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("backup", "/etc/group"), ("backup", "/etc/gshadow"),
                                     ("run", "gpasswd -d bob shadow")])
        self.assertTrue(fx.partial)
        self.assertIn("alice", fx.notes[0])


# ---- root PATH ----

MARK = "__GCB_PATH__"


def path_runner(path):
    return FakeRunner({"su - root": res(0, "motd\n%s%s%s" % (MARK, path, MARK)) if path is not None
                       else res(1, err="su: Authentication failure")})


# RHEL8 0073 / RHEL9 0073 root 帳號之路徑變數
class TestRootPath(Base):
    r = rule(s.RootPath)

    def test_check(self):
        with env(runner=path_runner(None)):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, ERROR)
        self.assertIn("Authentication failure", c.current)
        with env(runner=path_runner("/usr/bin:.")):
            self.assertEqual(self.r.check(FakeCtx()).status, FAIL)
        with env(runner=path_runner("/usr/bin:/bin")):
            self.assertEqual(self.r.check(FakeCtx()).current, "PATH=/usr/bin:/bin")


# RHEL8 0074 / RHEL9 0074 root 帳號之路徑變數不包含 world-writable 或 group-writable 目錄
class TestRootPathWritable(Base):
    r = rule(s.RootPathWritable)
    STATS = {"/usr/bin": st(DIR | 0o755), "/opt/bin": st(DIR | 0o775), "/tmp": st(DIR | 0o1777),
             "/shared": st(DIR | 0o777), "/usr/bin/x": st(0o100777)}

    def _env(self, path):
        return env(runner=path_runner(path), os_=FakeOs(self.STATS, real={"/shared": "/var/tmp"}))

    def test_writable_dirs(self):
        with self._env(None):
            bad, missing = s.writable_path_dirs("rel:/usr/bin:/usr/bin:/usr/bin/x:/opt/bin:/none")
        self.assertEqual((bad, missing), ([("/opt/bin", 0o775)], ["/none"]))

    def test_check(self):
        with self._env(None):
            self.assertEqual(self.r.check(FakeCtx()).status, ERROR)
        with self._env("/usr/bin:/opt/bin:/none"):
            c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "/opt/bin（0775）；不存在（略過）：/none"))

    def test_fix(self):
        fx = FakeFx(FakeCtx())
        with self._env(None):
            with self.assertRaises(ManualRequired):
                self.r.fix(fx.ctx, fx)
        with self._env("/usr/bin:/opt/bin:/tmp:/shared"):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [("chmod", "/opt/bin", 0o755)])  # 共用暫存目錄不改
        self.assertTrue(fx.partial)
        self.assertIn("/tmp、/shared", fx.notes[0])


# ---- 家目錄 ----

# RHEL8 0079–0082 / RHEL9 0079–0082 使用者家目錄權限、擁有者、擁有群組、「.」檔案權限
class TestHomeDirs(Base):
    PW = ("alice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n"
          "carol:x:1002:1002::/home/carol:/bin/bash\nbad:x:abc:1::/home/bad:/bin/bash\n")
    STATS = {"/home/alice": st(DIR | 0o755, 1000, 1000), "/home/bob": st(DIR | 0o700, 2000, 3000),
             "/home/alice/.bashrc": st(0o100666), "/home/alice/.ssh": st(DIR | 0o777)}
    GLOBS = {"/home/alice/.[A-Za-z0-9]*": ["/home/alice/.bashrc", "/home/alice/.gone", "/home/alice/.ssh"],
             "/home/bob/.[A-Za-z0-9]*": []}

    def _env(self, login_defs="UID_MIN x\nUID_MAX y\n"):
        fs = {"/etc/passwd": self.PW, "/etc/login.defs": login_defs}
        return env(fs, os_=FakeOs(self.STATS), users={2000: "zed"}, groups={3000: "grp3000"}, globs=self.GLOBS)

    def test_uid_range_invalid(self):
        with self._env():
            self.assertEqual(s._uid_range(), (1000, 60000))

    def test_problems(self):
        with self._env():
            c = rule(s.HomeDirs, kind="mode").check(FakeCtx())
            self.assertEqual(c.status, FAIL)
            self.assertIn("/home/alice 權限 755", c.current)
            self.assertIn("略過：carol（家目錄 /home/carol 不存在）", c.current)
            self.assertIn("/home/bob 擁有者 zed（應為 bob）", rule(s.HomeDirs, kind="owner").check(FakeCtx()).current)
            self.assertIn("/home/bob 群組 grp3000（應為 GID 1001）",
                          rule(s.HomeDirs, kind="group").check(FakeCtx()).current)
            bad, _ = rule(s.HomeDirs, kind="dotfiles")._problems()
        self.assertEqual(bad, [("/home/alice/.bashrc", "/home/alice/.bashrc 權限 666")])

    def test_fix(self):
        fx = FakeFx(FakeCtx())
        with self._env():
            rule(s.HomeDirs, kind="mode").fix(fx.ctx, fx)
            rule(s.HomeDirs, kind="dotfiles").fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("chmod"), ["/home/alice", "/home/alice/.bashrc"])
        self.assertEqual([e[2] for e in fx.events], [0o700, 0o644])


# RHEL8 0083–0085 / RHEL9 0083–0085 使用者家目錄之「.forward」「.netrc」「.rhosts」檔案
class TestHomeFile(Base):
    def test_check(self):
        r = rule(s.HomeFile, name=".netrc")
        stats = {"/home/alice/.netrc": st(0o100600), "/root/.netrc": st(0o100600)}
        fs = {"/etc/passwd": "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"}
        with env(fs, os_=FakeOs(stats)):
            c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertEqual(c.current, "存在：/home/alice/.netrc；另有 /root/.netrc（文件不檢查 root，供參考）")


# ---- RHEL 9 新增 ----

# RHEL9 0305 /etc/shells 中不應存在 nologin
class TestShellsNologin(Base):
    def test_check_fix(self):
        r = rule(s.ShellsNologin)
        with env({}):
            self.assertEqual(r.check(FakeCtx()).status, NA)
        fs = {s.SHELLS: "/bin/bash\n/sbin/nologin\n"}
        fx = FakeFx(FakeCtx(), fs=fs)
        with env(fs):
            r.fix(fx.ctx, fx)
            self.assertEqual(r.check(fx.ctx).status, PASS)
        self.assertEqual(fs[s.SHELLS], "/bin/bash\n")


# RHEL9 0306 禁止 chrony 以 root 權限執行
class TestChrony(Base):
    r = rule(s.ChronyNotRoot)

    def test_eval_attached_F(self):
        self.assertEqual(s.chrony_eval(["-F2"]), (False, "2"))

    def test_check(self):
        ps = FakeRunner({"ps -o user=": res(0, "root\n")})
        with env({s.CHRONY_SYSCONFIG: 'OPTIONS="-F 2'}, ps):
            self.assertIn("引號不成對", self.r.check(FakeCtx()).current)
        with env({s.CHRONY_SYSCONFIG: 'OPTIONS="-F 2"\n'}, ps):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("需重新啟動 chronyd", c.current)
        with env({}, FakeRunner({"ps -o user=": res(1)})):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.current, "%s 不存在；chronyd 執行身分：未執行" % s.CHRONY_SYSCONFIG)
        with env({s.CHRONY_SYSCONFIG: 'OPTIONS="-F 2"\n'}, FakeRunner({"ps -o user=": res(0, "chrony\n")})):
            self.assertEqual(self.r.check(FakeCtx()).status, PASS)

    def test_fix(self):
        fx = FakeFx(FakeCtx())
        with env({s.CHRONY_SYSCONFIG: 'OPTIONS="-F 2'}):
            with self.assertRaises(ManualRequired):
                self.r.fix(fx.ctx, fx)
        fs = {s.CHRONY_SYSCONFIG: '# x\nOPTIONS="-4 -u root -F 1"\n'}
        fx = FakeFx(FakeCtx(), fs=fs)
        with env(fs):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(s.te.get_kv(fs[s.CHRONY_SYSCONFIG], "OPTIONS"), '"-4 -F 2"')
        self.assertEqual(fx.events, [("undo", "systemctl try-restart chronyd.service"),
                                     ("write", s.CHRONY_SYSCONFIG),
                                     ("run", "systemctl try-restart chronyd.service")])


# RHEL9 0307 ptrace 限制模式
class TestPtrace(Base):
    r = rule(s.PtraceScope)

    def _env(self, rt, pv, where=(), fs=None, real=None):
        stack = env(fs or {}, os_=FakeOs(real=real or {}))
        stack.enter_context(mock.patch.object(s.pkgsvc, "sysctl_runtime", lambda k: rt))
        stack.enter_context(mock.patch.object(s.pkgsvc, "sysctl_persistent",
                                              lambda k: (pv, where[-1][0] if where else None, list(where))))
        return stack

    def test_check(self):
        with self._env(None, None):
            self.assertEqual(self.r.check(FakeCtx()).status, NA)
        with self._env("1", "1", [(s.PTRACE_OWN, "1")]):
            c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "%s 目前=1 開機=1（%s）" % (s.PTRACE_KEY, s.PTRACE_OWN)))
        with self._env("2", None):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("開機=未設定", c.current)
        self.assertIn("更嚴格", c.current)

    def test_fix_stricter_kept(self):
        fx = FakeFx(FakeCtx())
        with self._env("1", "3"):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])
        self.assertTrue(fx.partial)

    def test_fix_conflicts(self):
        k = s.PTRACE_KEY
        where = [("/usr/lib/sysctl.d/10-default-yama-scope.conf", "0"),  # 排在本檔之前，不需處理
                 (s.PTRACE_OWN, "0"), ("/etc/sysctl.d/70-ok.conf", "1"),
                 ("/etc/sysctl.d/80-x.conf", "0"), ("/usr/lib/sysctl.d/99-pkg.conf", "0"),
                 ("/etc/sysctl.conf", "0")]
        fs = {"/etc/sysctl.d/80-x.conf": "%s = 0\n" % k, "/usr/lib/sysctl.d/99-pkg.conf": "%s=0\nx=1\n" % k,
              "/etc/sysctl.conf": "%s = 0\n" % k}
        fx = FakeFx(FakeCtx(), fs=fs)
        with self._env("0", "0", where, fs):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("write"), ["/etc/sysctl.d/80-x.conf", "/etc/sysctl.d/99-pkg.conf",
                                             "/etc/sysctl.conf", s.PTRACE_OWN])
        self.assertIn("# *REMOVED*", fs["/etc/sysctl.d/80-x.conf"])
        self.assertIn("x=1", fs["/etc/sysctl.d/99-pkg.conf"])  # 套件檔以 /etc 同名檔覆蓋，不改原檔
        self.assertEqual(fs["/usr/lib/sysctl.d/99-pkg.conf"], "%s=0\nx=1\n" % k)
        self.assertEqual(s.te.get_kv(fs[s.PTRACE_OWN], k), "1")
        self.assertEqual(fx.events[-1], ("sysctl", k, "1"))

    def test_fix_runtime_ok(self):
        fx = FakeFx(FakeCtx())
        with self._env("1", None):
            self.r.fix(fx.ctx, fx)
        self.assertEqual(fx.kinds("sysctl"), [])
        self.assertEqual(fx.kinds("write"), [s.PTRACE_OWN])


# ---- 僅檢測路徑補強（不依賴容器測試） ----

# 共用：/proc/self/mounts 解析與掛載點篩選
class TestMounts(Base):
    def test_proc_mounts_and_roots(self):
        fs = {"/proc/self/mounts": ("/dev/sda1 / xfs rw,relatime 0 0\n/dev/sdb1 /data\\040x ext4 rw 0 0\n"
                                    "short line\n/dev/sdc1 /mnt/gone ext4 rw 0 0\n")}
        fos = FakeOs({"/": st(DIR, dev=1), "/data x": st(DIR, dev=2)})
        with env(fs, os_=fos):
            m = s.proc_mounts()
            roots = s.scan_roots()
        self.assertEqual(m[1], ("/dev/sdb1", "/data x", "ext4", ["rw"]))
        self.assertEqual(len(m), 3)
        self.assertEqual(roots, ["/", "/data x"])  # 掛載點目錄不存在者略過


# RHEL8 0066–0071 / RHEL9 0066–0071 掃描結果與 RPM 屬性快取
class TestTreeCaches(Base):
    def test_tree_result_cache(self):
        calls = []

        def scan(dirs, deadline):
            calls.append(dirs)
            return {"x": len(calls)} if dirs == ("/ok",) else "逾時"
        with mock.patch.object(s, "tree_scan", scan):
            self.assertIs(s.tree_result(("/ok",)), s.tree_result(("/ok",)))
            self.assertEqual(s.tree_result(("/slow",)), "逾時")
            s.tree_result(("/slow",))
        self.assertEqual(calls, [("/ok",), ("/slow",), ("/slow",)])  # 錯誤結果不快取

    def test_rpm_file_attrs(self):
        runner = FakeRunner({"rpm -qa": res(0, "/usr/bin/a\troot\troot\n/usr/sbin/postdrop\troot\tpostdrop\nbad\n")})
        with env(runner=runner):
            attrs = s.rpm_file_attrs()
            self.assertIs(s.rpm_file_attrs(), attrs)
        self.assertEqual(attrs, {"/usr/bin/a": ("root", "root"), "/usr/sbin/postdrop": ("root", "postdrop")})
        self.assertEqual(len(runner.calls), 1)
        s._rpm_cache.clear()
        with env(), mock.patch.object(s, "which", lambda n: None):
            self.assertEqual(s.rpm_file_attrs(), {})

    def test_check_group_and_pass(self):
        item = ("/usr/lib/x.so", "/usr/lib/x.so", 0o755, 0, 50)
        tree = {"mode": [], "file_mode": [], "owner": [], "group": [item], "cmd_group": [], "roots": ["/usr/lib"]}
        with env(groups={50: "staff"}), mock.patch.object(s, "tree_result", lambda d: tree), \
                mock.patch.object(s, "rpm_file_attrs", lambda: {}):
            c = rule(s.TreePerm, kind="group").check(FakeCtx())
            self.assertEqual(c.current, "/usr/lib/x.so（群組 staff）；範圍：/usr/lib")
            c = rule(s.TreePerm, kind="file_mode").check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "皆符合；範圍：/usr/lib"))


# RHEL8 0078、0086–0090 / RHEL9 0078、0086–0090 UID=0 之帳號與帳號/群組資料庫
class TestAccountDbCheck(Base):
    PW = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
    GR = "root:x:0:\nalice:x:1000:\nusers:x:1000:\nusers:x:100:\n"

    def test_dup_group(self):
        fs = {"/etc/gshadow": "root:::\nusers:::\nusers:::\n\nbroken\n"}
        with env(fs):
            self.assertEqual(s._names("/etc/gshadow"), ["root", "users", "users"])
            gr = s.parse_group(self.GR)
            self.assertEqual(s.bad_dup_gid([], gr), ["GID 1000：alice,users"])
            self.assertEqual(s.bad_dup_group([], gr), ["群組名稱重複：users", "/etc/gshadow 群組名稱重複：users"])

    def test_check(self):
        fs = {"/etc/passwd": self.PW, "/etc/group": self.GR}
        with env(fs):
            c = rule(s.AccountDb, func=s.bad_dup_gid).check(FakeCtx())
            self.assertEqual((c.status, c.current), (FAIL, "GID 1000：alice,users"))
            c = rule(s.AccountDb, func=s.bad_uid0).check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "僅 root 之 UID 為 0"))


# RHEL8 0075–0077 / RHEL9 0075–0077 檔案行首之「+」符號（合格）
class TestPlusLinesPass(Base):
    def test_pass(self):
        with env({"/etc/group": "root:x:0:\n"}):
            c = rule(s.PlusLines, path="/etc/group").check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "無行首為「+」的行"))


# RHEL8 0083–0085 / RHEL9 0083–0085 使用者家目錄之「.forward」等檔案（未發現）
class TestHomeFileNone(Base):
    def test_pass(self):
        fs = {"/etc/passwd": "alice:x:1000:1000::/home/alice:/bin/bash\n"}
        stats = {"/home/alice/.forward": st(DIR | 0o755)}  # 同名目錄不算檔案
        with env(fs, os_=FakeOs(stats)):
            self.assertEqual(rule(s.HomeFile, name=".forward").check(FakeCtx()).current, "未發現")
            self.assertEqual(rule(s.HomeFile, name=".rhosts").check(FakeCtx()).status, PASS)


if __name__ == "__main__":
    unittest.main()
