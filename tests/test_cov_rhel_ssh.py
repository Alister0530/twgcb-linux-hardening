# -*- coding: utf-8 -*-
"""RHEL SSH 規則（gcb/rules/rhel/ssh.py）check／fix 的模擬測試（不執行 sshd、不碰真實檔案）。"""
import fnmatch
import os
import sys
import unittest
from contextlib import ExitStack

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402  (fakes 會把專案根目錄加入 sys.path)
from fakes import FakeCtx, FakeFx, FakeRunner, mock, res  # noqa: E402
from gcb.fixer import FixError, ManualRequired  # noqa: E402
from gcb.util import cmd_str  # noqa: E402
from gcb.rules.base import ERROR, FAIL, NA, PASS  # noqa: E402
from gcb.rules.rhel import ssh as s  # noqa: E402


# ---- 模擬環境 ----

class FakePath(object):
    """os.path 替身：fs 中的鍵視為存在的檔案；broken 中的路徑 isfile 拋出 OSError。"""

    def __init__(self, fs, broken=()):
        self.fs = fs
        self.broken = broken
        self.basename = os.path.basename
        self.join = os.path.join

    def isfile(self, p):
        if p in self.broken:
            raise OSError(13, "Permission denied")
        return p in self.fs

    def exists(self, p):
        return p in self.fs


class FakeOs(object):
    def __init__(self, fs, uids=None, broken=()):
        self.path = FakePath(fs, broken)
        self.uids = uids or {}

    def stat(self, p):
        if p not in self.uids:
            raise OSError(2, "No such file")
        return mock.Mock(st_uid=self.uids[p])


class FakeGlob(object):
    def __init__(self, fs):
        self.fs = fs

    def glob(self, pat):
        pp = pat.split("/")
        return sorted(k for k in self.fs if len(k.split("/")) == len(pp)
                      and all(fnmatch.fnmatchcase(x, y) for x, y in zip(k.split("/"), pp)))


def env(fs, runner=None, which=True, os_=None):
    st = ExitStack()
    st.enter_context(mock.patch.object(s, "read_text", fakes.fs_reader(fs)))
    st.enter_context(mock.patch.object(s, "run", runner or FakeRunner()))
    st.enter_context(mock.patch.object(s, "which", (lambda n: "/usr/sbin/" + n) if which else (lambda n: None)))
    st.enter_context(mock.patch.object(s, "glob", FakeGlob(fs)))
    st.enter_context(mock.patch.object(s, "os", os_ or FakeOs(fs)))
    return st


def sshd_T(**kw):
    """組 sshd -T 輸出；預設為合格的 GCB 演算法。"""
    d = {"ciphers": "aes256-ctr,aes128-ctr", "macs": "hmac-sha2-512", "kexalgorithms": "ecdh-sha2-nistp256"}
    d.update(kw)
    return "".join("%s %s\n" % (k, v) for k, v in d.items())


def param(opt):
    return [r for r in s.RULES if isinstance(r, s.SshdParam) and r.opt == opt][0]


def rule(cls):
    return [r for r in s.RULES if type(r) is cls][0]


def idx(fx, ev):
    return fx.events.index(ev)


UNIT9 = "[Service]\nEnvironmentFile=-/etc/sysconfig/sshd\nExecStart=/usr/sbin/sshd -D $OPTIONS\n"
MAIN9 = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"
REDHAT9 = "Include /etc/crypto-policies/back-ends/opensshserver.config\nX11Forwarding yes\n"


def fs9(**extra):
    fs = {s.SSHD_MAIN: MAIN9, "/etc/ssh/sshd_config.d/50-redhat.conf": REDHAT9,
          s.CP_BACKEND: "Ciphers aes256-gcm@openssh.com\n", "/usr/lib/systemd/system/sshd.service": UNIT9}
    fs.update(extra)
    return fs


class Base(unittest.TestCase):
    def setUp(self):
        s._FIND_CACHE.clear()

    def tearDown(self):
        s._FIND_CACHE.clear()


# ---- sshd.service 解析 ----

# sshd.service 啟動參數（RHEL 8 的 $CRYPTO_POLICY）
class TestServiceInfo(Base):
    def test_parsing_edge_cases(self):
        self.assertEqual(s._shsplit('a "b'), ["a", '"b'])  # 引號不成對改以空白切
        lines = s._unit_lines("# c\nExecStart=/usr/sbin/sshd -D \\\n  $OPTIONS\nX=1 \\")
        self.assertEqual(lines, ["ExecStart=/usr/sbin/sshd -D  $OPTIONS", "X=1  "])
        env_, _, _ = s.parse_service([("u", "[Service]\nEnvironment=A=1\n"), ("d", "[Service]\nEnvironment=\n")])
        self.assertEqual(env_, [])
        self.assertEqual(s.parse_env_file("junk\n1BAD=x\nOK='a  b'\nE=\n"), {"OK": "a  b", "E": ""})

    def test_defaults_without_unit(self):
        fs = {s.CP_BACKEND: "CRYPTO_POLICY='-oCiphers=aes256-ctr'\n"}
        with env(fs):
            info = s.ServiceInfo("rhel8")
        self.assertEqual(info.env_files, [("預設", "-" + s.CP_BACKEND), ("預設", "-" + s.SYSCONFIG)])
        self.assertEqual(info.args, ["-oCiphers=aes256-ctr"])  # sysconfig 不存在略過
        self.assertEqual([p for p, _ in info.file_env], [s.CP_BACKEND])

    def test_dropin_etc_wins(self):
        fs = {"/usr/lib/systemd/system/sshd.service": UNIT9,
              "/usr/lib/systemd/system/sshd.service.d/10-x.conf": "[Service]\nExecStart=\nExecStart=/a -D -x\n",
              "/etc/systemd/system/sshd.service.d/10-x.conf": "[Service]\nExecStart=\nExecStart=/b -D -y\n"}
        with env(fs):
            self.assertEqual(s.ServiceInfo._files(), ["/usr/lib/systemd/system/sshd.service",
                                                      "/etc/systemd/system/sshd.service.d/10-x.conf"])
            self.assertEqual(s.ServiceInfo("rhel9").args, ["-y"])

    def test_rhel_sshd_args_hook(self):
        with env({s.SYSCONFIG: "OPTIONS=-u0\n"}):
            self.assertEqual(s._rhel_sshd_args(FakeCtx("rhel9")), ["-u0"])
        self.assertEqual(s._rhel_sshd_args(FakeCtx("ubuntu2204")), [])


# sshd -T／sshd -t 共用流程
class TestSshdHelpers(Base):
    def test_sshd_values(self):
        ctx = FakeCtx()
        with env({}, which=False):
            vals, err = s.sshd_values(ctx)
        self.assertIsNone(vals)
        self.assertEqual(err.status, NA)
        with env({}, FakeRunner({"sshd -T": res(255, err="Bad configuration option")})):
            vals, err = s.sshd_values(ctx)
        self.assertEqual(err.status, ERROR)
        self.assertIn("Bad configuration", err.current)

    def test_apply_syntax_error_no_reload(self):
        ctx = FakeCtx()
        runner = FakeRunner({"sshd -t": res(255, err="line 3: Bad option")})
        fx = FakeFx(ctx, runner=runner)
        with env({}, runner):
            with self.assertRaises(FixError):
                s.apply_sshd(ctx, fx)
        self.assertEqual(runner.ran("systemctl"), [])

    def test_apply_restart(self):
        ctx = FakeCtx("rhel8")
        fx = FakeFx(ctx)
        with env({}, fx.runner):
            s.apply_sshd(ctx, fx, restart=True)
        self.assertEqual(fx.kinds("run"), ["/usr/sbin/sshd -t", "systemctl restart sshd"])

    def test_config_lines_missing_and_loop(self):
        with env({}):
            self.assertEqual(s.config_lines(), [])
        fs = {s.SSHD_MAIN: "Include /etc/ssh/sshd_config\nPort 22\n"}
        with env(fs):
            lines = s.config_lines()
        self.assertEqual(len([x for x in lines if x[1] == "port"]), 9)  # 深度 0–8 後停止（避免 Include 迴圈）

    def test_startups_bad_shape(self):
        self.assertFalse(s.startups_ok("10:30"))
        self.assertFalse(s.startups_ok("0:30:60"))


# ---- sshd 參數 ----

# RHEL8 0272–0289 / RHEL9 0264–0281、0315 sshd 參數
class TestSshdParam(Base):
    def test_check_and_fix_error(self):
        r = param("LogLevel")
        ctx = FakeCtx()
        with env({}, FakeRunner({"sshd -T": res(1, err="boom")})):
            self.assertEqual(r.check(ctx).status, ERROR)
            with self.assertRaises(FixError):
                r.fix(ctx, FakeFx(ctx))

    def test_fix_writes_main_comments_dropin_then_reload(self):
        r = param("MaxAuthTries")
        dropin = "/etc/ssh/sshd_config.d/60-x.conf"
        fs = fs9(**{dropin: "MaxAuthTries 6\n"})
        runner = FakeRunner({"sshd -T": res(0, sshd_T(maxauthtries="6"))})
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs, runner=runner)
        with env(fs, runner):
            self.assertEqual(r.check(ctx).current, "MaxAuthTries 6")
            r.fix(ctx, fx)
        self.assertIn("MaxAuthTries 4", fs[s.SSHD_MAIN])
        self.assertEqual(fs[dropin], s.te.MARK + "MaxAuthTries 6\n")
        self.assertNotIn(s.CP_BACKEND, fx.kinds("write"))  # crypto-policies 檔不在 drop-in 範圍
        undo = idx(fx, ("undo", "systemctl reload sshd"))
        self.assertLess(undo, idx(fx, ("write", s.SSHD_MAIN)))
        self.assertLess(idx(fx, ("write", dropin)), idx(fx, ("run", "/usr/sbin/sshd -t")))
        self.assertLess(idx(fx, ("run", "/usr/sbin/sshd -t")), idx(fx, ("run", "systemctl reload sshd")))
        self.assertTrue(fx.notes)  # 提醒用戶端金鑰數量

    def test_fix_dry_run(self):
        r = param("X11Forwarding")
        fs = fs9()
        runner = FakeRunner({"sshd -T": res(0, sshd_T(x11forwarding="yes"))})
        ctx = FakeCtx(dry_run=True)
        fx = FakeFx(ctx, fs=fs, runner=runner)
        with env(fs, runner):
            r.fix(ctx, fx)
        self.assertEqual(fs, fs9())
        self.assertEqual(fx.kinds("undo"), [])
        self.assertEqual(runner.ran("systemctl"), [])

    def test_preconditions(self):
        ctx = FakeCtx()
        self.assertIsNone(param("MaxAuthTries").precondition(ctx))
        self.assertIsNone(param("LogLevel").precondition(ctx))
        ctx.pre_health_status["H04"] = "失敗"
        self.assertIn("SSH 實際登入", param("UsePAM").precondition(ctx))
        self.assertIn("SSH 實際登入", param("StrictModes").precondition(ctx))
        g = param("GSSAPIAuthentication")
        with env({"/etc/krb5.keytab": ""}):
            self.assertIn("krb5.keytab", g.precondition(ctx))
        with env({}):
            self.assertIsNone(g.precondition(ctx))


# RHEL8 0263 / RHEL9 0255 SSH 協定版本
class TestSshProtocol(Base):
    r = rule(s.SshProtocol)

    def test_version_fallback(self):
        runner = FakeRunner({"rpm -q": res(1), "ssh -V": res(0, err="OpenSSH_7.2p2, OpenSSL 1.0")})
        with env({s.SSHD_MAIN: "Protocol 2\n"}, runner):
            self.assertEqual(self.r.version(), (7, 2))
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("設定檔 Protocol 2", c.current)

    def test_unknown_version_and_old_without_protocol(self):
        with env({}, FakeRunner({"rpm -q": res(1), "ssh -V": res(127)})):
            self.assertEqual(self.r.check(FakeCtx()).status, ERROR)
        with env({}, FakeRunner({"rpm -q": res(0, "7.3p1")})):
            self.assertEqual(self.r.check(FakeCtx()).status, FAIL)

    def test_fix(self):
        fs = {s.SSHD_MAIN: "Port 22\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs, fx.runner):
            self.r.fix(ctx, fx)
        self.assertIn("Protocol 2", fs[s.SSHD_MAIN])
        self.assertEqual(fx.events[0], ("undo", "systemctl reload sshd"))


# RHEL8 0266 / RHEL9 0258 限制存取 SSH；RHEL8 0287 / RHEL9 0279 SSH Compression 參數（C 類）
class TestCheckOnly(Base):
    def test_access_limit(self):
        r = rule(s.SshAccessLimit)
        with env({}, FakeRunner({"sshd -T": res(1)})):
            self.assertEqual(r.check(FakeCtx()).status, ERROR)
        with env({}, FakeRunner({"sshd -T": res(0, sshd_T(allowgroups="wheel ops"))})):
            c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (PASS, "AllowGroups wheel ops"))

    def test_compression(self):
        r = rule(s.SshCompression)
        with env({}, FakeRunner({"sshd -T": res(1)})):
            self.assertEqual(r.check(FakeCtx()).status, ERROR)
        with env({}, FakeRunner({"sshd -T": res(0, "compression no\n")})):
            self.assertEqual(r.check(FakeCtx()).status, PASS)
        with env({s.SSHD_MAIN: "Compression delayed\n"}, FakeRunner({"sshd -T": res(0, "compression yes\n")})):
            c = r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("delayed", c.current)


# RHEL9 0259 SSH 主機私鑰檔案所有權
class TestHostKeyOwnerR9(Base):
    def test_fix_without_ssh_keys_group(self):
        r = [x for x in s.RULES if isinstance(x, s.HostKeyOwnerR9)][0]
        g = mock.Mock(getgrnam=mock.Mock(side_effect=KeyError("ssh_keys")))
        fx = FakeFx(FakeCtx())
        with mock.patch.object(s, "grp", g):
            with self.assertRaises(ManualRequired):
                r.fix(fx.ctx, fx)
        self.assertEqual(fx.events, [])


# ---- shosts ----

FIND = "find"


# RHEL8 0290 / RHEL9 0282 shosts.equiv 檔案
class TestShostsEquiv(Base):
    r = rule(s.ShostsEquiv)

    def test_check_and_fix(self):
        fs = {"/proc/mounts": "/dev/sda1 / xfs rw 0 0\n/dev/sdb1 /data\\040x ext4 rw 0 0\nproc /proc proc rw 0 0\n",
              "/etc/ssh/shosts.equiv": "host\n"}
        runner = FakeRunner({FIND: res(0, "/data x/shosts.equiv\n")})
        ctx = FakeCtx()
        fx = FakeFx(ctx, runner=runner)
        with env(fs, runner):
            c = self.r.check(ctx)
            self.r.fix(ctx, fx)
        self.assertEqual(c.status, FAIL)
        self.assertIn("/data x/shosts.equiv", c.current)
        self.assertIn("find / '/data x' -xdev", runner.calls[0])
        self.assertEqual(len(runner.ran(FIND)), 1)  # 第二次使用快取
        for p in ("/data x/shosts.equiv", "/etc/ssh/shosts.equiv"):
            self.assertLess(idx(fx, ("backup", p)), idx(fx, ("run", cmd_str(["rm", "-f", "--", p]))))
        self.assertEqual(s._FIND_CACHE, {})

    def test_timeout_note(self):
        with env({}, FakeRunner({FIND: res(124)})):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("逾時", c.current)


# RHEL8 0291 / RHEL9 0283 .shosts 檔案（C 類，只回報）
class TestUserShosts(Base):
    r = rule(s.UserShosts)

    def _env(self, fs, runner, users, uids, names, broken=()):
        st = env(fs, runner, os_=FakeOs(fs, uids, broken))
        pw = mock.Mock()
        pw.getpwall.return_value = [mock.Mock(pw_dir=d) for d in users]

        def getpwuid(uid):
            if uid not in names:
                raise KeyError(uid)
            return mock.Mock(pw_name=names[uid])
        pw.getpwuid.side_effect = getpwuid
        st.enter_context(mock.patch.object(s, "pwd", pw))
        return st

    def test_found(self):
        fs = {"/home/a/.shosts": ""}
        found = "".join("/srv/%02d.shosts\n" % i for i in range(11))
        uids = {"/home/a/.shosts": 1000, "/srv/00.shosts": 0}
        with self._env(fs, FakeRunner({FIND: res(0, found)}), ["/home/a", "/home/b", ""], uids, {1000: "alice"},
                       broken=("/home/b/.shosts",)):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertIn("/home/a/.shosts（alice）", c.current)
        self.assertIn("/srv/00.shosts、", c.current)   # uid 0 查無名稱只列路徑
        self.assertIn("…另 2 個", c.current)

    def test_none(self):
        with self._env({}, FakeRunner({FIND: res(0, "")}), [], {}, {}):
            self.assertEqual(self.r.check(FakeCtx()).status, PASS)

    def test_find_cache_not_mutated(self):
        cached = ["/srv/x.shosts"]
        fs = {"/home/a/.shosts": ""}
        with self._env(fs, FakeRunner(), ["/home/a"], {}, {}):
            with mock.patch.object(s, "find_files", return_value=(cached, False)):
                self.r.check(FakeCtx())
        self.assertEqual(cached, ["/srv/x.shosts"])  # 家目錄的 .shosts 不得加進快取清單


# ---- 加密演算法 ----

# RHEL8 0292 / RHEL9 0284 覆寫全系統加密原則：覆寫來源判定
class TestCryptoOverrides(Base):
    def test_rhel8_sources(self):
        unit = ("[Service]\nEnvironment=CRYPTO_POLICY=-oCiphers=x\nEnvironmentFile=-/etc/default/sshx\n"
                "EnvironmentFile=-/etc/sysconfig/sshd\nExecStart=/usr/sbin/sshd -D $OPTIONS\n")
        fs = {"/etc/systemd/system/sshd.service": unit, "/etc/default/sshx": "CRYPTO_POLICY=\n",
              s.SYSCONFIG: "OPTIONS=\nCRYPTO_POLICY=-oCiphers=aes128-ctr\n"}
        with env(fs):
            sysconf, manual = s.crypto_overrides(FakeCtx("rhel8"))
        self.assertEqual(sysconf, ["CRYPTO_POLICY=-oCiphers=aes128-ctr"])
        self.assertEqual(len(manual), 3)
        self.assertIn("Environment=", manual[0])
        self.assertIn("/etc/default/sshx", manual[1])
        self.assertIn("ExecStart", manual[2])

    def test_rhel9_include(self):
        with env({s.SSHD_MAIN: "PermitRootLogin no\n"}):
            self.assertIn("未 Include", s.crypto_overrides(FakeCtx())[1][0])
        fs = fs9(**{s.SSHD_MAIN: "Ciphers aes256-ctr\n" + MAIN9})
        with env(fs):
            self.assertEqual(s.crypto_overrides(FakeCtx())[1],
                             ["%s 在 crypto-policies 之前設定 ciphers aes256-ctr" % s.SSHD_MAIN])
        with env(fs9()):
            self.assertEqual(s.crypto_overrides(FakeCtx()), ([], []))


def ucp_runner(show="DEFAULT\n", set_rc=0, T=None):
    return FakeRunner({"--show": res(0, show) if show is not None else res(1, err="x"),
                       "--set": set_rc if callable(set_rc) else res(set_rc, err="unknown key"),
                       "sshd -T": res(0, T or sshd_T())})


# crypto-policies 子原則（GCB-SSH）套用流程
class TestApplyGcbPolicy(Base):
    def test_rhel8_old_refused(self):
        ctx = FakeCtx("rhel8", version="8.1")
        fx = FakeFx(ctx)
        with self.assertRaises(ManualRequired):
            s.apply_gcb_policy(ctx, fx)
        self.assertEqual(fx.events, [])

    def test_success_backup_and_undo_first(self):
        ctx = FakeCtx()
        runner = ucp_runner(show="DEFAULT:NO-SHA1\n")
        fx = FakeFx(ctx, runner=runner)
        with env({}, runner):
            s.apply_gcb_policy(ctx, fx)
        new = "/usr/sbin/update-crypto-policies --set DEFAULT:NO-SHA1:GCB-SSH"
        undo = ("undo", "/usr/sbin/update-crypto-policies --set DEFAULT:NO-SHA1")
        self.assertEqual(fx.kinds("backup"), [s.CP_DIR + "/config", s.CP_DIR + "/state/current"])
        self.assertLess(idx(fx, ("backup", s.CP_DIR + "/state/current")), idx(fx, undo))
        self.assertLess(idx(fx, undo), idx(fx, ("run", new)))
        self.assertEqual(fx.fs[s.CP_PMOD], s.PMOD_TEXT + s.PMOD_ETM[0] + "\n")
        self.assertTrue(fx.fs[s.CP_PMOD].encode("ascii"))  # 必須是純 ASCII

    def test_module_already_in_policy_and_etm_fallback(self):
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        # 第一種 etm 寫法不被支援時改用第二種
        fx.runner = ucp_runner(show="DEFAULT:GCB-SSH\n",
                               set_rc=lambda c: res(1, err="bad") if "ssh_etm" in fx.fs[s.CP_PMOD] else res(0))
        with env({}, fx.runner):
            s.apply_gcb_policy(ctx, fx)
        self.assertEqual(fx.fs[s.CP_PMOD], s.PMOD_TEXT + s.PMOD_ETM[1] + "\n")
        self.assertEqual(len(fx.runner.ran("--set DEFAULT:GCB-SSH")), 2)

    def test_installs_scripts_and_show_failure(self):
        ctx = FakeCtx()
        runner = ucp_runner(show=None)
        fx = FakeFx(ctx, runner=runner)
        with env({}, runner, which=False):
            with self.assertRaises(FixError):
                s.apply_gcb_policy(ctx, fx)
        self.assertEqual(fx.events, [("pkg_install", "crypto-policies-scripts")])

    def test_dry_run_unknown_policy(self):
        ctx = FakeCtx(dry_run=True)
        runner = ucp_runner(show="")
        fx = FakeFx(ctx, runner=runner)
        with env({}, runner):
            s.apply_gcb_policy(ctx, fx)
        self.assertIn(("run", "/usr/sbin/update-crypto-policies --set DEFAULT:GCB-SSH"), fx.events)
        self.assertEqual(fx.fs, {})
        self.assertEqual(runner.ran("--set"), [])

    def test_still_violating(self):
        ctx = FakeCtx()
        runner = ucp_runner(T=sshd_T(macs="hmac-sha2-512,umac-128@openssh.com"))
        fx = FakeFx(ctx, runner=runner)
        with env({}, runner):
            with self.assertRaises(FixError) as cm:
                s.apply_gcb_policy(ctx, fx)
        self.assertIn("umac-128@openssh.com", str(cm.exception))

    def test_sshd_T_fails_after_apply(self):
        ctx = FakeCtx()
        runner = ucp_runner()
        runner.add("sshd -T", res(1, err="sshd broken"))
        fx = FakeFx(ctx, runner=runner)
        with env({}, runner):
            with self.assertRaises(FixError) as cm:
                s.apply_gcb_policy(ctx, fx)
        self.assertIn("sshd broken", str(cm.exception))


# RHEL8 0271 / RHEL9 0263 SSH 加密演算法
class TestSshCrypto(Base):
    r = rule(s.SshCrypto)

    def test_check(self):
        with env({}, FakeRunner({"sshd -T": res(1)})):
            self.assertEqual(self.r.check(FakeCtx()).status, ERROR)
        with env({}, FakeRunner({"sshd -T": res(0, sshd_T())})):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("Ciphers aes256-ctr,aes128-ctr", c.current)

    def test_precondition(self):
        ctx = FakeCtx()
        self.assertIsNone(self.r.precondition(ctx))
        ctx.pre_health_status["H04"] = "失敗"
        self.assertIsNotNone(self.r.precondition(ctx))

    def test_fix_manual_override(self):
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        with env({s.SSHD_MAIN: "Ciphers x\n"}):
            with self.assertRaises(ManualRequired):
                self.r.fix(ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_rhel9_with_sysconfig(self):
        fs = fs9(**{s.SYSCONFIG: "CRYPTO_POLICY=-oCiphers=aes128-ctr\n"})
        ctx = FakeCtx()
        runner = ucp_runner()
        fx = FakeFx(ctx, fs=fs, runner=runner)
        with env(fs, runner):
            self.r.fix(ctx, fx)
        self.assertEqual(fs[s.SYSCONFIG], s.te.MARK + "CRYPTO_POLICY=-oCiphers=aes128-ctr\n")
        undo = idx(fx, ("undo", "systemctl restart sshd"))  # sysconfig 變更需 restart
        self.assertLess(undo, idx(fx, ("write", s.SYSCONFIG)))
        self.assertLess(idx(fx, ("run", "/usr/sbin/sshd -t")), idx(fx, ("run", "systemctl restart sshd")))
        self.assertIn(s.CRYPTO_NOTE, fx.notes)


# RHEL8 0292 / RHEL9 0284 覆寫全系統加密原則
class TestCryptoNoOverride(Base):
    r = rule(s.CryptoNoOverride)

    def test_check(self):
        with env(fs9(**{s.SYSCONFIG: "CRYPTO_POLICY=x\n"})):
            c = self.r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "%s：CRYPTO_POLICY=x" % s.SYSCONFIG))
        with env(fs9()):
            c = self.r.check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("未被覆寫", c.current)
        ctx = FakeCtx()
        ctx.pre_health_status["H04"] = "略過"
        self.assertIsNotNone(self.r.precondition(ctx))

    def test_fix_nothing_in_sysconfig(self):
        ctx = FakeCtx()
        fx = FakeFx(ctx)
        with env({s.SSHD_MAIN: ""}):
            with self.assertRaises(ManualRequired):
                self.r.fix(ctx, fx)
        self.assertEqual(fx.events, [])

    def test_fix_partial_when_other_overrides(self):
        fs = {s.SSHD_MAIN: "", s.SYSCONFIG: "CRYPTO_POLICY=x\n"}
        ctx = FakeCtx()
        fx = FakeFx(ctx, fs=fs)
        with env(fs, fx.runner):
            self.r.fix(ctx, fx)
        self.assertTrue(fx.partial)
        self.assertLess(idx(fx, ("undo", "systemctl reload sshd")), idx(fx, ("write", s.SYSCONFIG)))
        self.assertEqual(fx.kinds("run")[-1], "systemctl reload sshd")

    def test_fix_dry_run(self):
        fs = fs9(**{s.SYSCONFIG: "CRYPTO_POLICY=x\n"})
        ctx = FakeCtx("rhel9", dry_run=True)
        fx = FakeFx(ctx, fs=fs)
        with env(fs, fx.runner):
            self.r.fix(ctx, fx)
        self.assertEqual(fs[s.SYSCONFIG], "CRYPTO_POLICY=x\n")
        self.assertTrue(any("預覽" in n for n in fx.notes))
        self.assertEqual(fx.runner.calls, [])

    def test_fix_rhel8_applies_policy_when_violating(self):
        unit = ("[Service]\nEnvironmentFile=-%s\nEnvironmentFile=-%s\n"
                "ExecStart=/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY\n" % (s.CP_BACKEND, s.SYSCONFIG))
        fs = {"/usr/lib/systemd/system/sshd.service": unit, s.SYSCONFIG: "CRYPTO_POLICY=-oCiphers=x\n"}
        ctx = FakeCtx("rhel8")
        runner = ucp_runner()
        state = {"n": 0}

        def T(cmd):  # 取消覆寫後第一次仍不合格，套用子原則後合格
            state["n"] += 1
            return res(0, sshd_T(ciphers="chacha20-poly1305@openssh.com") if state["n"] == 1 else sshd_T())
        runner.add("sshd -T", T)
        fx = FakeFx(ctx, fs=fs, runner=runner)
        with env(fs, runner):
            self.r.fix(ctx, fx)
        self.assertIn(s.CP_PMOD, fx.fs)
        self.assertIn(s.CRYPTO_NOTE, fx.notes)
        self.assertLess(idx(fx, ("undo", "systemctl restart sshd")), idx(fx, ("write", s.SYSCONFIG)))
        self.assertEqual(fx.kinds("run")[-1], "systemctl restart sshd")

    def test_fix_no_policy_when_compliant(self):
        fs = fs9(**{s.SYSCONFIG: "CRYPTO_POLICY=x\n"})
        ctx = FakeCtx()
        runner = FakeRunner({"sshd -T": res(0, sshd_T())})
        fx = FakeFx(ctx, fs=fs, runner=runner)
        with env(fs, runner):
            self.r.fix(ctx, fx)
        self.assertNotIn(s.CP_PMOD, fx.fs)
        self.assertEqual(runner.ran("update-crypto-policies"), [])


# ---- 僅檢測路徑補強（不依賴容器測試） ----

# sshd_config 解析：空行與註解略過
class TestConfigLinesComments(Base):
    def test_skip_blank_and_comment(self):
        with env({s.SSHD_MAIN: "# c\n\n  \nPort 22\nMatch all\nX11Forwarding no\n"}):
            lines = s.config_lines()
        self.assertEqual([(k, v, g) for _, k, v, g in lines],
                         [("port", "22", True), ("match", "all", True), ("x11forwarding", "no", True)])


# RHEL8 0284 / RHEL9 0276 SSH MaxStartups 參數；RHEL8 0280 / RHEL9 0272 SSH 逾時時間
class TestSshdParamCheck(Base):
    def test_startups(self):
        r = param("MaxStartups")
        with env({}, FakeRunner({"sshd -T": res(0, "maxstartups 10:30:100\n")})):
            c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "MaxStartups 10:30:100"))
        with env({}, FakeRunner({"sshd -T": res(0, "maxstartups 5:50:20\n")})):
            self.assertEqual(r.check(FakeCtx()).status, PASS)

    def test_multi_options(self):
        r = param("ClientAliveInterval")
        with env({}, FakeRunner({"sshd -T": res(0, "clientaliveinterval 300\n")})):
            c = r.check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "ClientAliveInterval 300；ClientAliveCountMax 未設定"))


# RHEL8 0263 / RHEL9 0255 SSH 協定版本（7.4 以上）
class TestSshProtocolModern(Base):
    def test_modern_openssh(self):
        with env({}, FakeRunner({"rpm -q": res(0, "8.7p1")})):
            c = rule(s.SshProtocol).check(FakeCtx())
        self.assertEqual(c.status, PASS)
        self.assertIn("OpenSSH 8.7 只支援 SSH-2", c.current)
        self.assertIn("設定檔未設定 Protocol", c.current)


# RHEL8 0266 / RHEL9 0258 限制存取 SSH；RHEL8 0287 / RHEL9 0279 SSH Compression 參數（不合格）
class TestCheckOnlyFail(Base):
    def test_access_limit_unset(self):
        with env({}, FakeRunner({"sshd -T": res(0, sshd_T(allowusers=""))})):
            c = rule(s.SshAccessLimit).check(FakeCtx())
        self.assertEqual(c.status, FAIL)

    def test_compression_fail(self):
        r = rule(s.SshCompression)
        yes = FakeRunner({"sshd -T": res(0, "compression yes\n")})
        with env({s.SSHD_MAIN: "Compression yes\n"}, yes):
            c = r.check(FakeCtx())
        self.assertEqual(c.status, FAIL)
        self.assertTrue(c.current.startswith("Compression yes（%s）；" % s.SSHD_MAIN))
        with env({}, yes):
            c = r.check(FakeCtx())
        self.assertTrue(c.current.startswith("Compression 未設定（預設 yes）；"))


# RHEL9 0259 SSH 主機私鑰檔案所有權（root:ssh_keys）
class TestHostKeyOwnerR9Check(Base):
    r = [x for x in s.RULES if isinstance(x, s.HostKeyOwnerR9)][0]

    def test_check_root_group_note(self):
        bad = s.Check(FAIL, "/etc/ssh/ssh_host_rsa_key（群組 root）")
        with mock.patch.object(s.FilePerm, "check", lambda self, ctx: bad):
            c = self.r.check(FakeCtx())
        self.assertIn("不符 GCB 字面 root:ssh_keys", c.current)
        other = s.Check(FAIL, "/etc/ssh/ssh_host_rsa_key（群組 wheel）")
        with mock.patch.object(s.FilePerm, "check", lambda self, ctx: other):
            self.assertEqual(self.r.check(FakeCtx()).current, "/etc/ssh/ssh_host_rsa_key（群組 wheel）")

    def test_fix_delegates_when_group_exists(self):
        fx = FakeFx(FakeCtx())
        g = mock.Mock(getgrnam=mock.Mock(return_value=mock.Mock(gr_gid=998)))
        with mock.patch.object(s, "grp", g), mock.patch.object(s.FilePerm, "fix") as base_fix:
            self.r.fix(fx.ctx, fx)
        base_fix.assert_called_once_with(self.r, fx.ctx, fx)


# RHEL8 0271 / RHEL9 0263 SSH 加密演算法（不合格）
class TestSshCryptoFail(Base):
    def test_violation(self):
        T = sshd_T(ciphers="aes256-ctr,chacha20-poly1305@openssh.com")
        with env({}, FakeRunner({"sshd -T": res(0, T)})):
            c = rule(s.SshCrypto).check(FakeCtx())
        self.assertEqual((c.status, c.current), (FAIL, "不在 GCB 清單：Ciphers 含 chacha20-poly1305@openssh.com"))


if __name__ == "__main__":
    unittest.main()
