# -*- coding: utf-8 -*-
"""設定精靈（gcb/setup.py）模擬測試：輸入以假資料提供，建立帳號、設定密碼等指令全部模擬。"""
import argparse
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fakes import FakeCtx, FakeRunner, fs_reader, res  # noqa: E402
from gcb import setup as s  # noqa: E402
from gcb.util import read_text  # noqa: E402


class Ctx(FakeCtx):
    def __init__(self, key="rhel9", **cfg):
        FakeCtx.__init__(self, key, **cfg)
        self.events, self.out, self.saved = [], [], 0
        self.state = {"ip": "10.0.0.5"}

    def say(self, msg):
        self.out.append(msg)

    def log_event(self, rid, action, detail, result="資訊"):
        self.events.append((rid, action, detail, result))

    def save(self):
        self.saved += 1


class Pw(object):
    def __init__(self, name, uid=1000, shell="/bin/bash"):
        self.pw_name, self.pw_uid, self.pw_shell = name, uid, shell


SUDO_OK = res(0, "User x may run the following commands:\n    (ALL) ALL\n")


class Base(unittest.TestCase):
    def setUp(self):
        self.answers, self.passwords = [], []
        self.users = {}
        self.shadow = {}
        self.runner = FakeRunner({"sudo -l": SUDO_OK})
        self.patch(s, "run", self.runner)
        self.patch(s, "read_text", fs_reader(self.shadow))
        self.patch(s.pwd, "getpwnam", self._getpwnam)
        self.patch(s.pwd, "getpwall", lambda: list(self.users.values()))
        self.patch(s.getpass, "getpass", lambda prompt: self._pop(self.passwords))
        p = mock.patch("builtins.input", lambda prompt: self._pop(self.answers))
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def _pop(q):
        if not q:
            raise EOFError
        return q.pop(0)

    def _getpwnam(self, name):
        if name not in self.users:
            raise KeyError(name)
        return self.users[name]

    def patch(self, obj, attr, val):
        p = mock.patch.object(obj, attr, val)
        p.start()
        self.addCleanup(p.stop)


class TestHelpers(Base):
    def test_ask_and_yes(self):
        self.assertEqual(s.ask("q", "d"), "d")            # EOF → 預設值
        self.answers = ["  x  ", ""]
        self.assertEqual(s.ask("q", "d"), "x")
        self.assertTrue(s.yes("q", "y"))
        self.answers = ["No"]
        self.assertFalse(s.yes("q", "y"))
        self.assertEqual(s.sudo_group(FakeCtx("ubuntu2204").osi), "sudo")

    def test_candidate_users(self):
        self.users = {"root": Pw("root", 0), "bob": Pw("bob"), "svc": Pw("svc", 1001, "/sbin/nologin"),
                      "nobody": Pw("nobody", 65534), "eve": Pw("eve", 1002)}
        self.runner.add("sudo -l -U eve", res(0, "User eve is not allowed to run sudo"))
        self.assertEqual(s.candidate_users(), ["bob"])

    def test_has_password(self):
        self.shadow["/etc/shadow"] = "bob:$6$x:1:0:99999:7:::\neve:!:1:0:99999:7:::\n"
        self.assertTrue(s._has_password("bob"))
        self.assertFalse(s._has_password("eve"))
        self.assertFalse(s._has_password("ghost"))

    def test_check_user(self):
        self.assertEqual(s.check_user(Ctx(), "ghost"), ["帳號不存在"])
        self.users["root"] = Pw("root", 0, "/sbin/nologin")
        self.runner.add("sudo -l", res(1))
        self.assertEqual(s.check_user(Ctx(), "root"),
                         ["不可為 root", "登入 shell 為 /sbin/nologin，無法登入", "沒有 sudo 權限"])


class TestPasswordAndCreate(Base):
    def test_set_password_retries(self):
        self.passwords = ["", "", "a", "b", "secret", "secret"]
        ctx = Ctx()
        self.assertTrue(s.set_password(ctx, "bob"))
        self.assertEqual(self.runner.calls, ["chpasswd"])
        self.assertIn("  密碼不可為空白。", ctx.out)
        self.assertIn("  兩次輸入不一致。", ctx.out)
        # 密碼不可出現在 log
        self.assertFalse(any("secret" in str(e) for e in ctx.events))

    def test_set_password_passes_stdin(self):
        seen = {}
        orig = self.runner

        def fake_run(cmd, timeout=120, env=None, input_text=None):
            seen["input"] = input_text
            return orig(cmd, timeout=timeout)
        self.patch(s, "run", fake_run)
        self.passwords = ["pw1", "pw1"]
        s.set_password(Ctx(), "bob")
        self.assertEqual(seen["input"], "bob:pw1\n")

    def test_set_password_fails(self):
        self.runner.add("chpasswd", res(1, "", "BAD PASSWORD"))
        self.passwords = ["a", "a", "a", "a", "a", "a"]
        ctx = Ctx()
        self.assertFalse(s.set_password(ctx, "bob"))
        self.assertEqual(len(self.runner.calls), 3)
        self.assertEqual(ctx.events[-1][3], "失敗")
        self.passwords = []
        self.assertFalse(s.set_password(Ctx(), "bob"))     # EOF

    def test_create_user(self):
        ctx = Ctx("ubuntu2204")
        self.passwords = ["p", "p"]
        self.assertTrue(s.create_user(ctx, "gcbtest"))
        self.assertEqual(self.runner.calls[:2], ["useradd -m -s /bin/bash gcbtest", "usermod -aG sudo gcbtest"])
        self.runner.add("useradd", res(9, "", "useradd: user exists"))
        ctx = Ctx()
        self.runner.calls[:] = []
        self.assertFalse(s.create_user(ctx, "gcbtest"))
        self.assertEqual(self.runner.calls, ["useradd -m -s /bin/bash gcbtest"])
        self.assertEqual(ctx.events[0][3], "失敗")


class TestChooseUser(Base):
    def test_preset_root_then_existing(self):
        self.users["bob"] = Pw("bob")
        self.shadow["/etc/shadow"] = "bob:$6$x:1:0:99999:7:::\n"
        self.answers = ["bob"]
        self.assertEqual(s.choose_user(Ctx(), "root"), "bob")

    def test_candidate_default_and_offer_password(self):
        self.users["bob"] = Pw("bob")
        self.answers = ["", "y"]
        self.passwords = ["p", "p"]
        ctx = Ctx()
        self.assertEqual(s.choose_user(ctx, None), "bob")
        self.assertIn("  已有符合條件的帳號：bob", ctx.out)
        self.assertEqual(self.runner.ran("chpasswd"), ["chpasswd"])

    def test_create_missing_user(self):
        def useradd(cmd):
            self.users["gcbtest"] = Pw("gcbtest")
            return res(0)
        self.runner.add("useradd", useradd)
        self.answers = ["", "y", "n"]                 # 預設 gcbtest、建立、之後不再設定密碼
        self.passwords = ["p", "p"]
        self.assertEqual(s.choose_user(Ctx(), None), "gcbtest")

    def test_create_fails(self):
        self.runner.add("useradd", res(1))
        self.answers = ["y"]
        self.assertIsNone(s.choose_user(Ctx(), "newbie"))

    def test_decline_create_then_other(self):
        self.users["bob"] = Pw("bob")
        self.shadow["/etc/shadow"] = "bob:$6$x:1:0:99999:7:::\n"
        self.answers = ["n", "bob"]
        self.assertEqual(s.choose_user(Ctx(), "ghost"), "bob")

    def test_add_to_sudo_group(self):
        self.users["bob"] = Pw("bob")
        self.shadow["/etc/shadow"] = "bob:$6$x:1:0:99999:7:::\n"
        state = {"sudo": False}
        self.runner.add("sudo -l", lambda c: SUDO_OK if state["sudo"] else res(1))

        def usermod(cmd):
            state["sudo"] = True
            return res(0)
        self.runner.add("usermod", usermod)
        self.answers = ["y"]
        ctx = Ctx()
        self.assertEqual(s.choose_user(ctx, "bob"), "bob")
        self.assertIn("usermod -aG wheel bob", self.runner.calls)
        self.assertEqual(ctx.events[0][1:], ("加入 sudo 群組", "usermod -aG wheel bob → rc=0", "成功"))

    def test_too_many_tries(self):
        self.users["svc"] = Pw("svc", 1001, "/usr/sbin/nologin")
        self.answers = ["svc"] * 5
        ctx = Ctx()
        self.assertIsNone(s.choose_user(ctx, "svc"))
        self.assertIn("嘗試次數過多", ctx.out[-1])


class TestServicesRepoConfig(Base):
    RUNNING = ("sshd.service loaded active running\nnginx.service loaded active running\n"
               "systemd-journald.service loaded active running\nmyapp loaded active running\n")

    def test_choose_services(self):
        self.assertEqual(s.choose_services(Ctx(), ["a"]), ["a"])
        self.runner.add("--state=running", res(0, self.RUNNING))
        self.answers = ["all"]
        ctx = Ctx()
        self.assertEqual(s.choose_services(ctx, None), ["myapp", "nginx"])
        self.assertIn("myapp、nginx", ctx.out[-1])
        self.answers = [" nginx , ,db "]
        self.assertEqual(s.choose_services(Ctx(), None), ["nginx", "db"])
        self.runner.add("--state=running", res(0, "sshd.service loaded active running\n"))
        ctx = Ctx()
        self.assertEqual(s.choose_services(ctx, None), [])
        self.assertIn("沒有偵測到", ctx.out[-1])

    def test_check_repo(self):
        ctx = Ctx("rhel9")
        self.assertTrue(s.check_repo(ctx))
        self.assertEqual(self.runner.calls[-1], "dnf -q makecache")
        self.runner.add("apt-get", res(0, "W: Failed to fetch http://x\n"))
        ctx = Ctx("ubuntu2204")
        self.assertFalse(s.check_repo(ctx))
        self.assertEqual(ctx.events[-1][3], "失敗")

    def test_write_config(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "config.ini")
        self.patch(s, "read_text", read_text)
        with mock.patch("gcb.util.restorecon", lambda p: None):
            s.write_config(Ctx(), path, {"test_user": "bob"})
            self.assertEqual(read_text(path), "[general]\ntest_user = bob\n")
            s.write_config(Ctx(), path, {"test_user": "eve", "critical_services": "a,b"})
        self.assertEqual(read_text(path), "[general]\ntest_user = eve\ncritical_services = a,b\n")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)


class TestCmdSetup(Base):
    def setUp(self):
        Base.setUp(self)
        self.users["bob"] = Pw("bob")
        self.shadow["/etc/shadow"] = "bob:$6$x:1:0:99999:7:::\n"
        self.written = {}
        self.patch(s, "write_config", lambda ctx, path, values: self.written.update(values))
        self.health = []
        self.patch(s.engine, "do_health", lambda ctx, label: self.health)

    def args(self, user="bob", services="nginx, db"):
        return argparse.Namespace(user=user, services=services)

    def test_success(self):
        from gcb import health
        self.health = [health.item("H04", "SSH", True, health.OK, ""), health.item("H08", "x", False, health.WARN, "")]
        ctx = Ctx()
        self.assertEqual(s.cmd_setup(ctx, "/x/config.ini", self.args()), 0)
        self.assertEqual(self.written, {"test_user": "bob", "critical_services": "nginx,db"})
        self.assertEqual((ctx.cfg.test_user, ctx.cfg.critical_services), ("bob", ["nginx", "db"]))
        self.assertEqual(ctx.saved, 1)
        self.assertTrue(any("ssh bob@10.0.0.5" in l for l in ctx.out))

    def test_login_check_failed(self):
        from gcb import health
        self.health = [health.item("H05", "sudo", True, health.BAD, "")]
        ctx = Ctx()
        self.assertEqual(s.cmd_setup(ctx, "/x/config.ini", self.args(services="")), 1)
        self.assertEqual(self.written["critical_services"], "")
        self.assertIn("H05 sudo", ctx.out[-2])

    def test_no_user(self):
        self.runner.add("useradd", res(1))
        self.answers = ["y"]
        ctx = Ctx()
        self.assertEqual(s.cmd_setup(ctx, "/x/config.ini", self.args(user="ghost")), 1)
        self.assertEqual(self.written, {})


if __name__ == "__main__":
    unittest.main()
