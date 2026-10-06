# -*- coding: utf-8 -*-
"""修復入口（gcb/fixer.py）與回滾紀錄（gcb/journal.py）測試：在暫存目錄操作真實檔案，只模擬指令與套件查詢。"""
import json
import os
import shutil
import sys
import tempfile
import unittest
import warnings
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fakes import FakeCfg, FakeRunner, make_osi, res  # noqa: E402
from gcb import fixer, journal, util  # noqa: E402
from gcb.fixer import FixError, Fx, ManualRequired  # noqa: E402
from gcb.util import read_text  # noqa: E402

# apt 安裝指令（保留被修改過的設定檔、不詢問）
APT = "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install "


class Ctx(object):
    """最小的執行環境：真實 Journal，其餘以假物件代替。"""

    def __init__(self, run_dir, key="rhel9", dry_run=False):
        self.journal = journal.Journal(run_dir)
        self.dry_run = dry_run
        self.cfg = FakeCfg(package_timeout=77)
        self.osi = make_osi(key)
        self.steps = []
        self.intended_stops = set()

    def add_step(self, rec):
        self.steps.append(rec)


class TmpBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.run_dir = os.path.join(self.tmp, "run")
        os.makedirs(self.run_dir)
        # 不呼叫真正的 restorecon
        for mod in (util, journal):
            p = mock.patch.object(mod, "restorecon", lambda path: None)
            p.start()
            self.addCleanup(p.stop)
        self.uid, self.gid = os.getuid(), os.getgid()

    def patch(self, obj, attr, val):
        p = mock.patch.object(obj, attr, val)
        p.start()
        self.addCleanup(p.stop)
        return val

    def path(self, name, text=None, mode=0o644):
        p = os.path.join(self.tmp, name)
        if text is not None:
            d = os.path.dirname(p)
            if not os.path.isdir(d):
                os.makedirs(d)
            with open(p, "w") as f:
                f.write(text)
            os.chmod(p, mode)
        return p

    def mode(self, p):
        return os.stat(p).st_mode & 0o7777

    def say_log(self):
        log = []
        return log, lambda rid, action, msg, result: log.append((rid, action, msg, result))


# ====================================================================
# fixer.Fx
# ====================================================================

class TestFxFiles(TmpBase):
    def test_write_backup_and_rollback(self):
        p = self.path("etc/a.conf", "old\n", 0o640)
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        self.assertFalse(fx.write_file(p, "old\n"))           # 內容相同不寫
        self.assertTrue(fx.edit_file(p, lambda t: t + "new\n"))
        self.assertEqual(read_text(p), "old\nnew\n")
        self.assertEqual(self.mode(p), 0o640)                 # 保留原權限
        e = ctx.journal.entries[0]
        self.assertEqual((e["type"], e["data"]["existed"], e["data"]["mode"]), ("file", True, 0o640))
        self.assertEqual(read_text(e["data"]["backup"]), "old\n")
        self.assertEqual([s["action"] for s in fx.steps], ["備份檔案", "修改檔案"])
        # 寫入前已存入 rollback.json（write-ahead）
        with open(ctx.journal.path) as f:
            self.assertEqual(json.load(f)[0]["data"]["path"], p)
        os.chmod(p, 0o600)
        log, say = self.say_log()
        self.assertEqual(journal.rollback(ctx.journal, ctx.osi, say), (1, 0))
        self.assertEqual(read_text(p), "old\n")
        self.assertEqual(self.mode(p), 0o640)
        self.assertEqual(os.stat(p).st_uid, self.uid)
        self.assertTrue(ctx.journal.entries[0]["rolled_back"])
        self.assertEqual(log[0][1], "還原檔案")

    def test_new_file_in_new_dirs_removed_on_rollback(self):
        p = os.path.join(self.tmp, "x", "y", "new.conf")
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.write_file(p, "hi\n", mode=0o600)
        self.assertEqual(self.mode(p), 0o600)
        d = ctx.journal.entries[0]["data"]
        self.assertEqual(d["made_dirs"], [os.path.join(self.tmp, "x", "y"), os.path.join(self.tmp, "x")])
        self.assertEqual([s["action"] for s in fx.steps], ["修改檔案"])
        log, say = self.say_log()
        journal.rollback(ctx.journal, ctx.osi, say)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "x")))
        self.assertEqual([l[1] for l in log], ["刪除新建檔案", "刪除新建目錄", "刪除新建目錄"])

    def test_dry_run_changes_nothing(self):
        p = self.path("a.conf", "old\n")
        ctx = Ctx(self.run_dir, dry_run=True)
        fx = Fx(ctx, "R1")
        self.assertTrue(fx.write_file(p, "new\n"))
        fx.backup_only(p)
        self.assertIsNone(fx.backup_dir(self.tmp))
        fx.chmod(p, 0o600)
        fx.chown(p, self.uid, self.gid, "me")
        fx.add_undo(["x"], "x")
        self.assertIsNone(fx.run(["rm", "-rf", "/"], "危險"))
        self.assertEqual(read_text(p), "old\n")
        self.assertEqual(self.mode(p), 0o644)
        self.assertEqual(ctx.journal.entries, [])
        self.assertFalse(os.path.exists(ctx.journal.path))
        self.assertTrue(all(s["result"] == "預覽" for s in fx.steps))

    def test_backup_only_and_dir(self):
        p = self.path("d/a", "1")
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.backup_only(os.path.join(self.tmp, "none"))       # 不存在不備份
        fx.backup_only(p)
        tar = fx.backup_dir(os.path.dirname(p))
        self.assertTrue(os.path.exists(tar))
        self.assertEqual([e["type"] for e in ctx.journal.entries], ["file", "dir"])

    def test_chmod_chown_record_meta_first(self):
        p = self.path("a", "1", 0o666)
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.chmod(p, 0o600)
        fx.chown(p, self.uid, self.gid, "me:me")
        self.assertEqual(self.mode(p), 0o600)
        self.assertEqual([(e["type"], e["data"]["mode"]) for e in ctx.journal.entries], [("meta", 0o666), ("meta", 0o600)])
        log, say = self.say_log()
        self.assertEqual(journal.rollback(ctx.journal, ctx.osi, say), (2, 0))
        self.assertEqual(self.mode(p), 0o666)
        self.assertEqual([l[1] for l in log], ["還原權限", "還原權限"])


class TestFxCommands(TmpBase):
    def setUp(self):
        TmpBase.setUp(self)
        self.runner = self.patch(fixer, "run", FakeRunner())

    def test_run_check_and_undo(self):
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.add_undo(["systemctl", "reload", "x"], "還原")
        self.assertEqual(ctx.journal.entries[0]["data"]["cmd"], ["systemctl", "reload", "x"])
        self.runner.add("false", res(1, "", "壞了"))
        r = fx.run(["false"], "失敗但不檢查", check=False)
        self.assertFalse(r.ok)
        self.assertEqual(fx.steps[-1]["result"], "失敗 (rc=1)")
        with self.assertRaises(FixError):
            fx.run(["false"], "失敗")

    def test_long_step_notice(self):
        # 逾時設定達 LONG_STEP 的步驟（安裝套件、AIDE 初始化）執行前先在畫面提示
        ctx = Ctx(self.run_dir)
        said = []
        ctx.say = said.append
        fx = Fx(ctx, "TWGCB-01-014-0033")
        fx.run(["aideinit", "-y", "-f"], "初始化 AIDE 資料庫", timeout=7200)
        fx.run(["true"], "短步驟")
        self.assertEqual(said, ["      … TWGCB-01-014-0033：初始化 AIDE 資料庫 — 可能需要數分鐘，請稍候"])
        fx.dry = True
        fx.run(["aideinit"], "預覽", timeout=7200)
        self.assertEqual(len(said), 1)  # 預覽不提示

    def test_run_tracked_logs_diff(self):
        p = self.path("pam", "a\n")

        def change(cmd):
            with open(p, "w") as f:
                f.write("b\n")
            return res(0)
        self.runner.add("pam-auth-update", change)
        fx = Fx(Ctx(self.run_dir), "R1")
        fx.run_tracked(["/usr/sbin/pam-auth-update", "--enable", "x"], "pam", [p, self.path("other", "z")])
        st = [s for s in fx.steps if s["action"].startswith("檔案變更")]
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["action"], "檔案變更（pam-auth-update）")
        self.assertIn("-a\n+b", st[0]["detail"])

    def test_service_mask_and_enable(self):
        self.patch(fixer.pkgsvc, "svc_state", lambda u: ("enabled", "active"))
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.service_mask("avahi-daemon")
        fx.service_enable("auditd")
        self.assertEqual(ctx.intended_stops, {"avahi-daemon"})
        self.assertEqual([e["data"]["unit"] for e in ctx.journal.entries], ["avahi-daemon", "auditd"])
        self.assertEqual(self.runner.calls, ["systemctl --now mask avahi-daemon", "systemctl --now enable auditd"])

    def test_pkg_install_records_new_dependencies(self):
        lists = [{"a"}, {"a", "aide", "libdep"}]
        self.patch(fixer.pkgsvc, "pkg_list", lambda osi: lists.pop(0))
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.pkg_install("aide")
        e = ctx.journal.entries[0]
        self.assertEqual((e["type"], e["data"]["pkgs"]), ("pkg_installed", ["aide", "libdep"]))
        self.assertEqual(self.runner.calls, ["dnf -y install aide"])
        with open(ctx.journal.path) as f:
            self.assertEqual(json.load(f)[0]["data"]["pkgs"], ["aide", "libdep"])

    def test_pkg_install_debian_retry_then_manual(self):
        self.patch(fixer.pkgsvc, "pkg_list", lambda osi: {"a"})
        self.runner.add("install", res(100, "", "E: Unable to locate package"))
        ctx = Ctx(self.run_dir, key="ubuntu2204")
        fx = Fx(ctx, "R1")
        with self.assertRaises(ManualRequired):
            fx.pkg_install("auditd")
        self.assertEqual(self.runner.calls, [APT + "auditd", "apt-get update", APT + "auditd"])
        # 安裝失敗也要更新紀錄：沒有新增套件，回滾不會移除原有套件
        self.assertEqual(ctx.journal.entries[0]["data"]["pkgs"], [])

    def test_pkg_install_debian_retry_success(self):
        self.patch(fixer.pkgsvc, "pkg_list", lambda osi: set())
        n = {"i": 0}

        def first_fails(cmd):
            n["i"] += 1
            return res(100 if n["i"] == 1 else 0)
        self.runner.add("install", first_fails)
        fx = Fx(Ctx(self.run_dir, key="ubuntu2204"), "R1")
        fx.pkg_install("auditd")
        self.assertEqual(n["i"], 2)

    def test_pkg_install_dry_run(self):
        ctx = Ctx(self.run_dir, dry_run=True)
        Fx(ctx, "R1").pkg_install("aide")
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(ctx.journal.entries, [])

    def test_pkg_remove(self):
        self.patch(fixer.pkgsvc, "pkg_dependents", lambda osi, p: ["x", "y"] if p == "busy" else [])
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        with self.assertRaises(ManualRequired):
            fx.pkg_remove("busy")
        self.assertEqual(ctx.journal.entries, [])
        fx.pkg_remove("telnet")
        self.assertEqual(ctx.journal.entries[0]["type"], "pkg_removed")
        self.assertEqual(self.runner.calls, ["dnf -y remove telnet"])
        self.runner.add("remove", res(1))
        with self.assertRaises(FixError):
            fx.pkg_remove("rsh")

    def test_sysctl_and_chage(self):
        self.patch(fixer.pkgsvc, "sysctl_runtime", lambda k: "1")
        ctx = Ctx(self.run_dir)
        fx = Fx(ctx, "R1")
        fx.sysctl_set("net.ipv4.ip_forward", "0")
        fx.chage_max("bob", "", 90)
        fx.chage("bob", "-X", "3", 5)
        self.assertEqual([(e["type"], e["data"]) for e in ctx.journal.entries],
                         [("sysctl", {"key": "net.ipv4.ip_forward", "value": "1"}),
                          ("chage", {"user": "bob", "opt": "-M", "old": ""}),
                          ("chage", {"user": "bob", "opt": "-X", "old": "3"})])
        self.assertEqual(self.runner.calls, ["sysctl -w net.ipv4.ip_forward=0", "chage -M 90 bob", "chage -X 5 bob"])
        self.assertIn("未設定", fx.steps[1]["action"])
        ctx2 = Ctx(self.run_dir + "2", dry_run=True)
        Fx(ctx2, "R1").chage("bob", "-M", "1", 2)
        self.assertEqual(ctx2.journal.entries, [])


# ====================================================================
# journal 回滾
# ====================================================================

class TestJournal(TmpBase):
    def setUp(self):
        TmpBase.setUp(self)
        self.runner = self.patch(journal, "run", FakeRunner())
        self.osi = make_osi("rhel9")

    def test_reload_from_disk(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "cmd", cmd=["true"], desc="x")
        j2 = journal.Journal(self.run_dir)
        self.assertEqual(j2.entries[0]["data"]["cmd"], ["true"])
        self.assertEqual(j2.entries[0]["seq"], 1)

    def test_reverse_order_and_rule_filter(self):
        j = journal.Journal(self.run_dir)
        for i in range(3):
            j.add("R%d" % (i % 2), "cmd", cmd=["c%d" % i], desc="")
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say, rule_id="R0"), (2, 0))
        self.assertEqual(self.runner.calls, ["c2", "c0"])
        self.assertEqual(journal.rollback(j, self.osi, say), (1, 0))   # 已回滾的不再執行
        self.assertEqual(self.runner.calls, ["c2", "c0", "c1"])

    def test_cmd_failure_counts(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "cmd", cmd=["bad"], desc="")
        j.add("R1", "cmd", cmd=["good"], desc="")
        self.runner.add("bad", res(1, "", "錯誤訊息"))
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (1, 1))
        self.assertFalse(j.entries[0]["rolled_back"])
        self.assertTrue(j.entries[1]["rolled_back"])
        self.assertIn("錯誤訊息", [l for l in log if l[1] == "執行還原指令"][1][2])
        self.assertEqual(log[-1][1:], ("回滾未完全成功", "cmd #1", "失敗"))

    def test_exception_and_unknown_type(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "weird")
        j.add("R1", "file", path=os.path.join(self.tmp, "x"), existed=True, backup=os.path.join(self.tmp, "nope"),
              mode=0o644, uid=0, gid=0)
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (0, 2))
        acts = [l[1] for l in log]
        self.assertEqual(acts, ["回滾失敗", "回滾未完全成功", "未知的回滾類型", "回滾未完全成功"])

    def test_dir_restore(self):
        d = os.path.join(self.tmp, "apparmor.d")
        self.path("apparmor.d/a", "A")
        self.path("apparmor.d/sub/b", "B")
        j = journal.Journal(self.run_dir)
        e = j.backup_dir_tree("R1", d)
        self.assertTrue(e["data"]["tar"].endswith(".tar"))
        os.unlink(os.path.join(d, "a"))
        shutil.rmtree(os.path.join(d, "sub"))
        self.path("apparmor.d/new", "N")
        os.symlink("/nonexistent", os.path.join(d, "lnk"))
        os.makedirs(os.path.join(d, "newdir"))
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (1, 0))
        self.assertEqual(sorted(os.listdir(d)), ["a", "sub"])
        self.assertEqual(read_text(os.path.join(d, "sub", "b")), "B")

    def test_dir_restore_old_python(self):
        # Python 沒有 extraction filter 時直接 extractall
        d = os.path.join(self.tmp, "conf")
        self.path("conf/a", "A")
        j = journal.Journal(self.run_dir)
        j.backup_dir_tree("R1", d)
        shutil.rmtree(d)
        with mock.patch("gcb.journal.hasattr", create=True, return_value=False), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            log, say = self.say_log()
            self.assertEqual(journal.rollback(j, self.osi, say), (1, 0))
        self.assertEqual(read_text(os.path.join(d, "a")), "A")

    def test_pkg_installed(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "pkg_installed", pkg="aide", pkgs=["aide", "dep"])
        j.add("R2", "pkg_installed", pkg="x")                 # 舊紀錄沒有 pkgs
        installed = {"aide", "dep"}
        self.patch(journal.pkgsvc, "pkg_installed", lambda osi, p: p in installed)
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (2, 0))
        self.assertEqual(self.runner.calls, ["dnf -y remove aide dep"])

    def test_pkg_installed_batch_fails_then_one_by_one(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "pkg_installed", pkg="aide", pkgs=["aide", "dep", "gone"])
        installed = {"aide", "dep", "gone"}

        def remove(cmd):
            if cmd == "dnf -y remove aide dep gone":
                installed.discard("gone")      # 批次失敗前已移除部分套件
                return res(1)
            return res(1) if "dep" in cmd else res(0)
        self.runner.add("remove", remove)
        self.patch(journal.pkgsvc, "pkg_installed", lambda osi, p: p in installed)
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (0, 1))
        self.assertEqual(self.runner.calls, ["dnf -y remove aide dep gone", "dnf -y remove aide", "dnf -y remove dep"])
        self.assertEqual(log[1][1:], ("逐一移除先前安裝的套件", "無法移除：dep", "失敗"))

    def test_pkg_installed_one_by_one_success(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "pkg_installed", pkg="aide", pkgs=["aide"])
        self.patch(journal.pkgsvc, "pkg_installed", lambda osi, p: True)
        self.runner.add("remove aide", lambda c: res(1) if len(self.runner.calls) == 1 else res(0))
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (1, 0))
        self.assertEqual(log[1][2], "無法移除：無")

    def test_pkg_removed(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "pkg_removed", pkg="telnet")
        j.add("R2", "pkg_removed", pkg="rsh")
        self.runner.add("rsh", res(1, "", "no repo"))
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, make_osi("ubuntu2204"), say), (1, 1))
        self.assertEqual(self.runner.calls, [APT + "rsh", APT + "telnet"])
        self.assertIn("no repo", log[0][2])

    def test_sysctl(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "sysctl", key="a.b", value=None)           # 原本沒有此參數
        j.add("R1", "sysctl", key="c.d", value="1")            # 目前已是原值
        j.add("R1", "sysctl", key="e.f", value="1")
        j.add("R1", "sysctl", key="g.h", value="2")
        self.patch(journal.pkgsvc, "sysctl_runtime", lambda k: "1" if k == "c.d" else "0")
        self.runner.add("g.h", res(255))
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (3, 1))
        self.assertEqual(self.runner.calls, ["sysctl -w g.h=2", "sysctl -w e.f=1"])

    def test_chage(self):
        j = journal.Journal(self.run_dir)
        j.add("R1", "chage", user="bob", opt="-W", old="7")
        j.add("R1", "chage", user="bob", opt="-M", old="")
        j.add("R1", "chage", user="old", max="99999")          # 舊版紀錄
        log, say = self.say_log()
        self.assertEqual(journal.rollback(j, self.osi, say), (3, 0))
        self.assertEqual(self.runner.calls, ["chage -M 99999 old", "chage -M -1 bob", "chage -W 7 bob"])

    def services(self, entries, states):
        """states：每次 svc_state 呼叫依序回傳的狀態。"""
        j = journal.Journal(self.run_dir)
        for e in entries:
            j.add("R1", "service", **e)
        seq = list(states)
        self.patch(journal.pkgsvc, "svc_state", lambda u: seq.pop(0))
        log, say = self.say_log()
        return journal.rollback(j, self.osi, say), log

    def test_service_unmask_enable_start(self):
        (ok, fail), log = self.services([dict(unit="avahi", enabled="enabled", active="active")],
                                        [("masked", "inactive"), ("enabled", "active")])
        self.assertEqual((ok, fail), (1, 0))
        self.assertEqual(self.runner.calls, ["systemctl unmask avahi", "systemctl enable avahi", "systemctl start avahi"])

    def test_service_disable_stop_with_fallback(self):
        self.runner.add("systemctl stop", res(1))
        (ok, fail), log = self.services([dict(unit="auditd.service", enabled="disabled", active="inactive")],
                                        [("enabled", "active"), ("disabled", "inactive")])
        self.assertEqual((ok, fail), (1, 0))
        self.assertEqual(self.runner.calls, ["systemctl disable auditd.service", "systemctl stop auditd.service",
                                             "service auditd stop"])

    def test_service_mask_and_mismatch(self):
        (ok, fail), log = self.services([dict(unit="x", enabled="masked", active="inactive")],
                                        [("enabled", "inactive"), ("enabled", "inactive")])
        self.assertEqual((ok, fail), (0, 1))
        self.assertEqual(self.runner.calls, ["systemctl mask x"])
        self.assertEqual(log[0][3], "失敗")

    def test_service_static_not_started(self):
        (ok, fail), log = self.services([dict(unit="y", enabled="static", active="active")],
                                        [("static", "inactive"), ("static", "failed")])
        self.assertEqual((ok, fail), (0, 1))
        self.assertEqual(self.runner.calls, ["systemctl start y"])

    def test_later_conflicts(self):
        j = journal.Journal(self.run_dir)
        self.assertEqual(journal.later_conflicts(j, "R1"), [])
        j.add("R1", "cmd", cmd=["x"])
        self.assertEqual(journal.later_conflicts(j, "R1"), [])   # 沒有檔案類紀錄
        j.add("R1", "file", path="/etc/a")
        j.add("R2", "meta", path="/etc/a")
        j.add("R3", "file", path="/etc/b")
        j.add("R4", "dir", path="/etc/a")
        j.add("R2", "file", path="/etc/a")
        self.assertEqual(journal.later_conflicts(j, "R1"), ["R2", "R4"])
        j.entries[2]["rolled_back"] = True
        j.entries[5]["rolled_back"] = True
        self.assertEqual(journal.later_conflicts(j, "R1"), ["R4"])


if __name__ == "__main__":
    unittest.main()
