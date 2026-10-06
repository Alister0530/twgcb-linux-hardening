# -*- coding: utf-8 -*-
"""系統健康檢查（gcb/health.py）模擬測試：各 H 項目的狀態與關鍵旗標、SSH 登入測試的金鑰放入與移除。"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fakes import FakeCtx, FakeRunner, fs_reader, res  # noqa: E402
from gcb import health as h  # noqa: E402
from gcb.util import read_text  # noqa: E402


class Ctx(FakeCtx):
    def __init__(self, key="rhel9", **cfg):
        FakeCtx.__init__(self, key, **cfg)
        self.events = []

    def log_event(self, rid, action, detail, result="資訊"):
        self.events.append((rid, action, detail))


class Base(unittest.TestCase):
    def env(self, runner=None, which=None, fs=None):
        self.runner = runner or FakeRunner()
        which = which if which is not None else {}
        self.patch(h, "run", self.runner)
        self.patch(h, "which", lambda n: which.get(n))
        if fs is not None:
            self.patch(h, "read_text", fs_reader(fs))

    def patch(self, obj, attr, val):
        p = mock.patch.object(obj, attr, val)
        p.start()
        self.addCleanup(p.stop)


SSHD = {"sshd": "/usr/sbin/sshd"}


class TestSsh(Base):
    def test_no_sshd(self):
        self.env(which={})
        self.assertIsNone(h._sshd_T())
        i = h.chk_sshd_syntax(Ctx())
        self.assertEqual((i["id"], i["status"], i["critical"]), ("H02", h.BAD, True))
        self.assertEqual(h._ssh_ports(), ["22"])

    def test_sshd_syntax_error(self):
        self.env(which=SSHD, runner=FakeRunner({"sshd -t": res(1, "", "line 3: Bad configuration option")}))
        i = h.chk_sshd_syntax(Ctx())
        self.assertEqual(i["status"], h.BAD)
        self.assertIn("Bad configuration option", i["detail"])

    def test_ssh_service(self):
        self.patch(h.pkgsvc, "svc_state", lambda u: ("enabled", "failed"))
        i = h.chk_ssh_service(Ctx("ubuntu2204"))
        self.assertEqual((i["status"], i["critical"], i["detail"]), (h.BAD, True, "ssh: enabled=enabled active=failed"))

    def test_listen_ports(self):
        self.env(which=SSHD, runner=FakeRunner({"sshd -T": res(0, "port 22\nlistenaddress 0.0.0.0:2222\n"),
                                                "ss -Htln": res(0, "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")}))
        i = h.chk_ssh_listen(Ctx())
        self.assertEqual(i["status"], h.BAD)
        self.assertIn("未監聽：2222", i["detail"])

    def test_target(self):
        for addrs, want in ((["[::]:22", "10.1.1.1:22"], "10.1.1.1"), (["[::1]:22"], "127.0.0.1"),
                            (["0.0.0.0:22"], "127.0.0.1")):
            out = "".join("listenaddress %s\n" % a for a in addrs)
            self.env(which=SSHD, runner=FakeRunner({"sshd -T": res(0, out)}))
            self.assertEqual(h._ssh_target(), want)

    def test_external_target(self):
        self.env(which=SSHD, runner=FakeRunner({"sshd -T": res(0, "listenaddress 192.168.0.9:22\n")}))
        self.patch(h, "primary_ip", lambda: "127.0.1.1")
        self.assertEqual(h._external_target(), (None, "找不到主要網卡的 IP"))
        self.patch(h, "primary_ip", lambda: "10.0.0.5")
        ip, why = h._external_target()
        self.assertIsNone(ip)
        self.assertIn("sshd 未在 10.0.0.5 監聽", why)
        self.runner.add("sshd -T", res(0, "listenaddress [::]:22\n"))
        self.assertEqual(h._external_target(), ("10.0.0.5", ""))

    def test_authorized_keys_path(self):
        pw = mock.Mock(pw_dir="/home/bob")
        self.patch(h.pwd, "getpwnam", lambda u: pw)
        self.env(which=SSHD, runner=FakeRunner({"sshd -T": res(0, "authorizedkeysfile /etc/keys/%u .ssh/x\n")}))
        self.assertEqual(h._authorized_keys_path("bob"), "/etc/keys/bob")
        self.runner.add("sshd -T", res(0, "authorizedkeysfile %h/.ssh/k%%\n"))
        self.assertEqual(h._authorized_keys_path("bob"), "/home/bob/.ssh/k%")
        self.env(which={})
        self.assertEqual(h._authorized_keys_path("bob"), "/home/bob/.ssh/authorized_keys")

    def test_remove_stale_keys_unknown_user(self):
        self.patch(h.pwd, "getpwnam", mock.Mock(side_effect=KeyError))
        ctx = Ctx()
        h._remove_stale_keys(ctx, "ghost")
        self.assertEqual(ctx.events, [])


class TestLoginGuards(Base):
    def both(self, ctx):
        r = h.ssh_login_test(ctx)
        self.assertEqual([i["id"] for i in r], ["H04", "H19"])
        self.assertEqual(r[1]["status"], h.SKIP)
        return r[0]

    def test_guards(self):
        self.env(which={})
        self.assertEqual(self.both(Ctx(test_user=""))["status"], h.SKIP)
        self.patch(h.pwd, "getpwnam", mock.Mock(side_effect=KeyError))
        i = self.both(Ctx())
        self.assertEqual((i["status"], i["critical"], i["detail"]), (h.BAD, True, "測試帳號 gcbtest 不存在"))
        self.patch(h.pwd, "getpwnam", lambda u: mock.Mock(pw_uid=0))
        self.assertEqual(self.both(Ctx())["detail"], "測試帳號不可為 root")
        self.patch(h.pwd, "getpwnam", lambda u: mock.Mock(pw_uid=1000))
        self.assertEqual(self.both(Ctx())["detail"], "找不到 ssh 指令")
        self.env(which={"ssh": "/usr/bin/ssh"})
        self.assertEqual(self.both(Ctx())["detail"], "找不到 ssh-keygen 指令")


class TestLoginFlow(Base):
    """在暫存家目錄實際放入與移除測試金鑰。"""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        # 以 root 執行（容器）時 uid 0 會被判定為「測試帳號不可為 root」；root 可 chown 給任意 uid
        uid = os.getuid() or 1000
        self.pw = mock.Mock(pw_dir=self.home, pw_uid=uid, pw_gid=os.getgid() if os.getuid() else 1000)
        self.patch(h.pwd, "getpwnam", lambda u: self.pw)
        self.patch(h, "restorecon", lambda p: None)
        self.patch(h, "write_text_atomic", self._write)
        self.ak = os.path.join(self.home, ".ssh", "authorized_keys")
        self.during = []

    def _write(self, path, text, mode=None):
        from gcb import util
        with mock.patch.object(util, "restorecon", lambda p: None):
            util.write_text_atomic(path, text, mode)

    def keygen(self, cmd):
        key = cmd.split()[-1]
        with open(key, "w") as f:
            f.write("PRIVATE")
        with open(key + ".pub", "w") as f:
            f.write("ssh-rsa AAAA %s\n" % cmd.split()[cmd.split().index("-C") + 1])
        return res(0)

    def ssh(self, ok_hosts):
        def _f(cmd):
            self.during.append(read_text(self.ak))
            host = cmd.split()[-3].split("@")[1]
            return res(0, "GCB_LOGIN_OK\n") if host in ok_hosts else res(255, "", "Connection refused")
        return _f

    def test_new_ssh_dir_created_and_removed(self):
        self.env(which={"ssh": "/usr/bin/ssh", "ssh-keygen": "/usr/bin/ssh-keygen", "sshd": "/usr/sbin/sshd"},
                 runner=FakeRunner({"ssh-keygen": self.keygen, "sshd -T": res(0, "port 22\nlistenaddress 0.0.0.0:22\n"),
                                    "ssh -i": self.ssh({"127.0.0.1"})}))
        self.patch(h, "primary_ip", lambda: "10.0.0.5")
        ctx = Ctx()
        r = h.ssh_login_test(ctx)
        self.assertEqual([(i["id"], i["status"]) for i in r], [("H04", h.OK), ("H19", h.BAD)])
        self.assertIn("Connection refused", r[1]["detail"])
        # 登入時金鑰在 authorized_keys 中，測完連同新建的 .ssh 一起移除
        self.assertIn("gcb-checker-temp-test", self.during[0])
        self.assertFalse(os.path.exists(os.path.join(self.home, ".ssh")))
        self.assertEqual([e[1] for e in ctx.events], ["暫時加入測試金鑰", "移除測試金鑰"])

    def test_existing_keys_preserved_and_stale_removed(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(self.ak, "w") as f:
            f.write("ssh-rsa OLD bob\nssh-rsa STALE gcb-checker-temp-old")
        os.chmod(self.ak, 0o600)
        self.env(which={"ssh": "/usr/bin/ssh", "ssh-keygen": "/usr/bin/ssh-keygen"},
                 runner=FakeRunner({"ssh-keygen": self.keygen, "ssh -i": self.ssh({"127.0.0.1"})}))
        self.patch(h, "primary_ip", lambda: "")
        ctx = Ctx()
        r = h.ssh_login_test(ctx)
        self.assertEqual([(i["id"], i["status"]) for i in r], [("H04", h.OK), ("H19", h.SKIP)])
        self.assertEqual(self.during[0], "ssh-rsa OLD bob\nssh-rsa AAAA gcb-checker-temp-test\n")
        self.assertEqual(read_text(self.ak), "ssh-rsa OLD bob\n")
        self.assertEqual(os.stat(self.ak).st_mode & 0o777, 0o600)
        self.assertEqual(ctx.events[0][1], "移除先前遺留的測試金鑰")

    def test_existing_file_without_newline(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        with open(self.ak, "w") as f:
            f.write("ssh-rsa OLD bob")
        self.env(which={"ssh": "/usr/bin/ssh", "ssh-keygen": "/usr/bin/ssh-keygen"},
                 runner=FakeRunner({"ssh-keygen": self.keygen, "ssh -i": self.ssh(set())}))
        self.patch(h, "primary_ip", lambda: "")
        r = h.ssh_login_test(Ctx())
        self.assertEqual(r[0]["status"], h.BAD)
        self.assertEqual(self.during[0], "ssh-rsa OLD bob\nssh-rsa AAAA gcb-checker-temp-test\n")
        self.assertEqual(read_text(self.ak), "ssh-rsa OLD bob\n")


class TestAccount(Base):
    def test_sudo_and_su(self):
        self.env()
        self.assertEqual(h.chk_sudo(Ctx(test_user=""))["status"], h.SKIP)
        self.assertEqual(h.chk_su_pam(Ctx(test_user=""))["status"], h.SKIP)
        self.runner.add("sudo -l", res(0, "User gcbtest may run:\n    (ALL) ALL\n"))
        self.runner.add("su -", res(1, "", "su: Authentication failure"))
        self.assertEqual(h.chk_sudo(Ctx())["status"], h.OK)
        i = h.chk_su_pam(Ctx())
        self.assertEqual((i["status"], i["critical"]), (h.BAD, True))
        self.runner.add("sudo -l", res(1, "", "not allowed"))
        i = h.chk_sudo(Ctx())
        self.assertEqual(i["status"], h.BAD)
        self.assertIn("not allowed", i["detail"])

    def test_root_account(self):
        self.env(runner=FakeRunner({"passwd -S": res(0, "root L 2024-01-01 0 99999 7 -1\n")}))
        i = h.chk_root_account(Ctx())
        self.assertEqual((i["status"], i["critical"], i["detail"]), (h.INFO, False, "root 狀態=L（已鎖定）"))
        self.runner.add("passwd -S", res(1))
        self.assertEqual(h.chk_root_account(Ctx())["detail"], "root 狀態=?")


class TestSystem(Base):
    def test_units(self):
        self.env(runner=FakeRunner({"--state=failed": res(0, "b.service loaded failed\na.service loaded failed\n"),
                                    "--state=running": res(0, "sshd.service loaded active running\n")}))
        i = h.chk_failed_units(Ctx())
        self.assertEqual((i["status"], i["data"]), (h.WARN, ["a.service", "b.service"]))
        self.assertEqual(h.chk_running_services(Ctx())["data"], ["sshd.service"])

    def test_critical_services(self):
        self.patch(h.pkgsvc, "svc_state", lambda u: ("enabled", "active" if u == "nginx" else "failed"))
        self.assertEqual(h.chk_critical_services(Ctx())["status"], h.SKIP)
        i = h.chk_critical_services(Ctx(critical_services=["nginx", "db"]))
        self.assertEqual((i["status"], i["critical"], i["detail"]), (h.BAD, True, "未運作：db"))
        i = h.chk_critical_services(Ctx(critical_services=["nginx"]))
        self.assertEqual(i["status"], h.OK)

    def test_route_and_ping(self):
        self.env(runner=FakeRunner({"ip route": res(0, "")}))
        self.assertEqual(h.chk_route(Ctx())["status"], h.BAD)
        i = h.chk_gateway_ping(Ctx())
        self.assertEqual((i["status"], i["critical"]), (h.SKIP, False))
        self.runner.add("ip route", res(0, "default via 10.0.0.1 dev eth0\n"))
        self.runner.add("ping", res(1))
        self.assertEqual(h.chk_route(Ctx())["detail"], "閘道 10.0.0.1")
        self.assertEqual(h.chk_gateway_ping(Ctx())["status"], h.WARN)

    def test_dns(self):
        fs = {"/etc/resolv.conf": "nameserver 8.8.8.8\n"}
        self.env(fs=fs, runner=FakeRunner({"getent": res(2)}))
        self.assertEqual(h.chk_dns(Ctx())["detail"], "DNS 伺服器：8.8.8.8")
        fs.clear()
        self.assertEqual(h.chk_dns(Ctx())["status"], h.WARN)
        i = h.chk_dns(Ctx(dns_test_name="example.com"))
        self.assertEqual((i["status"], i["detail"]), (h.BAD, "解析 example.com 失敗"))
        self.runner.add("getent", res(0, "93.184.216.34 example.com\n"))
        self.assertEqual(h.chk_dns(Ctx(dns_test_name="example.com"))["detail"], "解析 example.com 成功：93.184.216.34")

    def test_disk(self):
        out = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
               "/dev/sda1 100 96 4 96% /\n/dev/sda1 100 96 4 96% /\n/dev/sda2 100 10 90 10% /boot\n")
        self.env(runner=FakeRunner({"df": res(0, out)}))
        i = h.chk_disk(Ctx())
        self.assertEqual((i["status"], i["detail"]), (h.WARN, "/ 96%、/boot 10%"))

    def test_fstab(self):
        self.env(runner=FakeRunner({"findmnt": res(1, "[E] unreachable source")}))
        i = h.chk_fstab(Ctx())
        self.assertEqual((i["status"], i["critical"]), (h.BAD, True))

    def test_grub_rhel(self):
        self.env(which={"grub2-script-check": "/usr/bin/grub2-script-check", "grubby": "/usr/sbin/grubby"},
                 runner=FakeRunner({"grub2-script-check": res(0), "grubby": res(0, "/boot/vmlinuz-5.14\n")}))
        self.patch(h.os.path, "exists", lambda p: p == "/boot/efi/EFI/rocky/grub.cfg")
        i = h.chk_grub(Ctx("rhel9"))
        self.assertEqual(i["status"], h.OK)
        self.assertEqual(i["detail"], "/boot/efi/EFI/rocky/grub.cfg；語法正常；預設核心 /boot/vmlinuz-5.14")
        self.runner.add("grubby", res(1))
        self.assertEqual(h.chk_grub(Ctx("rhel9"))["status"], h.BAD)

    def test_grub_debian(self):
        self.env(which={"grub-script-check": "/usr/bin/grub-script-check"},
                 runner=FakeRunner({"grub-script-check": res(1, "", "syntax error")}))
        self.patch(h.os.path, "exists", lambda p: False)
        i = h.chk_grub(Ctx("ubuntu2204"))
        self.assertEqual((i["status"], i["detail"]), (h.BAD, "找不到 grub.cfg"))
        self.patch(h.os.path, "exists", lambda p: p == "/boot/grub/grub.cfg")
        i = h.chk_grub(Ctx("ubuntu2204"))
        self.assertEqual(i["status"], h.BAD)
        self.assertIn("錯誤：syntax error", i["detail"])

    def test_pkg_mgr_and_mac(self):
        self.env(runner=FakeRunner({"dpkg --audit": res(0, "The following packages are only half configured\n"),
                                    "rpm -q rpm": res(1, "", "rpmdb broken"), "getenforce": res(0, "")}),
                 fs={"/sys/module/apparmor/parameters/enabled": "Y\n"})
        i = h.chk_pkg_mgr(Ctx("ubuntu2204"))
        self.assertEqual((i["status"], i["critical"]), (h.WARN, False))
        self.assertEqual(h.chk_pkg_mgr(Ctx("rhel9"))["detail"], "rpmdb broken")
        self.assertEqual(h.chk_mac(Ctx("rhel9"))["detail"], "未知")
        self.assertEqual(h.chk_mac(Ctx("ubuntu2204"))["detail"], "已啟用")


class TestRunAllCompare(Base):
    def test_run_all_errors_keep_meta(self):
        def boom(ctx):
            raise RuntimeError("壞了")
        boom.__name__ = "ssh_login_test"

        def other(ctx):
            raise RuntimeError("x")
        self.patch(h, "CHECKS", [boom, other])
        out = h.run_all(Ctx())
        self.assertEqual([(i["id"], i["status"], i["critical"]) for i in out],
                         [("H04", h.BAD, True), ("H19", h.BAD, True), ("other", h.BAD, False)])
        self.assertEqual(out[0]["detail"], "檢查程式錯誤：壞了")

    def test_compare_skips_new_items(self):
        pre = [h.item("H01", "a", True, h.OK, "")]
        post = [h.item("H01", "a", True, h.OK, ""), h.item("H99", "new", True, h.BAD, "")]
        self.assertEqual(h.compare(pre, post), {"H01": ("無變化", False)})


if __name__ == "__main__":
    unittest.main()
