# -*- coding: utf-8 -*-
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gcb import textedit as te  # noqa: E402


class KV(unittest.TestCase):
    def test_get_last_wins(self):
        self.assertEqual(te.get_kv("minlen = 8\n# minlen = 20\nminlen=10\n", "minlen"), "10")

    def test_get_whitespace_sep(self):
        self.assertEqual(te.get_kv("PASS_MAX_DAYS\t99999\n", "PASS_MAX_DAYS"), "99999")

    def test_get_not_prefix(self):
        self.assertIsNone(te.get_kv("deny_root = 1\n", "deny"))

    def test_set_replace_and_comment_dup(self):
        out = te.set_kv("a=1\nPASS_MAX_DAYS 99999\nPASS_MAX_DAYS 30\n", "PASS_MAX_DAYS", "90", sep="\t")
        lines = out.splitlines()
        self.assertEqual(lines[1], "PASS_MAX_DAYS\t90")
        self.assertTrue(lines[2].startswith(te.MARK))
        self.assertEqual(te.get_kv(out, "PASS_MAX_DAYS"), "90")

    def test_set_append(self):
        self.assertEqual(te.set_kv("# deny = 3\n", "deny", "5"), "# deny = 3\ndeny = 5\n")
        self.assertEqual(te.set_kv("", "deny", "5"), "deny = 5\n")


class Sysctl(unittest.TestCase):
    def test_parse(self):
        items = te.parse_sysctl("# c\n; c\nnet/ipv4/ip_forward = 1\n-net.ipv6.conf.all.forwarding=1\n")
        self.assertEqual(items, [("net.ipv4.ip_forward", "1"), ("net.ipv6.conf.all.forwarding", "1")])

    def test_comment_conflict_only(self):
        out = te.comment_sysctl("net.ipv4.ip_forward = 1\nnet.ipv4.ip_forward=0\nvm.x=1\n", "net.ipv4.ip_forward", "0")
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("# *REMOVED*"))
        self.assertEqual(lines[1], "net.ipv4.ip_forward=0")
        self.assertEqual(lines[2], "vm.x=1")


class Grub(unittest.TestCase):
    def test_add(self):
        t = 'GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX="crashkernel=auto rhgb quiet"\n'
        out = te.grub_cmdline_add(t, "audit=1")
        self.assertEqual(te.grub_cmdline_get(out), "crashkernel=auto rhgb quiet audit=1")

    def test_replace_existing_value(self):
        out = te.grub_cmdline_add('GRUB_CMDLINE_LINUX="audit=0 quiet"\n', "audit=1")
        self.assertEqual(te.grub_cmdline_get(out), "quiet audit=1")

    def test_empty_and_missing(self):
        self.assertEqual(te.grub_cmdline_get(te.grub_cmdline_add('GRUB_CMDLINE_LINUX=""\n', "audit=1")), "audit=1")
        self.assertEqual(te.grub_cmdline_get(te.grub_cmdline_add("X=1\n", "audit=1")), "audit=1")

    def test_trailing_comment_kept(self):
        t = 'GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=rl/root" # local\n'
        out = te.grub_cmdline_add(t, "audit=1")
        self.assertEqual(out, 'GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=rl/root audit=1" # local\n')

    def test_unparsable_raises(self):
        with self.assertRaises(ValueError):
            te.grub_cmdline_add('GRUB_CMDLINE_LINUX="a"$X"b"\n', "audit=1")

    def test_ignores_default_var(self):
        t = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\nGRUB_CMDLINE_LINUX=""\n'
        out = te.grub_cmdline_add(t, "audit=1")
        self.assertIn('GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"', out)
        self.assertEqual(te.grub_cmdline_get(out), "audit=1")


class Sshd(unittest.TestCase):
    def test_replace_global_keep_match(self):
        t = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User bob\n  PermitRootLogin yes\n"
        out = te.sshd_set_option(t, "PermitRootLogin", "no")
        self.assertEqual(out.splitlines()[1], "PermitRootLogin no")
        self.assertEqual(out.splitlines()[3], "  PermitRootLogin yes")

    def test_insert_before_match(self):
        out = te.sshd_set_option("Port 22\nMatch Group x\n  X11Forwarding no\n", "PermitRootLogin", "no")
        self.assertEqual(out.splitlines(), ["Port 22", "PermitRootLogin no", "Match Group x", "  X11Forwarding no"])

    def test_append_when_no_match(self):
        out = te.sshd_set_option("#PermitRootLogin prohibit-password\n", "PermitRootLogin", "no")
        self.assertEqual(out.splitlines()[-1], "PermitRootLogin no")

    def test_dropin_comment(self):
        out = te.sshd_comment_option("PermitRootLogin yes\n", "PermitRootLogin", "no")
        self.assertTrue(out.startswith(te.MARK))
        self.assertEqual(te.sshd_comment_option("permitrootlogin no\n", "PermitRootLogin", "no"), "permitrootlogin no\n")

    def test_includes(self):
        self.assertEqual(te.sshd_includes("Include sshd_config.d/*.conf /x/y.conf\n"),
                         ["/etc/ssh/sshd_config.d/*.conf", "/x/y.conf"])

    def test_listen_ports(self):
        d = te.parse_sshd_T("port 22\nlistenaddress 0.0.0.0:2222\nlistenaddress [::]:2222\nlistenaddress 10.0.0.1:22\n")
        self.assertEqual(te.sshd_listen_ports(d), ["22", "2222"])

    def test_parse_T(self):
        d = te.parse_sshd_T("port 22\nport 2222\npermitrootlogin no\n")
        self.assertEqual(d["port"], ["22", "2222"])


class Modprobe(unittest.TestCase):
    def test_status(self):
        self.assertEqual(te.modprobe_status(["install cramfs /bin/true\n", "blacklist cramfs\n"], "cramfs"), (True, True))
        self.assertEqual(te.modprobe_status(["install cramfs /sbin/modprobe x\n"], "cramfs"), (False, False))

    def test_conf(self):
        out = te.modprobe_conf("install cramfs /bin/true\n# note\n", "cramfs", "/bin/false")
        self.assertEqual(out, "# note\ninstall cramfs /bin/false\nblacklist cramfs\n")


class Fstab(unittest.TestCase):
    T = "# c\nUUID=1 / ext4 defaults 0 1\nUUID=2 /var ext4 defaults,nodev 0 2\n"

    def test_options(self):
        self.assertEqual(te.fstab_options(self.T, "/var"), ["defaults", "nodev"])
        self.assertIsNone(te.fstab_options(self.T, "/tmp"))

    def test_add_option(self):
        out = te.fstab_add_option(self.T, "/var", "nosuid")
        self.assertEqual(te.fstab_options(out, "/var"), ["defaults", "nodev", "nosuid"])
        self.assertEqual(te.fstab_add_option(out, "/var", "nosuid"), out)  # 不重複加入

    def test_add_dev_shm_line(self):
        out = te.fstab_add_option(self.T, "/dev/shm", "noexec")
        self.assertEqual(te.fstab_options(out, "/dev/shm"), ["defaults", "nodev", "nosuid", "noexec"])

    def test_missing_mount_raises(self):
        with self.assertRaises(ValueError):
            te.fstab_add_option(self.T, "/home", "nodev")


class WriteAtomic(unittest.TestCase):
    def test_keeps_symlink(self):
        import tempfile
        from gcb.util import write_text_atomic, read_text
        d = tempfile.mkdtemp()
        real, link = os.path.join(d, "sysctl.conf"), os.path.join(d, "99-sysctl.conf")
        with open(real, "w") as f:
            f.write("a=1\n")
        os.symlink(real, link)
        write_text_atomic(link, "a=0\n")
        self.assertTrue(os.path.islink(link))
        self.assertEqual(read_text(real), "a=0\n")


class SysctlOverride(unittest.TestCase):
    def test_package_file_goes_to_etc(self):
        from gcb.rules.common import sysctl_override_path
        self.assertEqual(sysctl_override_path("/usr/lib/sysctl.d/10-default-yama-scope.conf"),
                         "/etc/sysctl.d/10-default-yama-scope.conf")
        self.assertEqual(sysctl_override_path("/etc/sysctl.d/99-x.conf"), "/etc/sysctl.d/99-x.conf")


class ModuleLoaded(unittest.TestCase):
    def test_exact_name(self):
        from unittest import mock
        from gcb.rules import common
        mods = "ext4 1 0 - Live\nvfat 2 0 - Live\nusb_storage 1 0 - Live\n"
        with mock.patch.object(common, "read_text", return_value=mods):
            self.assertFalse(common.module_loaded("ext"))
            self.assertFalse(common.module_loaded("fat"))
            self.assertTrue(common.module_loaded("vfat"))
            self.assertTrue(common.module_loaded("usb-storage"))


class DirRollback(unittest.TestCase):
    def test_restore_dir_in_place(self):
        import tempfile
        from gcb import journal
        base = tempfile.mkdtemp()
        target = os.path.join(base, "conf.d")
        os.makedirs(os.path.join(target, "sub"))
        with open(os.path.join(target, "a.conf"), "w") as f:
            f.write("old\n")
        run_dir = os.path.join(base, "run")
        os.makedirs(run_dir)
        j = journal.Journal(run_dir)
        j.backup_dir_tree("R1", target)
        ino = os.stat(target).st_ino
        with open(os.path.join(target, "a.conf"), "w") as f:
            f.write("new\n")
        with open(os.path.join(target, "added.conf"), "w") as f:
            f.write("x\n")
        ok, fail = journal.rollback(j, None, lambda *a: None)
        self.assertEqual((ok, fail), (1, 0))
        self.assertEqual(os.stat(target).st_ino, ino)  # 目錄本身沒被替換
        with open(os.path.join(target, "a.conf")) as f:
            self.assertEqual(f.read(), "old\n")
        self.assertFalse(os.path.exists(os.path.join(target, "added.conf")))
        self.assertTrue(os.path.isdir(os.path.join(target, "sub")))


class Shadow(unittest.TestCase):
    def test_parse(self):
        u = te.parse_shadow("root:$6$x:19000:0:99999:7:::\nbin:*:19000:0:99999:7:::\nbad:line\n")
        self.assertEqual([x["name"] for x in u], ["root", "bin"])
        self.assertTrue(te.has_usable_password(u[0]["pw"]))
        self.assertFalse(te.has_usable_password(u[1]["pw"]))
        self.assertFalse(te.has_usable_password("!$6$x"))


if __name__ == "__main__":
    unittest.main()
