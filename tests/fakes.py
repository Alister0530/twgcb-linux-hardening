# -*- coding: utf-8 -*-
"""單元測試用的模擬環境：不執行真實指令、不修改真實檔案。

    fx = FakeFx(ctx=FakeCtx("rhel9"), fs={"/etc/fstab": "..."}, runner=FakeRunner({"sshd -t": res(0)}))
    rule.fix(fx.ctx, fx)
    fx.fs["/etc/fstab"]       # 修改後內容
    fx.events                 # [("undo", "..."), ("write", path), ("run", "..."), ...] 依發生順序
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from gcb.config import DEFAULTS  # noqa: E402
from gcb.osinfo import OSInfo  # noqa: E402
from gcb.util import CmdResult, cmd_str  # noqa: E402

try:
    from unittest import mock  # noqa: F401
except ImportError:  # pragma: no cover
    mock = None

OS = {
    "rhel8": ("rhel8", "rhel", "Rocky Linux 8.10", "rocky", "8.10"),
    "rhel9": ("rhel9", "rhel", "Rocky Linux 9.5", "rocky", "9.5"),
    "ubuntu2204": ("ubuntu2204", "debian", "Ubuntu 22.04.5 LTS", "ubuntu", "22.04"),
}


def make_osi(key="rhel9", version=None):
    k, fam, pretty, os_id, ver = OS[key]
    return OSInfo(k, fam, pretty, os_id, version or ver)


def res(rc=0, out="", err="", cmd=""):
    return CmdResult(cmd, rc, out, err)


class FakeCfg(object):
    def __init__(self, **kw):
        self.test_user = "gcbtest"
        self.critical_services = []
        self.exclude_rules = []
        self.manual_login_confirm = True
        self.auto_rollback = True
        self.dns_test_name = ""
        self.report_dir = "/tmp/gcb-test-reports"
        self.package_timeout = int(DEFAULTS.get("package_timeout", "900"))
        self.firewall_backend = "auto"
        self.path = None
        for k, v in kw.items():
            setattr(self, k, v)


class FakeCtx(object):
    def __init__(self, key="rhel9", dry_run=False, include_risky=True, version=None, **cfg):
        self.osi = make_osi(key, version)
        self.cfg = FakeCfg(**cfg)
        self.dry_run = dry_run
        self.include_risky = include_risky
        self.intended_stops = set()
        self.pre_health_status = {"H04": "通過", "H05": "通過", "H19": "通過"}
        self.journal = None
        self.steps = []
        self.run_id = "test"
        self.run_dir = "/tmp/gcb-test-run"

    def add_step(self, rec):
        self.steps.append(rec)

    def say(self, *a, **k):
        pass


class FakeRunner(object):
    """依指令字串的「子字串」回傳結果；未對應的指令回傳 rc=0、空輸出。

    rules 可為 {子字串: CmdResult 或 callable(cmd_str) -> CmdResult}；先符合者優先（依插入順序）。
    """

    def __init__(self, rules=None, default=None):
        self.rules = list((rules or {}).items())
        self.default = default if default is not None else res(0)
        self.calls = []

    def add(self, pattern, result):
        self.rules.insert(0, (pattern, result))

    def __call__(self, cmd, timeout=120, env=None, input_text=None):
        s = cmd_str(cmd)
        self.calls.append(s)
        for pat, r in self.rules:
            if pat in s:
                r = r(s) if callable(r) else r
                return CmdResult(s, r.rc, r.out, r.err)
        return CmdResult(s, self.default.rc, self.default.out, self.default.err)

    def ran(self, pattern):
        return [c for c in self.calls if pattern in c]


class FakeFx(object):
    """與 gcb.fixer.Fx 相同介面；修改寫入 self.fs（記憶體），動作依序記在 self.events。"""

    def __init__(self, ctx=None, fs=None, runner=None, rid="TWGCB-TEST"):
        self.ctx = ctx or FakeCtx()
        self.rid = rid
        self.dry = self.ctx.dry_run
        self.osi = self.ctx.osi
        self.fs = fs if fs is not None else {}
        self.runner = runner or FakeRunner()
        self.steps, self.notes, self.events = [], [], []
        self.partial = False
        self.modes = {}

    # ---- 紀錄 ----
    def step(self, action, detail, result="資訊"):
        self.steps.append((action, detail, result))

    def note(self, text):
        self.notes.append(text)
        self.step("備註", text)

    # ---- 指令 ----
    def run(self, cmd, desc, timeout=120, check=True, env=None):
        from gcb.fixer import FixError
        self.events.append(("run", cmd_str(cmd)))
        if self.dry:
            return None
        r = self.runner(cmd, timeout=timeout, env=env)
        self.step(desc, r.cmd, "成功" if r.ok else "失敗")
        if check and not r.ok:
            raise FixError("%s 失敗：%s" % (desc, r.text()[-300:]))
        return r

    def run_tracked(self, cmd, desc, paths, **kw):
        return self.run(cmd, desc, **kw)

    def add_undo(self, cmd, desc):
        if not self.dry:
            self.events.append(("undo", cmd_str(cmd)))

    # ---- 檔案 ----
    def write_file(self, path, text, mode=0o644):
        if self.fs.get(path) == text:
            return False
        self.events.append(("write", path))
        if not self.dry:
            self.fs[path] = text
            self.modes[path] = mode
        return True

    def edit_file(self, path, func, mode=0o644):
        return self.write_file(path, func(self.fs.get(path) or ""), mode)

    def backup_only(self, path):
        self.events.append(("backup", path))

    def backup_dir(self, path):
        self.events.append(("backup_dir", path))
        return None if self.dry else "/tmp/backup.tar"

    def chmod(self, path, mode):
        self.events.append(("chmod", path, mode))

    def chown(self, path, uid, gid, label):
        self.events.append(("chown", path, label))

    # ---- 服務／套件／參數 ----
    def service_mask(self, unit):
        self.ctx.intended_stops.add(unit)
        self.events.append(("mask", unit))
        self.run(["systemctl", "--now", "mask", unit], "停用服務 %s" % unit)

    def service_enable(self, unit):
        self.events.append(("enable", unit))
        self.run(["systemctl", "--now", "enable", unit], "啟用服務 %s" % unit)

    def pkg_install(self, pkg, track=()):
        self.events.append(("pkg_install", pkg))
        r = self.runner(["install", pkg])
        if not self.dry and not r.ok:
            from gcb.fixer import ManualRequired
            raise ManualRequired("無法安裝套件 %s" % pkg)

    def pkg_remove(self, pkg):
        self.events.append(("pkg_remove", pkg))

    def sysctl_set(self, key, value):
        self.events.append(("sysctl", key, str(value)))

    def chage(self, user, opt, old, new):
        self.events.append(("chage", user, opt, str(new)))

    def chage_max(self, user, old_max, days):
        self.chage(user, "-M", old_max, days)

    # ---- 輔助 ----
    def kinds(self, kind):
        return [e[1] for e in self.events if e[0] == kind]


def fs_reader(fs):
    """回傳可用來 patch 模組 read_text 的函式（檔案不存在回傳 None）。"""
    return lambda path, *a, **k: fs.get(path)
