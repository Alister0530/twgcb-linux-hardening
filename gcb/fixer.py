# -*- coding: utf-8 -*-
"""修復動作的統一入口：每個動作都會寫 log、先記錄回滾資訊，並支援預覽修改內容（dry-run）。"""
import os

from . import pkgsvc
from .util import activity, cmd_str, diff_summary, now, read_text, run, write_text_atomic


LONG_STEP = 300  # 逾時設定達此秒數的步驟視為長時間步驟


class FixError(Exception):
    """修復失敗。"""


class ManualRequired(Exception):
    """需要人工處理。"""


class Fx(object):
    def __init__(self, ctx, rule_id):
        self.ctx = ctx
        self.rid = rule_id
        self.dry = ctx.dry_run
        self.osi = ctx.osi
        self.steps = []
        self.notes = []
        self.partial = False

    # ---- 紀錄 ----

    def step(self, action, detail, result="資訊"):
        rec = {"time": now(), "rule": self.rid, "action": action, "detail": detail, "result": result}
        self.steps.append(rec)
        self.ctx.add_step(rec)

    def note(self, text):
        self.notes.append(text)
        self.step("備註", text)

    # ---- 指令 ----

    def run(self, cmd, desc, timeout=120, check=True, env=None):
        if self.dry:
            self.step(desc, "[預覽] " + cmd_str(cmd), "預覽")
            return None
        if timeout >= LONG_STEP:  # 安裝套件、AIDE 初始化等可能需數分鐘的步驟，先告知
            self.ctx.say("      … %s：%s — 可能需要數分鐘，請稍候" % (self.rid, desc))
        with activity("%s：%s" % (self.rid, desc)):
            r = run(cmd, timeout=timeout, env=env)
        out = r.text()
        detail = r.cmd + ("\n輸出：" + out[-800:] if out else "")
        self.step(desc, detail, "成功" if r.ok else "失敗 (rc=%s)" % r.rc)
        if check and not r.ok:
            raise FixError("%s 失敗：%s" % (desc, out[-300:]))
        return r

    def run_tracked(self, cmd, desc, paths, **kw):
        """執行會改寫檔案的外部指令（如 pam-auth-update），並把檔案差異寫入 log。"""
        before = {p: read_text(p) for p in paths}
        r = self.run(cmd, desc, **kw)
        if not self.dry:
            for p in paths:
                after = read_text(p)
                if after != before[p]:
                    self.step("檔案變更（%s）" % os.path.basename(cmd[0]),
                              "%s\n%s" % (p, diff_summary(before[p], after)), "成功")
        return r

    def add_undo(self, cmd, desc):
        """登記一個回滾時要執行的指令（需在實際修改前呼叫）。"""
        if not self.dry:
            self.ctx.journal.add(self.rid, "cmd", cmd=cmd, desc=desc)

    # ---- 檔案 ----

    def write_file(self, path, text, mode=0o644):
        old = read_text(path)
        if old == text:
            return False
        if self.dry:
            self.step("修改檔案", "[預覽] %s\n%s" % (path, diff_summary(old, text)), "預覽")
            return True
        e = self.ctx.journal.backup_file(self.rid, path)
        if e["data"]["existed"]:
            self.step("備份檔案", "%s → %s" % (path, e["data"]["backup"]), "成功")
        write_text_atomic(path, text, mode)
        self.step("修改檔案", "%s\n%s" % (path, diff_summary(old, text)), "成功")
        return True

    def edit_file(self, path, func, mode=0o644):
        return self.write_file(path, func(read_text(path) or ""), mode)

    def backup_only(self, path):
        """只備份不修改（例如之後會被其他指令改寫的檔案）。"""
        if self.dry or not os.path.exists(path):
            return
        e = self.ctx.journal.backup_file(self.rid, path)
        self.step("備份檔案", "%s → %s" % (path, e["data"]["backup"]), "成功")

    def backup_dir(self, path):
        """備份整個目錄，回傳備份 tar 路徑（預覽時為 None）。"""
        if self.dry:
            self.step("備份目錄", "[預覽] " + path, "預覽")
            return None
        e = self.ctx.journal.backup_dir_tree(self.rid, path)
        self.step("備份目錄", "%s → %s" % (path, e["data"]["tar"]), "成功")
        return e["data"]["tar"]

    def chmod(self, path, mode):
        old = os.stat(path).st_mode & 0o7777
        if self.dry:
            self.step("變更權限", "[預覽] chmod %04o %s（目前 %04o）" % (mode, path, old), "預覽")
            return
        self.ctx.journal.record_meta(self.rid, path)
        os.chmod(path, mode)
        self.step("變更權限", "chmod %04o %s（修改前 %04o）" % (mode, path, old), "成功")

    def chown(self, path, uid, gid, label):
        st = os.stat(path)
        if self.dry:
            self.step("變更擁有者", "[預覽] chown %s %s" % (label, path), "預覽")
            return
        self.ctx.journal.record_meta(self.rid, path)
        os.chown(path, uid, gid)
        self.step("變更擁有者", "chown %s %s（修改前 uid=%s gid=%s）" % (label, path, st.st_uid, st.st_gid), "成功")

    # ---- 服務 ----

    def _record_service(self, unit):
        en, act = pkgsvc.svc_state(unit)
        if not self.dry:
            self.ctx.journal.add(self.rid, "service", unit=unit, enabled=en, active=act)
        return en, act

    def service_mask(self, unit):
        en, act = self._record_service(unit)
        self.ctx.intended_stops.add(unit)
        self.run(["systemctl", "--now", "mask", unit], "停用服務 %s（原 %s/%s）" % (unit, en, act))

    def service_enable(self, unit):
        en, act = self._record_service(unit)
        self.run(["systemctl", "--now", "enable", unit], "啟用服務 %s（原 %s/%s）" % (unit, en, act))

    # ---- 套件 ----

    def pkg_install(self, pkg, track=()):
        before = set()
        if not self.dry:
            before = pkgsvc.pkg_list(self.osi)
            entry = self.ctx.journal.add(self.rid, "pkg_installed", pkg=pkg, pkgs=[pkg])
        t = self.ctx.cfg.package_timeout
        try:
            self._pkg_install(pkg, track, t)
        finally:
            if not self.dry:
                # 記錄本次新增的所有套件（含相依），回滾時一併移除
                new = sorted(pkgsvc.pkg_list(self.osi) - before)
                entry["data"]["pkgs"] = new  # 沒有新增時為空，回滾不會移除原本就有的套件
                self.ctx.journal.save()
                if new:
                    self.step("新增套件清單", "、".join(new), "資訊")

    def _pkg_install(self, pkg, track, t):
        r = self.run_tracked(pkgsvc.pkg_install_cmd(self.osi, pkg), "安裝套件 %s" % pkg, list(track),
                             timeout=t, check=False, env=pkgsvc.APT_ENV)
        if r is not None and not r.ok and self.osi.family == "debian":
            # 套件索引過舊時更新一次再試
            self.run(["apt-get", "update"], "更新套件索引", timeout=t, check=False, env=pkgsvc.APT_ENV)
            r = self.run(pkgsvc.pkg_install_cmd(self.osi, pkg), "重新安裝套件 %s" % pkg,
                         timeout=t, check=False, env=pkgsvc.APT_ENV)
        if r is not None and not r.ok:
            raise ManualRequired("無法安裝套件 %s（可能無法連線套件庫），請人工安裝後重新執行" % pkg)

    def pkg_remove(self, pkg):
        deps = pkgsvc.pkg_dependents(self.osi, pkg)
        if deps:
            raise ManualRequired("移除 %s 會連帶影響其他套件：%s，請人工評估" % (pkg, ", ".join(deps[:10])))
        if not self.dry:
            self.ctx.journal.add(self.rid, "pkg_removed", pkg=pkg)
        r = self.run(pkgsvc.pkg_remove_cmd(self.osi, pkg), "移除套件 %s" % pkg,
                     timeout=self.ctx.cfg.package_timeout, check=False, env=pkgsvc.APT_ENV)
        if r is not None and not r.ok:
            raise FixError("移除套件 %s 失敗" % pkg)

    # ---- sysctl / 帳號 ----

    def sysctl_set(self, key, value):
        old = pkgsvc.sysctl_runtime(key)
        if not self.dry:
            self.ctx.journal.add(self.rid, "sysctl", key=key, value=old)
        self.run(["sysctl", "-w", "%s=%s" % (key, value)], "設定核心參數 %s（原值 %s）" % (key, old))

    CHAGE_NAMES = {"-M": "通行碼最長期限", "-m": "通行碼最短期限", "-W": "到期前提醒天數", "-I": "到期後停用天數"}

    def chage(self, user, opt, old, new):
        """修改帳號通行碼期限欄位（opt：-M/-m/-W/-I），回滾時還原原值（空值以 -1 還原）。"""
        if not self.dry:
            self.ctx.journal.add(self.rid, "chage", user=user, opt=opt, old=old)
        self.run(["chage", opt, str(new), user],
                 "設定帳號 %s %s（原值 %s）" % (user, self.CHAGE_NAMES.get(opt, opt), old or "未設定"))

    def chage_max(self, user, old_max, days):
        self.chage(user, "-M", old_max, days)
