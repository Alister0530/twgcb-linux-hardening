# -*- coding: utf-8 -*-
"""備份與回滾紀錄。

每個修改動作「執行前」先寫入 rollback.json（write-ahead），
即使程式中途中斷也能依紀錄還原。回滾時依相反順序執行。
"""
import json
import re
import os
import shutil
import tarfile

from . import pkgsvc
from .util import activity, now, run, restorecon


class Journal(object):
    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.path = os.path.join(run_dir, "rollback.json")
        self.backup_dir = os.path.join(run_dir, "backup")
        self.entries = []
        if os.path.exists(self.path):
            with open(self.path, "rb") as f:
                self.entries = json.loads(f.read().decode("utf-8"))

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(json.dumps(self.entries, ensure_ascii=False, indent=1).encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def add(self, rule_id, kind, **data):
        e = {"seq": len(self.entries) + 1, "rule": rule_id, "type": kind, "time": now(),
             "data": data, "rolled_back": False}
        self.entries.append(e)
        self.save()
        return e

    # ---- 各類備份 ----

    def backup_file(self, rule_id, path):
        """備份檔案（含權限與擁有者）；檔案不存在則記錄為新建，回滾時刪除。"""
        if os.path.exists(path):
            st = os.stat(path)
            seq = len(self.entries) + 1
            dest = os.path.join(self.backup_dir, "%04d" % seq + path)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(path, dest)
            return self.add(rule_id, "file", path=path, existed=True, backup=dest,
                            mode=st.st_mode & 0o7777, uid=st.st_uid, gid=st.st_gid)
        made, d = [], os.path.dirname(path)
        while d and d != "/" and not os.path.exists(d):
            made.append(d)
            d = os.path.dirname(d)
        return self.add(rule_id, "file", path=path, existed=False, backup=None, made_dirs=made)

    def backup_dir_tree(self, rule_id, path):
        seq = len(self.entries) + 1
        os.makedirs(self.backup_dir, exist_ok=True)
        tar = os.path.join(self.backup_dir, "%04d_%s.tar" % (seq, path.strip("/").replace("/", "_")))
        with tarfile.open(tar, "w") as t:
            t.add(path, arcname=os.path.basename(path))
        return self.add(rule_id, "dir", path=path, tar=tar)

    def record_meta(self, rule_id, path):
        st = os.stat(path)
        return self.add(rule_id, "meta", path=path, mode=st.st_mode & 0o7777,
                        uid=st.st_uid, gid=st.st_gid)


# ---------- 回滾 ----------

def _undo(entry, osi, say):
    d = entry["data"]
    t = entry["type"]
    if t == "file":
        if d["existed"]:
            shutil.copy2(d["backup"], d["path"])
            os.chown(d["path"], d["uid"], d["gid"])
            os.chmod(d["path"], d["mode"])
            restorecon(d["path"])
            say("還原檔案", "%s ← %s" % (d["path"], d["backup"]))
        else:
            if os.path.exists(d["path"]):
                os.unlink(d["path"])
                say("刪除新建檔案", d["path"])
            for md in d.get("made_dirs", []):
                if os.path.isdir(md) and not os.listdir(md):
                    os.rmdir(md)
                    say("刪除新建目錄", md)
        return True
    if t == "dir":
        # 保留目錄本身、只替換內容：不用 rename 換整個目錄（overlayfs 等會出現 Invalid cross-device link）
        target = d["path"]
        if os.path.isdir(target):
            for name in os.listdir(target):
                p = os.path.join(target, name)
                if os.path.isdir(p) and not os.path.islink(p):
                    shutil.rmtree(p)
                else:
                    os.unlink(p)
        with tarfile.open(d["tar"]) as t2:
            if hasattr(tarfile, "fully_trusted_filter"):
                # 不用 "tar" filter：它會清掉 setgid/sticky 與群組、其他人的寫入權限
                t2.extractall(os.path.dirname(target), filter="fully_trusted")
            else:
                t2.extractall(os.path.dirname(target))
        restorecon(target)
        say("還原目錄", "%s ← %s" % (target, d["tar"]))
        return True
    if t == "meta":
        os.chown(d["path"], d["uid"], d["gid"])
        os.chmod(d["path"], d["mode"])
        say("還原權限", "%s → %04o uid=%s gid=%s" % (d["path"], d["mode"], d["uid"], d["gid"]))
        return True
    if t == "service":
        return _undo_service(d, say)
    if t == "pkg_installed":
        pkgs = [p for p in d.get("pkgs", [d["pkg"]]) if pkgsvc.pkg_installed(osi, p)]
        if not pkgs:
            return True
        cmd = pkgsvc.pkg_remove_cmd(osi, pkgs[0])[:-1] + pkgs
        r = run(cmd, timeout=600, env=pkgsvc.APT_ENV)
        say("移除先前安裝的套件（含相依）", "%s → rc=%s" % (" ".join(pkgs), r.rc), r.ok)
        if r.ok:
            return True
        # 整批移除失敗（例如某個相依套件已被其他套件需要）時，改為逐一移除，盡量減少殘留
        left = []
        for p in pkgs:
            if pkgsvc.pkg_installed(osi, p):
                rr = run(pkgsvc.pkg_remove_cmd(osi, p), timeout=300, env=pkgsvc.APT_ENV)
                if not rr.ok:
                    left.append(p)
        say("逐一移除先前安裝的套件", "無法移除：%s" % ("、".join(left) or "無"), not left)
        return not left
    if t == "pkg_removed":
        r = run(pkgsvc.pkg_install_cmd(osi, d["pkg"]), timeout=600, env=pkgsvc.APT_ENV)
        say("重新安裝先前移除的套件", "%s → rc=%s %s" % (d["pkg"], r.rc, r.text()[-200:] if not r.ok else ""), r.ok)
        return r.ok
    if t == "sysctl":
        if d["value"] is None or pkgsvc.sysctl_runtime(d["key"]) == d["value"]:
            return True
        r = run(["sysctl", "-w", "%s=%s" % (d["key"], d["value"])], timeout=30)
        say("還原核心參數", "%s=%s → rc=%s" % (d["key"], d["value"], r.rc), r.ok)
        return r.ok
    if t == "chage":
        opt = d.get("opt", "-M")
        old = d.get("old", d.get("max"))  # 舊版紀錄只有 max
        val = old if old not in ("", None) else "-1"
        r = run(["chage", opt, val, d["user"]], timeout=30)
        say("還原通行碼期限", "%s %s %s → rc=%s" % (d["user"], opt, val, r.rc), r.ok)
        return r.ok
    if t == "cmd":
        r = run(d["cmd"], timeout=600, env=pkgsvc.APT_ENV)
        say("執行還原指令", "%s → rc=%s%s" % (r.cmd, r.rc, "；" + r.text()[-200:] if not r.ok else ""), r.ok)
        return r.ok
    say("未知的回滾類型", t)
    return False


def _undo_service(d, say):
    unit = d["unit"]
    cur_en, cur_act = pkgsvc.svc_state(unit)
    if cur_en == "masked" and d["enabled"] != "masked":
        run(["systemctl", "unmask", unit], timeout=60)
    if d["enabled"] in ("enabled", "enabled-runtime"):
        run(["systemctl", "enable", unit], timeout=60)
    elif d["enabled"] == "disabled":
        run(["systemctl", "disable", unit], timeout=60)
    elif d["enabled"] == "masked":
        run(["systemctl", "mask", unit], timeout=60)
    if d["active"] == "active":
        run(["systemctl", "start", unit], timeout=120)
    elif cur_act == "active":
        r = run(["systemctl", "stop", unit], timeout=120)
        if not r.ok:  # auditd 不允許 systemctl stop
            run(["service", unit.replace(".service", ""), "stop"], timeout=120)
    en, act = pkgsvc.svc_state(unit)
    good = not (d["active"] == "active" and act != "active")
    if d["enabled"] in ("enabled", "disabled", "masked") and en != d["enabled"]:
        good = False
    say("還原服務狀態", "%s → enabled=%s active=%s（原為 %s/%s）" % (unit, en, act, d["enabled"], d["active"]), good)
    return good


PATH_TYPES = ("file", "meta", "dir")


def later_conflicts(journal, rule_id):
    """回傳在 rule_id 之後、修改過同一路徑且尚未回滾的其他規則（單獨回滾 rule_id 會被它們的備份蓋回去）。"""
    mine = [e for e in journal.entries if e["rule"] == rule_id and e["type"] in PATH_TYPES and not e["rolled_back"]]
    if not mine:
        return []
    first = min(e["seq"] for e in mine)
    paths = set(e["data"]["path"] for e in mine)
    out = []
    for e in journal.entries:
        if (e["rule"] != rule_id and e["seq"] > first and not e["rolled_back"] and e["type"] in PATH_TYPES
                and e["data"]["path"] in paths and e["rule"] not in out):
            out.append(e["rule"])
    return out


def is_audit_reload(entry):
    """回滾指令是否為重新載入稽核規則（augenrules --load、service auditd reload）。"""
    if entry["type"] != "cmd":
        return False
    c = entry["data"]["cmd"]
    c = " ".join(c) if isinstance(c, list) else c
    return "augenrules --load" in c or ("auditd" in c and "reload" in c)


def audit_locked():
    """稽核規則是否已設為不可變更（-e 2）：此時核心拒絕任何變更，直到重開機。"""
    r = run(["auditctl", "-s"], timeout=15)
    return r.ok and bool(re.search(r"^enabled\s+2\b", r.out, re.M))


def rollback(journal, osi, say, rule_id=None):
    """依相反順序回滾；rule_id 指定時只回滾該規則。回傳 (成功數, 失敗數)。

    稽核規則已鎖定（-e 2）時，重新載入稽核規則必定失敗；設定檔已由其他紀錄還原，
    此類步驟記為「需重開機生效」而非失敗，並設定 journal.reboot_audit。
    """
    ok = fail = 0
    locked = None
    journal.reboot_audit = False
    for e in reversed(journal.entries):
        if e["rolled_back"] or (rule_id and e["rule"] != rule_id):
            continue
        rid = e["rule"]
        if is_audit_reload(e):
            if locked is None:
                locked = audit_locked()
            if locked:
                say(rid, "略過重新載入稽核規則", "稽核規則已鎖定（-e 2），設定檔已還原，重開機後生效", "需重開機")
                journal.reboot_audit = True
                e["rolled_back"] = True
                ok += 1
                journal.save()
                continue
        try:
            with activity("回滾 %s（%s #%s）" % (rid, e["type"], e["seq"])):
                good = _undo(e, osi, lambda a, m, ok=True: say(rid, a, m, "成功" if ok else "失敗"))
        except Exception as ex:  # 單一項目失敗不中斷其餘回滾
            good = False
            say(rid, "回滾失敗", "%s #%s: %s" % (e["type"], e["seq"], ex), "失敗")
        if good:
            e["rolled_back"] = True
            ok += 1
        else:
            fail += 1
            say(rid, "回滾未完全成功", "%s #%s" % (e["type"], e["seq"]), "失敗")
        journal.save()
    return ok, fail
