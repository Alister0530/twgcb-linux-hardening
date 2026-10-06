# -*- coding: utf-8 -*-
"""系統健康檢查（前測與後測使用同一套）。

狀態：通過 / 失敗 / 警告 / 略過 / 資訊
關鍵項目（critical）在後測由「通過」變「失敗」時會觸發自動回滾。
"""
import os
import pwd
import re
import shutil
import tempfile

from . import hints, pkgsvc
from . import textedit as te
from .util import activity, primary_ip, read_text, restorecon, run, which, write_text_atomic

OK, BAD, WARN, SKIP, INFO = "通過", "失敗", "警告", "略過", "資訊"


def item(hid, name, critical, status, detail, data=None):
    return {"id": hid, "name": name, "critical": critical, "status": status,
            "detail": detail, "data": data or []}


# ---------- SSH 相關 ----------

def _sshd_T():
    sshd = which("sshd")
    if not sshd:
        return None
    r = run([sshd, "-T"], timeout=30)
    return te.parse_sshd_T(r.out) if r.ok else None


def chk_ssh_service(ctx):
    en, act = pkgsvc.svc_state(ctx.osi.ssh_unit)
    return item("H01", "SSH 服務運作中", True, OK if act == "active" else BAD,
                "%s: enabled=%s active=%s" % (ctx.osi.ssh_unit, en, act))


def chk_sshd_syntax(ctx):
    sshd = which("sshd")
    if not sshd:
        return item("H02", "sshd 設定語法", True, BAD, "找不到 sshd")
    r = run([sshd, "-t"], timeout=30)
    return item("H02", "sshd 設定語法", True, OK if r.ok else BAD, "sshd -t 正常" if r.ok else r.text()[-300:])


def _ssh_ports():
    return te.sshd_listen_ports(_sshd_T() or {}) or ["22"]


def chk_ssh_listen(ctx):
    ports = _ssh_ports()
    r = run(["ss", "-Htln"], timeout=15)
    listening = []
    for line in r.out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            listening.append(parts[3].rsplit(":", 1)[-1])
    miss = [p for p in ports if p not in listening]
    return item("H03", "SSH 連接埠監聽", True, BAD if miss else OK,
                "設定埠 %s，未監聽：%s" % (",".join(ports), ",".join(miss)) if miss
                else "監聽中：%s" % ",".join(ports))


def _ssh_target():
    t = _sshd_T() or {}
    for a in t.get("listenaddress", []):
        host = a.rsplit(":", 1)[0].strip("[]")
        if host in ("0.0.0.0", "127.0.0.1"):
            return "127.0.0.1"
        if host in ("::", "::1"):
            continue
        return host
    return "127.0.0.1"


def _authorized_keys_path(user):
    t = _sshd_T() or {}
    pw = pwd.getpwnam(user)
    first = (t.get("authorizedkeysfile", [".ssh/authorized_keys"])[0].split() or [".ssh/authorized_keys"])[0]
    path = first.replace("%h", pw.pw_dir).replace("%u", user).replace("%%", "%")
    return path if path.startswith("/") else os.path.join(pw.pw_dir, path)


def _external_target():
    """主要網卡的 IP（非迴路），sshd 有在該位址監聽時才回傳；否則回傳 (None, 原因)。"""
    ip = primary_ip()
    if not ip or ip.startswith("127.") or ip == "::1":
        return None, "找不到主要網卡的 IP"
    addrs = [a.rsplit(":", 1)[0].strip("[]") for a in (_sshd_T() or {}).get("listenaddress", [])]
    if addrs and not any(a in ("0.0.0.0", "::", ip) for a in addrs):
        return None, "sshd 未在 %s 監聽（ListenAddress：%s）" % (ip, "、".join(addrs))
    return ip, ""


def _ssh_try(key, user, host, port):
    r = run(["ssh", "-i", key, "-p", port, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
             "%s@%s" % (user, host), "echo GCB_LOGIN_OK"], timeout=40)
    good = r.ok and "GCB_LOGIN_OK" in r.out
    return good, "%s 以金鑰登入 %s:%s %s" % (user, host, port, "成功" if good else "失敗：" + r.text()[-300:])


def _remove_stale_keys(ctx, user):
    """移除先前執行被中斷（斷線、kill）時遺留在 authorized_keys 的測試金鑰。"""
    try:
        ak = _authorized_keys_path(user)
    except KeyError:
        return
    text = read_text(ak)
    if text and "gcb-checker-temp-" in text:
        write_text_atomic(ak, "".join(l + "\n" for l in text.splitlines() if "gcb-checker-temp-" not in l))
        ctx.log_event("H04", "移除先前遺留的測試金鑰", ak)


def ssh_login_test(ctx):
    """以測試帳號實際 SSH 登入：暫時放入一把金鑰，測完立即移除（步驟寫入 log）。

    H04 連本機（127.0.0.1）：驗證 sshd、PAM、帳號可登入。
    H19 連主要網卡 IP：防火牆一律放行迴路介面，只有從對外 IP 連線，才測得出防火牆是否擋住 SSH。
    """
    name4, name19 = "SSH 實際登入測試", "SSH 從主要網卡 IP 登入"
    user = ctx.cfg.test_user

    def both(status, detail):
        return [item("H04", name4, True, status, detail), item("H19", name19, True, SKIP, "略過：" + detail)]
    if not user:
        return both(SKIP, "config.ini 未設定 test_user")
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return both(BAD, "測試帳號 %s 不存在" % user)
    if pw.pw_uid == 0:
        return both(BAD, "測試帳號不可為 root")
    for b in ("ssh", "ssh-keygen"):
        if not which(b):
            return both(BAD, "找不到 %s 指令" % b)

    marker = "gcb-checker-temp-%s" % ctx.run_id
    _remove_stale_keys(ctx, user)
    tmpd = tempfile.mkdtemp(prefix="gcb-ssh-")
    key = os.path.join(tmpd, "id")
    ak = _authorized_keys_path(user)
    sshdir = os.path.dirname(ak)
    made_dir = not os.path.isdir(sshdir)
    existed = os.path.exists(ak)
    try:
        run(["ssh-keygen", "-q", "-t", "rsa", "-b", "3072", "-N", "", "-C", marker, "-f", key], timeout=60)
        pub = read_text(key + ".pub").strip()
        if made_dir:
            os.makedirs(sshdir, 0o700)
            os.chown(sshdir, pw.pw_uid, pw.pw_gid)
        old = read_text(ak) or ""
        if existed:
            write_text_atomic(ak, old + ("" if old.endswith("\n") or not old else "\n") + pub + "\n")
        else:
            write_text_atomic(ak, pub + "\n", mode=0o600)
            os.chown(ak, pw.pw_uid, pw.pw_gid)
        restorecon(sshdir)
        ctx.log_event("H04", "暫時加入測試金鑰", "%s（註記 %s）" % (ak, marker))

        port = _ssh_ports()[0]
        good, detail = _ssh_try(key, user, _ssh_target(), port)
        out = [item("H04", name4, True, OK if good else BAD, detail)]
        ext, why = _external_target()
        if ext:
            good19, detail19 = _ssh_try(key, user, ext, port)
            out.append(item("H19", name19, True, OK if good19 else BAD, detail19))
        else:
            out.append(item("H19", name19, True, SKIP, why))
        return out
    finally:
        # 移除測試金鑰，還原 authorized_keys
        if existed:
            text = read_text(ak) or ""
            write_text_atomic(ak, "".join(l + "\n" for l in text.splitlines() if marker not in l))
        elif os.path.exists(ak):
            os.unlink(ak)
        if made_dir and os.path.isdir(sshdir) and not os.listdir(sshdir):
            os.rmdir(sshdir)
        shutil.rmtree(tmpd, ignore_errors=True)
        ctx.log_event("H04", "移除測試金鑰", ak)


def chk_sudo(ctx):
    user = ctx.cfg.test_user
    if not user:
        return item("H05", "測試帳號 sudo 權限", True, SKIP, "未設定 test_user")
    r = run(["sudo", "-l", "-U", user], timeout=30)
    good = r.ok and re.search(r"\((ALL|root)", r.out) is not None
    return item("H05", "測試帳號 sudo 權限", True, OK if good else BAD,
                "%s 具有 sudo 權限" % user if good else "%s 無 sudo 權限：%s" % (user, r.text()[-200:]))


def chk_su_pam(ctx):
    """以 su - 走一次 PAM account/session 流程，偵測 PAM 設定損壞。"""
    user = ctx.cfg.test_user
    if not user:
        return item("H06", "PAM 登入流程（su -）", True, SKIP, "未設定 test_user")
    r = run(["su", "-", user, "-c", "echo GCB_SU_OK"], timeout=30)
    good = "GCB_SU_OK" in r.out
    return item("H06", "PAM 登入流程（su -）", True, OK if good else BAD,
                "su - %s 正常" % user if good else r.text()[-300:])


def chk_root_account(ctx):
    r = run(["passwd", "-S", "root"], timeout=15)
    parts = r.out.split()
    st = parts[1] if len(parts) > 1 else "?"
    locked = st in ("L", "LK")
    return item("H07", "root 帳號狀態", False, INFO, "root 狀態=%s%s" % (st, "（已鎖定）" if locked else ""))


# ---------- 系統 ----------

def chk_failed_units(ctx):
    r = run(["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"], timeout=30)
    units = sorted(l.split()[0] for l in r.out.splitlines() if l.strip())
    return item("H08", "失敗的系統服務", False, WARN if units else OK,
                "、".join(units) if units else "無", units)


def chk_running_services(ctx):
    r = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"], timeout=30)
    units = sorted(l.split()[0] for l in r.out.splitlines() if l.strip())
    return item("H09", "運作中的服務", False, OK, "%d 個服務運作中" % len(units), units)


def chk_critical_services(ctx):
    svcs = ctx.cfg.critical_services
    if not svcs:
        return item("H10", "重要業務服務", True, SKIP, "config.ini 未設定 critical_services")
    bad = [s for s in svcs if pkgsvc.svc_state(s)[1] != "active"]
    return item("H10", "重要業務服務", True, BAD if bad else OK,
                "未運作：" + "、".join(bad) if bad else "全部運作中：" + "、".join(svcs))


# ---------- 網路 ----------

def _gateway():
    r = run(["ip", "route", "show", "default"], timeout=10)
    m = re.search(r"default via (\S+)", r.out)
    return m.group(1) if m else None


def chk_route(ctx):
    gw = _gateway()
    return item("H11", "預設路由", True, OK if gw else BAD, "閘道 %s" % gw if gw else "沒有預設路由")


def chk_gateway_ping(ctx):
    gw = _gateway()
    if not gw:
        return item("H12", "閘道連通", False, SKIP, "沒有預設路由")
    r = run(["ping", "-c", "2", "-W", "2", gw], timeout=15)
    return item("H12", "閘道連通", False, OK if r.ok else WARN,
                "ping %s %s" % (gw, "成功" if r.ok else "失敗（閘道可能封鎖 ICMP）"))


def chk_dns(ctx):
    servers = re.findall(r"^\s*nameserver\s+(\S+)", read_text("/etc/resolv.conf") or "", re.M)
    name = ctx.cfg.dns_test_name
    if not name:
        return item("H13", "DNS 設定", False, OK if servers else WARN,
                    "DNS 伺服器：" + "、".join(servers) if servers else "未設定 DNS 伺服器")
    r = run(["getent", "hosts", name], timeout=15)
    return item("H13", "DNS 解析", False, OK if r.ok else BAD,
                "解析 %s %s" % (name, "成功：" + r.out.split()[0] if r.ok and r.out.split() else "失敗"))


# ---------- 磁碟 / 開機 / 套件 ----------

def chk_disk(ctx):
    r = run(["df", "-P", "/", "/var", "/boot"], timeout=15)
    full, rows = [], []
    for line in r.out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 6:
            rows.append("%s %s" % (p[5], p[4]))
            if int(p[4].rstrip("%") or 0) >= 95:
                full.append(p[5])
    rows = sorted(set(rows))
    return item("H14", "磁碟空間", False, WARN if full else OK, "、".join(rows))


def chk_fstab(ctx):
    r = run(["findmnt", "--verify"], timeout=30)
    return item("H15", "fstab 設定", True, OK if r.ok else BAD,
                "findmnt --verify 正常" if r.ok else r.text()[-300:])


def chk_grub(ctx):
    if ctx.osi.family == "rhel":
        cands = ["/boot/grub2/grub.cfg"] + [os.path.join("/boot/efi/EFI", d, "grub.cfg")
                                            for d in ("redhat", "rocky", "almalinux", "centos")]
        checker = which("grub2-script-check")
    else:
        cands = ["/boot/grub/grub.cfg"]
        checker = which("grub-script-check")
    cfg = next((c for c in cands if os.path.exists(c)), None)
    if not cfg:
        return item("H16", "GRUB 開機設定", True, BAD, "找不到 grub.cfg")
    msgs, good = [cfg], True
    if checker:
        r = run([checker, cfg], timeout=30)
        good = r.ok
        msgs.append("語法%s" % ("正常" if r.ok else "錯誤：" + r.text()[-200:]))
    if ctx.osi.family == "rhel" and which("grubby"):
        r = run(["grubby", "--default-kernel"], timeout=30)
        good = good and r.ok
        msgs.append("預設核心 %s" % r.out.strip())
    return item("H16", "GRUB 開機設定", True, OK if good else BAD, "；".join(msgs))


def chk_pkg_mgr(ctx):
    if ctx.osi.family == "rhel":
        r = run(["rpm", "-q", "rpm"], timeout=30)
        detail = "rpm 正常" if r.ok else r.text()[-200:]
    else:
        r = run(["dpkg", "--audit"], timeout=60)
        r.rc = 0 if r.ok and not r.out.strip() else 1
        detail = "dpkg 正常" if r.ok else r.text()[-200:]
    return item("H17", "套件管理系統", False, OK if r.ok else WARN, detail)


def chk_mac(ctx):
    if ctx.osi.family == "rhel":
        r = run(["getenforce"], timeout=10)
        return item("H18", "SELinux 狀態", False, INFO, r.out.strip() or "未知")
    en = (read_text("/sys/module/apparmor/parameters/enabled") or "").strip()
    return item("H18", "AppArmor 狀態", False, INFO, "已啟用" if en == "Y" else "未啟用")


CHECKS = [chk_ssh_service, chk_sshd_syntax, chk_ssh_listen, ssh_login_test, chk_sudo, chk_su_pam,
          chk_root_account, chk_failed_units, chk_running_services, chk_critical_services,
          chk_route, chk_gateway_ping, chk_dns, chk_disk, chk_fstab, chk_grub, chk_pkg_mgr, chk_mac]


# 檢查程式本身出錯時使用的編號、名稱、是否關鍵（關鍵項目出錯視為失敗，才會停止修復或觸發回滾）
CHECK_META = {
    "chk_ssh_service": [("H01", "SSH 服務運作中", True)],
    "chk_sshd_syntax": [("H02", "sshd 設定語法", True)],
    "chk_ssh_listen": [("H03", "SSH 連接埠監聽", True)],
    "ssh_login_test": [("H04", "SSH 實際登入測試", True), ("H19", "SSH 從主要網卡 IP 登入", True)],
    "chk_sudo": [("H05", "測試帳號 sudo 權限", True)],
    "chk_su_pam": [("H06", "PAM 登入流程（su -）", True)],
    "chk_root_account": [("H07", "root 帳號狀態", False)],
    "chk_failed_units": [("H08", "失敗的系統服務", False)],
    "chk_running_services": [("H09", "運作中的服務", False)],
    "chk_critical_services": [("H10", "重要業務服務", True)],
    "chk_route": [("H11", "預設路由", True)],
    "chk_gateway_ping": [("H12", "閘道連通", False)],
    "chk_dns": [("H13", "DNS 設定", False)],
    "chk_disk": [("H14", "磁碟空間", False)],
    "chk_fstab": [("H15", "fstab 設定", True)],
    "chk_grub": [("H16", "GRUB 開機設定", True)],
    "chk_pkg_mgr": [("H17", "套件管理系統", False)],
    "chk_mac": [("H18", "SELinux / AppArmor 狀態", False)],
}


def run_all(ctx):
    out = []
    for fn in CHECKS:
        meta = CHECK_META.get(fn.__name__, [(fn.__name__, fn.__name__, False)])
        try:
            with activity("健康檢查 %s" % "、".join("%s %s" % (m[0], m[1]) for m in meta)):
                res = fn(ctx)
        except Exception as e:  # 單一檢查錯誤不影響其他項目
            res = [item(hid, name, crit, BAD, "檢查程式錯誤：%s" % e) for hid, name, crit in meta]
        for i in (res if isinstance(res, list) else [res]):  # 一個檢查函式可回傳多項（H04、H19）
            i["advice"] = hints.explain(i["detail"]) if i["status"] in (BAD, WARN) else []
            out.append(i)
    return out


def compare(pre, post, intended_stops=()):
    """比對前後測，回傳 {id: (變化說明, 是否關鍵退步)}。"""
    pre_map = {i["id"]: i for i in pre}
    result = {}
    for p in post:
        b = pre_map.get(p["id"])
        if not b:
            continue
        if p["id"] == "H08":  # 新增的失敗服務
            new = sorted(set(p["data"]) - set(b["data"]))
            result[p["id"]] = ("新增失敗服務：" + "、".join(new), False) if new else ("無變化", False)
            continue
        if p["id"] == "H09":  # 原本運作、修復後停止的服務（排除刻意停用者）
            stopped = sorted(u for u in set(b["data"]) - set(p["data"]) if u not in intended_stops)
            result[p["id"]] = ("修復後停止：" + "、".join(stopped), False) if stopped else ("無變化", False)
            continue
        if p["id"] in ("H15", "H16") and b["status"] == BAD and p["status"] == BAD:
            new = [l for l in p["detail"].splitlines() if l.strip() and l not in b["detail"].splitlines()]
            if new:
                result[p["id"]] = ("退步（新增錯誤：%s）" % new[0][:80], p["critical"])
                continue
        if b["status"] == OK and p["status"] == BAD:
            result[p["id"]] = ("退步（通過→失敗）", p["critical"])
        elif b["status"] == BAD and p["status"] == OK:
            result[p["id"]] = ("改善（失敗→通過）", False)
        elif b["status"] != p["status"]:
            result[p["id"]] = ("%s→%s" % (b["status"], p["status"]), False)
        else:
            result[p["id"]] = ("無變化", False)
    return result
