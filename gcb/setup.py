# -*- coding: utf-8 -*-
"""設定精靈：建立/選擇測試帳號、選擇業務服務、檢查套件庫、寫入 config.ini、執行健康檢查。

所有對系統的修改（建立帳號、加入群組）都會寫入 reports/setup_*/remediation.log。
"""
import getpass
import pwd
import re

from . import engine
from . import textedit as te
from .util import read_text, run, write_text_atomic

# 作業系統本身的服務，不列入業務服務建議
BASE_SERVICES = re.compile(
    r"^(systemd-|dbus|getty@|serial-getty@|user@|sshd?\.|chronyd|cron|crond|atd|auditd|rsyslog|"
    r"NetworkManager|networkd-dispatcher|firewalld|ufw|tuned|polkit|irqbalance|gssproxy|sssd|kdump|"
    r"lvm2-|multipathd|udisks2|snapd|unattended-upgrades|cloud-|qemu-guest-agent|vmtoolsd|open-vm-tools|"
    r"vgauth|hv-|hypervkvpd|ModemManager|accounts-daemon|rngd|smartd|packagekit|wpa_supplicant|"
    r"mdmonitor|thermald|upower|fwupd|apport|rhsmcertd|insights-client|nscd|nslcd|avahi-daemon|"
    r"switcheroo|rtkit|bolt|colord|cups|gdm|lightdm|plymouth|blk-availability|mcelog|abrt)")


def ask(prompt, default=""):
    try:
        ans = input("%s%s：" % (prompt, "［預設 %s］" % default if default else "")).strip()
    except EOFError:
        ans = ""
    return ans or default


def yes(prompt, default="n"):
    return ask(prompt + " [y/n]", default).lower().startswith("y")


def sudo_group(osi):
    return "wheel" if osi.family == "rhel" else "sudo"


def has_sudo(user):
    r = run(["sudo", "-l", "-U", user], timeout=30)
    return r.ok and re.search(r"\((ALL|root)", r.out) is not None


def candidate_users():
    """可登入、非 root 且有 sudo 權限的帳號。"""
    out = []
    for p in pwd.getpwall():
        if p.pw_uid < 1000 or p.pw_uid >= 60000 or p.pw_shell.endswith(("nologin", "false")):
            continue
        if has_sudo(p.pw_name):
            out.append(p.pw_name)
    return out


def _has_password(user):
    for u in te.parse_shadow(read_text("/etc/shadow") or ""):
        if u["name"] == user:
            return te.has_usable_password(u["pw"])
    return False


def check_user(ctx, user):
    """回傳不符合條件的原因清單。"""
    try:
        p = pwd.getpwnam(user)
    except KeyError:
        return ["帳號不存在"]
    problems = []
    if p.pw_uid == 0:
        problems.append("不可為 root")
    if p.pw_shell.endswith(("nologin", "false")):
        problems.append("登入 shell 為 %s，無法登入" % p.pw_shell)
    if not has_sudo(user):
        problems.append("沒有 sudo 權限")
    return problems


def create_user(ctx, user):
    group = sudo_group(ctx.osi)
    ctx.say("\n建立帳號 %s 並加入 %s 群組..." % (user, group))
    for cmd, desc in ((["useradd", "-m", "-s", "/bin/bash", user], "建立帳號"),
                      (["usermod", "-aG", group, user], "加入 %s 群組" % group)):
        r = run(cmd, timeout=60)
        ctx.log_event("setup", desc, "%s → rc=%s %s" % (r.cmd, r.rc, r.text()[-200:]), "成功" if r.ok else "失敗")
        if not r.ok:
            ctx.say("  失敗：%s" % r.text())
            return False
    set_password(ctx, user)
    return True


def set_password(ctx, user, tries=3):
    """由操作人員輸入密碼，以 chpasswd 經 stdin 設定（不出現在指令參數與 log 中）。"""
    ctx.say("\n請設定 %s 的密碼（人工登入確認時會用到，輸入時不會顯示）" % user)
    for _ in range(tries):
        try:
            p1 = getpass.getpass("  新密碼：")
            p2 = getpass.getpass("  再輸入一次：")
        except EOFError:
            break
        if not p1:
            ctx.say("  密碼不可為空白。")
            continue
        if p1 != p2:
            ctx.say("  兩次輸入不一致。")
            continue
        r = run(["chpasswd"], timeout=30, input_text="%s:%s\n" % (user, p1))
        if r.ok:
            ctx.log_event("setup", "設定密碼", "%s（由操作人員輸入）" % user, "成功")
            ctx.say("  ✓ 密碼已設定")
            return True
        ctx.say("  密碼設定失敗：%s" % r.text()[-200:])
    ctx.log_event("setup", "設定密碼", "%s 未設定，需人工以 passwd 設定" % user, "失敗")
    ctx.say("  ! 未設定密碼。帳號仍可用於自動登入測試（金鑰），但人工登入確認前請執行：sudo passwd %s" % user)
    return False


def choose_user(ctx, preset=None):
    ctx.say("\n【1/4】測試帳號")
    ctx.say("  用來在修復前後實際 SSH 登入，確認系統可以正常登入。條件：一般帳號、有 sudo 權限、可 SSH 登入。")
    if preset:
        user = preset
    else:
        cands = candidate_users()
        if cands:
            ctx.say("  已有符合條件的帳號：%s" % "、".join(cands))
        default = cands[0] if cands else "gcbtest"
        user = ask("  請輸入要使用的帳號（不存在會建立新帳號）", default)
    for _ in range(5):
        if user == "root":
            user = ask("  不可使用 root，請輸入其他帳號", "gcbtest")
            continue
        try:
            pwd.getpwnam(user)
        except KeyError:
            if yes("  帳號 %s 不存在，要建立嗎？" % user, "y"):
                if not create_user(ctx, user):
                    return None
            else:
                user = ask("  請輸入其他帳號")
                continue
        problems = check_user(ctx, user)
        if not problems:
            ctx.say("  ✓ %s 符合條件" % user)
            if not _has_password(user) and yes("  %s 沒有可用的密碼（人工登入確認需要），要設定嗎？" % user, "y"):
                set_password(ctx, user)
            return user
        ctx.say("  ✗ %s 不符合條件：%s" % (user, "、".join(problems)))
        if "沒有 sudo 權限" in problems and len(problems) == 1 and \
                yes("  要把 %s 加入 %s 群組嗎？" % (user, sudo_group(ctx.osi)), "y"):
            r = run(["usermod", "-aG", sudo_group(ctx.osi), user], timeout=60)
            ctx.log_event("setup", "加入 sudo 群組", "%s → rc=%s" % (r.cmd, r.rc), "成功" if r.ok else "失敗")
            continue
        user = ask("  請輸入其他帳號", "gcbtest")
    ctx.say("  嘗試次數過多，請確認帳號後重新執行設定精靈。")
    return None


def choose_services(ctx, preset=None):
    ctx.say("\n【2/4】業務服務")
    ctx.say("  修復後若這些服務停止，程式會自動回滾。")
    if preset is not None:
        return preset
    r = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"], timeout=30)
    running = sorted(l.split()[0] for l in r.out.splitlines() if l.strip())
    sugg = [s[:-8] if s.endswith(".service") else s for s in running if not BASE_SERVICES.match(s)]
    if sugg:
        ctx.say("  目前運作中、可能是業務服務的有：%s" % "、".join(sugg))
    else:
        ctx.say("  沒有偵測到作業系統以外的服務。")
    ans = ask("  請輸入業務服務（逗號分隔，Enter 略過；輸入 all 選取上面全部）", "")
    if ans.lower() == "all":
        return sugg
    return [s.strip() for s in ans.split(",") if s.strip()]


def _rhel_repo_problem():
    """回傳 (問題說明或空字串, 指令結果)。未註冊的 RHEL 執行 makecache 也可能成功，需先確認有已啟用的套件庫。"""
    r = run(["dnf", "-q", "repolist", "--enabled"], timeout=120)
    text = r.text().lower()
    if "not registered" in text or "consumer identity" in text:
        return "RHEL 尚未註冊訂閱（請執行 subscription-manager register），沒有可用的官方套件庫", r
    repos = [l for l in r.out.splitlines() if l.strip() and not l.lower().startswith("repo id")]
    if not r.ok or not repos:
        return "沒有任何已啟用的套件庫（RHEL 請註冊訂閱，或設定內部鏡像站）", r
    r = run(["dnf", "-q", "makecache"], timeout=120)
    return ("" if r.ok else "套件庫無法連線"), r


def check_repo(ctx):
    ctx.say("\n【3/4】檢查套件庫連線（最多等 2 分鐘）")
    if ctx.osi.family == "rhel":
        why, r = _rhel_repo_problem()
    else:
        r = run(["apt-get", "-q", "update"], timeout=120, env={"DEBIAN_FRONTEND": "noninteractive"})
        why = "" if r.ok and not re.search(r"^(W|E): ", r.out + r.err, re.M) else "套件庫無法連線"
    if not why:
        ctx.say("  ✓ 可以連線套件庫")
    else:
        ctx.say("  ! 無法使用套件庫：%s" % why)
        ctx.say("    需要安裝套件的項目（如 aide、auditd、rsyslog）會標示為需人工處理，其他項目不受影響；"
                "建議先排除後再開始修復")
    ctx.log_event("setup", "檢查套件庫", (why + "；" if why else "") + r.text()[-300:], "失敗" if why else "成功")
    return not why


def write_config(ctx, path, values):
    text = read_text(path) or "[general]\n"
    for k, v in values.items():
        text = te.set_kv(text, k, v)
    write_text_atomic(path, text, mode=0o644)
    ctx.log_event("setup", "寫入設定檔", "%s：%s" % (path, "、".join("%s=%s" % kv for kv in values.items())), "成功")


def cmd_setup(ctx, config_path, args):
    ctx.say("============ GCB 檢測工具 設定精靈 ============")
    ctx.say("作業系統：%s（%s）" % (ctx.osi.pretty, ctx.osi.gcb_doc))
    ctx.say("\n提醒：修改系統前請先在 VM 管理平台建立快照。設定精靈只會建立/設定測試帳號，不會修改 GCB 項目。")

    user = choose_user(ctx, args.user)
    if not user:
        ctx.say("\n無法設定測試帳號，設定中止。")
        return 1
    services = choose_services(ctx, None if args.services is None else
                               [s.strip() for s in args.services.split(",") if s.strip()])
    repo = check_repo(ctx)

    ctx.say("\n【4/4】寫入 config.ini")
    write_config(ctx, config_path, {"test_user": user, "critical_services": ",".join(services)})
    ctx.say("  test_user = %s" % user)
    ctx.say("  critical_services = %s" % (",".join(services) or "（無）"))

    ctx.cfg.test_user = user
    ctx.cfg.critical_services = services
    items = engine.do_health(ctx, "設定完成後的健康檢查")
    bad = [i for i in items if i["id"] in engine.LOGIN_CHECKS and i["status"] != "通過"]
    ctx.save()

    ctx.say("\n============ 設定結果 ============")
    ctx.say("測試帳號：%s　業務服務：%s　套件庫：%s" % (
        user, ",".join(services) or "無", "可連線" if repo else "無法連線"))
    if bad:
        ctx.say("✗ 登入相關檢查未通過：%s" % "、".join("%s %s" % (i["id"], i["name"]) for i in bad))
        ctx.say("  請依畫面上的「原因／建議」排除後，重新執行 sudo ./setup.sh")
        return 1
    ctx.say("✓ 設定完成，可以開始測試。")
    ctx.say("\n下一步（請先確認已建立 VM 快照）：")
    ctx.say("  1. 從你的電腦另開視窗，確認可以登入：ssh %s@%s，再執行 sudo -v" % (user, ctx.state["ip"]))
    ctx.say("  2. sudo ./gcb.sh check                       # 產出不合格清單")
    ctx.say("  3. sudo ./gcb.sh run --dry-run --include-risky  # 預覽修改內容（不會修改系統）")
    ctx.say("  4. sudo ./gcb.sh run                         # 修復 A 類")
    return 0
