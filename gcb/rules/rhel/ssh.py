# -*- coding: utf-8 -*-
"""RHEL 8 / 9 SSH 設定（RHEL 8 0262–0292；RHEL 9 0254–0284、0315）。

sshd 參數一律以 sshd 實際生效值判定（sshd -T）。RHEL 8 的 sshd.service 會把
crypto-policies 的 $CRYPTO_POLICY 帶入命令列，所以先依 unit 的 EnvironmentFile /
ExecStart 組出相同參數再執行 sshd -T，才看得到實際的 Ciphers/MACs/KexAlgorithms。
"""
import glob
import grp
import os
import pwd
import re
import time
import shlex

from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from .. import common
from ..common import ServiceEnabled, SshdOption
from ..generic import FilePerm, compare, installed
from .helpers import R

SSH = "SSH 設定"
SSHD_MAIN = "/etc/ssh/sshd_config"
SYSCONFIG = "/etc/sysconfig/sshd"
CP_DIR = "/etc/crypto-policies"
CP_BACKEND = CP_DIR + "/back-ends/opensshserver.config"
CP_MODULE = "GCB-SSH"
CP_PMOD = CP_DIR + "/policies/modules/%s.pmod" % CP_MODULE
CP_TRACK = [CP_DIR + "/config", CP_BACKEND, CP_DIR + "/back-ends/openssh.config"]
CRYPTO_RX = re.compile(r"^\s*CRYPTO_POLICY\s*=")

# GCB 允許的演算法（0271 / 0263 修改方法列出的三組清單）
GCB_ALGOS = [
    ("Ciphers", "ciphers", ["aes128-ctr", "aes192-ctr", "aes256-ctr"]),
    ("MACs", "macs", ["hmac-sha2-512", "hmac-sha2-256"]),
    ("KexAlgorithms", "kexalgorithms",
     ["ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
      "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512"]),
]

# crypto-policies 子原則：只限定 @SSH（openssh、libssh），其他程式仍用全系統原則
# 內容必須是純 ASCII：RHEL 8 的 update-crypto-policies 以 C locale 讀檔，非 ASCII 會讀取失敗
PMOD_TEXT = """# gcb-checker: GCB SSH algorithms (RHEL 8 0271 / RHEL 9 0263), SSH scope only
cipher@SSH = AES-256-CTR AES-192-CTR AES-128-CTR
mac@SSH = HMAC-SHA2-512 HMAC-SHA2-256
key_exchange@SSH = ECDHE DHE
group@SSH = -X25519
hash@SSH = -SHA1
"""
# 排除 *-etm MAC 的寫法依 crypto-policies 版本不同，依序嘗試
PMOD_ETM = ["ssh_etm = 0", "etm@SSH = DISABLE_ETM"]

# RHEL 9：在 crypto-policies Include 之前出現即會覆寫全系統原則的參數
CRYPTO_KEYS = ("ciphers", "macs", "kexalgorithms", "gssapikexalgorithms", "hostkeyalgorithms",
               "pubkeyacceptedalgorithms", "pubkeyacceptedkeytypes", "casignaturealgorithms")

UNIT = "sshd.service"
UNIT_DIRS = ["/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]
UNIT_DEFAULT = {
    "rhel8": (["-" + CP_BACKEND, "-" + SYSCONFIG], "/usr/sbin/sshd -D $OPTIONS $CRYPTO_POLICY"),
    "rhel9": (["-" + SYSCONFIG], "/usr/sbin/sshd -D $OPTIONS"),
}

LOCAL_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs", "jfs", "reiserfs", "f2fs", "vfat", "overlay")

HOSTKEY_PRIV = ["/etc/ssh/ssh_host_*_key", "/etc/ssh/*/ssh_host_*_key"]
HOSTKEY_PUB = ["/etc/ssh/ssh_host_*_key.pub", "/etc/ssh/*/ssh_host_*_key.pub"]

SSHD_INSTALLED = installed("openssh-server")

LOGIN_TEST_NOTE = "修復後工具的健康檢查會實際測試 SSH 登入，失敗會自動回滾；請保留目前的連線，另開新連線確認可登入。"


# ====================================================================
# sshd.service 啟動參數（RHEL 8 的 $CRYPTO_POLICY）
# ====================================================================

def _shsplit(text):
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _unit_lines(text):
    """unit 檔的有效行（處理行尾 \\ 續行）。"""
    out, buf = [], ""
    for line in (text or "").splitlines():
        s = line.strip()
        if not buf and (not s or s[0] in "#;"):
            continue
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        out.append(buf + s)
        buf = ""
    if buf:
        out.append(buf)
    return out


def parse_service(files):
    """解析 [(path, text)]（主 unit 在前、drop-in 依序在後），回傳 Environment、EnvironmentFile、ExecStart。"""
    env, env_files, exec_start = [], [], None
    for path, text in files:
        section = None
        for line in _unit_lines(text):
            if line.startswith("["):
                section = line
                continue
            if section != "[Service]" or "=" not in line:
                continue
            k, v = [x.strip() for x in line.split("=", 1)]
            if k == "Environment":
                if not v:
                    env = []
                for a in _shsplit(v):
                    if "=" in a:
                        env.append((path,) + tuple(a.split("=", 1)))
            elif k == "EnvironmentFile":
                env_files = [] if not v else env_files + [(path, v)]
            elif k == "ExecStart":
                exec_start = v or None
    return env, env_files, exec_start


def parse_env_file(text):
    """systemd EnvironmentFile：KEY=VALUE，值可加引號。"""
    out = {}
    for line in _unit_lines(text):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if not re.match(r"^[A-Za-z_]\w*$", k):
            continue
        out[k] = " ".join(_shsplit(v)) if v else ""
    return out


def expand_exec(exec_start, env):
    """依 systemd 規則展開 ExecStart 的變數，回傳傳給 sshd 的參數（去掉 -D）。"""
    toks = _shsplit(exec_start or "")
    args = []
    for t in toks[1:]:
        m = re.match(r"^\$(\w+)$", t)
        if m:  # $VAR：依空白拆成多個參數
            args += env.get(m.group(1), "").split()
            continue
        m = re.match(r"^\$\{(\w+)\}$", t)
        if m:  # ${VAR}：單一參數
            if env.get(m.group(1)):
                args.append(env[m.group(1)])
            continue
        t = re.sub(r"\$\{(\w+)\}|\$(\w+)", lambda x: env.get(x.group(1) or x.group(2), ""), t)
        if t:
            args.append(t)
    return [a for a in args if a != "-D"]


class ServiceInfo(object):
    def __init__(self, osi_key):
        files = self._files()
        if files:
            env_list, env_files, exec_start = parse_service([(f, read_text(f) or "") for f in files])
        else:  # 找不到 unit 檔時使用套件預設值
            names, exec_start = UNIT_DEFAULT.get(osi_key, UNIT_DEFAULT["rhel9"])
            env_list, env_files = [], [("預設", n) for n in names]
        self.env_list = env_list
        self.env_files = env_files
        self.exec_start = exec_start
        env = dict((k, v) for _, k, v in env_list)
        self.file_env = []
        for src, f in env_files:  # EnvironmentFile 覆寫 Environment=，後面的檔案覆寫前面的
            path = f.lstrip("-")
            text = read_text(path)
            if text is None:
                continue
            vals = parse_env_file(text)
            self.file_env.append((path, vals))
            env.update(vals)
        self.env = env
        self.args = expand_exec(exec_start, env)

    @staticmethod
    def _files():
        main = None
        for d in UNIT_DIRS:
            p = os.path.join(d, UNIT)
            if os.path.isfile(p):
                main = p
                break
        drop = {}
        for d in reversed(UNIT_DIRS):  # 同名 drop-in 以 /etc 優先
            for f in glob.glob(os.path.join(d, UNIT + ".d", "*.conf")):
                drop[os.path.basename(f)] = f
        return ([main] if main else []) + [drop[k] for k in sorted(drop)]


def sshd_values(ctx):
    """回傳 (sshd -T 結果 dict, 錯誤 Check)；兩者其一為 None。"""
    sshd = which("sshd")
    if not sshd:
        return None, Check(NA, "未安裝 SSH 伺服器，沒有 SSH 設定需要檢查")
    args = ServiceInfo(ctx.osi.key).args
    r = run([sshd, "-T"] + args, timeout=30)
    if not r.ok:
        return None, Check(ERROR, "sshd -T 執行失敗：" + r.text()[-200:])
    return te.parse_sshd_T(r.out), None


def apply_sshd(ctx, fx, restart=False):
    """sshd -t 驗證（含 unit 帶入的參數）後才 reload / restart。"""
    sshd = which("sshd") or "/usr/sbin/sshd"
    r = fx.run([sshd, "-t"] + ServiceInfo(ctx.osi.key).args, "檢查 sshd 設定語法", check=False)
    if r is not None and not r.ok:
        raise FixError("sshd 設定語法錯誤，不重新載入服務：" + r.text()[-200:])
    if restart:
        fx.run(["systemctl", "restart", ctx.osi.ssh_unit], "重新啟動 SSH 服務")
    else:
        fx.run(["systemctl", "reload", ctx.osi.ssh_unit], "重新載入 SSH 服務")


def undo_sshd(ctx, fx, restart=False):
    act = "restart" if restart else "reload"
    fx.add_undo(["systemctl", act, ctx.osi.ssh_unit], "重新%s SSH 服務" % ("啟動" if restart else "載入"))


# ====================================================================
# sshd_config 解析（含 Include）
# ====================================================================

def config_lines(path=SSHD_MAIN, in_match=False, depth=0):
    """展開 Include 後的有效設定 [(檔案, 關鍵字小寫, 值, 是否全域)]，順序即 sshd 讀取順序。"""
    out = []
    text = read_text(path)
    if text is None or depth > 8:
        return out
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            in_match = val.lower() != "all"
        out.append((path, key, val, not in_match))
        if key == "include":
            for pat in val.split():
                p = pat if pat.startswith("/") else "/etc/ssh/" + pat
                for f in sorted(glob.glob(p)):
                    out += config_lines(f, in_match, depth + 1)
    return out


def first_global(lines, key):
    """sshd 以第一個出現的全域值為準。"""
    for f, k, v, g in lines:
        if g and k == key:
            return f, v
    return None


def comment_bad(text, opt, ok):
    """註解 drop-in 中全域區段、值不合格的 opt 設定。"""
    rx = re.compile(r"^\s*" + re.escape(opt) + r"\s+(.*?)\s*$", re.I)
    out, in_match = [], False
    for line in text.splitlines():
        active = line.strip() and not line.strip().startswith("#")
        if active and re.match(r"^\s*Match\s", line, re.I):
            in_match = True
        m = rx.match(line) if active and not in_match else None
        out.append(te.MARK + line if m and not ok(m.group(1)) else line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _dropins():
    files = []
    for pat in te.sshd_includes(read_text(SSHD_MAIN) or ""):
        files += [f for f in sorted(glob.glob(pat)) if not f.startswith(CP_DIR + "/")]
    return files


def set_sshd_options(ctx, fx, items, restart=False):
    """items：[(參數, 寫入值, 判定函式)]。寫入主檔全域區段、註解 drop-in 衝突設定，驗證後 reload。"""
    undo_sshd(ctx, fx, restart)
    for opt, value, ok in items:
        fx.edit_file(SSHD_MAIN, lambda t, o=opt, v=value: te.sshd_set_option(t, o, v))
        for f in _dropins():  # drop-in 先於主檔生效，衝突設定一併註解
            fx.edit_file(f, lambda t, o=opt, k=ok: comment_bad(t, o, k))
    apply_sshd(ctx, fx, restart)


# ====================================================================
# 判定方式
# ====================================================================

def startups_ok(value, target="10:30:60"):
    """MaxStartups start:rate:full 是否不比 GCB 值寬鬆。

    start、full 越小越嚴格（不大於 GCB 值）；rate 是超過 start 後拒絕新連線的機率（%），越大越嚴格（不小於 GCB 值）。
    """
    try:
        cur = [int(x) for x in str(value).split(":")]
        lim = [int(x) for x in target.split(":")]
    except ValueError:
        return False
    if len(cur) == 1:  # 單一數字等同 n:100:n
        cur = [cur[0], 100, cur[0]]
    if len(cur) != 3 or cur[0] <= 0:
        return False
    return cur[0] <= lim[0] and lim[1] <= cur[1] <= 100 and cur[2] <= lim[2]


def value_ok(value, cmp, target):
    if value is None:
        return False
    if cmp == "startups":
        return startups_ok(value, target)
    return compare(value, cmp, target)


def crypto_violations(vals):
    """回傳 [(參數, 不在 GCB 清單的演算法)]；未取得的參數視為不合格。"""
    bad = []
    for name, key, allowed in GCB_ALGOS:
        cur = [a.strip() for a in vals.get(key, [""])[0].split(",") if a.strip()]
        extra = [a for a in cur if a not in allowed]
        if not cur:
            bad.append((name, ["（未取得）"]))
        elif extra:
            bad.append((name, extra))
    return bad


def _ssh_login_precondition(ctx):
    if ctx.pre_health_status.get("H04") != "通過":
        return "前測未確認 SSH 實際登入可用，修復後無法驗證連線，為避免鎖定而略過"
    return None


# ====================================================================
# 規則類別
# ====================================================================

# [SshdService] RHEL8 0262 / RHEL9 0254 sshd 守護程序
class SshdService(ServiceEnabled):
    risk = "B"

    def __init__(self, ids):
        ServiceEnabled.__init__(self, "sshd 守護程序", SSH, UNIT, {"rhel": "openssh-server"}, ids)
        self.expected = "啟用"


# [SshdParam] RHEL8 0272–0289 / RHEL9 0264–0281、0315 sshd 參數（比較方式 eq/in/range/startups）
class SshdParam(SshdOption):
    """opts：[(參數, 修復寫入值, 比較方式, 目標)]；多個參數同一次修復只 reload 一次。"""

    def __init__(self, title, ids, opts, expected, hint="", precondition=None):
        self.title = title
        self.ids = ids
        self.opts = opts
        self.expected = expected
        self.manual_hint = hint
        self.when = SSHD_INSTALLED
        self._pre = precondition
        self.opt, self.value = opts[0][0], opts[0][1]

    def _state(self, vals):
        out = []
        for opt, value, cmp, target in self.opts:
            cur = vals.get(opt.lower(), [None])[0]
            out.append((opt, value, cmp, target, cur, value_ok(cur, cmp, target)))
        return out

    def check(self, ctx):
        vals, err = sshd_values(ctx)
        if err:
            return err
        st = self._state(vals)
        cur = "；".join("%s %s" % (o, c if c is not None else "未設定") for o, _, _, _, c, _ in st)
        return Check(PASS if all(s[5] for s in st) else FAIL, cur)

    def precondition(self, ctx):
        return self._pre(ctx) if self._pre else None

    def fix(self, ctx, fx):
        vals, err = sshd_values(ctx)
        if err:
            raise FixError(err.current)
        items = [(o, v, (lambda x, c=c, t=t: value_ok(x, c, t)))
                 for o, v, c, t, _, ok in self._state(vals) if not ok]
        if self.manual_hint:
            fx.note(self.manual_hint)
        set_sshd_options(ctx, fx, items)


def sshd_param(title, ids, opt, value, cmp="eq", target=None, expected=None, hint="", precondition=None):
    return SshdParam(title, ids, [(opt, value, cmp, value if target is None else target)],
                     expected or value, hint, precondition)


# [SshProtocol] RHEL8 0263 / RHEL9 0255 SSH 協定版本
class SshProtocol(Rule):
    ids = R(r8=263, r9=255)
    title = "SSH 協定版本"
    category = SSH
    expected = "Protocol 2"
    when = staticmethod(SSHD_INSTALLED)

    @staticmethod
    def version():
        r = run(["rpm", "-q", "--qf", "%{VERSION}", "openssh-server"], timeout=30)
        m = re.match(r"^(\d+)\.(\d+)", r.out.strip()) if r.ok else None
        if not m:
            r = run(["ssh", "-V"], timeout=30)
            m = re.search(r"OpenSSH_(\d+)\.(\d+)", r.text())
        return (int(m.group(1)), int(m.group(2))) if m else None

    def check(self, ctx):
        ver = self.version()
        lit = first_global(config_lines(), "protocol")
        cfg = "設定檔 Protocol %s" % lit[1] if lit else "設定檔未設定 Protocol"
        if ver is None:
            return Check(ERROR, "無法取得 OpenSSH 版本")
        if ver >= (7, 4):  # OpenSSH 7.4 起已移除 SSH-1，Protocol 參數不再有作用
            return Check(PASS, "OpenSSH %d.%d 只支援 SSH-2（Protocol 參數自 7.4 起已移除）；%s" % (ver + (cfg,)))
        return Check(PASS if lit and lit[1] == "2" else FAIL, "OpenSSH %d.%d；%s" % (ver + (cfg,)))

    def fix(self, ctx, fx):
        set_sshd_options(ctx, fx, [("Protocol", "2", lambda v: v.strip() == "2")])


# [SshAccessLimit] RHEL8 0266 / RHEL9 0258 限制存取 SSH（C 類）
class SshAccessLimit(Rule):
    ids = R(r8=266, r9=258)
    title = "限制存取 SSH"
    category = SSH
    risk = "C"
    expected = "啟用"
    when = staticmethod(SSHD_INSTALLED)
    OPTS = ("AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups")
    manual_hint = ("允許／拒絕清單需由單位提供：請在 /etc/ssh/sshd_config 全域區段（第一個 Match 之前）設定 "
                   "AllowUsers 或 AllowGroups（或 DenyUsers／DenyGroups），務必包含維運帳號與 config.ini 的 test_user；"
                   "AllowUsers 與 AllowGroups 同時設定時兩者都須符合。保留一個已登入的連線，sshd -t 通過後 "
                   "systemctl reload sshd，再以新連線確認可登入。")

    def check(self, ctx):
        vals, err = sshd_values(ctx)
        if err:
            return err
        found = ["%s %s" % (o, " ".join(vals[o.lower()])) for o in self.OPTS if any(vals.get(o.lower(), []))]
        if found:
            return Check(PASS, "；".join(found))
        return Check(FAIL, "未設定 AllowUsers／AllowGroups／DenyUsers／DenyGroups")


# [SshCompression] RHEL8 0287 / RHEL9 0279 SSH Compression 參數（C 類）
class SshCompression(Rule):
    """依決策紀錄：照字面只認 no、delayed，預設值不合格且不自動修改。

    sshd -T 會把 delayed 顯示為 yes，所以 yes 時再看設定檔第一個生效的字面值。
    """
    ids = R(r8=287, r9=279)
    title = "SSH Compression 參數"
    category = SSH
    risk = "C"
    expected = "delayed 或 no"
    when = staticmethod(SSHD_INSTALLED)
    NOTE = "OpenSSH 7.4 起已移除驗證前壓縮，delayed 與 yes 行為相同，實質已符合 GCB 目的，但字面不符"
    manual_hint = ("照 GCB 字面只接受 Compression no 或 delayed。" + NOTE + "，由人工判斷是否修改。"
                   "如需字面符合，請在 /etc/ssh/sshd_config 全域區段設定 Compression no（RHEL 9 另需註解 "
                   "/etc/ssh/sshd_config.d/ 中的 Compression 設定），sshd -t 通過後 systemctl reload sshd。")

    def check(self, ctx):
        vals, err = sshd_values(ctx)
        if err:
            return err
        eff = vals.get("compression", ["yes"])[0].lower()
        if eff == "no":
            return Check(PASS, "Compression no")
        lit = first_global(config_lines(), "compression")
        if lit and lit[1].lower() == "delayed":
            return Check(PASS, "Compression delayed（%s；sshd -T 顯示 %s）" % (lit[0], eff))
        cur = "Compression %s（%s）" % (lit[1], lit[0]) if lit else "Compression 未設定（預設 %s）" % eff
        return Check(FAIL, "%s；%s" % (cur, self.NOTE))


# [HostKeyOwnerR9] RHEL9 0259 SSH 主機私鑰檔案所有權
class HostKeyOwnerR9(FilePerm):
    """依決策紀錄照字面要求 root:ssh_keys；root:root 判不合格但備註說明。"""

    def check(self, ctx):
        c = FilePerm.check(self, ctx)
        if c.status == FAIL and "群組 root" in c.current:
            c.current += "（root:root 權限比 root:ssh_keys 更嚴格、不影響連線，但不符 GCB 字面 root:ssh_keys）"
        return c

    def fix(self, ctx, fx):
        try:
            grp.getgrnam("ssh_keys")
        except KeyError:
            raise ManualRequired("系統沒有 ssh_keys 群組，無法設定為 root:ssh_keys；root:root 權限更嚴格，可維持現狀並註記")
        FilePerm.fix(self, ctx, fx)


def _local_mounts():
    starts = ["/"]
    for line in (read_text("/proc/mounts") or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in LOCAL_FS:
            mnt = parts[1].replace("\\040", " ")
            if mnt not in starts and not mnt.startswith(("/proc", "/sys", "/dev", "/run")):
                starts.append(mnt)
    return starts


_FIND_CACHE = {}


def find_files(pattern, timeout=300):
    """在本機檔案系統（各掛載點 -xdev）尋找檔名，回傳 (路徑清單, 是否逾時)；結果快取 2 分鐘。"""
    c = _FIND_CACHE.get(pattern)
    if c and time.time() - c[0] < 120:
        return c[1]
    r = run(["find"] + _local_mounts() + ["-xdev", "-type", "f", "-name", pattern, "-print"], timeout=timeout)
    res = (sorted(set(l for l in r.out.splitlines() if l.strip())), r.rc == 124)
    _FIND_CACHE[pattern] = (time.time(), res)
    return res


# [ShostsEquiv] RHEL8 0290 / RHEL9 0282 shosts.equiv 檔案
class ShostsEquiv(Rule):
    ids = R(r8=290, r9=282)
    title = "shosts.equiv 檔案"
    category = SSH
    expected = "移除"
    when = staticmethod(SSHD_INSTALLED)
    KNOWN = ["/etc/ssh/shosts.equiv", "/etc/shosts.equiv"]

    def _found(self):
        found, timed_out = find_files("shosts.equiv")
        found = sorted(set(found + [p for p in self.KNOWN if os.path.isfile(p)]))
        return found, timed_out

    def check(self, ctx):
        found, timed_out = self._found()
        note = "（全系統掃描逾時，僅涵蓋已掃描部分）" if timed_out else ""
        if found:
            return Check(FAIL, "找到：" + "、".join(found[:10]) + note)
        return Check(PASS, "未找到 shosts.equiv" + note)

    def fix(self, ctx, fx):
        # 先備份（回滾時還原，含擁有者與權限）再刪除，等同移到備份區
        for p in self._found()[0]:
            fx.backup_only(p)
            fx.run(["rm", "-f", "--", p], "移除 %s（已備份）" % p)
        _FIND_CACHE.clear()  # 檔案已變動，修復後的重新檢測要重新搜尋


# [UserShosts] RHEL8 0291 / RHEL9 0283 .shosts 檔案（C 類，只回報）
class UserShosts(Rule):
    ids = R(r8=291, r9=283)
    title = ".shosts 檔案"
    category = SSH
    risk = "C"
    expected = "移除"
    when = staticmethod(SSHD_INSTALLED)
    manual_hint = ("依決策紀錄只回報、不移動或刪除使用者檔案。hostbased 驗證已停用（HostbasedAuthentication no、"
                   "IgnoreRhosts yes）時此檔不會被使用；請與檔案擁有者確認後人工移除（建議先備份）。")

    def check(self, ctx):
        found, timed_out = find_files("*.shosts")
        found = list(found)  # 複製一份，避免改到 find_files 的快取
        for pw in pwd.getpwall():
            p = os.path.join(pw.pw_dir or "/", ".shosts")
            try:
                if os.path.isfile(p):
                    found.append(p)
            except OSError:
                pass
        found = sorted(set(found))
        note = "（全系統掃描逾時，僅涵蓋已掃描部分）" if timed_out else ""
        if not found:
            return Check(PASS, "未找到 .shosts 檔案" + note)
        show = []
        for p in found[:10]:
            try:
                show.append("%s（%s）" % (p, pwd.getpwuid(os.stat(p).st_uid).pw_name))
            except (OSError, KeyError):
                show.append(p)
        more = "…另 %d 個" % (len(found) - 10) if len(found) > 10 else ""
        return Check(FAIL, "找到：" + "、".join(show) + more + note)


# ---------- 加密演算法 / 全系統加密原則 ----------

def crypto_overrides(ctx):
    """回傳 (/etc/sysconfig/sshd 的 CRYPTO_POLICY 行, 需人工處理的覆寫說明)。"""
    sysconf = [l.strip() for l in (read_text(SYSCONFIG) or "").splitlines() if CRYPTO_RX.match(l)]
    manual = []
    svc = ServiceInfo(ctx.osi.key)
    for src, k, _ in svc.env_list:
        if k == "CRYPTO_POLICY":
            manual.append("%s 以 Environment= 設定 CRYPTO_POLICY" % src)
    for path, vals in svc.file_env:
        if "CRYPTO_POLICY" in vals and path not in (CP_BACKEND, SYSCONFIG):
            manual.append("%s 設定 CRYPTO_POLICY" % path)
    if ctx.osi.key == "rhel8":
        if svc.exec_start and "CRYPTO_POLICY" not in svc.exec_start:
            manual.append("sshd.service 的 ExecStart 未帶入 $CRYPTO_POLICY")
    else:
        lines = config_lines()
        idx = None
        for i, (f, k, v, g) in enumerate(lines):
            if g and k == "include" and any(CP_BACKEND in glob.glob(p) or p == CP_BACKEND for p in v.split()):
                idx = i
                break
        if idx is None:
            manual.append("sshd 設定未 Include %s（50-redhat.conf 的 Include 可能被移除或註解，"
                          "可用 rpm -V openssh-server 比對）" % CP_BACKEND)
        else:
            for f, k, v, g in lines[:idx]:
                if g and k in CRYPTO_KEYS:
                    manual.append("%s 在 crypto-policies 之前設定 %s %s" % (f, k, v[:60]))
    return sysconf, manual


def comment_crypto_policy(text):
    return "\n".join(te.MARK + l if CRYPTO_RX.match(l) else l for l in text.splitlines()) + \
        ("\n" if text.endswith("\n") else "")


def _fmt_bad(bad):
    return "；".join("%s 含 %s" % (n, ",".join(a)) for n, a in bad)


def apply_gcb_policy(ctx, fx):
    """以 crypto-policies 子原則（目前原則:GCB-SSH）把 SSH 演算法限縮為 GCB 清單，並驗證結果。"""
    if ctx.osi.key == "rhel8" and ctx.osi.version_tuple() < (8, 2):
        raise ManualRequired("RHEL 8.0／8.1 的 crypto-policies 不支援子原則，無法在不覆寫全系統原則下限縮 SSH 演算法，"
                             "請升級至 8.2 以上或人工評估")
    ucp = which("update-crypto-policies")
    if not ucp:
        fx.pkg_install("crypto-policies-scripts")
        ucp = which("update-crypto-policies") or "update-crypto-policies"
    r = run([ucp, "--show"], timeout=60)
    cur = r.out.strip().splitlines()[-1].strip() if r.ok and r.out.strip() else ""
    if not cur:
        if not fx.dry:
            raise FixError("無法取得目前的全系統加密原則：" + r.text()[-200:])
        cur = "DEFAULT"
    parts = cur.split(":")
    new = ":".join(parts if CP_MODULE in parts else parts + [CP_MODULE])
    # update-crypto-policies 會改寫 config、state、back-ends：回滾時以原原則重新產生（先登記，最後執行）
    for p in CP_TRACK[:1] + [CP_DIR + "/state/current"]:
        fx.backup_only(p)
    fx.add_undo([ucp, "--set", cur], "還原全系統加密原則 %s" % cur)
    last = ""
    for etm in PMOD_ETM:
        fx.write_file(CP_PMOD, PMOD_TEXT + etm + "\n")
        r = fx.run_tracked([ucp, "--set", new], "套用加密原則 %s（原 %s）" % (new, cur), CP_TRACK,
                           timeout=300, check=False)
        if r is None:  # 預覽
            return
        if not r.ok:
            last = r.text()[-300:]
            continue
        vals, err = sshd_values(ctx)
        bad = crypto_violations(vals) if vals is not None else None
        if vals is not None and not bad:
            fx.note("全系統加密原則改為 %s（原 %s），只限定 SSH 範圍，其他程式不受影響" % (new, cur))
            return
        last = "套用後仍不符 GCB 清單：" + _fmt_bad(bad) if bad else err.current
    raise FixError("crypto-policies 子原則無法達成 GCB 演算法清單（%s），請人工處理" % last)


CRYPTO_NOTE = ("加密演算法限縮為 GCB 清單後，chacha20-poly1305、AES-GCM、curve25519 與 *-etm MAC 將不可用，"
               "GSSAPI 金鑰交換（GSSAPIKeyExchange）也會停用（GSSAPI 驗證不受影響）；不支援 CTR／HMAC-SHA2／ECDH 的舊用戶端、網路設備或程式庫（舊版 Java、Paramiko）將無法連線。" + LOGIN_TEST_NOTE)


# [SshCrypto] RHEL8 0271 / RHEL9 0263 SSH 加密演算法
class SshCrypto(Rule):
    """依決策紀錄以 crypto-policies 子原則（只限定 @SSH）修復，同時符合 0292／0284 不覆寫全系統原則。"""
    ids = R(r8=271, r9=263)
    title = "SSH 加密演算法"
    category = SSH
    risk = "B"
    expected = "aes128-ctr,aes192-ctr,aes256-ctr（並檢查 GCB 列出的 MACs、KexAlgorithms）"
    when = staticmethod(SSHD_INSTALLED)
    manual_hint = CRYPTO_NOTE

    def check(self, ctx):
        vals, err = sshd_values(ctx)
        if err:
            return err
        bad = crypto_violations(vals)
        if bad:
            return Check(FAIL, "不在 GCB 清單：" + _fmt_bad(bad))
        return Check(PASS, "；".join("%s %s" % (n, vals[k][0]) for n, k, _ in GCB_ALGOS))

    def precondition(self, ctx):
        return _ssh_login_precondition(ctx)

    def fix(self, ctx, fx):
        sysconf, manual = crypto_overrides(ctx)
        if manual:
            raise ManualRequired("sshd 的加密設定被覆寫，crypto-policies 子原則無法生效，請先人工處理：" + "；".join(manual))
        restart = ctx.osi.key == "rhel8" or bool(sysconf)  # RHEL 8 的 $CRYPTO_POLICY 只在 restart 時重新讀取
        undo_sshd(ctx, fx, restart)
        if sysconf:
            fx.edit_file(SYSCONFIG, comment_crypto_policy)
            fx.note("已註解 %s 的 CRYPTO_POLICY（覆寫全系統原則，子原則才會生效；同時符合 0292／0284）" % SYSCONFIG)
        apply_gcb_policy(ctx, fx)
        apply_sshd(ctx, fx, restart)
        fx.note(CRYPTO_NOTE)


# [CryptoNoOverride] RHEL8 0292 / RHEL9 0284 覆寫全系統加密原則
class CryptoNoOverride(Rule):
    ids = R(r8=292, r9=284)
    title = "覆寫全系統加密原則"
    category = SSH
    risk = "B"
    expected = "停用"
    when = staticmethod(SSHD_INSTALLED)
    manual_hint = ("取消覆寫後 SSH 改用全系統加密原則；若因此不符 SSH 加密演算法（RHEL 8 0271／RHEL 9 0263），"
                   "修復時會一併套用 GCB-SSH 子原則。" + LOGIN_TEST_NOTE)

    def check(self, ctx):
        sysconf, manual = crypto_overrides(ctx)
        issues = ["%s：%s" % (SYSCONFIG, l[:80]) for l in sysconf] + manual
        if issues:
            return Check(FAIL, "；".join(issues))
        cur = "%s 未設定 CRYPTO_POLICY" % SYSCONFIG
        if ctx.osi.key == "rhel9":
            cur += "；sshd 已載入 crypto-policies 設定且未被覆寫"
        return Check(PASS, cur)

    def precondition(self, ctx):
        return _ssh_login_precondition(ctx)

    def fix(self, ctx, fx):
        sysconf, manual = crypto_overrides(ctx)
        if not sysconf:
            raise ManualRequired("請人工處理：" + "；".join(manual))
        restart = ctx.osi.key == "rhel8"
        undo_sshd(ctx, fx, restart)
        fx.edit_file(SYSCONFIG, comment_crypto_policy)  # 等同 GCB 的 sed（修正 PDF 斷行的 ". *"）
        if manual:
            fx.partial = True
            fx.note("其餘覆寫需人工處理：" + "；".join(manual))
        elif fx.dry:
            fx.note("預覽：取消覆寫後若 SSH 演算法不符 GCB 清單，會一併套用 %s 子原則" % CP_MODULE)
        else:
            vals, err = sshd_values(ctx)
            if err or crypto_violations(vals):
                # 避免取消覆寫後 0271／0263 變成不合格：同時套用 GCB-SSH 子原則
                apply_gcb_policy(ctx, fx)
                fx.note(CRYPTO_NOTE)
        apply_sshd(ctx, fx, restart)


def _gssapi_precondition(ctx):
    if os.path.exists("/etc/krb5.keytab"):
        return "主機有 /etc/krb5.keytab（可能加入 IdM／AD 網域），停用 GSSAPI 會使 Kerberos 票證登入失效，請人工確認"
    return None


# ====================================================================
# 規則清單
# ====================================================================

RULES = [
    # RHEL8 0262 / RHEL9 0254 sshd 守護程序
    SshdService(R(r8=262, r9=254)),
    # RHEL8 0263 / RHEL9 0255 SSH 協定版本（OpenSSH 7.4 起只支援 SSH-2，依版本判定）
    SshProtocol(),
    # RHEL8 0264 / RHEL9 0256 /etc/ssh/sshd_config 檔案所有權
    FilePerm("/etc/ssh/sshd_config 檔案所有權", SSH, R(r8=264, r9=256), SSHD_MAIN, owner="root",
             groups=["root"], expected="root:root", when=SSHD_INSTALLED),
    # RHEL8 0265 / RHEL9 0257 /etc/ssh/sshd_config 檔案權限
    FilePerm("/etc/ssh/sshd_config 檔案權限", SSH, R(r8=265, r9=257), SSHD_MAIN, max_mode=0o600,
             expected="600 或更低權限", when=SSHD_INSTALLED),
    # RHEL8 0266 / RHEL9 0258 限制存取 SSH（C 類）
    SshAccessLimit(),
    # RHEL8 0267 SSH 主機私鑰檔案所有權（root:root）
    FilePerm("SSH 主機私鑰檔案所有權", SSH, R(r8=267), HOSTKEY_PRIV, owner="root", groups=["root"],
             expected="root:root", when=SSHD_INSTALLED),
    # RHEL9 0259 SSH 主機私鑰檔案所有權（照字面 root:ssh_keys）
    HostKeyOwnerR9("SSH 主機私鑰檔案所有權", SSH, R(r9=259), HOSTKEY_PRIV, owner="root", groups=["ssh_keys"],
                   expected="root:ssh_keys", when=SSHD_INSTALLED),
    # RHEL8 0268 SSH 主機私鑰檔案權限（600）
    FilePerm("SSH 主機私鑰檔案權限", SSH, R(r8=268), HOSTKEY_PRIV, max_mode=0o600,
             expected="600 或更低權限", when=SSHD_INSTALLED),
    # RHEL9 0260 SSH 主機私鑰檔案權限（GCB 設定值 640；內文寫 600 為筆誤）
    FilePerm("SSH 主機私鑰檔案權限", SSH, R(r9=260), HOSTKEY_PRIV, max_mode=0o640,
             expected="640 或更低權限", when=SSHD_INSTALLED),
    # RHEL8 0269 / RHEL9 0261 SSH 主機公鑰檔案所有權
    FilePerm("SSH 主機公鑰檔案所有權", SSH, R(r8=269, r9=261), HOSTKEY_PUB, owner="root", groups=["root"],
             expected="root:root", when=SSHD_INSTALLED),
    # RHEL8 0270 / RHEL9 0262 SSH 主機公鑰檔案權限
    FilePerm("SSH 主機公鑰檔案權限", SSH, R(r8=270, r9=262), HOSTKEY_PUB, max_mode=0o644,
             expected="644 或更低權限", when=SSHD_INSTALLED),
    # RHEL8 0271 / RHEL9 0263 SSH 加密演算法（crypto-policies 子原則）
    SshCrypto(),
    # RHEL8 0272 / RHEL9 0264 SSH 日誌記錄等級
    sshd_param("SSH 日誌記錄等級", R(r8=272, r9=264), "LogLevel", "VERBOSE", "in", ["VERBOSE", "INFO"],
               expected="VERBOSE 或 INFO"),
    # RHEL8 0273 / RHEL9 0265 SSH X11Forwarding 功能
    sshd_param("SSH X11Forwarding 功能", R(r8=273, r9=265), "X11Forwarding", "no",
               hint="停用後需要遠端圖形介面（X11）的維運方式將失效。"),
    # RHEL8 0274 / RHEL9 0266 SSH MaxAuthTries 參數
    sshd_param("SSH MaxAuthTries 參數", R(r8=274, r9=266), "MaxAuthTries", "4", "range", (1, 4),
               expected="4 以下，但須大於 0",
               hint="ssh-agent 載入多把金鑰的用戶端可能在試到正確金鑰前就因「Too many authentication failures」"
                    "被斷線，請在用戶端以 IdentitiesOnly／IdentityFile 指定金鑰。" + LOGIN_TEST_NOTE,
               precondition=_ssh_login_precondition),
    # RHEL8 0275 / RHEL9 0267 SSH IgnoreRhosts 參數
    sshd_param("SSH IgnoreRhosts 參數", R(r8=275, r9=267), "IgnoreRhosts", "yes"),
    # RHEL8 0276 / RHEL9 0268 SSH HostbasedAuthentication 參數
    sshd_param("SSH HostbasedAuthentication 參數", R(r8=276, r9=268), "HostbasedAuthentication", "no"),
    # RHEL8 0277 / RHEL9 0269 SSH PermitRootLogin 參數 → common.py
    # RHEL8 0278 / RHEL9 0270 SSH PermitEmptyPasswords 參數
    sshd_param("SSH PermitEmptyPasswords 參數", R(r8=278, r9=270), "PermitEmptyPasswords", "no"),
    # RHEL8 0279 / RHEL9 0271 SSH PermitUserEnvironment 參數
    sshd_param("SSH PermitUserEnvironment 參數", R(r8=279, r9=271), "PermitUserEnvironment", "no"),
    # RHEL8 0280 / RHEL9 0272 SSH 逾時時間
    SshdParam("SSH 逾時時間", R(r8=280, r9=272),
              [("ClientAliveInterval", "600", "range", (1, 600)), ("ClientAliveCountMax", "1", "eq", "1")],
              "ClientAliveInterval 設為 600 以下，但須大於 0，且 ClientAliveCountMax 設為 1",
              "用戶端連續 600 秒未回應 keepalive 即中斷連線；仍在線但閒置的連線不受影響。"),
    # RHEL8 0281 / RHEL9 0273 SSH LoginGraceTime 參數
    sshd_param("SSH LoginGraceTime 參數", R(r8=281, r9=273), "LoginGraceTime", "60", "range", (1, 60),
               expected="60 以下，但須大於 0"),
    # RHEL8 0282 / RHEL9 0274 SSH UsePAM 參數
    sshd_param("SSH UsePAM 參數", R(r8=282, r9=274), "UsePAM", "yes", precondition=_ssh_login_precondition),
    # RHEL8 0283 / RHEL9 0275 SSH AllowTcpForwarding 參數
    sshd_param("SSH AllowTcpForwarding 參數", R(r8=283, r9=275), "AllowTcpForwarding", "no",
               hint="停用後 SSH 通道（ssh -L／-R／-D）、VS Code Remote-SSH、資料庫工具的 SSH tunnel 將失效，請先告知維運人員。"),
    # RHEL8 0284 / RHEL9 0276 SSH MaxStartups 參數（每欄不大於 10:30:60 即合格）
    sshd_param("SSH MaxStartups 參數", R(r8=284, r9=276), "MaxStartups", "10:30:60", "startups", "10:30:60"),
    # RHEL8 0285 / RHEL9 0277 SSH MaxSessions 參數
    sshd_param("SSH MaxSessions 參數", R(r8=285, r9=277), "MaxSessions", "4", "range", (1, 4),
               expected="4 以下，但須大於 0",
               hint="同一連線的工作階段上限降為 4，會影響 ControlMaster 多工連線（例如 Ansible 平行作業）。"),
    # RHEL8 0286 / RHEL9 0278 SSH StrictModes 參數
    sshd_param("SSH StrictModes 參數", R(r8=286, r9=278), "StrictModes", "yes",
               hint="家目錄或 ~/.ssh 權限過寬的使用者將無法以金鑰登入。", precondition=_ssh_login_precondition),
    # RHEL8 0287 / RHEL9 0279 SSH Compression 參數（C 類，照字面判定、不自動修改）
    SshCompression(),
    # RHEL8 0288 / RHEL9 0280 SSH IgnoreUserKnownHosts 參數
    sshd_param("SSH IgnoreUserKnownHosts 參數", R(r8=288, r9=280), "IgnoreUserKnownHosts", "yes"),
    # RHEL8 0289 / RHEL9 0281 SSH PrintLastLog 參數
    sshd_param("SSH PrintLastLog 參數", R(r8=289, r9=281), "PrintLastLog", "yes"),
    # RHEL8 0290 / RHEL9 0282 shosts.equiv 檔案
    ShostsEquiv(),
    # RHEL8 0291 / RHEL9 0283 .shosts 檔案（C 類，只回報）
    UserShosts(),
    # RHEL8 0292 / RHEL9 0284 覆寫全系統加密原則
    CryptoNoOverride(),
    # RHEL9 0315 停用 GSSAPI 驗證
    sshd_param("停用 GSSAPI 驗證", R(r9=315), "GSSAPIAuthentication", "no", expected="停用",
               hint="使用 Kerberos／IdM（FreeIPA、AD）單一登入的環境停用後將無法以票證登入。",
               precondition=_gssapi_precondition),
]


# 讓 common.SshdOption（PermitRootLogin）也以 sshd 實際啟動參數（含 RHEL 8 的 $CRYPTO_POLICY）檢測與驗證
def _rhel_sshd_args(ctx):
    return ServiceInfo(ctx.osi.key).args if ctx.osi.family == "rhel" else []


common.SSHD_ARGS_HOOK = _rhel_sshd_args
