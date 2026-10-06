# -*- coding: utf-8 -*-
"""Ubuntu 22.04 校時、防火牆、GNOME GUI（TWGCB-01-014-0194 ～ 0234）。

這段規則多為「多選一」，由下列函式判斷系統實際使用哪一套，其餘組回傳不適用：
  校時   time_choice()      Chrony 0194–0197 / systemd-timesyncd 0198–0200 / NTP 0201–0204
  防火牆 firewall_choice()  UFW 0205–0209 / Nftables 0210–0217 / Iptables 0218–0226
  GNOME  gnome_when()       0227–0234（未安裝 gdm3 或 gnome-shell 時不適用）

防火牆修復的安全措施（任何預設拒絕「進入」或啟用防火牆的修復都會）：
  1. 先備份目前規則集（nft list ruleset / iptables-save）並登記回滾時還原
  2. 先放行 sshd 使用的埠（sshd -T，可能多個）、迴路介面、已建立的連線
  3. 以 systemd-run 排程 5 分鐘後自動還原的保險；修復完成（成功或失敗）即取消，
     若程式因連線中斷被終止，保險會還原規則
  4. 修改後立即確認 SSH 埠放行規則存在，不存在就立刻還原並回報失敗
預設拒絕「外出」（outgoing/OUTPUT）會中斷 DNS、套件更新、校時等連線，只檢測不自動修復。
"""
import glob
import os
import re
import time

from ... import pkgsvc
from ... import textedit as te
from ...fixer import FixError, ManualRequired
from ...util import read_text, run, which, write_text_atomic
from ..base import ERROR, FAIL, NA, PASS, Check, Rule
from ..generic import PackagePresent, all_of
from .helpers import U

ON_STATES = ("enabled", "enabled-runtime")
ACTIVE_STATES = ("active", "activating", "reloading")


def _unq(v):
    return (v or "").strip().strip('"').strip("'")


def _svc_on(unit):
    """服務已啟用或運作中。"""
    en, act = pkgsvc.svc_state(unit)
    return en in ON_STATES or act in ACTIVE_STATES


def _svc_ok(unit):
    """回傳 (是否 enabled 且 active, 說明)。"""
    en, act = pkgsvc.svc_state(unit)
    return en in ON_STATES and act == "active", "%s=%s/%s" % (unit, en, act)


def _uptime_boot():
    try:
        return time.time() - float((read_text("/proc/uptime") or "0").split()[0])
    except (ValueError, IndexError):
        return 0


# ====================================================================
# 校時套件判斷（Chrony / systemd-timesyncd / NTP）
# ====================================================================

TIME_LABEL = {"chrony": "Chrony", "ntp": "NTP", "timesyncd": "systemd-timesyncd"}
TIME_PKGS = (("chrony", "chrony", "chrony.service"),
             ("ntp", "ntp", "ntp.service"),
             ("timesyncd", "systemd-timesyncd", "systemd-timesyncd.service"))


def choose_time(state):
    """依各套件狀態決定校時組別（純函式，方便測試）。

    state = {組別: (已安裝, 服務啟用或運作中)}；回傳 (組別, 判斷依據)。
    優先順序：
      1. 服務啟用或運作中者，依 chrony > ntp > systemd-timesyncd 擇一（同時多套時在依據註明衝突）
      2. 都沒有運作：已安裝 chrony 或 ntp 者（Ubuntu 安裝兩者會移除 timesyncd，代表管理者已選用）
      3. 都沒有：systemd-timesyncd（Ubuntu 預設），由 0198/0200 回報不合格，不自動改裝其他套件
    """
    order = ["chrony", "ntp", "timesyncd"]
    on = [g for g in order if state[g][0] and state[g][1]]
    if on:
        why = "%s 服務啟用中" % TIME_LABEL[on[0]]
        if len(on) > 1:
            why += "；同時啟用 %s，建議只保留一套" % "、".join(TIME_LABEL[g] for g in on[1:])
        return on[0], why
    for g in ("chrony", "ntp"):
        if state[g][0]:
            return g, "已安裝 %s（服務未啟用）" % TIME_LABEL[g]
    return "timesyncd", "未啟用任何校時服務，依 Ubuntu 預設採用 systemd-timesyncd"


def time_choice(ctx):
    state = {}
    for g, pkg, unit in TIME_PKGS:
        inst = pkgsvc.pkg_installed(ctx.osi, pkg)
        state[g] = (inst, inst and _svc_on(unit))
    return choose_time(state)


def time_is(group):
    def _when(ctx):
        cur, why = time_choice(ctx)
        return None if cur == group else ("GCB 校時規則 Chrony／NTP／systemd-timesyncd 三選一；本機採用 %s（依據：%s），"
                                         "本項目屬 %s，不需設定" % (TIME_LABEL[cur], why, TIME_LABEL[group]))
    return _when


# ====================================================================
# 防火牆判斷（UFW / Nftables / Iptables）
# ====================================================================

FW_LABEL = {"ufw": "UFW", "nftables": "Nftables", "iptables": "Iptables", "firewalld": "firewalld"}
UFW_CONF = "/etc/ufw/ufw.conf"
UFW_DEFAULT = "/etc/default/ufw"
UFW_USER4 = "/etc/ufw/user.rules"
UFW_USER6 = "/etc/ufw/user6.rules"
UFW_BEFORE = "/etc/ufw/before.rules"
NFT_CONF = "/etc/nftables.conf"
RULES_V4 = "/etc/iptables/rules.v4"
RULES_V6 = "/etc/iptables/rules.v6"


def ufw_enabled_conf():
    return _unq(te.get_kv(read_text(UFW_CONF) or "", "ENABLED")).lower() == "yes"


def choose_firewall(state):
    """依各防火牆狀態決定組別（純函式，方便測試）。

    state = {"ufw": ufw 已安裝且 ENABLED=yes, "nftables": nftables.service 啟用或運作中,
             "iptables": iptables-persistent 已安裝且 netfilter-persistent 啟用或運作中,
             "ipt_installed": iptables-persistent 已安裝}
    優先順序：
      1. 使用中者依 UFW > Nftables > Iptables 擇一（同時多套時在依據註明衝突）。
         ufw 啟用後 nft list ruleset 也會出現 ufw 的鏈，因此不以規則集內容判斷 nftables。
      2. 都沒有使用：已安裝 iptables-persistent（與 ufw 套件衝突，代表管理者已選用）→ Iptables
      3. 都沒有：UFW（Ubuntu 預設已安裝 ufw），由 0205/0207 等回報不合格
    """
    order = ["ufw", "nftables", "iptables"]
    on = [g for g in order if state.get(g)]
    if on:
        why = "%s 使用中" % FW_LABEL[on[0]]
        if len(on) > 1:
            why += "；同時使用 %s，建議只保留一套" % "、".join(FW_LABEL[g] for g in on[1:])
        return on[0], why
    if state.get("ipt_installed"):
        return "iptables", "已安裝 iptables-persistent（服務未啟用）"
    return "ufw", "未啟用任何防火牆，依 Ubuntu 預設採用 UFW"


def firewall_choice(ctx):
    """config.ini 的 firewall_backend 不是 auto 時以它為準（firewalld 在 Ubuntu GCB 無對應規則，三組皆不適用）；
    auto 或無法辨識的值才依 choose_firewall() 自動判斷。"""
    backend = (getattr(ctx.cfg, "firewall_backend", "auto") or "auto").strip().lower()
    if backend in FW_LABEL:
        return backend, "config.ini 指定 firewall_backend=%s" % backend
    osi = ctx.osi
    ipt = pkgsvc.pkg_installed(osi, "iptables-persistent")
    state = {
        "ufw": pkgsvc.pkg_installed(osi, "ufw") and ufw_enabled_conf(),
        "nftables": pkgsvc.pkg_installed(osi, "nftables") and _svc_on("nftables.service"),
        "iptables": ipt and _svc_on("netfilter-persistent.service"),
        "ipt_installed": ipt,
    }
    return choose_firewall(state)


def fw_is(group):
    def _when(ctx):
        cur, why = firewall_choice(ctx)
        return None if cur == group else ("GCB 防火牆規則 UFW／Nftables／Iptables 三選一；本機採用 %s（依據：%s），"
                                         "本項目屬 %s，不需設定" % (FW_LABEL.get(cur, cur), why, FW_LABEL[group]))
    return _when


def ipv6_enabled(ctx):
    return None if os.path.exists("/proc/net/if_inet6") else "核心已停用 IPv6，沒有 IPv6 流量需要以 ip6tables 管制"


def _forwarding(v6=False):
    key = "net/ipv6/conf/all/forwarding" if v6 else "net/ipv4/ip_forward"
    return (read_text("/proc/sys/" + key) or "0").strip() == "1"


# ---------- SSH 埠 ----------

def ssh_ports():
    """目前 sshd 使用的埠：sshd -T（port 與 listenaddress）、ss 監聽中的 sshd、目前 SSH 連線的本機埠；都沒有時為 22。"""
    ports = []
    sshd = which("sshd")
    if sshd:
        r = run([sshd, "-T"], timeout=30)
        if r.ok:
            ports = te.sshd_listen_ports(te.parse_sshd_T(r.out))
    # 另加入 ss 中 sshd 實際監聽的埠
    for line in run(["ss", "-Htlnp"], timeout=15).out.splitlines():
        p = line.split()
        if '"sshd"' in line and len(p) >= 4:
            ports.append(p[3].rsplit(":", 1)[-1])
    conn = os.environ.get("SSH_CONNECTION", "").split()
    if len(conn) == 4:
        ports.append(conn[3])
    ports = [p for p in ports if p.isdigit()] or ["22"]
    return sorted(set(ports), key=int)


# ---------- 防火牆保險與規則備份 ----------

class _Guard(object):
    """N 秒後自動執行還原指令的保險（systemd-run 計時器）；cancel() 取消。"""

    def __init__(self, fx, cmd, seconds=300):
        self.fx = fx
        self.unit = None
        if fx.dry or not which("systemd-run"):
            return
        unit = "gcb-fw-guard-%s-%d" % (fx.rid[-4:], int(time.time()))
        r = fx.run(["systemd-run", "--unit", unit, "--on-active=%d" % seconds] + cmd,
                   "排程防火牆自動還原保險（%d 秒後，完成後取消）" % seconds, check=False)
        if r is not None and r.ok:
            self.unit = unit

    def cancel(self):
        if self.unit:
            self.fx.run(["systemctl", "stop", self.unit + ".timer"], "取消防火牆自動還原保險", check=False)
            self.unit = None


def _snapshot(ctx, fx, kind):
    """備份目前規則集到執行紀錄目錄，並登記回滾時還原。kind：nft / v4 / v6。回傳備份檔（預覽為 None）。"""
    cmd, restore = {"nft": (["nft", "list", "ruleset"], "nft"),
                    "v4": (["iptables-save"], "iptables-restore"),
                    "v6": (["ip6tables-save"], "ip6tables-restore")}[kind]
    if fx.dry:
        fx.step("備份規則集", "[預覽] " + " ".join(cmd), "預覽")
        return None
    r = run(cmd, timeout=60)
    if not r.ok:
        raise FixError("無法讀取目前規則集（%s）：%s" % (" ".join(cmd), r.text()[-200:]))
    text = r.out
    if kind == "nft":
        foreign = nft_foreign_tables(nft_parse(text)[0], nft_parse(text)[1])
        if foreign:
            raise ManualRequired("目前規則集含其他程式（iptables-nft/ufw/docker）建立的表：%s，"
                                 "無法安全備份還原，請人工處理" % "、".join(foreign))
        text = "flush ruleset\n" + text
    elif "*filter" not in text:
        # filter 表尚未載入時 *-save 沒有輸出；補上空的 ACCEPT 表，回滾時才能清掉新增的規則
        text += "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
    path = os.path.join(ctx.run_dir, "fw-%s-%s-%d.save" % (fx.rid[-4:], kind, int(time.time() * 1000)))
    write_text_atomic(path, text, 0o600)
    fx.step("備份規則集", "%s → %s" % (" ".join(cmd), path), "成功")
    fx.add_undo([which(restore) or restore, path] if kind != "nft" else [which("nft") or "nft", "-f", path],
                "還原防火牆規則集")
    return path


def _restore_cmd(kind, path):
    if kind == "nft":
        return [which("nft") or "nft", "-f", path]
    restore = "ip6tables-restore" if kind == "v6" else "iptables-restore"
    return [which(restore) or restore, path]


# ====================================================================
# UFW 解析
# ====================================================================

def ufw_tuples(text):
    """解析 user.rules 的 ### tuple ### 行：回傳 [dict(action, proto, dport, dst, sport, src, dir)]。"""
    out = []
    for line in (text or "").splitlines():
        if not line.startswith("### tuple ###"):
            continue
        t = line[len("### tuple ###"):].split()
        t = [x for x in t if not x.startswith("comment=")]
        if len(t) < 7:
            continue
        out.append({"action": t[0].split("_")[0], "proto": t[1], "dport": t[2], "dst": t[3],
                    "sport": t[4], "src": t[5], "dir": t[-1]})
    return out


def _port_in(spec, port):
    """spec：22 / 22,2222 / 1000:2000 / any。"""
    if spec == "any":
        return True
    for part in spec.split(","):
        if ":" in part:
            a, b = part.split(":", 1)
            if a.isdigit() and b.isdigit() and int(a) <= int(port) <= int(b):
                return True
        elif part == str(port):
            return True
    return False


def ufw_allows_port(tuples, port):
    return any(t["action"] in ("allow", "limit") and t["dir"] == "in" and t["proto"] in ("tcp", "any")
               and t["dport"] != "any" and _port_in(t["dport"], port) for t in tuples)


ANY4, ANY6 = "0.0.0.0/0", "::/0"


def ufw_loopback_status(t4, t6, v6=True):
    """回傳缺少或順序錯誤的回送規則說明清單。"""
    def idx(ts, pred):
        for i, t in enumerate(ts):
            if pred(t):
                return i
        return None
    lo_in = lambda t: t["action"] == "allow" and t["dir"] == "in_lo"
    lo_out = lambda t: t["action"] == "allow" and t["dir"] == "out_lo"
    d4 = lambda t: t["action"] == "deny" and t["dir"] == "in" and t["src"] == "127.0.0.0/8"
    d6 = lambda t: t["action"] == "deny" and t["dir"] == "in" and t["src"] in ("::1", "::1/128")
    miss = []
    i_lo, i_d4 = idx(t4, lo_in), idx(t4, d4)
    if i_lo is None:
        miss.append("allow in on lo")
    if idx(t4, lo_out) is None:
        miss.append("allow out on lo")
    if i_d4 is None:
        miss.append("deny in from 127.0.0.0/8")
    elif i_lo is not None and i_d4 < i_lo:
        miss.append("deny 127.0.0.0/8 排在 allow in on lo 之前")
    if v6:
        j_lo, j_d6 = idx(t6, lo_in), idx(t6, d6)
        if j_d6 is None:
            miss.append("deny in from ::1")
        elif j_lo is not None and j_d6 < j_lo:
            miss.append("deny ::1 排在 allow in on lo 之前")
    return miss


def ufw_ipv6():
    return _unq(te.get_kv(read_text(UFW_DEFAULT) or "", "IPV6")).lower() != "no"


UFW_WORD = {"DROP": "deny", "ACCEPT": "allow", "REJECT": "reject"}


def ufw_policies():
    text = read_text(UFW_DEFAULT) or ""
    return {d: _unq(te.get_kv(text, k)).upper() or "未設定" for d, k in
            (("incoming", "DEFAULT_INPUT_POLICY"), ("outgoing", "DEFAULT_OUTPUT_POLICY"),
             ("routed", "DEFAULT_FORWARD_POLICY"))}


def _ufw_prepare(fx, ports):
    """啟用 ufw 或預設拒絕進入前：確認迴路介面與已建立連線已放行，並放行 SSH 埠。"""
    before = read_text(UFW_BEFORE) or ""
    if "ESTABLISHED" not in before:
        raise ManualRequired("%s 缺少放行已建立連線的規則（已被修改），自動啟用可能中斷連線，請人工確認" % UFW_BEFORE)
    if "-i lo -j ACCEPT" not in before and not any(t["dir"] == "in_lo" for t in ufw_tuples(read_text(UFW_USER4))):
        fx.run(["ufw", "allow", "in", "on", "lo"], "放行迴路介面")
    tuples = ufw_tuples(read_text(UFW_USER4))
    for p in ports:
        if not ufw_allows_port(tuples, p):
            fx.run(["ufw", "allow", "in", "%s/tcp" % p], "放行 SSH 埠 %s/tcp" % p)


def _ufw_verify_ssh(fx, ports):
    if fx.dry:
        return
    tuples = ufw_tuples(read_text(UFW_USER4))
    miss = [p for p in ports if not ufw_allows_port(tuples, p)]
    if miss:
        fx.run(["ufw", "--force", "disable"], "緊急停用 ufw（找不到 SSH 放行規則）", check=False)
        raise FixError("修改後找不到 SSH 埠 %s 的放行規則，已緊急停用 ufw" % ",".join(miss))
    fx.step("確認 SSH 放行規則", "SSH 埠 %s 已放行" % ",".join(ports), "成功")


# ====================================================================
# nftables 解析
# ====================================================================

_NFT_TOK = re.compile(r'"[^"\n]*"|[{};]|[^\s{};"]+')


def _strip_hash(line):
    out, q = [], False
    for ch in line:
        if ch == '"':
            q = not q
        if ch == "#" and not q:
            break
        out.append(ch)
    return "".join(out)


def nft_parse(text):
    """解析 nft 規則集（nft list ruleset 輸出或 nftables.conf）。

    回傳 (tables, chains)：tables=[(family, name)]；chains=[dict(family, table, chain, type, hook, policy,
    rules, rule_lines, start, hook_line, policy_line, end)]，行號從 0 起。
    """
    tables, chains, stack = [], [], []
    words, wline, inline = [], None, 0

    def finish():
        top = stack[-1] if stack else None
        if not words or not top or top[0] != "chain":
            return
        c = top[1]
        if words[0] == "type":
            s = " ".join(words)
            c["type"] = words[1] if len(words) > 1 else None
            m = re.search(r"\bhook\s+(\w+)", s)
            c["hook"] = m.group(1) if m else None
            c["hook_line"] = wline
        elif words[0] == "policy" and len(words) > 1:
            c["policy"] = words[1]
            c["policy_line"] = wline
        else:
            c["rules"].append(" ".join(words))
            c["rule_lines"].append(wline)

    for n, raw in enumerate((text or "").splitlines()):
        for t in _NFT_TOK.findall(_strip_hash(raw)):
            if inline:
                words.append(t)
                inline += {"{": 1, "}": -1}.get(t, 0)
                continue
            top = stack[-1] if stack else None
            if t == "{":
                kw = words[0] if words else ""
                if top is None and kw == "table" and len(words) >= 2:
                    fam, name = (words[1], words[2]) if len(words) >= 3 else ("ip", words[1])
                    tables.append((fam, name))
                    stack.append(("table", fam, name))
                elif top and top[0] == "table" and kw == "chain" and len(words) >= 2:
                    c = {"family": top[1], "table": top[2], "chain": words[1], "type": None, "hook": None,
                         "policy": None, "rules": [], "rule_lines": [], "start": n, "hook_line": None,
                         "policy_line": None, "end": None}
                    chains.append(c)
                    stack.append(("chain", c))
                elif top and top[0] == "chain" and words:
                    words.append(t)
                    inline = 1
                    continue
                else:
                    stack.append(("skip",))
                words = []
                continue
            if t in (";", "}"):
                finish()
                words = []
                if t == "}" and stack:
                    e = stack.pop()
                    if e[0] == "chain":
                        e[1]["end"] = n
                continue
            if not words:
                wline = n
            words.append(t)
        if not inline:
            finish()
            words = []
    return tables, chains


def nft_base(chains, hook=None):
    return [c for c in chains if c["type"] == "filter" and c["hook"] in ("input", "forward", "output")
            and (hook is None or c["hook"] == hook)]


IPT_BUILTIN = ("INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING")


def nft_foreign_tables(tables, chains):
    """iptables-nft（含 ufw、docker）建立的表：鏈名為大寫內建鏈或 ufw-/DOCKER 開頭。"""
    out = []
    for fam, name in tables:
        cs = [c["chain"] for c in chains if c["family"] == fam and c["table"] == name]
        if any(c in IPT_BUILTIN or c.startswith(("ufw", "DOCKER")) for c in cs):
            out.append("%s %s" % (fam, name))
    return out


def _clean_rule(r):
    return re.sub(r'\s+comment\s+"[^"]*"', "", r).strip()


def nft_is_lo(r):
    return bool(re.match(r'^iif(name)?\s+"?lo"?\s+(counter\b.*\s)?accept$', _clean_rule(r)))


def nft_is_established(r):
    m = re.search(r"\bct\s+state\s+(\{[^}]*\}|\S+)", r)
    return bool(m and "established" in m.group(1)) and _clean_rule(r).endswith("accept")


def nft_accepts_port(r, port):
    r = _clean_rule(r)
    m = re.search(r"\b(?:tcp|th)\s+dport\s+(\{[^}]*\}|\S+)", r)
    if not m or not r.endswith("accept"):
        return False
    for el in re.split(r"[\s,{}]+", m.group(1)):
        el = "22" if el == "ssh" else el
        if "-" in el:
            a, b = el.split("-", 1)
            if a.isdigit() and b.isdigit() and int(a) <= int(port) <= int(b):
                return True
        elif el == str(port):
            return True
    return False


def nft_chain_ssh_safe(chain, ports):
    """policy drop 的 input 鏈須放行迴路介面、已建立連線與 SSH 埠。回傳 (安全, 缺少說明)。"""
    if (chain.get("policy") or "accept") != "drop" or chain.get("hook") != "input":
        return True, ""
    rules = chain["rules"]
    miss = []
    if not any(nft_is_lo(r) for r in rules):
        miss.append("迴路介面")
    if not any(nft_is_established(r) for r in rules):
        miss.append("已建立連線")
    miss += ["SSH 埠 %s" % p for p in ports if not any(nft_accepts_port(r, p) for r in rules)]
    if nft_needs_nd(chain) and not any(nft_is_nd(r) for r in rules):
        miss.append("IPv6 鄰居探索（ICMPv6）")
    return not miss, "、".join(miss)


NFT_LO = 'iif "lo" accept'
NFT_ND = "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept"


def ipv6_active():
    return os.path.isdir("/proc/sys/net/ipv6") and (read_text("/proc/sys/net/ipv6/conf/all/disable_ipv6") or "0").strip() != "1"


def nft_needs_nd(chain):
    """inet / ip6 表的 input 鏈在 IPv6 啟用時須放行鄰居探索，否則鄰居快取過期後 IPv6 連線（含 SSH）中斷。"""
    return ipv6_active() and (chain or {}).get("family", "inet") in ("inet", "ip6")


def nft_is_nd(r):
    return "nd-neighbor-solicit" in r or "nd-neighbor-advert" in r
NFT_LO4 = "ip saddr 127.0.0.0/8 counter drop"
NFT_LO6 = "ip6 saddr ::1 counter drop"


def nft_is_lo4(r):
    return bool(re.match(r"^ip\s+saddr\s+127\.0\.0\.0/8\b.*\bdrop$", _clean_rule(r)))


def nft_is_lo6(r):
    return bool(re.match(r"^ip6\s+saddr\s+::1(/128)?\b.*\bdrop$", _clean_rule(r)))


def nft_loopback_missing(chain):
    """回傳 input 鏈缺少或順序錯誤的回送規則說明。"""
    rules = chain["rules"]

    def idx(pred):
        for i, r in enumerate(rules):
            if pred(r):
                return i
        return None
    i_lo, i4, i6 = idx(nft_is_lo), idx(nft_is_lo4), idx(nft_is_lo6)
    miss = []
    if i_lo is None:
        miss.append(NFT_LO)
    if i4 is None:
        miss.append(NFT_LO4)
    if i6 is None:
        miss.append(NFT_LO6)
    if i_lo is not None and any(i is not None and i < i_lo for i in (i4, i6)):
        miss.append("drop 規則排在 iif lo accept 之前")
    return miss


# ---------- nftables 設定檔編輯（純函式） ----------

def _find_chain(chains, key):
    for c in chains:
        if (c["family"], c["table"], c["chain"]) == key:
            return c
    return None


def nft_conf_insert_rules(text, key, rules, after_lo=False):
    """在設定檔指定鏈中插入規則：預設插在 type/policy 宣告之後（鏈的最前面）；
    after_lo=True 時插在 iif lo accept 之後。鏈為單行寫法時回傳 None。"""
    _, chains = nft_parse(text)
    c = _find_chain(chains, key)
    if not c or c["hook_line"] is None or c["hook_line"] in (c["start"], c["end"]):
        return None
    lines = text.splitlines()
    pos = max(c["hook_line"], c["policy_line"] if c["policy_line"] is not None else -1)
    if after_lo:
        for r, ln in zip(c["rules"], c["rule_lines"]):
            if nft_is_lo(r):
                pos = ln
                break
    indent = re.match(r"^\s*", lines[c["hook_line"]]).group(0)
    lines[pos + 1:pos + 1] = [indent + r for r in rules]
    return "\n".join(lines) + "\n"


def nft_conf_set_policy(text, key, policy):
    _, chains = nft_parse(text)
    c = _find_chain(chains, key)
    if not c or c["hook_line"] is None:
        return None
    lines = text.splitlines()
    ln = c["policy_line"] if c["policy_line"] is not None else c["hook_line"]
    line = lines[ln]
    if re.search(r"\bpolicy\s+\w+", line):
        lines[ln] = re.sub(r"\bpolicy\s+\w+", "policy " + policy, line)
    elif c["hook_line"] in (c["start"], c["end"]):
        return None
    else:
        s = line.rstrip()
        lines[ln] = s + ("" if s.endswith(";") else ";") + " policy %s;" % policy
    return "\n".join(lines) + "\n"


NFT_HEADER = "#!/usr/sbin/nft -f\n\nflush ruleset\n\n"
NFT_CHAINS_BLOCK = ("table inet filter {\n" + "".join(
    "\tchain %s {\n\t\ttype filter hook %s priority filter; policy accept;\n\t}\n" % (h, h)
    for h in ("input", "forward", "output")) + "}\n")


def _nft_conf_files():
    """/etc/nftables.conf 與其 include 的檔案：[(path, text)]。"""
    out = []
    main = read_text(NFT_CONF)
    if main is None:
        return out
    out.append((NFT_CONF, main))
    for line in main.splitlines():
        m = re.match(r'^\s*include\s+"([^"]+)"', line)
        if m:
            pat = m.group(1) if m.group(1).startswith("/") else os.path.join("/etc", m.group(1))
            for f in sorted(glob.glob(pat)):
                out.append((f, read_text(f) or ""))
    return out


def _nft_conf():
    """回傳 (tables, chains)，chains 多一個 file 欄位。"""
    tables, chains = [], []
    for path, text in _nft_conf_files():
        t, c = nft_parse(text)
        tables += t
        for x in c:
            x["file"] = path
        chains += c
    return tables, chains


def _nft_runtime():
    """回傳 (tables, chains) 或在無法讀取時 raise。排除 iptables-nft 建立的表。"""
    if not which("nft"):
        raise RuntimeError("找不到 nft 指令")
    r = run(["nft", "list", "ruleset"], timeout=30)
    if not r.ok:
        raise RuntimeError("nft list ruleset 失敗：%s" % r.text()[-200:])
    tables, chains = nft_parse(r.out)
    foreign = set(nft_foreign_tables(tables, chains))
    tables = [t for t in tables if "%s %s" % t not in foreign]
    chains = [c for c in chains if "%s %s" % (c["family"], c["table"]) not in foreign]
    return tables, chains


def _nft_check_conf(fx):
    r = fx.run(["nft", "-c", "-f", NFT_CONF], "檢查 %s 語法" % NFT_CONF, check=False)
    if r is not None and not r.ok:
        raise FixError("%s 語法檢查失敗：%s" % (NFT_CONF, r.text()[-200:]))


def _nft_target(hook, need_inet=True):
    """找出設定檔與執行中都存在的 inet 基本鏈（family, table, chain）；回傳 (key, conf_chain)。"""
    _, cc = _nft_conf()
    try:
        _, rc = _nft_runtime()
    except RuntimeError as e:
        raise ManualRequired(str(e))
    rkeys = set((c["family"], c["table"], c["chain"]) for c in nft_base(rc, hook))
    for c in nft_base(cc, hook):
        key = (c["family"], c["table"], c["chain"])
        if key in rkeys and (c["family"] == "inet" or not need_inet):
            return key, c
    raise ManualRequired("找不到同時存在於 %s 與執行中規則集的 inet %s 基本鏈，請先完成 0214（建立基本鏈）與 0212（nftables 服務）"
                         % (NFT_CONF, hook))


def _nft_handles(key):
    """回傳 [(rule 文字, handle)]。"""
    r = run(["nft", "-a", "list", "chain"] + list(key), timeout=30)
    out = []
    for line in r.out.splitlines():
        m = re.match(r"^\s*(.*?)\s*#\s*handle\s+(\d+)\s*$", line)
        if m and not m.group(1).startswith(("chain", "type", "table", "policy", "}")):
            out.append((m.group(1), m.group(2)))
    return out


# ====================================================================
# iptables 解析
# ====================================================================

def ipt_policy(lines, chain):
    for l in lines:
        p = l.split()
        if len(p) >= 3 and p[0] == "-P" and p[1] == chain:
            return p[2]
    return None


def _ipt_port(line, port):
    m = re.search(r"--dports?\s+(\S+)", line)
    if not m:
        return False
    return _port_in(m.group(1), port)


def ipt_input_safe(lines, ports):
    """INPUT 預設 DROP 時須放行迴路介面、已建立連線與 SSH 埠。回傳 (安全, 缺少說明)。"""
    if ipt_policy(lines, "INPUT") != "DROP":
        return True, ""
    rules = [l for l in lines if l.startswith("-A INPUT ") and l.rstrip().endswith("-j ACCEPT")]
    miss = []
    if not any(re.search(r"(^|\s)-i lo(\s|$)", l) for l in rules):
        miss.append("迴路介面")
    if not any("ESTABLISHED" in l for l in rules):
        miss.append("已建立連線")
    miss += ["SSH 埠 %s" % p for p in ports
             if not any(re.search(r"-p tcp\b", l) and _ipt_port(l, p) for l in rules)]
    return not miss, "、".join(miss)


def ipt_file_policies(text):
    """iptables-save 格式檔案中 *filter 區段的鏈政策。"""
    pol, in_filter = {}, False
    for l in (text or "").splitlines():
        if l.startswith("*"):
            in_filter = l.strip() == "*filter"
        elif in_filter and l.startswith(":"):
            p = l[1:].split()
            if len(p) >= 2:
                pol[p[0]] = p[1]
    return pol


def _norm_ipt(text):
    return [re.sub(r"\[\d+:\d+\]", "", l).strip() for l in (text or "").splitlines()
            if l.strip() and not l.startswith("#")]


def _ipt(v6):
    return "ip6tables" if v6 else "iptables"


def _ipt_lines(v6):
    """回傳 iptables -S 的行；失敗 raise RuntimeError。"""
    cmd = which(_ipt(v6))
    if not cmd:
        raise RuntimeError("找不到 %s 指令" % _ipt(v6))
    r = run([cmd, "-S"], timeout=30)
    if not r.ok:
        raise RuntimeError("%s -S 失敗：%s" % (_ipt(v6), r.text()[-200:]))
    return r.out.splitlines()


def _ipt_persist(fx, v6):
    """把目前規則保存到 rules.v4 / rules.v6（開機由 netfilter-persistent 載入）。"""
    path = RULES_V6 if v6 else RULES_V4
    if fx.dry:
        fx.step("保存規則", "[預覽] %s-save > %s" % (_ipt(v6), path), "預覽")
        return
    r = run(["%s-save" % _ipt(v6)], timeout=30)
    if not r.ok:
        raise FixError("%s-save 失敗：%s" % (_ipt(v6), r.text()[-200:]))
    fx.write_file(path, r.out, mode=0o640)


def _ipt_has(v6, spec):
    return run([_ipt(v6), "-C"] + spec, timeout=15).ok


# ====================================================================
# 客製規則：校時
# ====================================================================

# [TimePackage] TWGCB-01-014-0194 chrony 校時套件、0198 systemd-timesyncd 校時套件、0201 ntp 校時套件
class TimePackage(Rule):
    """安裝選用的校時套件，移除（或遮蔽）其他校時套件。"""
    risk = "B"
    expected = "安裝"

    def __init__(self, title, category, ids, group, pkg, absent, mask_timesyncd):
        self.title = title
        self.category = category
        self.ids = ids
        self.group = group
        self.pkg = pkg
        self.absent = absent
        self.mask_timesyncd = mask_timesyncd
        self.when = time_is(group)

    def _problems(self, ctx):
        bad = []
        if not pkgsvc.pkg_installed(ctx.osi, self.pkg):
            bad.append("未安裝 %s" % self.pkg)
        bad += ["仍安裝 %s" % p for p in self.absent if pkgsvc.pkg_installed(ctx.osi, p)]
        en, act = pkgsvc.svc_state("systemd-timesyncd.service")
        if self.mask_timesyncd and en not in ("masked", "not-found"):
            bad.append("systemd-timesyncd.service 未遮蔽（%s/%s）" % (en, act))
        if not self.mask_timesyncd and en == "masked":
            bad.append("systemd-timesyncd.service 被遮蔽")
        return bad

    def check(self, ctx):
        bad = self._problems(ctx)
        why = time_choice(ctx)[1]
        return Check(FAIL if bad else PASS, ("；".join(bad) if bad else "已安裝 %s，無其他校時套件" % self.pkg)
                     + "（%s）" % why)

    def fix(self, ctx, fx):
        osi = ctx.osi
        for p in self.absent:
            if pkgsvc.pkg_installed(osi, p):
                if p == "chrony" and os.path.isdir("/etc/chrony"):
                    fx.backup_dir("/etc/chrony")
                for f in ("/etc/ntp.conf", "/etc/default/ntp"):
                    if p == "ntp" and os.path.exists(f):
                        fx.backup_only(f)
                fx.pkg_remove(p)
        if not pkgsvc.pkg_installed(osi, self.pkg):
            fx.pkg_install(self.pkg)
        en, _ = pkgsvc.svc_state("systemd-timesyncd.service")
        if self.mask_timesyncd and en not in ("masked", "not-found"):
            fx.service_mask("systemd-timesyncd.service")
        if not self.mask_timesyncd and en == "masked":
            fx.add_undo(["systemctl", "mask", "systemd-timesyncd.service"], "恢復遮蔽 systemd-timesyncd")
            fx.run(["systemctl", "unmask", "systemd-timesyncd.service"], "解除遮蔽 systemd-timesyncd")


# [TimeService] TWGCB-01-014-0197 chrony 校時服務、0200 systemd-timesyncd 校時服務、0204 ntp 校時服務
class TimeService(Rule):
    expected = "啟用"

    def __init__(self, title, category, ids, group, pkg, unit, pkg_rule):
        self.title = title
        self.category = category
        self.ids = ids
        self.pkg = pkg
        self.unit = unit
        self.pkg_rule = pkg_rule
        self.when = time_is(group)

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, self.pkg):
            return Check(FAIL, "未安裝套件 %s" % self.pkg)
        ok, cur = _svc_ok(self.unit)
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, self.pkg):
            raise ManualRequired("未安裝 %s，請先完成 %s（校時套件，B 類需 --include-risky）" % (self.pkg, self.pkg_rule))
        if pkgsvc.svc_state(self.unit)[0] == "masked":
            fx.add_undo(["systemctl", "mask", self.unit], "恢復遮蔽 %s" % self.unit)
            fx.run(["systemctl", "unmask", self.unit], "解除遮蔽 %s" % self.unit)
        fx.service_enable(self.unit)


CHRONY_CONF = "/etc/chrony/chrony.conf"


def chrony_files():
    return [CHRONY_CONF] + sorted(glob.glob("/etc/chrony/conf.d/*.conf")) + \
        sorted(glob.glob("/etc/chrony/sources.d/*.sources"))


def chrony_directives(text, name):
    """回傳 chrony 設定中指定指令的參數清單（忽略 # ! ; % 開頭的註解）。"""
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s[0] in "#!;%":
            continue
        p = s.split()
        if p[0].lower() == name:
            out.append(" ".join(p[1:]))
    return out


# [TimeSources] TWGCB-01-014-0195 chrony 校時設定、0199 systemd-timesyncd 校時設定、0202 ntp 校時設定（C 類）
class TimeSources(Rule):
    risk = "C"
    expected = "設定 1 個以上校時來源"

    def __init__(self, title, category, ids, group, hint):
        self.title = title
        self.category = category
        self.ids = ids
        self.group = group
        self.when = time_is(group)
        self.manual_hint = hint

    def _sources(self):
        if self.group == "chrony":
            out = []
            for f in chrony_files():
                t = read_text(f) or ""
                out += ["%s %s" % (k, v.split()[0]) for k in ("server", "pool")
                        for v in chrony_directives(t, k) if v]
            return out
        if self.group == "ntp":
            t = read_text("/etc/ntp.conf") or ""
            return ["%s %s" % (k, v.split()[0]) for k in ("server", "pool") for v in chrony_directives(t, k) if v]
        return timesyncd_ntp()

    def check(self, ctx):
        src = self._sources()
        if src:
            return Check(PASS, "校時來源：%s" % "、".join(src[:5]))
        return Check(FAIL, "未設定校時來源" + ("（僅有 FallbackNTP 不算）" if self.group == "timesyncd" else ""))


def timesyncd_files():
    """依 systemd 規則：主設定檔，再依檔名排序 drop-in（同名以 /etc 優先）。"""
    chosen = {}
    for d in ("/usr/lib/systemd/timesyncd.conf.d", "/run/systemd/timesyncd.conf.d", "/etc/systemd/timesyncd.conf.d"):
        for f in glob.glob(d + "/*.conf"):
            chosen[os.path.basename(f)] = f
    return ["/etc/systemd/timesyncd.conf"] + [chosen[k] for k in sorted(chosen)]


def timesyncd_ntp():
    val = None
    for f in timesyncd_files():
        v = ini_get(read_text(f) or "", "Time", "NTP")
        if v is not None:
            val = v
    return (val or "").split()


# [ChronyUser] TWGCB-01-014-0196 chrony 校時使用者設定
class ChronyUser(Rule):
    category = "Chrony 配置"
    title = "chrony 校時使用者設定"
    expected = "_chrony"

    def __init__(self, ids):
        self.ids = ids
        self.when = time_is("chrony")

    def _values(self):
        out = []
        for f in chrony_files()[:1] + sorted(glob.glob("/etc/chrony/conf.d/*.conf")):
            for v in chrony_directives(read_text(f) or "", "user"):
                out.append((f, v))
        return out

    def check(self, ctx):
        vals = self._values()
        if not vals:
            who = run(["ps", "-o", "user=", "-C", "chronyd"], timeout=15).out.split()
            return Check(FAIL, "未設定 user（執行身分：%s）" % (who[0] if who else "未執行"))
        bad = [(f, v) for f, v in vals if v != "_chrony"]
        return Check(FAIL if bad else PASS, "、".join("user %s（%s）" % (v, f) for f, v in vals))

    def fix(self, ctx, fx):
        fx.add_undo(["systemctl", "try-restart", "chrony.service"], "重新啟動 chrony")
        for f, v in self._values():
            if f != CHRONY_CONF and v != "_chrony":
                fx.edit_file(f, lambda t: te.comment_kv(t, "user"))
        fx.edit_file(CHRONY_CONF, lambda t: te.set_kv(t, "user", "_chrony", sep=" "))
        fx.run(["systemctl", "try-restart", "chrony.service"], "重新啟動 chrony")


NTP_USER_FILES = ["/etc/init.d/ntp", "/usr/lib/ntp/ntp-systemd-wrapper"]


# [NtpUser] TWGCB-01-014-0203 ntp 校時使用者設定
class NtpUser(Rule):
    category = "NTP 配置"
    title = "ntp 校時使用者設定"
    expected = "ntp"

    def __init__(self, ids):
        self.ids = ids
        self.when = time_is("ntp")

    def _values(self):
        return [(f, _unq(te.get_kv(read_text(f), "RUNASUSER"))) for f in NTP_USER_FILES if os.path.exists(f)]

    def check(self, ctx):
        vals = self._values()
        if not vals:
            return Check(FAIL, "找不到 %s" % "、".join(NTP_USER_FILES))
        bad = [x for x in vals if x[1] != "ntp"]
        return Check(FAIL if bad else PASS, "、".join("RUNASUSER=%s（%s）" % (v or "未設定", f) for f, v in vals))

    def fix(self, ctx, fx):
        fx.add_undo(["systemctl", "try-restart", "ntp.service"], "重新啟動 ntp")

        def _set(t):
            if te.get_kv(t, "RUNASUSER") is not None:
                return te.set_kv(t, "RUNASUSER", "ntp", sep="=")
            lines = t.splitlines()  # 加在 shebang 之後
            lines[1:1] = ["RUNASUSER=ntp"]
            return "\n".join(lines) + "\n"
        for f, v in self._values():
            if v != "ntp":
                fx.edit_file(f, _set)
        fx.run(["systemctl", "try-restart", "ntp.service"], "重新啟動 ntp")


# ====================================================================
# 客製規則：防火牆共用
# ====================================================================

# [FwPkgAbsent] TWGCB-01-014-0206 iptables-persistent 套件、0211 ufw 套件、0219 nftables 套件、0220 ufw 套件
class FwPkgAbsent(Rule):
    """移除其他防火牆套件；移除前備份其設定，使用中的防火牆不移除。"""
    risk = "B"
    expected = "移除"

    def __init__(self, title, category, ids, group, pkg, files=(), dirs=()):
        self.title = title
        self.category = category
        self.ids = ids
        self.pkg = pkg
        self.files = files
        self.dirs = dirs
        self.when = fw_is(group)

    def check(self, ctx):
        inst = pkgsvc.pkg_installed(ctx.osi, self.pkg)
        return Check(FAIL if inst else PASS, "已安裝" if inst else "未安裝")

    def fix(self, ctx, fx):
        in_use = {"ufw": ufw_enabled_conf, "nftables": lambda: _svc_on("nftables.service"),
                  "iptables-persistent": lambda: _svc_on("netfilter-persistent.service")}[self.pkg]()
        if in_use:
            raise ManualRequired("%s 目前仍在使用中，移除會改變封包過濾行為，請先確認規則已移轉後人工移除" % self.pkg)
        for d in self.dirs:
            if os.path.isdir(d):
                fx.backup_dir(d)
        for f in self.files:
            fx.backup_only(f)
        fx.pkg_remove(self.pkg)


# ====================================================================
# 客製規則：UFW
# ====================================================================

# [UfwService] TWGCB-01-014-0207 ufw 服務
class UfwService(Rule):
    category = "UFW 配置"
    title = "ufw 服務"
    expected = "啟用"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("ufw")

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "ufw"):
            return Check(FAIL, "未安裝 ufw")
        en, act = pkgsvc.svc_state("ufw.service")
        on = ufw_enabled_conf()
        return Check(PASS if en in ON_STATES and on else FAIL,
                     "ufw.service=%s/%s；防火牆 %s" % (en, act, "已啟用（ENABLED=yes）" if on else "未啟用（ENABLED=no）"))

    def fix(self, ctx, fx):
        if not which("ufw"):
            raise ManualRequired("未安裝 ufw，請先完成 0205")
        ports = ssh_ports()
        was_on = ufw_enabled_conf()
        fx.add_undo(["ufw", "reload"] if was_on else ["ufw", "--force", "disable"], "還原 ufw 啟用狀態")
        fx.backup_dir("/etc/ufw")
        fx.backup_only(UFW_DEFAULT)
        _ufw_prepare(fx, ports)
        guard = _Guard(fx, [which("ufw"), "--force", "disable"])
        try:
            if pkgsvc.svc_state("ufw.service")[0] not in ON_STATES:
                fx.service_enable("ufw.service")
            if not was_on:
                fx.run(["ufw", "--force", "enable"], "啟用 ufw 防火牆")
            _ufw_verify_ssh(fx, ports)
        finally:
            guard.cancel()


# [UfwLoopback] TWGCB-01-014-0208 在 ufw 設定回送流量規則
class UfwLoopback(Rule):
    category = "UFW 配置"
    title = "在 ufw 設定回送流量規則"
    expected = "建立回送流量規則"
    risk = "B"
    CMDS = {"allow in on lo": ["allow", "in", "on", "lo"], "allow out on lo": ["allow", "out", "on", "lo"],
            "deny in from 127.0.0.0/8": ["deny", "in", "from", "127.0.0.0/8"],
            "deny in from ::1": ["deny", "in", "from", "::1"]}

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("ufw")

    def _missing(self):
        return ufw_loopback_status(ufw_tuples(read_text(UFW_USER4)), ufw_tuples(read_text(UFW_USER6)), ufw_ipv6())

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "ufw"):
            return Check(FAIL, "未安裝 ufw")
        miss = self._missing()
        return Check(FAIL if miss else PASS, "缺少：" + "、".join(miss) if miss else "回送流量規則皆已設定")

    def fix(self, ctx, fx):
        if not which("ufw"):
            raise ManualRequired("未安裝 ufw，請先完成 0205")
        miss = self._missing()
        if any("排在" in m for m in miss):
            raise ManualRequired("ufw 規則順序不正確（%s），請以 ufw status numbered 檢視後人工調整" % "、".join(miss))
        fx.add_undo(["ufw", "reload"], "重新載入 ufw 規則")
        for f in (UFW_USER4, UFW_USER6):
            fx.backup_only(f)
        for m in miss:
            fx.run(["ufw"] + self.CMDS[m], "ufw " + m)


# [UfwDefaultDeny] TWGCB-01-014-0209 在 ufw 建立預設拒絕規則
class UfwDefaultDeny(Rule):
    category = "UFW 配置"
    title = "在 ufw 建立預設拒絕規則"
    expected = "deny"
    risk = "B"
    manual_hint = ("預設拒絕外出（ufw default deny outgoing）會中斷 DNS、套件更新、校時、監控等對外連線，"
                   "請先以 ufw allow out <埠> 放行必要的對外連線（例如 53、123/udp、80、443），確認後再執行")

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("ufw")

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "ufw"):
            return Check(FAIL, "未安裝 ufw")
        pol = ufw_policies()
        ok = all(v == "DROP" for v in pol.values())
        # 以 ufw status 與 GCB 的用語（deny / allow / reject）顯示 /etc/default/ufw 的設定
        cur = "、".join("%s=%s" % (d, UFW_WORD.get(v, v)) for d, v in sorted(pol.items()))
        if pol["routed"] == "DROP" and not _forwarding():
            cur += "（核心未開啟 IP 轉送，ufw status 的 routed 顯示為 disabled）"
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if not which("ufw"):
            raise ManualRequired("未安裝 ufw，請先完成 0205")
        pol = ufw_policies()
        need = [d for d in ("incoming", "routed") if pol[d] != "DROP"]
        if "routed" in need and _forwarding():
            need.remove("routed")
            fx.note("系統已開啟 IP 轉送（可能為容器或虛擬化主機），未自動設定 deny routed，請人工評估")
        if not need:
            raise ManualRequired(self.manual_hint)
        ports = ssh_ports()
        fx.add_undo(["ufw", "reload"], "重新載入 ufw 規則")
        for f in (UFW_DEFAULT, UFW_USER4, UFW_USER6):
            fx.backup_only(f)
        guard = None
        if "incoming" in need:
            _ufw_prepare(fx, ports)
            if ufw_enabled_conf():
                guard = _Guard(fx, [which("ufw"), "default", "allow", "incoming"])
        try:
            for d in need:
                fx.run(["ufw", "default", "deny", d], "ufw default deny %s" % d)
            _ufw_verify_ssh(fx, ports)
        finally:
            if guard:
                guard.cancel()
        if pol["outgoing"] != "DROP" or "routed" not in need and pol["routed"] != "DROP":
            fx.partial = True
            fx.note("未自動設定的項目需人工處理：" + self.manual_hint)


# ====================================================================
# 客製規則：Nftables
# ====================================================================

def _nft_current(desc_conf, desc_rt):
    return "設定檔：%s；執行中：%s" % (desc_conf, desc_rt)


# [NftService] TWGCB-01-014-0212 nftables 服務
class NftService(Rule):
    category = "Nftables 配置"
    title = "nftables 服務"
    expected = "啟用"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("nftables")

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "nftables"):
            return Check(FAIL, "未安裝 nftables")
        ok, cur = _svc_ok("nftables.service")
        return Check(PASS if ok else FAIL, cur)

    def fix(self, ctx, fx):
        if not which("nft"):
            raise ManualRequired("未安裝 nftables，請先完成 0210")
        if not os.path.exists(NFT_CONF):
            raise ManualRequired("找不到 %s，請先建立規則集設定（0213、0214）" % NFT_CONF)
        ports = ssh_ports()
        ctab, cch = _nft_conf()
        for c in nft_base(cch, "input"):
            ok, miss = nft_chain_ssh_safe(c, ports)
            if not ok:
                raise ManualRequired("%s 的 input 鏈為 policy drop 但未放行：%s，啟動服務會中斷連線，請先修正設定檔" % (c["file"], miss))
        try:
            rtab, _ = _nft_runtime()
        except RuntimeError as e:
            raise ManualRequired(str(e))
        extra = [t for t in rtab if t not in ctab]
        if extra:
            raise ManualRequired("啟動 nftables 服務會清除目前不在 %s 中的規則（%s），請人工確認" % (
                NFT_CONF, "、".join("%s %s" % t for t in extra)))
        _nft_check_conf(fx)
        snap = _snapshot(ctx, fx, "nft")
        guard = _Guard(fx, _restore_cmd("nft", snap)) if snap else None
        try:
            fx.service_enable("nftables.service")
            if not fx.dry:
                for c in nft_base(_nft_runtime()[1], "input"):
                    ok, miss = nft_chain_ssh_safe(c, ports)
                    if not ok:
                        raise FixError("啟動後 input 鏈未放行：%s（將還原）" % miss)
        finally:
            if guard:
                guard.cancel()


# [NftTable] TWGCB-01-014-0213 在 nftables 中建立表
class NftTable(Rule):
    category = "Nftables 配置"
    title = "在 nftables 中建立表"
    expected = "1 個以上"

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("nftables")

    def check(self, ctx):
        ctab, _ = _nft_conf()
        try:
            rtab, _ = _nft_runtime()
        except RuntimeError as e:
            return Check(ERROR, str(e))
        ok = any(t in rtab for t in ctab)
        fmt = lambda ts: "、".join("%s %s" % t for t in ts) or "無"
        return Check(PASS if ok else FAIL, _nft_current(fmt(ctab), fmt(rtab)))

    def fix(self, ctx, fx):
        ctab, _ = _nft_conf()
        if not ctab:
            fx.edit_file(NFT_CONF, lambda t: (t or NFT_HEADER) + "table inet filter {\n}\n")
            _nft_check_conf(fx)
            ctab = [("inet", "filter")]
        rtab, _ = _nft_runtime()
        missing = [t for t in ctab if t not in rtab]
        if missing:
            _snapshot(ctx, fx, "nft")
            for fam, name in missing:
                fx.run(["nft", "add", "table", fam, name], "建立表 %s %s" % (fam, name))


# [NftBaseChain] TWGCB-01-014-0214 在 nftables 建立基本鏈
class NftBaseChain(Rule):
    category = "Nftables 配置"
    title = "在 nftables 建立基本鏈"
    expected = "1 個以上"

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("nftables")

    def check(self, ctx):
        _, cch = _nft_conf()
        try:
            _, rch = _nft_runtime()
        except RuntimeError as e:
            return Check(ERROR, str(e))
        fmt = lambda cs: "、".join(sorted(set(c["hook"] for c in nft_base(cs)))) or "無"
        cur = _nft_current(fmt(cch), fmt(rch))
        hooks = set(c["hook"] for c in nft_base(rch))
        if nft_base(cch) and hooks and hooks != {"input", "forward", "output"}:
            cur += "（建議 input、forward、output 三者齊全）"
        return Check(PASS if nft_base(cch) and nft_base(rch) else FAIL, cur)

    def fix(self, ctx, fx):
        _, cch = _nft_conf()
        _, rch = _nft_runtime()
        if nft_base(cch) and not nft_base(rch):
            raise ManualRequired("%s 已有基本鏈但尚未載入，請完成 0212（啟用 nftables 服務）" % NFT_CONF)
        if not nft_base(cch):
            names = [c["chain"] for c in cch if (c["family"], c["table"]) == ("inet", "filter")]
            if any(h in names for h in ("input", "forward", "output")):
                raise ManualRequired("inet filter 表已有 input/forward/output 一般鏈，請人工改為基本鏈")
            fx.edit_file(NFT_CONF, lambda t: (t or NFT_HEADER) + NFT_CHAINS_BLOCK)
            _nft_check_conf(fx)
        if not nft_base(rch):
            _snapshot(ctx, fx, "nft")
            fx.run(["nft", "add", "table", "inet", "filter"], "建立表 inet filter")
            for h in ("input", "forward", "output"):
                fx.run(["nft", "add", "chain", "inet", "filter", h,
                        "{ type filter hook %s priority filter ; policy accept ; }" % h],
                       "建立基本鏈 %s（policy accept）" % h)


# [NftLoopback] TWGCB-01-014-0215 在 nftables 設定回送流量規則
class NftLoopback(Rule):
    category = "Nftables 配置"
    title = "在 nftables 設定回送流量規則"
    expected = "建立回送流量規則"
    risk = "B"
    RT = {NFT_LO: ["iif", "lo", "accept"], NFT_LO4: ["ip", "saddr", "127.0.0.0/8", "counter", "drop"],
          NFT_LO6: ["ip6", "saddr", "::1", "counter", "drop"]}

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("nftables")

    def check(self, ctx):
        _, cch = _nft_conf()
        try:
            _, rch = _nft_runtime()
        except RuntimeError as e:
            return Check(ERROR, str(e))
        rin = nft_base(rch, "input")
        if not rin:
            return Check(FAIL, "執行中沒有 input 基本鏈")
        best = min(rin, key=lambda c: len(nft_loopback_missing(c)))
        miss_rt = nft_loopback_missing(best)
        cc = _find_chain(cch, (best["family"], best["table"], best["chain"]))
        miss_cf = nft_loopback_missing(cc) if cc else ["設定檔無此鏈"]
        if not miss_rt and not miss_cf:
            return Check(PASS, "%s %s %s 已有回送流量規則" % (best["family"], best["table"], best["chain"]))
        return Check(FAIL, "執行中缺少：%s；設定檔缺少：%s" % ("、".join(miss_rt) or "無", "、".join(miss_cf) or "無"))

    def fix(self, ctx, fx):
        key, cc = _nft_target("input")
        rc = _find_chain(_nft_runtime()[1], key)
        if any("排在" in m for m in nft_loopback_missing(cc) + nft_loopback_missing(rc)):
            raise ManualRequired("回送規則順序不正確（drop 在 iif lo accept 之前），請人工調整")
        _snapshot(ctx, fx, "nft")
        # 設定檔
        miss = [r for r in (NFT_LO, NFT_LO4, NFT_LO6) if r in nft_loopback_missing(cc)]
        if miss:
            after_lo = NFT_LO not in miss
            new = nft_conf_insert_rules(read_text(cc["file"]) or "", key, miss, after_lo=after_lo)
            if new is None:
                raise ManualRequired("%s 的 %s 鏈為單行寫法，請人工加入：%s" % (cc["file"], key[2], "、".join(miss)))
            fx.write_file(cc["file"], new)
            _nft_check_conf(fx)
        # 執行中
        miss = [r for r in (NFT_LO, NFT_LO4, NFT_LO6) if r in nft_loopback_missing(rc)]
        if NFT_LO in miss:
            for r in reversed(miss):
                fx.run(["nft", "insert", "rule"] + list(key) + self.RT[r], "加入規則 %s" % r)
        elif miss:
            handle = [h for r, h in _nft_handles(key) if nft_is_lo(r)]
            for r in reversed(miss):
                fx.run(["nft", "add", "rule"] + list(key) + ["position", handle[0]] + self.RT[r] if handle
                       else ["nft", "insert", "rule"] + list(key) + self.RT[r], "加入規則 %s" % r)


# [NftDefaultDrop] TWGCB-01-014-0216 在 nftables 建立預設拒絕規則
class NftDefaultDrop(Rule):
    category = "Nftables 配置"
    title = "在 nftables 建立預設拒絕規則"
    expected = "Drop"
    risk = "B"
    manual_hint = ("output 鏈 policy drop 會中斷 DNS、套件更新、校時等對外連線，請先在 output 鏈加入 "
                   "ct state established,related accept、oif \"lo\" accept 與必要的對外放行規則，確認後再設定 policy drop")

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("nftables")

    @staticmethod
    def _pol(chains):
        out = {}
        for h in ("input", "forward", "output"):
            cs = nft_base(chains, h)
            out[h] = "drop" if any(c["policy"] == "drop" for c in cs) else ((cs and "accept") or "無基本鏈")
        return out

    def check(self, ctx):
        _, cch = _nft_conf()
        try:
            _, rch = _nft_runtime()
        except RuntimeError as e:
            return Check(ERROR, str(e))
        pr, pc = self._pol(rch), self._pol(cch)
        ok = all(v == "drop" for v in list(pr.values()) + list(pc.values()))
        fmt = lambda p: " ".join("%s=%s" % (h, p[h]) for h in ("input", "forward", "output"))
        return Check(PASS if ok else FAIL, _nft_current(fmt(pc), fmt(pr)))

    def fix(self, ctx, fx):
        _, cch = _nft_conf()
        _, rch = _nft_runtime()
        pr, pc = self._pol(rch), self._pol(cch)
        need = [h for h in ("input", "forward") if pr[h] != "drop" or pc[h] != "drop"]
        if "forward" in need and (_forwarding() or _forwarding(True)):
            need.remove("forward")
            fx.note("系統已開啟 IP 轉送（可能為容器或虛擬化主機），未自動設定 forward policy drop，請人工評估")
        if not need:
            raise ManualRequired(self.manual_hint)
        ports = ssh_ports()
        targets = dict((h, _nft_target(h)) for h in need)
        snap = _snapshot(ctx, fx, "nft")
        # 1. 設定檔：先放行迴路介面、已建立連線與 SSH 埠，再改 policy
        if "input" in need:
            key, cc = targets["input"]
            add = self._allow_rules(cc, ports)
            if add:
                new = nft_conf_insert_rules(read_text(cc["file"]) or "", key, [a[0] for a in add])
                if new is None:
                    raise ManualRequired("%s 的 input 鏈為單行寫法，請人工處理" % cc["file"])
                fx.write_file(cc["file"], new)
        for h in need:
            key, cc = targets[h]
            new = nft_conf_set_policy(read_text(cc["file"]) or "", key, "drop")
            if new is None:
                raise ManualRequired("%s 的 %s 鏈為單行寫法，請人工設定 policy drop" % (cc["file"], h))
            fx.write_file(cc["file"], new)
        _nft_check_conf(fx)
        # 2. 執行中規則
        guard = _Guard(fx, _restore_cmd("nft", snap)) if snap else None
        try:
            if "input" in need:
                key, _ = targets["input"]
                for text, args in reversed(self._allow_rules(_find_chain(rch, key), ports)):
                    fx.run(["nft", "insert", "rule"] + list(key) + args, "放行：%s" % text)
            for h in need:
                key, _ = targets[h]
                fx.run(["nft", "chain"] + list(key) + ["{ policy drop ; }"], "設定 %s 鏈 policy drop" % h)
            if not fx.dry:
                for c in nft_base(_nft_runtime()[1], "input"):
                    ok, miss = nft_chain_ssh_safe(c, ports)
                    if not ok:
                        fx.run(["nft", "chain", c["family"], c["table"], c["chain"], "{ policy accept ; }"],
                               "緊急恢復 input policy accept", check=False)
                        raise FixError("修改後 input 鏈未放行：%s，已緊急恢復 policy accept" % miss)
                fx.step("確認 SSH 放行規則", "SSH 埠 %s 已放行" % ",".join(ports), "成功")
        finally:
            if guard:
                guard.cancel()
        if pr["output"] != "drop" or pc["output"] != "drop" or len(need) < 2:
            fx.partial = True
            fx.note("未自動設定的項目需人工處理：" + self.manual_hint)

    @staticmethod
    def _allow_rules(chain, ports):
        """回傳要加在 input 鏈最前面的放行規則 [(設定檔文字, nft 參數)]，已存在者略過。"""
        rules = chain["rules"] if chain else []
        out = []
        if not any(nft_is_lo(r) for r in rules):
            out.append((NFT_LO, ["iif", "lo", "accept"]))
        if not any(nft_is_established(r) for r in rules):
            out.append(("ct state established,related accept", ["ct", "state", "established,related", "accept"]))
        if nft_needs_nd(chain) and not any(nft_is_nd(r) for r in rules):
            out.append((NFT_ND, NFT_ND.split()))
        miss = [p for p in ports if not any(nft_accepts_port(r, p) for r in rules)]
        if miss:
            s = "{ %s }" % ", ".join(miss)
            out.append(("tcp dport %s accept" % s, ["tcp", "dport", s, "accept"]))
        return out


# [NftBoot] TWGCB-01-014-0217 載入 nftables 規則
class NftBoot(Rule):
    category = "Nftables 配置"
    title = "載入 nftables 規則"
    expected = "開機時自動載入 nftables 規則集"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("nftables")

    def _problems(self):
        bad = []
        en, _ = pkgsvc.svc_state("nftables.service")
        if en not in ON_STATES:
            bad.append("nftables.service 開機未啟用（%s）" % en)
        if not os.path.exists(NFT_CONF):
            return bad + ["找不到 %s" % NFT_CONF]
        ctab, cch = _nft_conf()
        if not ctab:
            bad.append("設定檔未定義表")
        hooks = set(c["hook"] for c in nft_base(cch))
        miss = [h for h in ("input", "forward", "output") if h not in hooks]
        if miss:
            bad.append("設定檔缺少基本鏈：%s" % "、".join(miss))
        r = run(["nft", "-c", "-f", NFT_CONF], timeout=30) if which("nft") else None
        if r is None or not r.ok:
            bad.append("語法檢查失敗：%s" % (r.text()[-150:] if r else "找不到 nft"))
        return bad

    def check(self, ctx):
        bad = self._problems()
        return Check(FAIL if bad else PASS, "；".join(bad) if bad else "nftables.service 開機啟用，%s 規則集完整" % NFT_CONF)

    def fix(self, ctx, fx):
        bad = [b for b in self._problems() if "開機未啟用" not in b]
        if bad:
            raise ManualRequired("；".join(bad) + "。請先完成 0213、0214 或修正 %s" % NFT_CONF)
        fx.add_undo(["systemctl", "disable", "nftables.service"], "恢復 nftables.service 開機停用")
        fx.run(["systemctl", "enable", "nftables.service"], "設定開機載入 nftables 規則")


# ====================================================================
# 客製規則：Iptables
# ====================================================================

# [IptPackages] TWGCB-01-014-0218 iptables 防火牆套件
class IptPackages(Rule):
    category = "Iptables 配置"
    title = "iptables 防火牆套件"
    expected = "安裝"
    risk = "B"

    def __init__(self, ids):
        self.ids = ids
        self.when = fw_is("iptables")

    def check(self, ctx):
        miss = [p for p in ("iptables", "iptables-persistent") if not pkgsvc.pkg_installed(ctx.osi, p)]
        return Check(FAIL if miss else PASS, "未安裝：" + "、".join(miss) if miss else "皆已安裝")

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "iptables-persistent"):
            # 與 ufw 套件衝突，安裝會連帶移除 ufw，不自動安裝
            raise ManualRequired("安裝 iptables-persistent 會移除 ufw 等其他防火牆套件，請確認後人工安裝"
                                 "（apt install iptables-persistent）")
        fx.pkg_install("iptables")


# [NetfilterService] TWGCB-01-014-0221 iptables 服務、0222 ip6tables 服務（Ubuntu 為 netfilter-persistent.service）
class NetfilterService(Rule):
    category = "Iptables 配置"
    expected = "啟用"
    risk = "B"
    UNIT = "netfilter-persistent.service"

    def __init__(self, title, ids, v6):
        self.title = title
        self.ids = ids
        self.v6 = v6
        self.path = RULES_V6 if v6 else RULES_V4
        self.when = fw_is("iptables")

    def check(self, ctx):
        if not pkgsvc.pkg_installed(ctx.osi, "iptables-persistent"):
            return Check(FAIL, "未安裝 iptables-persistent")
        ok, cur = _svc_ok(self.UNIT)
        has = os.path.exists(self.path)
        return Check(PASS if ok and has else FAIL, "%s；%s %s" % (cur, self.path, "存在" if has else "不存在"))

    def fix(self, ctx, fx):
        if not pkgsvc.pkg_installed(ctx.osi, "iptables-persistent"):
            raise ManualRequired("未安裝 iptables-persistent，請先完成 0218")
        r = run(["%s-save" % _ipt(self.v6)], timeout=30)
        if not r.ok:
            raise FixError("%s-save 失敗：%s" % (_ipt(self.v6), r.text()[-200:]))
        if not os.path.exists(self.path):
            fx.write_file(self.path, r.out, mode=0o640)
        elif pkgsvc.svc_state(self.UNIT)[1] != "active":
            for p, save in ((RULES_V4, "iptables-save"), (RULES_V6, "ip6tables-save")):
                if os.path.exists(p) and _norm_ipt(read_text(p)) != _norm_ipt(run([save], timeout=30).out):
                    raise ManualRequired("%s 與目前執行中的規則不同，啟動服務會改套用檔案中的規則，"
                                         "請確認檔案內容（或以 netfilter-persistent save 保存目前規則）後再啟用" % p)
        _snapshot(ctx, fx, "v4")
        _snapshot(ctx, fx, "v6")
        fx.service_enable(self.UNIT)


# [IptDefaultDrop] TWGCB-01-014-0223 在 iptables 建立預設拒絕規則、0225 在 ip6tables 建立預設拒絕規則
class IptDefaultDrop(Rule):
    category = "Iptables 配置"
    expected = "Drop"
    risk = "B"
    manual_hint = ("OUTPUT 預設 DROP 會中斷 DNS、套件更新、校時等對外連線，請先加入 -A OUTPUT -o lo -j ACCEPT、"
                   "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 與必要的對外放行規則，"
                   "確認後再執行 -P OUTPUT DROP 並 netfilter-persistent save")

    def __init__(self, title, ids, v6):
        self.title = title
        self.ids = ids
        self.v6 = v6
        self.path = RULES_V6 if v6 else RULES_V4
        self.when = all_of(fw_is("iptables"), ipv6_enabled) if v6 else fw_is("iptables")

    def check(self, ctx):
        try:
            lines = _ipt_lines(self.v6)
        except RuntimeError as e:
            return Check(ERROR, str(e))
        fp = ipt_file_policies(read_text(self.path))
        chains = ("INPUT", "FORWARD", "OUTPUT")
        ok = all(ipt_policy(lines, c) == "DROP" and fp.get(c) == "DROP" for c in chains)
        return Check(PASS if ok else FAIL, "執行中：%s；%s：%s" % (
            " ".join("%s=%s" % (c, ipt_policy(lines, c)) for c in chains), self.path,
            " ".join("%s=%s" % (c, fp.get(c, "無")) for c in chains) if fp else "不存在或無 *filter"))

    def _allow_specs(self, ports):
        specs = [["-i", "lo", "-j", "ACCEPT"],
                 ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]]
        specs += [["-p", "tcp", "-m", "tcp", "--dport", p, "-j", "ACCEPT"] for p in ports]
        if self.v6:  # IPv6 鄰居探索，否則 IPv6 網路會中斷
            specs += [["-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", t, "-j", "ACCEPT"]
                      for t in ("133", "134", "135", "136")]
        return specs

    def fix(self, ctx, fx):
        ipt = _ipt(self.v6)
        lines = _ipt_lines(self.v6)
        fp = ipt_file_policies(read_text(self.path))
        need = [c for c in ("INPUT", "FORWARD") if ipt_policy(lines, c) != "DROP" or fp.get(c) != "DROP"]
        if "FORWARD" in need and _forwarding(self.v6):
            need.remove("FORWARD")
            fx.note("系統已開啟 IP 轉送（可能為容器或虛擬化主機），未自動設定 FORWARD DROP，請人工評估")
        if not need:
            raise ManualRequired(self.manual_hint)
        ports = ssh_ports()
        snap = _snapshot(ctx, fx, "v6" if self.v6 else "v4")
        guard = _Guard(fx, _restore_cmd("v6" if self.v6 else "v4", snap)) if snap else None
        try:
            if "INPUT" in need:
                # 由下往上插入到最前面：最後順序為 lo、已建立連線、SSH 埠（、ICMPv6）
                for spec in reversed(self._allow_specs(ports)):
                    if not _ipt_has(self.v6, ["INPUT"] + spec):
                        fx.run([ipt, "-I", "INPUT", "1"] + spec, "放行：%s" % " ".join(spec))
            for c in need:
                fx.run([ipt, "-P", c, "DROP"], "設定 %s 預設 DROP" % c)
            if not fx.dry:
                ok, miss = ipt_input_safe(_ipt_lines(self.v6), ports)
                if not ok:
                    fx.run([ipt, "-P", "INPUT", "ACCEPT"], "緊急恢復 INPUT ACCEPT", check=False)
                    raise FixError("修改後 INPUT 未放行：%s，已緊急恢復 ACCEPT" % miss)
                fx.step("確認 SSH 放行規則", "SSH 埠 %s 已放行" % ",".join(ports), "成功")
            _ipt_persist(fx, self.v6)
        finally:
            if guard:
                guard.cancel()
        if ipt_policy(lines, "OUTPUT") != "DROP" or fp.get("OUTPUT") != "DROP" or len(need) < 2:
            fx.partial = True
            fx.note("未自動設定的項目需人工處理：" + self.manual_hint)


# [IptLoopback] TWGCB-01-014-0224 在 iptables 設定回送流量規則、0226 在 ip6tables 設定回送流量規則
class IptLoopback(Rule):
    category = "Iptables 配置"
    expected = "建立回送流量規則"
    risk = "B"

    def __init__(self, title, ids, v6):
        self.title = title
        self.ids = ids
        self.v6 = v6
        self.path = RULES_V6 if v6 else RULES_V4
        self.src = "::1/128" if v6 else "127.0.0.0/8"
        self.when = all_of(fw_is("iptables"), ipv6_enabled) if v6 else fw_is("iptables")
        self.lo_in = "-A INPUT -i lo -j ACCEPT"
        self.lo_out = "-A OUTPUT -o lo -j ACCEPT"
        self.drop = "-A INPUT -s %s -j DROP" % self.src

    def missing(self, lines):
        lines = [" ".join(l.split()) for l in lines]
        miss = [r for r in (self.lo_in, self.lo_out, self.drop) if r not in lines]
        if not miss and lines.index(self.drop) < lines.index(self.lo_in):
            miss.append("DROP 規則排在 lo ACCEPT 之前")
        return miss

    def check(self, ctx):
        try:
            lines = _ipt_lines(self.v6)
        except RuntimeError as e:
            return Check(ERROR, str(e))
        m_rt = self.missing(lines)
        m_f = self.missing(_norm_ipt(read_text(self.path)))
        if not m_rt and not m_f:
            return Check(PASS, "執行中與 %s 皆有回送流量規則" % self.path)
        return Check(FAIL, "執行中缺少：%s；%s 缺少：%s" % ("、".join(m_rt) or "無", self.path, "、".join(m_f) or "無"))

    def fix(self, ctx, fx):
        ipt = _ipt(self.v6)
        rt = [" ".join(l.split()) for l in _ipt_lines(self.v6)]
        miss = self.missing(rt)
        if miss:
            _snapshot(ctx, fx, "v6" if self.v6 else "v4")
        drop = ["-s", self.src, "-j", "DROP"]
        has_drop = self.drop in rt
        if any("排在" in m for m in miss):
            fx.run([ipt, "-D", "INPUT"] + drop, "移除順序錯誤的 DROP 規則（稍後重新加入）")
            has_drop = False
        if self.lo_in not in rt:
            fx.run([ipt, "-I", "INPUT", "1", "-i", "lo", "-j", "ACCEPT"], "INPUT 放行 lo")
        if self.lo_out not in rt:
            fx.run([ipt, "-I", "OUTPUT", "1", "-o", "lo", "-j", "ACCEPT"], "OUTPUT 放行 lo")
        if not has_drop:
            pos = 2
            if not fx.dry:  # 插在 lo ACCEPT 之後
                rules = [" ".join(l.split()) for l in _ipt_lines(self.v6) if l.startswith("-A INPUT ")]
                pos = rules.index(self.lo_in) + 2 if self.lo_in in rules else 1
            fx.run([ipt, "-I", "INPUT", str(pos)] + drop, "INPUT 拒絕非 lo 的回送位址 %s" % self.src)
        _ipt_persist(fx, self.v6)


# ====================================================================
# 客製規則：GNOME（dconf）
# ====================================================================

DCONF_DB = "/etc/dconf/db"
PROFILE_DIRS = ("/etc/dconf/profile", "/usr/share/dconf/profile")
USER_PROFILE = ["user-db:user", "system-db:local"]
GDM_PROFILE = ["user-db:user", "system-db:gdm", "file-db:/usr/share/gdm/greeter-dconf-defaults"]


def gnome_when(ctx):
    if any(pkgsvc.pkg_installed(ctx.osi, p) for p in ("gdm3", "gnome-shell")):
        return None
    return "未安裝 GNOME 圖形介面（gdm3、gnome-shell），本項目是桌面設定，不需設定"


def gdm_when(ctx):
    return None if pkgsvc.pkg_installed(ctx.osi, "gdm3") else "未安裝 gdm3 圖形登入畫面，本項目是登入畫面設定，不需設定"


# ---------- INI / keyfile（純函式） ----------

def _section_of(line):
    m = re.match(r"^\s*\[(.+?)\]\s*$", line)
    return m.group(1).strip() if m else None


def ini_entries(text):
    """回傳 [(section, key, value, 行號)]，忽略 # ; 註解。"""
    out, sec = [], None
    for n, line in enumerate((text or "").splitlines()):
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        name = _section_of(line)
        if name is not None:
            sec = name
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            out.append((sec, k.strip(), v.strip(), n))
    return out


def ini_get(text, section, key):
    val = None
    for s, k, v, _ in ini_entries(text):
        if s == section and k == key:
            val = v
    return val


def ini_set(text, section, key, value):
    """在 [section] 設定 key=value：取代第一個、註解其餘；區段不存在則附加。保留其他內容與註解。"""
    lines = (text or "").splitlines()
    hits = [n for s, k, v, n in ini_entries(text) if s == section and k == key]
    if hits:
        lines[hits[0]] = "%s=%s" % (key, value)
        for n in hits[1:]:
            lines[n] = te.MARK + lines[n]
        return "\n".join(lines) + "\n"
    start = None
    for n, line in enumerate(lines):
        if _section_of(line) == section:
            start = n
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines += ["[%s]" % section, "%s=%s" % (key, value)]
        return "\n".join(lines) + "\n"
    pos = start
    for n in range(start + 1, len(lines)):
        if _section_of(lines[n]) is not None:
            break
        if lines[n].strip():
            pos = n
    lines.insert(pos + 1, "%s=%s" % (key, value))
    return "\n".join(lines) + "\n"


def ini_comment(text, section, key):
    lines = (text or "").splitlines()
    for s, k, v, n in ini_entries(text):
        if s == section and k == key:
            lines[n] = te.MARK + lines[n]
    return "\n".join(lines) + "\n"


def profile_merge(text, needed):
    """在 dconf profile 補上缺少的行（user-db 放第一行），不移除既有內容。"""
    lines = [l for l in (text or "").splitlines()]
    have = [l.strip() for l in lines]
    for i, n in enumerate(needed):
        if n in have:
            continue
        if n.startswith("user-db:"):
            lines.insert(0, n)
        else:
            lines.append(n)
        have = [l.strip() for l in lines]
    return "\n".join(lines) + "\n"


def dconf_uint(v):
    m = re.match(r"^(?:uint32\s+)?(\d+)$", (v or "").strip())
    return int(m.group(1)) if m else None


def _db_files(db):
    d = os.path.join(DCONF_DB, db + ".d")
    return [f for f in sorted(glob.glob(d + "/*")) if os.path.isfile(f)]


def dconf_values(db, section, key):
    """回傳 [(檔案, 值)]，依 dconf 讀取順序（檔名排序，後者覆蓋前者）。"""
    out = []
    for f in _db_files(db):
        v = ini_get(read_text(f) or "", section, key)
        if v is not None:
            out.append((f, v))
    return out


def dconf_locks(db):
    out = set()
    for f in sorted(glob.glob(os.path.join(DCONF_DB, db + ".d", "locks", "*"))):
        for line in (read_text(f) or "").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                out.add(s)
    return out


def dconf_compiled(db):
    """編譯後資料庫存在且不早於 .d 目錄與其檔案（代表已執行 dconf update）。"""
    target = os.path.join(DCONF_DB, db)
    if not os.path.isfile(target):
        return False
    d = os.path.join(DCONF_DB, db + ".d")
    srcs = [d, os.path.join(d, "locks")] + _db_files(db) + glob.glob(os.path.join(d, "locks", "*"))
    newest = max([os.path.getmtime(p) for p in srcs if os.path.exists(p)] or [0])
    return os.path.getmtime(target) >= newest


def _profile(name):
    """回傳 (生效的 profile 路徑, 內容)。/etc 優先於 /usr/share。"""
    for d in PROFILE_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p, read_text(p) or ""
    return None, ""


# [DconfRule] TWGCB-01-014-0227 GNOME 使用者清單、0228 GNOME 使用者會談逾時時間、0229 GNOME 使用者會談逾時時間鎖定、
#             0230 卸除式儲存裝置、0231 卸除式儲存裝置鎖定、0232 Autorun、0233 Autorun 鎖定
class DconfRule(Rule):
    """dconf 系統設定共用：profile、keyfile 或 locks、dconf update。

    keys  [(section, key, 合格判斷函式, 寫入值)]：寫入 db.d/<file>
    locks [鎖定路徑]：以「缺少才附加」方式寫入 db.d/locks/<file>（0231 與 0233 共用同一檔不互相覆寫）
    """
    category = "GNOME 設定"

    def __init__(self, title, ids, expected, file, keys=(), locks=(), db="local", profile="user"):
        self.title = title
        self.ids = ids
        self.expected = expected
        self.file = file
        self.keys = keys
        self.locks = locks
        self.db = db
        self.profile = profile
        self.profile_lines = GDM_PROFILE if profile == "gdm" else USER_PROFILE
        self.when = gdm_when if profile == "gdm" else gnome_when

    def _problems(self):
        bad = []
        for sec, key, ok, _ in self.keys:
            vals = dconf_values(self.db, sec, key)
            if not vals:
                bad.append("%s 未設定" % key)
            elif not ok(vals[-1][1]):
                bad.append("%s=%s（%s）" % (key, vals[-1][1], os.path.basename(vals[-1][0])))
        have = dconf_locks(self.db)
        bad += ["未鎖定 %s" % l for l in self.locks if l not in have]
        path, text = _profile(self.profile)
        miss = [l for l in self.profile_lines if l not in [x.strip() for x in text.splitlines()]]
        if miss:
            bad.append("dconf profile %s 缺少 %s" % (path or self.profile, "、".join(miss)))
        if not bad and not dconf_compiled(self.db):
            bad.append("設定尚未以 dconf update 編譯生效")
        return bad

    def check(self, ctx):
        bad = self._problems()
        if bad:
            return Check(FAIL, "；".join(bad))
        cur = "、".join("%s=%s" % (k, dconf_values(self.db, s, k)[-1][1]) for s, k, _, _ in self.keys)
        if self.locks:
            cur += ("、" if cur else "") + "已鎖定 %d 項" % len(self.locks)
        return Check(PASS, cur)

    def fix(self, ctx, fx):
        if not which("dconf"):
            raise ManualRequired("找不到 dconf 指令，請安裝 dconf-cli 套件後重新執行")
        fx.add_undo(["dconf", "update"], "重新編譯 dconf 資料庫")
        # profile：只補缺少的行，不覆寫
        path, text = _profile(self.profile)
        if [l for l in self.profile_lines if l not in [x.strip() for x in text.splitlines()]]:
            fx.write_file(os.path.join(PROFILE_DIRS[0], self.profile), profile_merge(text, self.profile_lines))
        # 編譯後的資料庫也納入回滾（原本不存在則回滾時刪除）
        compiled = os.path.join(DCONF_DB, self.db)
        if not fx.dry:
            e = ctx.journal.backup_file(fx.rid, compiled)
            fx.step("備份檔案", "%s（%s）" % (compiled, "已備份" if e["data"]["existed"] else "原本不存在，回滾時刪除"), "成功")
        d = os.path.join(DCONF_DB, self.db + ".d")
        target = os.path.join(d, self.file)
        for sec, key, ok, val in self.keys:
            for f, v in dconf_values(self.db, sec, key):
                if f != target and not ok(v):
                    fx.edit_file(f, lambda t, s=sec, k=key: ini_comment(t, s, k))
            if not all(ok(v) for _, v in dconf_values(self.db, sec, key)) or not dconf_values(self.db, sec, key):
                fx.edit_file(target, lambda t, s=sec, k=key, v=val: ini_set(t, s, k, v))
        if self.locks:
            have = dconf_locks(self.db)
            add = [l for l in self.locks if l not in have]
            if add:
                fx.edit_file(os.path.join(d, "locks", self.file),
                             lambda t: (t if not t or t.endswith("\n") else t + "\n") + "\n".join(add) + "\n")
        if not fx.dry and not dconf_compiled(self.db):
            # 只更新目錄時間戳記，讓 dconf update 重新編譯
            dirs = [p for p in (d, os.path.join(d, "locks")) if os.path.isdir(p)]
            if dirs:
                fx.run(["touch"] + dirs, "更新 dconf 設定目錄時間戳記")
        fx.run(["dconf", "update"], "dconf update 編譯設定")


# [GdmXdmcp] TWGCB-01-014-0234 XDMCP 協定
class GdmXdmcp(Rule):
    category = "GNOME 設定"
    title = "XDMCP 協定"
    expected = "false"
    needs_reboot = True
    PATH = "/etc/gdm3/custom.conf"

    def __init__(self, ids):
        self.ids = ids
        self.when = gdm_when

    def check(self, ctx):
        v = ini_get(read_text(self.PATH) or "", "xdmcp", "Enable")
        if v is None:
            return Check(FAIL, "[xdmcp] Enable 未設定（GDM 預設停用，但需明確設定）")
        if v.lower() != "false":
            return Check(FAIL, "Enable=%s" % v)
        cur = "Enable=false"
        if os.path.getmtime(self.PATH) > _uptime_boot():
            cur += "（需重新啟動 gdm3 或重開機生效）"
        return Check(PASS, cur)

    def fix(self, ctx, fx):
        fx.edit_file(self.PATH, lambda t: ini_set(t, "xdmcp", "Enable", "false"))
        fx.note("需重新啟動 gdm3 或重開機生效（重啟 gdm3 會結束桌面工作階段，未自動執行）")


def _eq(target):
    return lambda v: (v or "").strip().lower() == target


def _idle_ok(v):
    n = dconf_uint(v)
    return n is not None and 0 < n <= 900


# ====================================================================
# 規則清單（依 GCB 文件順序）
# ====================================================================

def _w(rule, when, risk=None):
    rule.when = when
    if risk:
        rule.risk = risk
    return rule


MH = "/org/gnome/desktop/media-handling/"

RULES = [
    # ---------------- Chrony 配置 ----------------
    # 0194 chrony 校時套件
    TimePackage("chrony 校時套件", "Chrony 配置", U(194), "chrony", "chrony", ["ntp"], mask_timesyncd=True),
    # 0195 chrony 校時設定
    TimeSources("chrony 校時設定", "Chrony 配置", U(195), "chrony",
                "請在 /etc/chrony/chrony.conf（或 /etc/chrony/conf.d/*.conf）加入 server <校時伺服器> iburst "
                "或 pool <NTP 池>，再執行 systemctl restart chrony"),
    # 0196 chrony 校時使用者設定
    ChronyUser(U(196)),
    # 0197 chrony 校時服務
    TimeService("chrony 校時服務", "Chrony 配置", U(197), "chrony", "chrony", "chrony.service", "0194"),

    # ---------------- systemd-timesyncd 配置 ----------------
    # 0198 systemd-timesyncd 校時套件
    TimePackage("systemd-timesyncd 校時套件", "systemd-timesyncd 配置", U(198), "timesyncd",
                "systemd-timesyncd", ["chrony", "ntp"], mask_timesyncd=False),
    # 0199 systemd-timesyncd 校時設定
    TimeSources("systemd-timesyncd 校時設定", "systemd-timesyncd 配置", U(199), "timesyncd",
                "請建立 /etc/systemd/timesyncd.conf.d/60-gcb.conf，內容 [Time] 與 NTP=<校時伺服器>"
                "（可多個，以空白分隔），再執行 systemctl restart systemd-timesyncd"),
    # 0200 systemd-timesyncd 校時服務
    TimeService("systemd-timesyncd 校時服務", "systemd-timesyncd 配置", U(200), "timesyncd",
                "systemd-timesyncd", "systemd-timesyncd.service", "0198"),

    # ---------------- NTP 配置 ----------------
    # 0201 ntp 校時套件
    TimePackage("ntp 校時套件", "NTP 配置", U(201), "ntp", "ntp", ["chrony"], mask_timesyncd=True),
    # 0202 ntp 校時設定
    TimeSources("ntp 校時設定", "NTP 配置", U(202), "ntp",
                "請在 /etc/ntp.conf 加入 server <校時伺服器> iburst 或 pool <NTP 池>，再執行 systemctl restart ntp"),
    # 0203 ntp 校時使用者設定
    NtpUser(U(203)),
    # 0204 ntp 校時服務
    TimeService("ntp 校時服務", "NTP 配置", U(204), "ntp", "ntp", "ntp.service", "0201"),

    # ---------------- UFW 配置 ----------------
    # 0205 ufw 防火牆套件
    _w(PackagePresent("ufw 防火牆套件", "ufw", U(205), "UFW 配置"), fw_is("ufw")),
    # 0206 iptables-persistent 套件（移除）
    FwPkgAbsent("iptables-persistent 套件", "UFW 配置", U(206), "ufw", "iptables-persistent",
                files=(RULES_V4, RULES_V6)),
    # 0207 ufw 服務
    UfwService(U(207)),
    # 0208 在 ufw 設定回送流量規則
    UfwLoopback(U(208)),
    # 0209 在 ufw 建立預設拒絕規則
    UfwDefaultDeny(U(209)),

    # ---------------- Nftables 配置 ----------------
    # 0210 nftables 防火牆套件
    _w(PackagePresent("nftables 防火牆套件", "nftables", U(210), "Nftables 配置"), fw_is("nftables")),
    # 0211 ufw 套件（移除）
    FwPkgAbsent("ufw 套件", "Nftables 配置", U(211), "nftables", "ufw", files=(UFW_DEFAULT,), dirs=("/etc/ufw",)),
    # 0212 nftables 服務
    NftService(U(212)),
    # 0213 在 nftables 中建立表
    NftTable(U(213)),
    # 0214 在 nftables 建立基本鏈
    NftBaseChain(U(214)),
    # 0215 在 nftables 設定回送流量規則
    NftLoopback(U(215)),
    # 0216 在 nftables 建立預設拒絕規則
    NftDefaultDrop(U(216)),
    # 0217 載入 nftables 規則（Ubuntu：nftables.service 讀取 /etc/nftables.conf）
    NftBoot(U(217)),

    # ---------------- Iptables 配置 ----------------
    # 0218 iptables 防火牆套件
    IptPackages(U(218)),
    # 0219 nftables 套件（移除）
    FwPkgAbsent("nftables 套件", "Iptables 配置", U(219), "iptables", "nftables", files=(NFT_CONF,)),
    # 0220 ufw 套件（移除）
    FwPkgAbsent("ufw 套件", "Iptables 配置", U(220), "iptables", "ufw", files=(UFW_DEFAULT,), dirs=("/etc/ufw",)),
    # 0221 iptables 服務（netfilter-persistent）
    NetfilterService("iptables 服務", U(221), v6=False),
    # 0222 ip6tables 服務（netfilter-persistent）
    NetfilterService("ip6tables 服務", U(222), v6=True),
    # 0223 在 iptables 建立預設拒絕規則
    IptDefaultDrop("在 iptables 建立預設拒絕規則", U(223), v6=False),
    # 0224 在 iptables 設定回送流量規則
    IptLoopback("在 iptables 設定回送流量規則", U(224), v6=False),
    # 0225 在 ip6tables 建立預設拒絕規則
    IptDefaultDrop("在 ip6tables 建立預設拒絕規則", U(225), v6=True),
    # 0226 在 ip6tables 設定回送流量規則
    IptLoopback("在 ip6tables 設定回送流量規則", U(226), v6=True),

    # ---------------- GNOME 設定 ----------------
    # 0227 GNOME 使用者清單
    DconfRule("GNOME 使用者清單", U(227), "true", "00-login-screen", db="gdm", profile="gdm",
              keys=[("org/gnome/login-screen", "disable-user-list", _eq("true"), "true")]),
    # 0228 GNOME 使用者會談逾時時間
    DconfRule("GNOME 使用者會談逾時時間", U(228), "900 秒以下，但須大於 0", "00-screensaver",
              keys=[("org/gnome/desktop/session", "idle-delay", _idle_ok, "uint32 900"),
                    ("org/gnome/desktop/screensaver", "lock-delay", lambda v: dconf_uint(v) == 0, "uint32 0")]),
    # 0229 GNOME 使用者會談逾時時間鎖定
    DconfRule("GNOME 使用者會談逾時時間鎖定", U(229), "啟用", "screensaver",
              locks=["/org/gnome/desktop/session/idle-delay", "/org/gnome/desktop/screensaver/lock-delay"]),
    # 0230 卸除式儲存裝置
    DconfRule("卸除式儲存裝置", U(230), "false", "00-media-automount",
              keys=[("org/gnome/desktop/media-handling", "automount", _eq("false"), "false"),
                    ("org/gnome/desktop/media-handling", "automount-open", _eq("false"), "false")]),
    # 0231 卸除式儲存裝置鎖定（與 0233 共用 locks/media-handling，缺少才附加）
    DconfRule("卸除式儲存裝置鎖定", U(231), "啟用", "media-handling",
              locks=[MH + "automount", MH + "automount-open"]),
    # 0232 Autorun
    DconfRule("Autorun", U(232), "true", "00-media-autorun",
              keys=[("org/gnome/desktop/media-handling", "autorun-never", _eq("true"), "true")]),
    # 0233 Autorun 鎖定（與 0231 共用 locks/media-handling，缺少才附加）
    DconfRule("Autorun 鎖定", U(233), "啟用", "media-handling", locks=[MH + "autorun-never"]),
    # 0234 XDMCP 協定
    GdmXdmcp(U(234)),
]
