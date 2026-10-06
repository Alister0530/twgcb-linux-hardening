# -*- coding: utf-8 -*-
"""設定檔文字處理（純函式，方便單元測試）。"""
import re

MARK = "# [gcb-checker 註解] "


def _lines(text):
    return (text or "").splitlines()


def _join(lines):
    return "\n".join(lines) + "\n" if lines else ""


def _is_active(line):
    s = line.strip()
    return bool(s) and not s.startswith("#")


def _kv_re(key):
    # 支援「key = value」「key=value」「KEY value」
    return re.compile(r"^\s*" + re.escape(key) + r"(\s*=\s*|\s+)(.*?)\s*$")


def get_kv(text, key):
    """取最後一個有效設定值（後面的覆蓋前面的）。"""
    val = None
    rx = _kv_re(key)
    for line in _lines(text):
        if not _is_active(line):
            continue
        m = rx.match(line.split("#", 1)[0])
        if m:
            val = m.group(2).strip()
    return val


def set_kv(text, key, value, sep=" = "):
    """設定 key：取代第一個有效行，其餘重複行註解掉；沒有則附加在檔尾。"""
    rx = _kv_re(key)
    out, done = [], False
    for line in _lines(text):
        if _is_active(line) and rx.match(line.split("#", 1)[0]):
            if not done:
                out.append(key + sep + value)
                done = True
            else:
                out.append(MARK + line)
        else:
            out.append(line)
    if not done:
        out.append(key + sep + value)
    return _join(out)


def comment_kv(text, key, keep=None):
    """註解掉 key 的設定行；keep(value) 回傳 True 的保留。"""
    rx = _kv_re(key)
    out = []
    for line in _lines(text):
        m = rx.match(line.split("#", 1)[0]) if _is_active(line) else None
        if m and not (keep and keep(m.group(2).strip())):
            out.append(MARK + line)
        else:
            out.append(line)
    return _join(out)


# ---------- sysctl ----------

def parse_sysctl(text):
    """回傳 [(key, value)]，key 統一為點號格式。"""
    items = []
    for line in _lines(text):
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = k.strip().lstrip("-").strip().replace("/", ".")
        items.append((k, v.strip()))
    return items


def comment_sysctl(text, key, target):
    """註解掉 key 不等於 target 的行（文件作法：# *REMOVED*）。"""
    out = []
    for line in _lines(text):
        s = line.strip()
        if s and s[0] not in "#;" and "=" in s:
            k, v = s.split("=", 1)
            if k.strip().lstrip("-").strip().replace("/", ".") == key and v.strip() != target:
                out.append("# *REMOVED* by gcb-checker: " + line)
                continue
        out.append(line)
    return _join(out)


# ---------- GRUB ----------

# 值可為 "..."、'...' 或不加引號；允許行尾註解（# …）
_GRUB_RX = re.compile(r'^(\s*GRUB_CMDLINE_LINUX=)(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'#]*))(\s*(?:#.*)?)$')


def _grub_value(m):
    return next(g for g in (m.group(2), m.group(3), m.group(4)) if g is not None)


def grub_cmdline_get(text):
    val = None
    for line in _lines(text):
        if _is_active(line):
            m = _GRUB_RX.match(line)
            if m:
                val = _grub_value(m)
    return val


def grub_cmdline_add(text, arg):
    """在 GRUB_CMDLINE_LINUX 加入參數；同名參數（如 audit=0）會被取代。保留行尾註解。

    有 GRUB_CMDLINE_LINUX 但寫法無法解析（例如含變數展開的多段引號）時拋 ValueError，不修改。
    """
    name = arg.split("=", 1)[0]
    lines = _lines(text)
    idx = None
    for i, line in enumerate(lines):
        if _is_active(line) and line.strip().startswith("GRUB_CMDLINE_LINUX="):
            if not _GRUB_RX.match(line):
                raise ValueError("無法解析 GRUB_CMDLINE_LINUX：%s" % line.strip())
            idx = i
    if idx is None:
        lines.append('GRUB_CMDLINE_LINUX="%s"' % arg)
        return _join(lines)
    m = _GRUB_RX.match(lines[idx])
    parts = [p for p in _grub_value(m).split() if p.split("=", 1)[0] != name]
    parts.append(arg)
    lines[idx] = '%s"%s"%s' % (m.group(1), " ".join(parts), m.group(5))
    return _join(lines)


# ---------- sshd ----------

def _sshd_opt_rx(opt):
    return re.compile(r"^\s*" + re.escape(opt) + r"\s+", re.I)


def sshd_set_option(text, opt, value):
    """設定全域區段（第一個 Match 之前）的選項；sshd 以第一個出現的值為準。"""
    rx = _sshd_opt_rx(opt)
    lines = _lines(text)
    out, done, in_match, match_idx = [], False, False, None
    for line in lines:
        if _is_active(line) and re.match(r"^\s*Match\s", line, re.I):
            in_match = True
            if match_idx is None:
                match_idx = len(out)
        if not in_match and _is_active(line) and rx.match(line):
            if not done:
                out.append("%s %s" % (opt, value))
                done = True
            else:
                out.append(MARK + line)
            continue
        out.append(line)
    if not done:
        new = "%s %s" % (opt, value)
        if match_idx is None:
            out.append(new)
        else:
            out.insert(match_idx, new)
    return _join(out)


def sshd_comment_option(text, opt, keep_value):
    """在 drop-in 檔中註解掉與目標值衝突的全域選項。"""
    rx = _sshd_opt_rx(opt)
    out, in_match = [], False
    for line in _lines(text):
        if _is_active(line) and re.match(r"^\s*Match\s", line, re.I):
            in_match = True
        if not in_match and _is_active(line) and rx.match(line):
            val = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if val.lower() != keep_value.lower():
                out.append(MARK + line)
                continue
        out.append(line)
    return _join(out)


def sshd_includes(text):
    """取出 Include 指令的路徑樣式（相對路徑以 /etc/ssh 為基準）。"""
    pats = []
    for line in _lines(text):
        if _is_active(line) and re.match(r"^\s*Include\s", line, re.I):
            for p in line.split()[1:]:
                pats.append(p if p.startswith("/") else "/etc/ssh/" + p)
    return pats


def sshd_listen_ports(conf):
    """sshd -T 結果中 sshd 實際使用的埠：port 加上 listenaddress 帶埠的寫法（例：0.0.0.0:2222、[::]:2222）。

    設定 ListenAddress 0.0.0.0:2222 時，sshd -T 的 port 仍會顯示 22，只看 port 會漏掉 2222。
    """
    ports = [p for p in conf.get("port", []) if p.isdigit()]
    for a in conf.get("listenaddress", []):
        m = re.match(r"^(\[[^\]]+\]|[^:\s]+):(\d+)$", a.strip())
        if m:
            ports.append(m.group(2))
    return sorted(set(ports), key=int)


def parse_sshd_T(text):
    """解析 sshd -T 輸出為 {key: [values]}。"""
    d = {}
    for line in _lines(text):
        parts = line.strip().split(None, 1)
        if parts:
            d.setdefault(parts[0].lower(), []).append(parts[1] if len(parts) > 1 else "")
    return d


# ---------- modprobe ----------

def modprobe_status(texts, module):
    """傳入多個 modprobe.d 檔內容，回傳 (install 已停用, 已 blacklist)。"""
    install_ok = blacklist_ok = False
    for text in texts:
        for line in _lines(text):
            parts = line.split("#", 1)[0].split()
            if len(parts) >= 3 and parts[0] == "install" and parts[1] == module \
                    and parts[2] in ("/bin/true", "/bin/false", "/usr/bin/true", "/usr/bin/false"):
                install_ok = True
            if parts == ["blacklist", module]:
                blacklist_ok = True
    return install_ok, blacklist_ok


def modprobe_conf(text, module, install_target):
    """確保檔案含 install 與 blacklist 兩行。"""
    keep = []
    for line in _lines(text):
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] in ("install", "blacklist") and parts[1] == module:
            continue
        keep.append(line)
    keep += ["install %s %s" % (module, install_target), "blacklist %s" % module]
    return _join(keep)


# ---------- /etc/shadow ----------

def parse_shadow(text):
    """回傳 [dict(name, pw, lastchg, max)]。"""
    users = []
    for line in _lines(text):
        f = line.split(":")
        if len(f) < 5:
            continue
        users.append({"name": f[0], "pw": f[1], "lastchg": f[2], "max": f[4]})
    return users


def has_usable_password(pw):
    return bool(pw) and not pw.startswith(("!", "*"))


# ---------- /etc/fstab（磁碟與檔案系統：掛載選項類規則） ----------

def fstab_options(text, mount):
    """回傳掛載點在 fstab 的選項清單；沒有該列回傳 None（同一掛載點多列時取最後一列）。"""
    opts = None
    for line in _lines(text):
        p = line.split()
        if _is_active(line) and len(p) >= 4 and p[1] == mount:
            opts = p[3].split(",")
    return opts


def fstab_add_option(text, mount, option):
    """在掛載點那一列加入選項；沒有該列時新增（/dev/shm 預設沒有列在 fstab）。"""
    lines = _lines(text)
    idx = None
    for i, line in enumerate(lines):
        p = line.split()
        if _is_active(line) and len(p) >= 4 and p[1] == mount:
            idx = i
    if idx is None:
        if mount == "/dev/shm":
            lines.append("tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev,nosuid,%s\t0\t0" % option
                         if option not in ("nodev", "nosuid") else
                         "tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev,nosuid\t0\t0")
        else:
            raise ValueError("fstab 沒有 %s 的設定" % mount)
        return _join(lines)
    p = lines[idx].split()
    opts = p[3].split(",")
    if option not in opts:
        opts.append(option)
    p[3] = ",".join(opts)
    lines[idx] = "\t".join(p)
    return _join(lines)
