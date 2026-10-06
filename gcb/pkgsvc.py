# -*- coding: utf-8 -*-
"""套件、服務、sysctl 的查詢工具（不做修改）。"""
import glob
import os

from .textedit import parse_sysctl
from .util import read_text, run, which

APT_ENV = {"DEBIAN_FRONTEND": "noninteractive"}


# ---------- 套件 ----------

def pkg_installed(osi, pkg):
    if osi.family == "rhel":
        return run(["rpm", "-q", pkg], timeout=30).ok
    r = run(["dpkg-query", "-W", "-f=${Status}", pkg], timeout=30)
    st = r.out.split()
    return r.ok and len(st) >= 3 and st[2] == "installed"  # 例："install ok installed"、"hold ok installed"


def pkg_list(osi):
    """目前已安裝的套件名稱集合（用來找出安裝時連帶加入的相依套件）。"""
    if osi.family == "rhel":
        r = run(["rpm", "-qa", "--qf", "%{NAME}\n"], timeout=120)
        return set(r.out.split())
    r = run(["dpkg-query", "-W", "-f=${Package} ${Status}\n"], timeout=120)
    return set(l.split()[0] for l in r.out.splitlines() if len(l.split()) >= 4 and l.split()[3] == "installed")


def pkg_install_cmd(osi, pkg):
    if osi.family == "rhel":
        return ["dnf", "-y", "install", pkg]
    # 設定檔被修改過時保留原檔、不詢問（否則 dpkg 會停下來等回答）
    return ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
            "install", pkg]


def pkg_remove_cmd(osi, pkg):
    if osi.family == "rhel":
        return ["dnf", "-y", "remove", pkg]
    return ["apt-get", "-y", "purge", pkg]


def pkg_dependents(osi, pkg):
    """移除前預覽：回傳會被連帶移除的其他套件。"""
    if osi.family == "rhel":
        r = run(["rpm", "-q", "--whatrequires", pkg], timeout=30)
        if r.ok:
            return [l for l in r.out.splitlines() if l.strip()]
        return []
    r = run(["apt-get", "-s", "purge", pkg], timeout=60, env=APT_ENV)
    names = [l.split()[1] for l in r.out.splitlines() if l.startswith(("Purg ", "Remv "))]
    return [n for n in names if n != pkg]


# ---------- 服務 ----------

def svc_state(unit):
    """回傳 (is-enabled, is-active) 字串；找不到為 not-found。"""
    if not which("systemctl"):
        return "not-found", "unknown"
    r = run(["systemctl", "is-enabled", unit], timeout=30)
    enabled = r.out.strip().splitlines()[-1] if r.out.strip() else ""
    if not enabled or "No such file" in r.err or "not-found" in r.err:
        enabled = "not-found"
    a = run(["systemctl", "is-active", unit], timeout=30).out.strip() or "unknown"
    return enabled, a


def svc_exists(unit):
    return svc_state(unit)[0] != "not-found"


# ---------- sysctl ----------

SYSCTL_DIRS = ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d",
               "/usr/lib/sysctl.d", "/lib/sysctl.d"]


def sysctl_files():
    """依 systemd-sysctl 的順序列出設定檔（同檔名以 /etc 優先）。"""
    chosen, real_seen = {}, set()
    for d in SYSCTL_DIRS:
        for f in sorted(glob.glob(os.path.join(d, "*.conf"))):
            base = os.path.basename(f)
            if base not in chosen:
                chosen[base] = f
    files = []
    for base in sorted(chosen):
        rp = os.path.realpath(chosen[base])
        if rp in real_seen:
            continue
        real_seen.add(rp)
        files.append(chosen[base])
    if os.path.exists("/etc/sysctl.conf") and os.path.realpath("/etc/sysctl.conf") not in real_seen:
        files.append("/etc/sysctl.conf")
    return files


def sysctl_persistent(key):
    """回傳 (開機後生效值, 來源檔, [所有設定位置])。"""
    val, src, where = None, None, []
    for f in sysctl_files():
        for k, v in parse_sysctl(read_text(f)):
            if k == key:
                val, src = v, f
                where.append((f, v))
    return val, src, where


def sysctl_runtime(key):
    """目前生效值；參數不存在（例如 IPv6 停用）回傳 None。"""
    val = read_text("/proc/sys/" + key.replace(".", "/"))
    return val.strip() if val is not None else None
