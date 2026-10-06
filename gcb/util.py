# -*- coding: utf-8 -*-
"""共用工具：執行指令、檔案讀寫、時間。需相容 Python 3.6（RHEL 8 platform-python）。"""
import contextlib
import datetime
import difflib
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time


class CmdResult(object):
    def __init__(self, cmd, rc, out, err):
        self.cmd = cmd
        self.rc = rc
        self.out = out
        self.err = err

    @property
    def ok(self):
        return self.rc == 0

    def text(self):
        return (self.out + "\n" + self.err).strip()


def cmd_str(cmd):
    if isinstance(cmd, str):
        return cmd
    return " ".join(shlex.quote(c) for c in cmd)


# ---- 執行進度：指令執行超過 HEARTBEAT 秒時，定期回報「仍在執行」，避免畫面空白看似當機 ----
HEARTBEAT = 30
_progress = None   # callable(目前工作說明, 已執行秒數)；由 engine 設定
_activity = []     # 目前工作說明（堆疊，內層優先）


def set_progress(fn):
    global _progress
    _progress = fn


@contextlib.contextmanager
def activity(text):
    """標示目前在做什麼（例：修復 TWGCB-01-014-0033：初始化 AIDE 資料庫），供進度回報使用。"""
    _activity.append(text)
    try:
        yield
    finally:
        _activity.pop()


def elapsed_str(sec):
    sec = int(sec)
    return "%d 分 %02d 秒" % (sec // 60, sec % 60) if sec >= 60 else "%d 秒" % sec


def run(cmd, timeout=120, env=None, input_text=None):
    """執行指令；字串走 shell，list 直接執行。輸出一律以 UTF-8 解碼，避免 C locale 下出錯。

    stdin 不接終端機：指令若要求互動輸入（例如 dpkg 詢問設定檔）會直接讀到結尾而失敗，不會無聲卡住。
    """
    shell = isinstance(cmd, str)
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    full_env["LANG"] = "C"
    if env:
        full_env.update(env)
    data = input_text.encode("utf-8") if input_text is not None else None
    try:
        p = subprocess.Popen(cmd, shell=shell, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=full_env)
    except OSError as e:
        return CmdResult(cmd_str(cmd), 127, "", str(e))
    start, first = time.time(), True
    while True:
        left = timeout - (time.time() - start)
        try:
            out, err = p.communicate(input=data if first else None, timeout=max(0.1, min(HEARTBEAT, left)))
            break
        except subprocess.TimeoutExpired:
            first = False
            spent = time.time() - start
            if spent >= timeout:
                p.kill()
                p.communicate()
                return CmdResult(cmd_str(cmd), 124, "", "執行逾時（%s 秒）" % timeout)
            if _progress:
                _progress(_activity[-1] if _activity else cmd_str(cmd)[:100], spent)
    return CmdResult(cmd_str(cmd), p.returncode, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))


def which(name):
    found = shutil.which(name)
    if found:
        return found
    for d in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        p = os.path.join(d, name)
        if os.access(p, os.X_OK):
            return p
    return None


def read_text(path):
    """讀檔，不存在回傳 None。"""
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except (IOError, OSError):
        return None


def write_text_atomic(path, text, mode=None):
    """以暫存檔 + rename 寫入，保留原檔權限與擁有者。

    path 是符號連結時寫入它指向的實際檔案，避免把連結換成一般檔案
    （例：Ubuntu 的 /etc/sysctl.d/99-sysctl.conf → /etc/sysctl.conf）。
    """
    path = os.path.realpath(path)
    d = os.path.dirname(path) or "."
    if not os.path.isdir(d):
        os.makedirs(d, 0o755)
    st = None
    if os.path.exists(path):
        st = os.stat(path)
    fd, tmp = tempfile.mkstemp(prefix=".gcb-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        if st is not None:
            os.chmod(tmp, st.st_mode & 0o7777)
            os.chown(tmp, st.st_uid, st.st_gid)
        else:
            os.chmod(tmp, mode if mode is not None else 0o644)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    restorecon(path)


def restorecon(path):
    """SELinux 系統上修正檔案標籤。"""
    rc = which("restorecon")
    if rc and os.path.exists("/sys/fs/selinux"):
        run([rc, "-R", path], timeout=60)


def diff_summary(old, new, limit=40):
    """產生 log 用的精簡差異（- 修改前 / + 修改後）。"""
    old_lines = (old or "").splitlines()
    new_lines = (new or "").splitlines()
    out = []
    for line in difflib.unified_diff(old_lines, new_lines, lineterm="", n=0):
        if line.startswith(("---", "+++", "@@")):
            continue
        out.append(line)
    if len(out) > limit:
        out = out[:limit] + ["...（其餘 %d 行省略）" % (len(out) - limit)]
    return "\n".join(out) if out else "（無差異）"


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def hostname():
    return socket.gethostname()


def primary_ip():
    r = run(["hostname", "-I"], timeout=10)
    if r.ok and r.out.split():
        return r.out.split()[0]
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.error:
        return ""


def split_csv(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]
