# -*- coding: utf-8 -*-
"""偵測作業系統，對應到 platforms.py 登記的平台與 GCB 文件。"""
from . import platforms
from .util import read_text


class OSInfo(object):
    def __init__(self, key, family, pretty, os_id, version):
        self.key = key            # 平台代號，例：rhel8 / rhel9 / ubuntu2204
        self.family = family      # rhel / debian
        self.pretty = pretty
        self.os_id = os_id
        self.version = version
        self.ssh_unit = "sshd" if family == "rhel" else "ssh"

    @property
    def platform(self):
        return platforms.BY_KEY.get(self.key)

    @property
    def gcb_doc(self):
        return self.platform.doc if self.platform else ""

    @property
    def compatible_note(self):
        if self.family == "rhel" and self.os_id != "rhel":
            return "%s 與 RHEL 相容，套用 RHEL 規範" % self.os_id
        return ""

    def version_tuple(self):
        try:
            return tuple(int(x) for x in self.version.split("."))
        except ValueError:
            return (0,)


def parse_os_release(text):
    data = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k] = v.strip().strip('"').strip("'")
    return data


def detect(path="/etc/os-release"):
    """回傳 (OSInfo, "")；不支援的系統回傳 (None, 說明)。"""
    data = parse_os_release(read_text(path))
    os_id = data.get("ID", "")
    ver = data.get("VERSION_ID", "")
    pretty = data.get("PRETTY_NAME", os_id)
    p = platforms.find(os_id, ver)
    if p:
        return OSInfo(p.key, p.family, pretty, os_id, ver), ""
    return None, "不支援的作業系統：%s（目前支援：%s）" % (pretty or "未知", platforms.supported_text())
