# -*- coding: utf-8 -*-
"""支援的作業系統登記表。新增作業系統時從這裡開始（步驟見 docs/開發指南.md「新增作業系統」）。

每個平台：
  key         平台代號，規則中用來對應 TWGCB-ID（例：rules 裡的 ids={"rhel9": ...}）
  family      系列：rhel / debian（決定套件管理、PAM 管理工具等共用行為）
  os_ids      /etc/os-release 的 ID（相容發行版一併列出）
  version     版本比對：主版號（"9"）或完整版號（"22.04"）
  doc_no      GCB 文件編號（TWGCB-01-<doc_no>）
  doc         報告中顯示的 GCB 文件名稱
  rules       規則套件名稱（gcb/rules/<rules>/），同系列多個版本可共用一個套件
  test_image  容器測試用的映像檔（tests/docker_test.sh）
"""


class Platform(object):
    def __init__(self, key, family, os_ids, version, doc_no, doc, rules, test_image):
        self.key = key
        self.family = family
        self.os_ids = os_ids
        self.version = version
        self.doc_no = doc_no
        self.doc = doc
        self.rules = rules
        self.test_image = test_image

    def matches(self, os_id, version_id):
        if os_id not in self.os_ids:
            return False
        if "." in self.version:
            return version_id == self.version
        return version_id.split(".")[0] == self.version


RHEL_LIKE = ("rhel", "rocky", "almalinux", "centos", "ol")

PLATFORMS = [
    Platform("rhel8", "rhel", RHEL_LIKE, "8", "008",
             "TWGCB-01-008 Red Hat Enterprise Linux 8 政府組態基準 v1.3", "rhel", "rockylinux:8"),
    Platform("rhel9", "rhel", RHEL_LIKE, "9", "012",
             "TWGCB-01-012 Red Hat Enterprise Linux 9 政府組態基準(伺服器) v1.2", "rhel", "rockylinux:9"),
    Platform("ubuntu2204", "debian", ("ubuntu",), "22.04", "014",
             "TWGCB-01-014 Ubuntu 22.04 LTS 政府組態基準 v1.2", "ubuntu", "ubuntu:22.04"),
]

BY_KEY = dict((p.key, p) for p in PLATFORMS)


def find(os_id, version_id):
    for p in PLATFORMS:
        if p.matches(os_id, version_id):
            return p
    return None


def rule_ids(**nums):
    """依平台代號產生 TWGCB-ID：rule_ids(rhel8=1, rhel9=1) → {"rhel8": "TWGCB-01-008-0001", ...}。"""
    out = {}
    for key, n in nums.items():
        if n:
            out[key] = "TWGCB-01-%s-%04d" % (BY_KEY[key].doc_no, n)
    return out


def supported_text():
    return "、".join("%s（%s）" % (p.key, p.doc.split(" ", 1)[1].split(" 政府")[0]) for p in PLATFORMS)
