# -*- coding: utf-8 -*-
"""Ubuntu 22.04 規則共用的小工具。"""


def U(n):
    """Ubuntu 22.04 的規則編號：U(2) → TWGCB-01-014-0002。"""
    return {"ubuntu2204": "TWGCB-01-014-%04d" % n}
