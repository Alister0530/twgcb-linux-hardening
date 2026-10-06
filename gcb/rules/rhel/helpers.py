# -*- coding: utf-8 -*-
"""RHEL 8 / 9 規則共用的小工具。"""
from ...platforms import rule_ids


def R(r8=None, r9=None):
    """RHEL 規則編號：R(r8=220, r9=218) → {"rhel8": "TWGCB-01-008-0220", "rhel9": "TWGCB-01-012-0218"}。

    只有單一版本的規則，另一版不填（例：R(r9=285)）。對照見 docs/specs/rhel/編號對照.md。
    """
    return rule_ids(rhel8=r8, rhel9=r9)
