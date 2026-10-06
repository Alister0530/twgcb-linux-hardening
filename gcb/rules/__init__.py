# -*- coding: utf-8 -*-
"""規則清單入口：合併跨平台共用規則（common.py）與 platforms.py 登記的各平台規則套件。"""
import importlib

from .. import platforms
from . import common
from .base import ERROR, FAIL, NA, PASS, Check, Rule  # noqa: F401


def _catalogs():
    cats = [common.RULES]
    for name in sorted(set(p.rules for p in platforms.PLATFORMS)):
        cats.append(importlib.import_module("." + name, __name__).RULES)  # 載入錯誤直接顯示，不可略過
    return cats


def rules_for(osi):
    """回傳 [(rule_id, rule)]，依 TWGCB-ID 排序；同一編號重複定義視為程式錯誤。"""
    found = {}
    for rules in _catalogs():
        for r in rules:
            rid = r.rule_id(osi)
            if not rid:
                continue
            if rid in found:
                raise RuntimeError("規則編號重複定義：%s" % rid)
            found[rid] = r
    return sorted(found.items())
