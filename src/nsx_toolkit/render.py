"""Shared formatting for tags and group membership criteria."""

import json

from .api import (
    F_CONJ_OP,
    F_EXPRESSIONS,
    F_IP_ADDRESSES,
    F_KEY,
    F_MEMBER_TYPE,
    F_OPERATOR,
    F_PATHS,
    F_TAG_SCOPE,
    F_TAG_VALUE,
    F_TAGS,
    F_VALUE,
    KEY_TAG,
    RT,
    RT_CONDITION,
    RT_CONJUNCTION,
    RT_IPADDRESS,
    RT_NESTED,
    RT_PATHEXPR,
    TAG_SCOPE_SEPARATOR,
)
from .output import cB, cC, cD, cG, strip_ansi


def tags_of(obj):
    return [(t.get(F_TAG_SCOPE, ""), t.get(F_TAG_VALUE, ""))
            for t in (obj.get(F_TAGS) or [])]


def fmt_tags(pairs):
    if not pairs:
        return cD("(none)")
    return ", ".join("{}={}".format(cC(s), t) if s else t
                     for s, t in sorted(pairs))


def fmt_tags_plain(pairs):
    if not pairs:
        return "(none)"
    return ", ".join("{}={}".format(s, t) if s else t for s, t in sorted(pairs))


def describe_expression(expr):
    """Human-readable lines for a group's membership criteria."""
    if not expr:
        return [cD("(no criteria)")]
    lines = []
    for item in expr:
        rt = item.get(RT)
        if rt == RT_CONJUNCTION:
            lines.append("  {}".format(cB(item.get(F_CONJ_OP, "?"))))
        elif rt == RT_CONDITION:
            key = item.get(F_KEY, "?")
            op = item.get(F_OPERATOR, "?")
            val = item.get(F_VALUE, "")
            mt = item.get(F_MEMBER_TYPE, "")
            if key == KEY_TAG and TAG_SCOPE_SEPARATOR in str(val):
                s, _, t = str(val).partition(TAG_SCOPE_SEPARATOR)
                lines.append("  {} Tag {} {}={}".format(mt, op, cC(s), cG(t)))
            else:
                lines.append("  {} {} {} '{}'".format(mt, key, op, val))
        elif rt == RT_NESTED:
            lines.append("  ( nested:")
            for sub in describe_expression(item.get(F_EXPRESSIONS, [])):
                lines.append("  {}".format(sub))
            lines.append("  )")
        elif rt == RT_IPADDRESS:
            ips = item.get(F_IP_ADDRESSES, [])
            lines.append("  IPs ({}): {}{}".format(
                len(ips), ", ".join(map(str, ips[:8])),
                " ..." if len(ips) > 8 else ""))
        elif rt == RT_PATHEXPR:
            paths = item.get(F_PATHS, [])
            lines.append("  Paths ({}):".format(len(paths)))
            for p in paths[:10]:
                lines.append("    {}".format(p))
        else:
            lines.append("  {}: {}".format(rt or "unknown", json.dumps(item)[:160]))
    return lines


def criteria_summary(expr, parts=3):
    """Flat one-line version of the criteria, for CSV columns."""
    lines = describe_expression(expr)
    return "; ".join(strip_ansi(ln).strip() for ln in lines[:parts])
