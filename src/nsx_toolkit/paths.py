"""Filesystem locations and time helpers.

Sensitive/operational data (credentials, audit log) lives in a hidden
per-user directory. Human-facing output (exports, change plans) goes
somewhere a person can actually find it.
"""

import datetime
import os


def utc_now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z")


def utc_now_stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")


def local_stamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


DATA_DIR = os.path.join(os.path.expanduser("~"), ".nsx_toolkit")
DEFAULT_INVENTORY_NAME = "inventory.json"
DEFAULT_TAXONOMY_NAMES = ("taxonomy.yaml", "taxonomy.yml", "taxonomy.json")
DEFAULT_CREDS_FILE = os.path.join(DATA_DIR, "credentials.env")
DEFAULT_AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")

# Audit log rotates at this size so it never grows without bound.
AUDIT_MAX_BYTES = 5 * 1024 * 1024
AUDIT_KEEP = 3


def _default_export_base():
    """Windows -> Documents\\nsxtoolkit ; Linux/Mac -> ~/nsxtoolkit"""
    home = os.path.expanduser("~")
    if os.name == "nt":
        docs = os.path.join(home, "Documents")
        base = docs if os.path.isdir(docs) else home
        return os.path.join(base, "nsxtoolkit")
    return os.path.join(home, "nsxtoolkit")


DEFAULT_EXPORT_DIR = os.path.join(_default_export_base(), "exports")
DEFAULT_TICKET_DIR = os.path.join(_default_export_base(), "change_plans")
DEFAULT_SNAPSHOT_DIR = os.path.join(_default_export_base(), "snapshots")


def config_search_dirs():
    """Where we look for inventory.json / taxonomy.yaml, in priority order.

    Current directory first so a per-project inventory wins, then the
    per-user data dir so a personal default always exists.
    """
    return [os.getcwd(), DATA_DIR]
