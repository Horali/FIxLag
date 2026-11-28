"""Only the SM-S936B is listed, so no tool can switch to another phone on adb."""
import subprocess
from types import SimpleNamespace

from tools.chat_viewer import ingest

DEVICES = """List of devices attached
0953925324001286       device product:X6815D-GL model:Infinix_X6815D device:Infinix-X6815D transport_id:29
192.168.1.52:5555      device product:X6815D-GL model:Infinix_X6815D device:Infinix-X6815D transport_id:30
192.168.1.6:39059      device product:pa2qxxx model:SM_S936B device:pa2q transport_id:22
"""


def _fake(monkeypatch):
    monkeypatch.setattr(ingest, "find_adb", lambda _p=None: "adb")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=DEVICES))


def test_only_the_samsung_is_listed(monkeypatch):
    _fake(monkeypatch)
    monkeypatch.delenv("FIXLAG_ADB_MODEL", raising=False)
    assert [d["serial"] for d in ingest.list_adb_devices()] == ["192.168.1.6:39059"]


def test_any_lists_every_device(monkeypatch):
    _fake(monkeypatch)
    monkeypatch.setenv("FIXLAG_ADB_MODEL", "any")
    assert len(ingest.list_adb_devices()) == 3
