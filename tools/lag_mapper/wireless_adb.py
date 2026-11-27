"""Trusted-Wi-Fi automatic Wireless ADB connection and USB handoff."""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence

from tools.chat_viewer.ingest import find_adb, list_adb_devices

TRUSTED_SSIDS: tuple[str, ...] = ("Kos gk atas", "Pribadi")

_STATE_LINE_RE = re.compile(r"^\s*State\s*:\s*(.+)$", re.IGNORECASE)
_SSID_LINE_RE = re.compile(r"^\s*SSID\s*:\s*(.+)$", re.IGNORECASE)


def parse_netsh_ssid(stdout: str) -> str | None:
    """Extract connected Wi-Fi SSID from `netsh wlan show interfaces` output."""
    ssid: str | None = None
    disconnected = False
    for line in stdout.splitlines():
        m_state = _STATE_LINE_RE.match(line)
        if m_state:
            val = m_state.group(1).strip().lower()
            if val != "connected":
                disconnected = True
            else:
                disconnected = False
            continue
        m_ssid = _SSID_LINE_RE.match(line)
        if m_ssid:
            candidate = m_ssid.group(1).strip()
            if candidate:
                ssid = candidate
    if disconnected:
        return None
    return ssid


def get_current_wifi_ssid() -> str | None:
    """Return the active Windows Wi-Fi SSID via `netsh`, or `None` if disconnected."""
    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_netsh_ssid(res.stdout or "")


def is_trusted_wifi(
    ssid: str | None,
    trusted_ssids: Sequence[str] = TRUSTED_SSIDS,
) -> bool:
    """Return True only when *ssid* matches one of the trusted Wi-Fi names."""
    if not ssid:
        return False
    norm = ssid.strip().casefold()
    if not norm:
        return False
    return any(norm == allowed.strip().casefold() for allowed in trusted_ssids)


def parse_mdns_services(stdout: str) -> list[dict[str, str]]:
    """Parse `adb mdns services` lines into service endpoint dicts."""
    services: list[dict[str, str]] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of discovered"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        instance, service, endpoint = parts[0], parts[1], parts[2]
        if service in ("_adb-tls-connect._tcp", "_adb._tcp") and ":" in endpoint:
            services.append({"instance": instance, "service": service, "endpoint": endpoint})
    return services


def discover_mdns_endpoints(adb_path: Path) -> list[dict[str, str]]:
    """Query `adb mdns services` without altering device state."""
    try:
        res = subprocess.run(
            [str(adb_path), "mdns", "services"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_mdns_services(res.stdout or "")


def _pick_usb_target(usb_devices: list[dict[str, str]]) -> dict[str, str]:
    for dev in usb_devices:
        model = dev.get("model", "")
        if dev["serial"] == "RRCY1032Y6F" or "SM_S936B" in model or "SM-S936B" in model:
            return dev
    return usb_devices[0]


def ensure_wireless_adb(
    adb_path: Path | str | None = None,
    *,
    trusted_ssids: Sequence[str] = TRUSTED_SSIDS,
    allow_usb_enable: bool = True,
    poll_seconds: float = 4.0,
    poll_interval: float = 0.5,
) -> dict[str, Any]:
    """Connect Wireless ADB automatically only when on a trusted Wi-Fi SSID."""
    adb = find_adb(adb_path)
    if adb is None:
        return {
            "ok": False,
            "trusted_wifi": False,
            "ssid": None,
            "trusted_ssids": list(trusted_ssids),
            "connected": [],
            "usb_devices": [],
            "safe_to_unplug": False,
            "devices": [],
            "message": "adb executable not found",
        }

    ssid = get_current_wifi_ssid()
    devices = list_adb_devices(adb)
    usb_devices = [d for d in devices if ":" not in d["serial"] and d.get("state") == "device"]

    if not is_trusted_wifi(ssid, trusted_ssids):
        return {
            "ok": False,
            "trusted_wifi": False,
            "ssid": ssid,
            "trusted_ssids": list(trusted_ssids),
            "connected": [],
            "usb_devices": [d["serial"] for d in usb_devices],
            "safe_to_unplug": False,
            "devices": devices,
            "message": (
                f"Wi-Fi '{ssid or 'disconnected'}' is not trusted. "
                f"Wireless ADB only auto-enables on: {', '.join(trusted_ssids)}."
            ),
        }

    def _wireless_serials(devs: list[dict[str, str]]) -> list[str]:
        return [d["serial"] for d in devs if ":" in d["serial"] and d.get("state") == "device"]

    def _try_connect_mdns(current_wireless: list[str]) -> tuple[list[dict[str, str]], list[str]]:
        endpoints = discover_mdns_endpoints(adb)
        tls_eps = [e["endpoint"] for e in endpoints if e["service"] == "_adb-tls-connect._tcp"]
        tcp_eps = [e["endpoint"] for e in endpoints if e["service"] == "_adb._tcp"]
        candidates = tls_eps if tls_eps else tcp_eps
        for ep in candidates:
            if ep in current_wireless:
                continue
            try:
                subprocess.run(
                    [str(adb), "connect", ep],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                continue
        updated = list_adb_devices(adb)
        return updated, _wireless_serials(updated)

    wireless = _wireless_serials(devices)
    if not wireless:
        devices, wireless = _try_connect_mdns(wireless)

    if not wireless and allow_usb_enable and usb_devices:
        target = _pick_usb_target(usb_devices)
        try:
            subprocess.run(
                [str(adb), "-s", target["serial"], "shell", "settings", "put", "global", "adb_wifi_enabled", "1"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass

        deadline = time.monotonic() + max(0.0, poll_seconds)
        while not wireless:
            devices, wireless = _try_connect_mdns(wireless)
            if wireless or time.monotonic() >= deadline:
                break
            time.sleep(max(0.01, poll_interval))

    usb_serials = [d["serial"] for d in devices if ":" not in d["serial"] and d.get("state") == "device"]
    if wireless:
        msg = f"Wi-Fi '{ssid}': wireless ADB ready ({', '.join(wireless)}) — safe to unplug USB"
    elif usb_serials:
        msg = f"Wi-Fi '{ssid}': USB device {usb_serials[0]} detected, waiting for wireless ADB advertisement"
    else:
        msg = f"Wi-Fi '{ssid}': no paired wireless ADB target advertised yet"

    return {
        "ok": bool(wireless),
        "trusted_wifi": True,
        "ssid": ssid,
        "trusted_ssids": list(trusted_ssids),
        "connected": wireless,
        "usb_devices": usb_serials,
        "safe_to_unplug": bool(wireless),
        "devices": devices,
        "message": msg,
    }


def disable_wireless_adb(
    adb_path: Path | str | None = None,
    *,
    serial: str | None = None,
) -> dict[str, Any]:
    """Turn off `adb_wifi_enabled` on the phone and disconnect wireless ADB endpoints."""
    adb = find_adb(adb_path)
    if adb is None:
        return {
            "ok": False,
            "trusted_wifi": False,
            "ssid": get_current_wifi_ssid(),
            "trusted_ssids": list(TRUSTED_SSIDS),
            "connected": [],
            "safe_to_unplug": False,
            "devices": [],
            "message": "adb executable not found",
        }

    devices = list_adb_devices(adb)
    online = [d for d in devices if d.get("state") == "device"]
    usb_online = [d for d in online if ":" not in d["serial"]]
    wireless_online = [d["serial"] for d in online if ":" in d["serial"]]

    target_serial = serial.strip() if serial else (
        usb_online[0]["serial"] if usb_online else (wireless_online[0] if wireless_online else None)
    )
    if target_serial:
        try:
            subprocess.run(
                [str(adb), "-s", target_serial, "shell", "settings", "put", "global", "adb_wifi_enabled", "0"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    for w_ep in wireless_online:
        try:
            subprocess.run(
                [str(adb), "disconnect", w_ep],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    updated = list_adb_devices(adb)
    remaining = [d["serial"] for d in updated if ":" in d["serial"] and d.get("state") == "device"]
    ssid = get_current_wifi_ssid()
    return {
        "ok": not remaining,
        "trusted_wifi": is_trusted_wifi(ssid),
        "ssid": ssid,
        "trusted_ssids": list(TRUSTED_SSIDS),
        "connected": remaining,
        "safe_to_unplug": False,
        "devices": updated,
        "message": "Wireless ADB disabled" if not remaining else f"Still connected: {', '.join(remaining)}",
    }
