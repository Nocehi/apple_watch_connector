#!/usr/bin/env python3
"""Forward Linux desktop (and KDE Connect) D-Bus notifications to Apple Watch Companion.

Monitors org.freedesktop.Notifications.Notify via org.freedesktop.DBus.Monitoring.BecomeMonitor
so it never replaces or interferes with the desktop notification daemon (DMS/Quickshell).
Encodes BulletinDistributorCodec.BulletinRequest in pure Python and submits it over the
same-user UNIX domain control socket exposed by apple_watch_companion.
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import re
import signal
import socket
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LENGTH_DELIMITED = 2

UPDATE_TYPE_ADD = 0
DEFAULT_FEED = 59
DEFAULT_SECTION_SUBTYPE = 2
DEFAULT_SOUND_ALERT_TYPE = 2

_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _encode_varint(value: int) -> bytes:
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _encode_tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_bytes_field(field_number: int, data: bytes) -> bytes:
    return _encode_tag(field_number, WIRE_LENGTH_DELIMITED) + _encode_varint(len(data)) + data


def _encode_string_field(field_number: int, value: str) -> bytes:
    return _encode_bytes_field(field_number, value.encode("utf-8"))


def _encode_double_field(field_number: int, value: float) -> bytes:
    return _encode_tag(field_number, WIRE_FIXED64) + struct.pack("<d", value)


def _encode_varint_field(field_number: int, value: int) -> bytes:
    return _encode_tag(field_number, WIRE_VARINT) + _encode_varint(value)


def encode_bulletin_request(
    *,
    title: str,
    body: str,
    section_id: str = "com.apple.MobileSMS",
    section_display_name: str = "Linux",
    subtitle: str | None = None,
    sound: bool = True,
    turns_on_display: bool | None = None,
    bulletin_id: str | None = None,
    timestamp_ms: int | None = None,
    update_type: int = UPDATE_TYPE_ADD,
) -> tuple[str, bytes]:
    """Encode a BulletinDistributorCodec.BulletinRequest matching the Java codec."""
    bid = bulletin_id or str(uuid.uuid4())
    ts_ms = timestamp_ms if timestamp_ms and timestamp_ms > 0 else int(time.time() * 1000)
    ts_sec = ts_ms / 1000.0
    wake = sound if turns_on_display is None else turns_on_display

    b = bytearray()
    b += _encode_string_field(1, bid)
    b += _encode_string_field(2, section_id)
    b += _encode_string_field(3, section_display_name)
    b += _encode_string_field(4, title)
    if subtitle:
        b += _encode_string_field(5, subtitle)
    b += _encode_string_field(6, body)
    b += _encode_double_field(7, ts_sec)
    b += _encode_varint_field(10, DEFAULT_FEED)
    b += _encode_string_field(12, bid)
    b += _encode_string_field(13, bid)
    b += _encode_varint_field(15, DEFAULT_SECTION_SUBTYPE)
    b += _encode_varint_field(19, 1 if sound else 0)
    b += _encode_varint_field(24, DEFAULT_SOUND_ALERT_TYPE)
    b += _encode_varint_field(30, 1 if wake else 0)
    b += _encode_string_field(43, str(uuid.uuid4()))

    req = bytearray()
    req += _encode_bytes_field(1, bytes(b))
    req += _encode_varint_field(2, 1 if sound else 0)
    req += _encode_double_field(3, ts_sec)
    req += _encode_varint_field(4, update_type)
    return bid, bytes(req)


def clean_text(text: str, max_len: int) -> str:
    if not text:
        return ""
    stripped = _HTML_TAG_RE.sub("", text)
    stripped = html.unescape(stripped)
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    joined = "\n".join(lines).strip()
    if len(joined) > max_len:
        return joined[: max_len - 1] + "…"
    return joined


def default_socket_path() -> Path:
    override = os.environ.get("WATCH_COMPANION_CONTROL_SOCKET")
    if override:
        return Path(override)
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        raise RuntimeError("XDG_RUNTIME_DIR is not set")
    return Path(runtime) / "watch-companion" / "control.sock"


def default_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "watch-companion" / "notify-relay.json"


@dataclass
class RelayConfig:
    enabled: bool = True
    section_id: str = "com.apple.MobileSMS"
    silent: bool = False
    ignore_transient: bool = True
    ignore_low_urgency: bool = False
    dedupe_window_sec: float = 5.0
    min_interval_sec: float = 0.5
    max_title_len: int = 160
    max_body_len: int = 800
    ignore_apps: list[str] = field(
        default_factory=lambda: [
            "apple_watch_companion",
            "Watch Companion",
            "notify-osd",
            "Volume",
            "Brightness",
        ]
    )
    ignore_categories: list[str] = field(
        default_factory=lambda: [
            "device.added",
            "device.removed",
            "transfer.complete",
        ]
    )

    @classmethod
    def load(cls, path: Path) -> "RelayConfig":
        cfg = cls()
        if not path.is_file():
            return cfg
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[watch-notify-relay] invalid config {path}: {exc}", file=sys.stderr)
            return cfg
        if not isinstance(raw, dict):
            return cfg
        for key in (
            "enabled",
            "section_id",
            "silent",
            "ignore_transient",
            "ignore_low_urgency",
            "dedupe_window_sec",
            "min_interval_sec",
            "max_title_len",
            "max_body_len",
            "ignore_apps",
            "ignore_categories",
        ):
            if key in raw:
                setattr(cfg, key, raw[key])
        return cfg


class NotificationFilter:
    def __init__(self, config: RelayConfig) -> None:
        self.config = config
        self._recent: dict[tuple[str, str, str], float] = {}
        self._last_sent_at: float = 0.0
        self._ignore_apps_lower = {a.lower() for a in config.ignore_apps}
        self._ignore_categories_lower = {c.lower() for c in config.ignore_categories}

    def evaluate(
        self,
        app_name: str,
        summary: str,
        body: str,
        hints: dict[str, Any],
        now: float | None = None,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        ts = time.monotonic() if now is None else now
        if not self.config.enabled:
            return False, "disabled", None

        app = clean_text(str(app_name or ""), 80) or "Linux"
        desktop_entry = str(hints.get("desktop-entry", "") or "").strip()
        if app.lower() in self._ignore_apps_lower or desktop_entry.lower() in self._ignore_apps_lower:
            return False, f"ignored_app:{app}", None

        category = str(hints.get("category", "") or "").strip().lower()
        if category and category in self._ignore_categories_lower:
            return False, f"ignored_category:{category}", None

        if self.config.ignore_transient and bool(hints.get("transient", False)):
            return False, "transient", None

        urgency = hints.get("urgency", 1)
        try:
            urgency_val = int(urgency)
        except (TypeError, ValueError):
            urgency_val = 1
        if self.config.ignore_low_urgency and urgency_val == 0:
            return False, "low_urgency", None

        title = clean_text(str(summary or ""), self.config.max_title_len)
        msg = clean_text(str(body or ""), self.config.max_body_len)
        if not title and not msg:
            return False, "empty", None
        if not title:
            title = app
        if not msg:
            msg = title
            title = app

        # Prune expired deduplication entries.
        cutoff = ts - self.config.dedupe_window_sec
        self._recent = {k: v for k, v in self._recent.items() if v >= cutoff}
        key = (app.lower(), title, msg)
        if key in self._recent:
            return False, "duplicate", None

        if self._last_sent_at > 0 and (ts - self._last_sent_at) < self.config.min_interval_sec:
            return False, "rate_limited", None

        self._recent[key] = ts
        self._last_sent_at = ts

        suppress_sound = bool(hints.get("suppress-sound", False))
        sound = (not self.config.silent) and (not suppress_sound)
        subtitle = app if app.lower() != title.lower() else None
        return True, "ok", {
            "section_display_name": app,
            "title": title,
            "subtitle": subtitle,
            "body": msg,
            "sound": sound,
        }


def send_to_socket(socket_path: Path, payload_b64: str, timeout: float = 2.0) -> dict[str, Any]:
    request = json.dumps({"method": "sendBulletin", "payload": payload_b64}, separators=(",", ":")) + "\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(str(socket_path))
        sock.sendall(request.encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\n" in data or sum(len(c) for c in chunks) > 65536:
                break
    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    return json.loads(raw) if raw else {"status": "EMPTY_RESPONSE"}


def _unwrap_dbus_hints(raw_hints: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not isinstance(raw_hints, dict):
        return result
    for k, v in raw_hints.items():
        key = str(k)
        if isinstance(v, (bool, int, float, str)):
            result[key] = v
        else:
            try:
                result[key] = int(v)
            except (TypeError, ValueError):
                result[key] = str(v)
    return result


def run_monitor(config: RelayConfig, socket_path: Path, dry_run: bool, verbose: bool) -> int:
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    filt = NotificationFilter(config)

    def on_message(_connection: Any, message: Any) -> Any:
        if message.get_type() != dbus.lowlevel.MESSAGE_TYPE_METHOD_CALL:
            return dbus.lowlevel.HANDLER_RESULT_HANDLED
        if message.get_interface() != "org.freedesktop.Notifications" or message.get_member() != "Notify":
            return dbus.lowlevel.HANDLER_RESULT_HANDLED
        args = message.get_args_list()
        if len(args) < 7:
            return dbus.lowlevel.HANDLER_RESULT_HANDLED
        app_name = str(args[0])
        summary = str(args[3])
        body = str(args[4])
        hints = _unwrap_dbus_hints(args[6])

        allow, reason, item = filt.evaluate(app_name, summary, body, hints)
        if not allow or item is None:
            if verbose:
                print(f"[watch-notify-relay] skip ({reason}) app={app_name!r}", flush=True)
            return dbus.lowlevel.HANDLER_RESULT_HANDLED

        bid, raw_proto = encode_bulletin_request(
            title=item["title"],
            subtitle=item["subtitle"],
            body=item["body"],
            section_id=config.section_id,
            section_display_name=item["section_display_name"],
            sound=item["sound"],
        )
        encoded = base64.b64encode(raw_proto).decode("ascii")
        if dry_run:
            print(
                f"[watch-notify-relay] dry-run id={bid} app={item['section_display_name']!r} "
                f"title={item['title']!r} len={len(raw_proto)}",
                flush=True,
            )
            return dbus.lowlevel.HANDLER_RESULT_HANDLED

        try:
            resp = send_to_socket(socket_path, encoded)
            print(
                f"[watch-notify-relay] sent id={bid} app={item['section_display_name']!r} "
                f"status={resp.get('status')}",
                flush=True,
            )
        except OSError as exc:
            print(f"[watch-notify-relay] socket unavailable ({socket_path}): {exc}", file=sys.stderr, flush=True)
        except Exception as exc:
            print(f"[watch-notify-relay] send error: {exc}", file=sys.stderr, flush=True)
        return dbus.lowlevel.HANDLER_RESULT_HANDLED

    bus.add_message_filter(on_message)
    mon = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
    iface = dbus.Interface(mon, "org.freedesktop.DBus.Monitoring")
    iface.BecomeMonitor(
        ["type='method_call',interface='org.freedesktop.Notifications',member='Notify'"],
        dbus.UInt32(0),
    )

    loop = GLib.MainLoop()

    def _stop(_sig: int, _frame: Any) -> None:
        loop.quit()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"[watch-notify-relay] listening on session D-Bus -> {socket_path}", flush=True)
    loop.run()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Relay Linux D-Bus notifications to Apple Watch Companion.")
    parser.add_argument("--socket", type=Path, default=None, help="Control socket path")
    parser.add_argument("--config", type=Path, default=None, help="JSON config path")
    parser.add_argument("--dry-run", action="store_true", help="Do not send to control socket")
    parser.add_argument("--verbose", action="store_true", help="Log skipped notifications")
    args = parser.parse_args()

    cfg = RelayConfig.load(args.config or default_config_path())
    sock_path = args.socket or default_socket_path()
    return run_monitor(cfg, sock_path, dry_run=args.dry_run, verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
