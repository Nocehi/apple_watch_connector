#!/usr/bin/env python3
"""Unit tests for watch_notify_relay.py, including Java BulletinDistributorCodec round-trip."""

from __future__ import annotations

import base64
import subprocess
import unittest
from pathlib import Path

import watch_notify_relay as relay

ROOT = Path(__file__).resolve().parent.parent
PROTOCOL_DIR = ROOT / "apple-watch-companion/build/linux/x64/release/bundle/lib/protocol"


class RelayFilterTests(unittest.TestCase):
    def test_ignores_transient_and_configured_apps(self) -> None:
        f = relay.NotificationFilter(relay.RelayConfig())
        ok, reason, _ = f.evaluate("Volume", "75%", "", {"transient": True}, now=10.0)
        self.assertFalse(ok)
        self.assertEqual(reason, "ignored_app:Volume")

        ok, reason, _ = f.evaluate("OSD", "Brightness", "50%", {"transient": True}, now=11.0)
        self.assertFalse(ok)
        self.assertEqual(reason, "transient")

    def test_dedupes_within_window_and_allows_after(self) -> None:
        f = relay.NotificationFilter(relay.RelayConfig(dedupe_window_sec=5.0, min_interval_sec=0.1))
        ok1, _, item1 = f.evaluate("KDE Connect", "WhatsApp", "Hello", {}, now=100.0)
        self.assertTrue(ok1)
        assert item1 is not None
        self.assertEqual(item1["section_display_name"], "KDE Connect")
        self.assertEqual(item1["title"], "WhatsApp")
        self.assertEqual(item1["body"], "Hello")

        ok2, reason2, _ = f.evaluate("KDE Connect", "WhatsApp", "Hello", {}, now=102.0)
        self.assertFalse(ok2)
        self.assertEqual(reason2, "duplicate")

        ok3, _, _ = f.evaluate("KDE Connect", "WhatsApp", "Hello", {}, now=106.0)
        self.assertTrue(ok3)

    def test_strips_html_and_respects_suppress_sound(self) -> None:
        f = relay.NotificationFilter(relay.RelayConfig())
        ok, _, item = f.evaluate("Mail", "<b>Subject</b>", "A &amp; B<br>Line 2", {"suppress-sound": True}, now=10.0)
        self.assertTrue(ok)
        assert item is not None
        self.assertEqual(item["title"], "Subject")
        self.assertEqual(item["body"], "A & BLine 2")
        self.assertFalse(item["sound"])


class ProtobufCrossCheckTests(unittest.TestCase):
    def test_java_codec_decodes_python_bulletin_request(self) -> None:
        if not (PROTOCOL_DIR / "watch-linux-protocol.jar").is_file():
            self.skipTest("protocol jar not built")
        bid, raw = relay.encode_bulletin_request(
            title="測試標題",
            subtitle="KDE Connect",
            body="內文 123",
            section_id="com.apple.MobileSMS",
            section_display_name="KDE Connect",
            sound=True,
            timestamp_ms=1764084000000,
        )
        b64 = base64.b64encode(raw).decode("ascii")
        code = f"""
import dev.applewatchandroid.bridge.BulletinDistributorCodec;
import java.util.Base64;
public class Check {{
    public static void main(String[] args) {{
        byte[] data = Base64.getDecoder().decode("{b64}");
        var req = BulletinDistributorCodec.BulletinRequest.decode(data);
        System.out.println(req.bulletin.bulletinId);
        System.out.println(req.bulletin.title);
        System.out.println(req.bulletin.subtitle);
        System.out.println(req.bulletin.messageTitle);
        System.out.println(req.bulletin.sectionDisplayName);
        System.out.println(req.shouldPlayLightsAndSirens);
    }}
}}
"""
        proc = subprocess.run(
            ["java", "-cp", f"{PROTOCOL_DIR}/*", "--source", "17", "/dev/stdin"],
            input=code,
            text=True,
            capture_output=True,
            check=False,
        )
        # Single-file source launch requires .java filename on JDK 17/27; use jshell or temp file if needed.
        if proc.returncode != 0:
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                src = Path(td) / "Check.java"
                src.write_text(code, encoding="utf-8")
                proc = subprocess.run(
                    ["java", "-cp", f"{PROTOCOL_DIR}/*", str(src)],
                    text=True,
                    capture_output=True,
                    check=True,
                )
        lines = proc.stdout.strip().splitlines()
        self.assertEqual(lines, [bid, "測試標題", "KDE Connect", "內文 123", "KDE Connect", "true"])


if __name__ == "__main__":
    unittest.main()
