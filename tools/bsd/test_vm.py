"""Offline behavior tests: python3 -m unittest discover -s scripts/bsd."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vm


class ImageTests(unittest.TestCase):
    def test_netbsd_restores_ipv4_transport_route(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vm, "STATE", Path(directory)),
        ):
            guest = vm.Guest("netbsd")
            vm.write_json(guest.dir / "runtime.json", {"management_only": True})
            replies = [
                vm.subprocess.CompletedProcess([], 0, "interface: tun0\n", ""),
                vm.subprocess.CompletedProcess([], 0, "", ""),
            ]
            with patch.object(guest, "admin", side_effect=replies) as admin:
                guest.netbsd_underlay()
                self.assertIn(
                    "route add -inet default 10.0.2.2", admin.call_args.args[0]
                )
            self.assertEqual(
                (guest.dir / "native-ipv4-gateway").read_text(), "10.0.2.2"
            )

    def test_netbsd_records_bridged_gateway_without_changing_routes(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vm, "STATE", Path(directory)),
        ):
            guest = vm.Guest("netbsd")
            response = vm.subprocess.CompletedProcess(
                [], 0, "gateway: 192.168.1.1\ninterface: vioif1\n", ""
            )
            with patch.object(guest, "admin", return_value=response) as admin:
                guest.netbsd_underlay()
                self.assertEqual(admin.call_count, 1)
            self.assertEqual(
                (guest.dir / "native-ipv4-gateway").read_text(), "192.168.1.1"
            )

    def test_stable_version_ordering(self):
        listing = (
            '<a href="9.9-RELEASE/"><a href="15.1-RELEASE/"><a href="15.2-BETA1/">'
        )
        self.assertEqual(vm.latest(listing, r'href="(\d+\.\d+)-RELEASE/'), "15.1")

    def test_missing_release_fails(self):
        with self.assertRaises(RuntimeError):
            vm.latest("snapshots/", r'href="(\d+\.\d+)/')

    def test_checksum_requires_exact_filename(self):
        digest = "a" * 64
        manifest = f"SHA256 (disk.img.old) = {digest}\nSHA256 (disk.img) = {digest}\n"
        self.assertEqual(vm.checksum(manifest, "disk.img", "sha256"), digest)
        with self.assertRaises(RuntimeError):
            vm.checksum(manifest, "other.img", "sha256")
        with self.assertRaises(RuntimeError):
            vm.checksum("SHA256 (disk.img) = abc", "disk.img", "sha256")

    def test_corruption_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            path.write_bytes(b"good")
            meta = {
                "algorithm": "sha256",
                "digest": hashlib.sha256(b"good").hexdigest(),
            }
            self.assertTrue(vm.verified(path, meta))
            path.write_bytes(b"corrupt")
            self.assertFalse(vm.verified(path, meta))

    def test_verified_cache_never_downloads(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vm, "STATE", Path(directory)),
        ):
            cached = Path(directory) / "downloads/image.img"
            cached.parent.mkdir()
            cached.write_bytes(b"good")
            meta = {
                "url": "https://example.invalid/image.img",
                "algorithm": "sha256",
                "digest": hashlib.sha256(b"good").hexdigest(),
            }
            with patch.object(
                vm, "run", side_effect=AssertionError("unexpected download")
            ):
                self.assertEqual(vm.acquire(meta), cached)

    def test_failed_checksum_discards_partial(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vm, "STATE", Path(directory)),
        ):
            cache = Path(directory) / "downloads"
            cache.mkdir()
            partial = cache / "image.img.part"
            partial.write_bytes(b"bad")
            meta = {
                "url": "https://example.invalid/image.img",
                "algorithm": "sha256",
                "digest": "a" * 64,
            }
            with patch.object(vm, "run"), self.assertRaises(RuntimeError):
                vm.acquire(meta)
            self.assertFalse(partial.exists())
            self.assertFalse((cache / "image.img").exists())

    def test_guest_lock_excludes_duplicate_operations(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vm, "STATE", Path(directory)),
        ):
            guest = vm.Guest("freebsd")
            with guest.lock():  # noqa: SIM117 - the second lock must be attempted inside the first
                with self.assertRaises(RuntimeError), guest.lock():
                    pass

    def test_bootstrap_contains_public_key_only(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(vm, "STATE", Path(directory)),
        ):
            guest = vm.Guest("freebsd")
            (guest.dir / "key.pub").write_text("ssh-ed25519 PUBLIC test\n")
            (guest.dir / "key").write_text("PRIVATE")
            with patch.object(vm, "run"):
                guest.seed()
            text = (guest.dir / "seed/user-data").read_text()
            self.assertIn("ssh-ed25519 PUBLIC test", text)
            self.assertNotIn("PRIVATE", text)
            self.assertTrue(text.startswith("#!/bin/sh\n"))


if __name__ == "__main__":
    unittest.main()
