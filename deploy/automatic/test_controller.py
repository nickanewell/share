"""Offline public discovery/download tests; never contacts a network or Docker."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request


spec = importlib.util.spec_from_file_location("controller", Path(__file__).with_name("controller.py"))
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)


def release(tag="rival-auto-v2.9.4", identifier=123):
    return {"id": identifier, "tag_name": tag, "draft": False, "prerelease": False,
            "published_at": "2026-10-25T08:23:00Z",
            "html_url": f"https://github.com/nickanewell/share/releases/tag/{tag}",
            "assets": [{"name": name, "size": 100,
                        "browser_download_url": f"https://github.com/nickanewell/share/releases/download/{tag}/{name}"}
                       for name in controller.ASSET_LIMITS]}


class ControllerTests(unittest.TestCase):
    def metadata(self, records):
        return lambda url, limit: json.dumps(records).encode()

    def trusted_install(self):
        files = {}
        for name in controller.INSTALLED_MODULES:
            path = controller.INSTALL_ROOT / name
            for parent in path.parents:
                files[parent] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
            files[path] = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o644)
        return files

    def test_apply_bootstrap_requires_isolation_fixed_root_and_all_trusted_modules(self):
        files = self.trusted_install()
        path = controller.INSTALL_ROOT / "controller.py"
        checked = []
        def lstat(candidate):
            checked.append(candidate)
            return files[candidate]
        controller.validate_bootstrap(path, isolated=True, lstat=lstat)
        self.assertEqual(set(checked), set(files))
        with self.assertRaisesRegex(controller.ControllerError, "isolated Python"):
            controller.validate_bootstrap(path, isolated=False, lstat=lstat)
        with self.assertRaisesRegex(controller.ControllerError, "fixed installation"):
            controller.validate_bootstrap(Path("/tmp/controller.py"), isolated=True, lstat=lstat)

    def test_apply_bootstrap_rejects_unsafe_module_or_ancestor_before_import(self):
        script = controller.INSTALL_ROOT / "controller.py"
        for path, change in ((controller.INSTALL_ROOT / "promote.py", {"st_uid": 501}),
                             (controller.INSTALL_ROOT / "provenance.py", {"st_mode": stat.S_IFREG | 0o666}),
                             (Path("/usr/local/lib"), {"st_mode": stat.S_IFLNK | 0o777}),
                             (controller.INSTALL_ROOT, {"st_mode": stat.S_IFREG | 0o644})):
            files = self.trusted_install()
            files[path] = SimpleNamespace(**{**vars(files[path]), **change})
            with self.subTest(path=path, change=change), self.assertRaises(controller.ControllerError):
                controller.validate_bootstrap(script, isolated=True, lstat=files.__getitem__)
        with patch.object(controller, "validate_bootstrap", side_effect=controller.ControllerError("untrusted")), patch.object(importlib.util, "spec_from_file_location") as load:
            with self.assertRaises(controller.ControllerError):
                controller.import_promoter(True)
        load.assert_not_called()

    def test_apply_loads_only_fixed_module_after_bootstrap(self):
        loader = SimpleNamespace(exec_module=Mock())
        specification = SimpleNamespace(loader=loader)
        module = SimpleNamespace()
        with patch.object(controller, "validate_bootstrap") as check, patch.object(importlib.util, "spec_from_file_location", return_value=specification) as locate, patch.object(importlib.util, "module_from_spec", return_value=module), patch.object(controller.sys, "path", list(sys.path)):
            self.assertIs(controller.import_promoter(True), module)
            self.assertEqual(controller.sys.path[0], str(controller.INSTALL_ROOT))
        check.assert_called_once()
        locate.assert_called_once_with("rival_share_trusted_promoter", controller.INSTALL_ROOT / "promote.py")
        loader.exec_module.assert_called_once_with(module)

    def test_selects_highest_stable_major_two_and_ignores_other_releases(self):
        records = [release(), release("rival-auto-v2.10.0", 124), release("v2.99.0", 125),
                   release("rival-auto-v3.0.0", 126), release("rival-auto-v2.99.0-rc.1", 127)]
        draft, prerelease = release("rival-auto-v2.98.0", 128), release("rival-auto-v2.97.0", 129)
        draft["draft"], prerelease["prerelease"] = True, True
        records.extend([draft, prerelease])
        result = controller.discover(self.metadata(records))
        self.assertEqual(result["tag"], "rival-auto-v2.10.0")
        self.assertEqual(result["upstream_tag"], "v2.10.0")

    def test_malformed_json_duplicates_and_unbounded_metadata_stop(self):
        for data in (b'[{"id":1,"id":2}]', b'not json', b'{}', b'[NaN]', b'x' * (2 * 1024 * 1024 + 1)):
            with self.subTest(data=data[:50]), self.assertRaises((ValueError, TypeError)):
                controller.discover(lambda url, limit: data)

    def test_eligible_identity_fields_are_strict(self):
        for key, value in (("id", True), ("id", 0), ("published_at", None),
                           ("published_at", "not a date"), ("html_url", "https://github.com/attacker/share/releases/tag/rival-auto-v2.9.4")):
            record = release()
            record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(controller.ControllerError):
                controller.discover(self.metadata([record]))

    def test_wrong_asset_repository_path_duplicate_and_size_are_rejected(self):
        for mutation in ("host", "repository", "traversal", "duplicate", "missing", "oversize", "boolsize"):
            record = release()
            asset = record["assets"][0]
            if mutation == "host":
                asset["browser_download_url"] = "https://github.com.evil.invalid/release.json"
            elif mutation == "repository":
                asset["browser_download_url"] = asset["browser_download_url"].replace("nickanewell/share", "other/share")
            elif mutation == "traversal":
                asset["browser_download_url"] = asset["browser_download_url"].replace("release.json", "../release.json")
            elif mutation == "duplicate":
                record["assets"].append(copy.deepcopy(asset))
            elif mutation == "missing":
                record["assets"].pop()
            elif mutation == "oversize":
                asset["size"] = 2**40
            else:
                asset["size"] = True
            with self.subTest(mutation=mutation), self.assertRaises(controller.ControllerError):
                controller.discover(self.metadata([record]))

    def test_ambiguous_versions_and_page_limit_fail_closed(self):
        with self.assertRaisesRegex(controller.ControllerError, "Ambiguous"):
            controller.discover(self.metadata([release(identifier=1), release(identifier=2)]))
        calls = []
        def endless(url, limit):
            calls.append(url)
            return json.dumps([release("unrelated", 1)] * 100).encode()
        with self.assertRaisesRegex(controller.ControllerError, "page limit"):
            controller.discover(endless)
        self.assertEqual(len(calls), 10)
        self.assertEqual(calls[-1], controller.API + "?per_page=100&page=10")

    def test_plan_and_no_eligible_release_never_download_write_or_promote(self):
        promoter = SimpleNamespace(load_policy=Mock(return_value={"state_dir": "/not-used"}),
                                   promote_release=Mock())
        save = Mock()
        fetched = []
        def fetch(url, limit):
            fetched.append(url)
            return json.dumps([release()]).encode()
        result = controller.run("unused", fetch=fetch, promoter=promoter, save=save)
        self.assertEqual(result["mode"], "plan")
        self.assertFalse(result["authenticated"])
        self.assertEqual(fetched, [controller.API + "?per_page=100&page=1"])
        save.assert_not_called()
        promoter.promote_release.assert_not_called()
        result = controller.run("unused", apply=True, fetch=self.metadata([]), promoter=promoter, save=save)
        self.assertEqual(result["result"], "no eligible release")
        save.assert_not_called()
        promoter.promote_release.assert_not_called()

    def test_root_policy_failure_precedes_fetch_and_writes(self):
        promoter = SimpleNamespace(load_policy=Mock(side_effect=ValueError("disabled or unsafe")), promote_release=Mock())
        fetch, save = Mock(), Mock()
        with self.assertRaises(ValueError):
            controller.run("unused", apply=True, fetch=fetch, promoter=promoter, save=save)
        promoter.load_policy.assert_called_once_with("unused", apply=True)
        fetch.assert_not_called()
        save.assert_not_called()
        promoter.promote_release.assert_not_called()

    def test_apply_hands_exact_files_and_expected_tag_to_authenticated_promoter(self):
        promoter = SimpleNamespace(load_policy=Mock(return_value={"state_dir": "/private/state"}),
                                   promote_release=Mock(return_value={"result": "promoted"}))
        manifest = b'{"upstream_tag":"v2.9.4"}'
        bundle = b'opaque untrusted attestation bytes'
        fetched = []
        def fetch(url, limit):
            fetched.append((url, limit))
            if url.startswith(controller.API):
                return json.dumps([release()]).encode()
            return manifest if url.endswith("release.json") else bundle
        save = Mock(return_value=(Path("/private/state/incoming/release.json"), Path("/private/state/incoming/release.sigstore.jsonl")))
        result = controller.run("policy", apply=True, fetch=fetch, promoter=promoter, save=save)
        self.assertEqual(result["result"], "promoted")
        self.assertEqual(len(fetched), 3)
        save.assert_called_once_with("/private/state", 123, manifest, bundle)
        promoter.promote_release.assert_called_once_with(*save.return_value,
            promoter.load_policy.return_value, apply=True, expected_upstream_tag="v2.9.4")

    def test_malformed_download_and_promotion_failure_never_fallback(self):
        promoter = SimpleNamespace(load_policy=Mock(return_value={"state_dir": "/private/state"}),
                                   promote_release=Mock(side_effect=RuntimeError("verification failed")))
        save = Mock(return_value=(Path("manifest"), Path("bundle")))
        def fetch(url, limit):
            return json.dumps([release()]).encode() if url.startswith(controller.API) else b'not-json'
        with self.assertRaises(controller.ControllerError):
            controller.run("policy", apply=True, fetch=fetch, promoter=promoter, save=save)
        save.assert_not_called()
        promoter.promote_release.assert_not_called()
        def valid_fetch(url, limit):
            return json.dumps([release()]).encode() if url.startswith(controller.API) else b'{}'
        with self.assertRaises(RuntimeError):
            controller.run("policy", apply=True, fetch=valid_fetch, promoter=promoter, save=save)
        self.assertEqual(promoter.promote_release.call_count, 1)

    def test_redirects_are_exact_https_hosts_and_api_redirects_are_forbidden(self):
        handler = controller.SafeRedirect()
        req = urllib.request.Request(release()["assets"][0]["browser_download_url"])
        good = "https://release-assets.githubusercontent.com/object?short-lived-signature=not-logged"
        self.assertEqual(handler.redirect_request(req, None, 302, "Found", {}, good).full_url, good)
        for bad in ("http://github.com/file", "https://127.0.0.1/file", "https://github.com.evil.invalid/file",
                    "https://user:password@github.com/file", "https://github.com:8443/file", "file:///etc/passwd"):
            with self.subTest(url=bad), self.assertRaises(controller.ControllerError):
                handler.redirect_request(req, None, 302, "Found", {}, bad)
        api = urllib.request.Request(controller.API + "?per_page=100&page=1")
        with self.assertRaisesRegex(controller.ControllerError, "API redirects"):
            handler.redirect_request(api, None, 301, "Moved", {}, controller.API)

    def test_fetch_has_no_auth_or_proxy_inheritance_and_bounds_reads(self):
        response = Mock(status=200)
        response.read.return_value = b'{}'
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(controller.urllib.request, "build_opener", return_value=opener) as build, patch.dict(os.environ, {"GH_TOKEN": "never-send-this", "HTTPS_PROXY": "https://user:secret@proxy.invalid"}):
            self.assertEqual(controller.fetch_bytes(controller.API + "?per_page=100&page=1", 10), b'{}')
        request = opener.open.call_args.args[0]
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(build.call_args.args[0].proxies, {})
        response.read.assert_called_once_with(11)
        response.read.return_value = b'x' * 11
        with patch.object(controller.urllib.request, "build_opener", return_value=opener), self.assertRaises(controller.ControllerError):
            controller.fetch_bytes(controller.API + "?per_page=100&page=1", 10)

    def test_private_input_files_use_exclusive_creation_and_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            first = controller.save_inputs(root, 123, b'{}', b'bundle', expected_uid=os.getuid())
            second = controller.save_inputs(root, 123, b'{}', b'bundle', expected_uid=os.getuid())
            self.assertNotEqual(first[0], second[0])
            for path in (*first, *second):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            external = root / "external"
            external.mkdir()
            unsafe = root / "unsafe"
            unsafe.symlink_to(external)
            with self.assertRaises(OSError):
                controller.save_inputs(unsafe, 1, b'{}', b'bundle', expected_uid=os.getuid())
            self.assertEqual(list(external.iterdir()), [])
            state = root / "new-state"
            state.mkdir(mode=0o700)
            (state / "incoming").symlink_to(external)
            with self.assertRaises(OSError):
                controller.save_inputs(state, 1, b'{}', b'bundle', expected_uid=os.getuid())

    def test_input_writer_rejects_path_shaped_ids_and_oversize_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            for identifier in (True, 0, "../../outside", "123"):
                with self.subTest(identifier=identifier), self.assertRaises(controller.ControllerError):
                    controller.save_inputs(root, identifier, b'{}', b'bundle', expected_uid=os.getuid())
            with self.assertRaises(controller.ControllerError):
                controller.save_inputs(root, 1, b'x' * (controller.ASSET_LIMITS["release.json"] + 1), b'bundle', expected_uid=os.getuid())
            self.assertEqual(list(root.iterdir()), [])

    def test_write_or_fsync_failure_never_calls_promoter(self):
        promoter = SimpleNamespace(load_policy=Mock(return_value={"state_dir": "state"}), promote_release=Mock())
        def fetch(url, limit):
            return json.dumps([release()]).encode() if url.startswith(controller.API) else b'{}'
        with self.assertRaises(OSError):
            controller.run("policy", apply=True, fetch=fetch, promoter=promoter, save=Mock(side_effect=OSError("disk full")))
        promoter.promote_release.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary, patch.object(controller.os, "fsync", side_effect=OSError("disk error")):
            Path(temporary).chmod(0o700)
            with self.assertRaises(OSError):
                controller.save_inputs(temporary, 1, b'{}', b'bundle', expected_uid=os.getuid())


if __name__ == "__main__":
    unittest.main()
