"""Offline promotion state-machine tests. No Docker, HTTP or root actions run."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("promoter", HERE / "promote.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
OLD = "sha256:" + "a" * 64
NEW = "sha256:" + "b" * 64
IMAGE = "ghcr.io/nickanewell/share@sha256:" + "c" * 64
SOURCE = "d" * 40


class Runtime:
    def __init__(self, compose, assets):
        self.path, self.assets = compose, assets
        self.calls, self.notes = [], {}
        self.image = OLD
        self.app_id, self.redis_id = "existing-app", "unchanged-production-redis"
        self.promotions = 0
        self.stage_bad = self.public_bad = self.rollback_bad = self.uncertain = self.concurrent = False
        self.stage_active = False
        self.configured_image = OLD
        self.bad_probe = False
        self.probe_uncertain = False
        self.concurrent_same_image = False
        self.concurrent_config = False

    def command(self, args, timeout=60):
        self.calls.append(list(args))
        assert args[0] == p.DOCKER
        private_config = self.path.parent.parent / "state" / "docker" / "config.json"
        assert private_config.read_bytes() == b'{"auths":{"ghcr.io":{}}}'
        assert private_config.stat().st_mode & 0o777 == 0o600
        assert isinstance(timeout, int) and timeout <= 300
        if args[1] == "inspect":
            name = args[2]
            if name == "share-app":
                return json.dumps({"id": self.app_id, "image": self.image, "running": True})
            if name == "share-redis":
                return json.dumps({"id": self.redis_id, "image": "sha256:" + "e" * 64, "running": True})
            if name == "f" * 64:
                return json.dumps({"id": name, "image": NEW, "running": True})
            raise AssertionError("Unapproved inspect target")
        if args[1:3] == ["image", "inspect"]:
            if args[3] == OLD:
                return json.dumps(self.configured_image)
            assert args[3] == IMAGE
            return json.dumps({"id": NEW, "revision": SOURCE})
        if args[1] == "pull":
            assert args[-1] in (IMAGE, p.REDIS, p.PROBE_IMAGE)
            return "pulled by exact digest"
        if args[1] == "run":
            assert args[args.index("--network") + 1] == "container:" + "f" * 64
            assert args[args.index("--entrypoint") + 1] == "node"
            assert args[args.index("--user") + 1] == "1000:1000"
            assert p.PROBE_IMAGE in args and IMAGE not in args and "--volume" not in args and "--mount" not in args
            assert args[args.index("-e") + 1] == p.PROBE_JS
            data = json.loads(args[-1])
            assert "must-never-reach-candidate" not in args[-1]
            if self.probe_uncertain: raise p.CommandError("probe timed out", uncertain=True)
            p.probe(self.request, "http://127.0.0.1:13211", data["expected"], data["assets"], shares=True)
            result = {"format": "rival-share-stage-probe", "version": 1, "status": "passed", "nonce": data["nonce"],
                      "image": data["image"], "observed": data["expected"], "asset_hashes": data["assets"], "checks": p.PROBE_CHECKS}
            if self.bad_probe: result["asset_hashes"] = {}
            return json.dumps(result)
        assert args[1] == "compose"
        project = args[args.index("-p") + 1]
        path = Path(args[args.index("-f") + 1])
        tail = args[args.index("-f") + 2:]
        if tail[:1] == ["config"]:
            return json.dumps(json.loads(path.read_text()))
        if project == "rival-share-candidate":
            cfg = json.loads(path.read_text())
            app = cfg["services"]["app"]
            assert app["cap_drop"] == ["ALL"] and app["security_opt"] == ["no-new-privileges:true"]
            assert not app.get("volumes") and not app.get("privileged")
            assert not app.get("ports") and not cfg["services"]["redis"].get("ports")
            assert cfg["networks"]["default"]["internal"] is True
            assert set(app["environment"]) <= p.ENV_KEYS | {"REDIS"}
            if tail[0] == "ps": return "f" * 64 if tail == ["ps", "-q", "app"] else ""
            if tail[0] == "up": self.stage_active = True; return ""
            if tail[0] == "port": raise AssertionError("An internal candidate must never publish a host port")
            if tail[0] == "down": self.stage_active = False; return ""
            raise AssertionError("Unapproved staging command")
        assert project == "share" and path == self.path
        assert tail == ["up", "-d", "--no-deps", "--no-build", "--pull", "never", "app"]
        image = json.loads(self.path.read_text())["services"]["app"]["image"]
        self.promotions += 1
        self.image = NEW if image == IMAGE else OLD
        self.app_id = "candidate-app" if self.image == NEW else "rollback-app"
        if self.concurrent: self.redis_id = "someone-changed-redis"
        if self.uncertain and self.promotions == 1:
            raise p.CommandError("outcome uncertain", uncertain=True)
        if self.rollback_bad and self.promotions == 2:
            raise p.CommandError("rollback failed")
        return ""

    def request(self, origin, path, method="GET", body=None, headers=None, limit=5242880):
        assert origin in ("http://127.0.0.1:13211", "http://127.0.0.1:8000", "https://share.rivalit.ai")
        stage = origin.endswith(":13211")
        status = {"version": "2.9.4" if stage or self.image == NEW else "2.9.3", "file_format_version": 2,
                  "max_size": 10000000, "max_views": 25, "max_expiration": 360, "allow_advanced": True, "allow_files": True}
        if path == "/api/status/":
            if stage and self.stage_bad: status["file_format_version"] = 1
            if origin.startswith("https") and self.public_bad and self.image == NEW:
                if self.concurrent_same_image: self.app_id = "operator-recreated-the-same-image"
                if self.concurrent_config:
                    cfg = json.loads(self.path.read_text()); cfg["services"]["app"]["environment"]["OPERATOR_CHANGE"] = "preserve"
                    self.path.write_text(json.dumps(cfg))
                return 503, b""
            return 200, json.dumps(status).encode()
        if path == "/api/live/": return 200, b""
        if path in self.assets: return 200, self.assets[path]
        assert stage, "Synthetic writes must never target production"
        if path == "/api/notes/" and method == "POST":
            note = json.loads(body)
            note_id = "generated" + str(len(self.notes) + 1)
            self.notes[note_id] = note
            return 200, json.dumps({"id": note_id}).encode()
        note_id = path.rsplit("/", 1)[-1]
        if note_id not in self.notes: return 404, b""
        note = self.notes[note_id]
        if method == "DELETE":
            if note["contents"].startswith("{") and not (headers or {}).get("X-Cryptgeon-File-Format"):
                return 426, b""
            del self.notes[note_id]
            return 200, json.dumps({k: note[k] for k in ("meta", "contents")}).encode()
        return 200, json.dumps({"meta": note["meta"]}).encode()


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rival-promoter-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.etc, self.state = self.root / "etc", self.root / "state"
        self.etc.mkdir(); self.state.mkdir()
        self.compose = self.etc / "compose.json"
        self.cfg = {"name": "share", "services": {
            "app": {"image": OLD, "container_name": "share-app", "ports": ["8000:8000"],
                    "environment": {"REDIS": "redis://redis/", "SIZE_LIMIT": "10MB", "MAX_VIEWS": "25", "PRIVATE_SENTINEL": "must-never-reach-candidate"}},
            "redis": {"image": p.REDIS, "container_name": "share-redis", "volumes": [{"type": "volume", "source": "redis-data", "target": "/data"}]}}}
        self.compose.write_text(json.dumps(self.cfg))
        self.raw = self.compose.read_bytes()
        self.assets = {"/" + x.removeprefix("packages/frontend/static/"): ("approved:" + x).encode() for x in p.ASSETS}
        asset_hashes = {x: hashlib.sha256(self.assets["/" + x.removeprefix("packages/frontend/static/")]).hexdigest() for x in p.ASSETS}
        self.identity_patch = mock.patch.dict(p.IDENTITY, compose_file=str(self.compose), state_dir=str(self.state))
        self.identity_patch.start(); self.addCleanup(self.identity_patch.stop)
        self.policy = dict(p.IDENTITY, enabled=True, repository_id="123456", allowed_control_commit="1" * 40,
                           branding_sha256="2" * 64, security_contract_sha256="3" * 64, branding_assets=asset_hashes)
        self.release = {"image": IMAGE, "upstream_tag": "v2.9.4", "source_commit": SOURCE}
        self.runtime = Runtime(self.compose, self.assets)
        self.verifications = 0
        self.uid = mock.patch.object(os, "geteuid", return_value=0)
        self.uid.start(); self.addCleanup(self.uid.stop)

    def verify(self, *args):
        self.verifications += 1
        return dict(self.release)

    def engine(self, verify=None):
        return p.Promoter(self.policy, self.runtime.command, request=self.runtime.request,
                          verifier=verify or self.verify, trust=lambda *a, **k: None, sleep=lambda seconds: None,
                          maintenance_gate=lambda commands: None)

    def execute(self, engine=None, **kwargs):
        return (engine or self.engine()).execute("release.json", "bundle.jsonl", apply=True, **kwargs)

    def test_valid_promotion_changes_only_app_image_and_keeps_redis(self):
        result = self.execute()
        self.assertEqual(result["status"], "promoted")
        expected = copy.deepcopy(self.cfg); expected["services"]["app"]["image"] = IMAGE
        self.assertEqual(json.loads(self.compose.read_text()), expected)
        self.assertEqual(self.runtime.redis_id, "unchanged-production-redis")
        self.assertEqual(self.runtime.promotions, 1)
        self.assertFalse(self.runtime.stage_active)
        self.assertEqual((self.state / ("compose-before-" + SOURCE + ".json")).read_bytes(), self.raw)
        self.assertEqual((self.state / ("compose-before-" + SOURCE + ".json")).stat().st_mode & 0o777, 0o600)
        self.assertEqual(p.read_json(self.state / "state.json")["last_upstream_tag"], "v2.9.4")

    def test_invalid_provenance_stops_before_every_docker_command_or_state_write(self):
        def invalid(*args): raise p.PromotionError("invalid signature")
        with self.assertRaisesRegex(p.PromotionError, "signature"):
            self.execute(self.engine(invalid))
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_anonymous_registry_config_is_exact_private_and_has_no_helper(self):
        self.release["upstream_tag"] = "v2.9.3"
        self.execute()
        path = self.state / "docker" / "config.json"
        self.assertEqual(path.read_bytes(), b'{"auths":{"ghcr.io":{}}}')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text()), {"auths": {"ghcr.io": {}}})
        inode = path.stat().st_ino
        self.execute()
        self.assertEqual(path.stat().st_ino, inode, "Known anonymous configuration must not be rewritten")

    def test_foreign_docker_config_is_preserved_and_stops_before_docker(self):
        folder = self.state / "docker"; folder.mkdir(mode=0o700)
        path = folder / "config.json"
        foreign = b'{"credsStore":"secretservice","auths":{}}'
        path.write_bytes(foreign); path.chmod(0o600)
        with self.assertRaisesRegex(p.PromotionError, "Unexpected private Docker configuration"):
            self.execute()
        self.assertEqual(path.read_bytes(), foreign)
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_discovery_tag_mismatch_is_bound_after_verification_before_docker(self):
        with self.assertRaisesRegex(p.PromotionError, "discovered release"):
            self.execute(expected_upstream_tag="v2.9.9")
        self.assertEqual(self.verifications, 1)
        self.assertEqual(self.runtime.calls, [])

    def test_default_is_verified_plan_without_root_or_mutations(self):
        self.policy["enabled"] = False
        self.uid.return_value = 501
        result = self.engine().execute("release.json", "bundle.jsonl")
        self.assertEqual(result["status"], "verified-plan-only")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(list(self.state.iterdir()), [])

    def test_staging_failure_cannot_change_production_and_quarantines_release(self):
        self.runtime.stage_bad = True
        with self.assertRaisesRegex(p.PromotionError, "staging failed"):
            self.execute()
        self.assertEqual(self.compose.read_bytes(), self.raw)
        self.assertEqual(self.runtime.promotions, 0)
        self.assertFalse(self.runtime.stage_active)
        self.assertEqual(p.read_json(self.state / "state.json")["failed_images"], [IMAGE])
        self.runtime.calls.clear()
        with self.assertRaisesRegex(p.PromotionError, "quarantined"):
            self.execute()
        self.assertEqual(self.runtime.calls, [])

    def test_failed_public_health_restores_original_config_and_compatible_image(self):
        self.runtime.public_bad = True
        with self.assertRaisesRegex(p.PromotionError, "previous compatible app/config restored"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 2)
        self.assertEqual(self.runtime.image, OLD)
        self.assertEqual(self.compose.read_bytes(), self.raw)
        self.assertIsNone(p.read_json(self.state / "state.json")["pending"])

    def test_rollback_failure_is_retained_for_manual_recovery(self):
        self.runtime.public_bad = self.runtime.rollback_bad = True
        with self.assertRaisesRegex(p.PromotionError, "manual recovery"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 2)
        self.assertEqual(p.read_json(self.state / "state.json")["pending"]["phase"], "rollback-failed-or-uncertain")

    def test_uncertain_activation_is_not_retried_or_blindly_rolled_back(self):
        self.runtime.uncertain = True
        with self.assertRaisesRegex(p.PromotionError, "uncertain outcome"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 1)
        self.assertEqual(p.read_json(self.state / "state.json")["pending"]["phase"], "promotion-uncertain")
        self.runtime.calls.clear()
        with self.assertRaisesRegex(p.PromotionError, "pending outcome"):
            self.execute()
        self.assertEqual(self.runtime.calls, [])

    def test_unexpected_redis_change_does_not_trigger_a_blind_rollback(self):
        self.runtime.concurrent = True
        with self.assertRaisesRegex(p.PromotionError, "inspect before rollback"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 1)
        self.assertEqual(p.read_json(self.state / "state.json")["pending"]["phase"], "unexpected-concurrent-change")

    def test_same_image_recreation_does_not_authorize_overwriting_an_operator(self):
        self.runtime.public_bad = self.runtime.concurrent_same_image = True
        with self.assertRaisesRegex(p.PromotionError, "inspect before rollback"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 1)

    def test_concurrent_config_edit_survives_failed_health_without_rollback(self):
        self.runtime.public_bad = self.runtime.concurrent_config = True
        with self.assertRaisesRegex(p.PromotionError, "inspect before rollback"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 1)
        self.assertEqual(json.loads(self.compose.read_text())["services"]["app"]["environment"]["OPERATOR_CHANGE"], "preserve")

    def test_configured_rollback_image_must_match_running_image_before_pull(self):
        self.runtime.configured_image = "sha256:" + "9" * 64
        with self.assertRaisesRegex(p.PromotionError, "rollback images differ"):
            self.execute()
        self.assertFalse(any(x[1] == "pull" or "up" in x for x in self.runtime.calls))
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_incomplete_probe_proof_cannot_promote(self):
        self.runtime.bad_probe = True
        with self.assertRaisesRegex(p.PromotionError, "staging failed"):
            self.execute()
        self.assertEqual(self.runtime.promotions, 0)
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_uncertain_probe_container_is_recorded_and_not_retried(self):
        self.runtime.probe_uncertain = True
        with self.assertRaisesRegex(p.PromotionError, "staging failed"):
            self.execute()
        self.assertEqual(len([x for x in self.runtime.calls if x[1] == "run"]), 1)
        pending = p.read_json(self.state / "state.json")["pending"]
        self.assertEqual(pending["phase"], "staging-uncertain")
        self.assertTrue(pending["probe_container"].startswith("rival-share-probe-"))
        self.assertEqual(self.runtime.promotions, 0)

    def test_non_newer_release_is_a_noop(self):
        self.release["upstream_tag"] = "v2.9.3"
        self.assertEqual(self.execute()["status"], "not-newer")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_required_guest_reboot_defers_before_any_docker_operation(self):
        marker = self.root / "reboot-required"; marker.touch()
        engine = self.engine()
        engine.maintenance_gate = lambda commands: p.package_maintenance_gate(commands, marker)
        result = self.execute(engine)
        self.assertEqual(result["reason"], "guest-reboot-required")
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_active_or_activating_apt_defers_before_docker(self):
        for active in ("active", "activating"):
            queried = []
            def systemctl(args, timeout=60):
                queried.append(args)
                return active + "\n\ninactive\n"
            engine = self.engine()
            engine.maintenance_gate = lambda commands: p.package_maintenance_gate(systemctl, self.root / "absent-reboot-marker")
            result = self.execute(engine)
            self.assertEqual(result["status"], "deferred-maintenance")
            self.assertEqual(queried, [[p.SYSTEMCTL, "show", "--property=ActiveState", "--value", "apt-daily.service", "apt-daily-upgrade.service"]])
            self.assertEqual(self.runtime.calls, [])

    def test_stock_old_reader_cannot_be_used_as_a_rollback_target(self):
        original = self.runtime.request
        def old_reader(origin, path, *args, **kwargs):
            code, body = original(origin, path, *args, **kwargs)
            if origin == "http://127.0.0.1:8000" and path == "/api/status/":
                status = json.loads(body)
                del status["file_format_version"]
                return code, json.dumps(status).encode()
            return code, body
        engine = self.engine(); engine.request = old_reader
        with self.assertRaisesRegex(p.PromotionError, "safe promotion and rollback"):
            self.execute(engine)
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.compose.read_bytes(), self.raw)

    def test_command_environment_cannot_inherit_remote_daemon_or_credentials(self):
        leaked = {"DOCKER_HOST": "tcp://unapproved.invalid:2375", "DOCKER_CONTEXT": "other", "DOCKER_CONFIG": "/home/user/.docker", "GH_TOKEN": "sentinel-not-a-real-token", "PATH": "/untrusted"}
        with mock.patch.dict(os.environ, leaked), mock.patch.object(p.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"{}")) as command:
            p.Commands(self.state)([p.DOCKER, "version"])
        env = command.call_args.kwargs["env"]
        self.assertEqual(env["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertEqual(env["DOCKER_CONFIG"], str(self.state / "docker"))
        self.assertNotIn("DOCKER_CONTEXT", env)
        self.assertNotIn("GH_TOKEN", env)
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertNotIn("shell", command.call_args.kwargs)

    def test_unsafe_compose_is_rejected_without_container_operations(self):
        for change in ({"privileged": True}, {"volumes": [{"type": "bind", "source": "/", "target": "/host"}]}, {"image": "mutable:latest"}):
            cfg = copy.deepcopy(self.cfg); cfg["services"]["app"].update(change)
            self.compose.write_text(json.dumps(cfg))
            with self.assertRaises(p.PromotionError):
                self.execute()
            self.assertFalse(any(x[1] == "pull" or "up" in x for x in self.runtime.calls))
            self.runtime.calls.clear()

    def test_policy_placeholders_and_unknown_options_fail_closed(self):
        for key, value in (("allowed_control_commit", "0" * 40), ("repository_id", "0"), ("production_origin", "https://attacker.invalid"), ("extra", "argument")):
            policy = dict(self.policy); policy[key] = value
            with self.assertRaises(p.PromotionError): p.validate_policy(policy)

    def test_private_api_probe_uses_no_redirects_or_proxy_credentials(self):
        with self.assertRaises(p.PromotionError):
            p.http("http://192.168.69.1", "/api/live/")
        with self.assertRaises(p.PromotionError):
            p.http("https://share.rivalit.ai", "//other-host/path")
        self.assertIsNone(p.NoRedirect().redirect_request(None, None, None, None, None, None))

    @unittest.skipUnless(shutil.which("node"), "Node is needed to execute the offline trusted probe")
    def test_actual_trusted_node_probe_and_crypto_failures_with_offline_fetch(self):
        # Execute the real probe source against a complete in-memory fetch stub;
        # there is deliberately no network fallback or candidate code execution.
        mock_fetch = r'''
const offline=JSON.parse(process.argv[1]); let next=1; const notes=new Map();
global.fetch=async (url, options)=>{
  const parsed=new URL(url); if(parsed.origin!=='http://127.0.0.1:8000') throw Error('network forbidden');
  const path=parsed.pathname; let status=200, body;
  if(options.redirect!=='error') throw Error('redirect policy');
  if(path==='/api/status/') body=JSON.stringify({...offline.expected,file_format_version:2});
  else if(path==='/api/live/') body='';
  else if(Object.hasOwn(offline.asset_bytes,path)) body=Buffer.from(offline.asset_bytes[path],'base64');
  else if(path==='/api/notes/' && options.method==='POST') { const id='synthetic'+next++;notes.set(id,JSON.parse(options.body));body=JSON.stringify({id}); }
  else {
    const id=path.split('/').pop(), note=notes.get(id);
    if(!note) {status=404;body='';}
    else if(options.method==='DELETE' && note.contents.startsWith('{') && !options.headers['X-Cryptgeon-File-Format']) {status=426;body='';}
    else if(options.method==='DELETE') {notes.delete(id);body=JSON.stringify({meta:note.meta,contents:note.contents});}
    else body=JSON.stringify({meta:note.meta});
  }
  const bytes=Buffer.isBuffer(body)?body:Buffer.from(body);
  return {status,body:(async function*(){yield bytes;})()};
};
'''
        payload = {"expected": {"version": "2.9.4", "max_size": 10000000, "max_views": 25, "max_expiration": 360, "allow_advanced": True, "allow_files": True},
                   "assets": self.policy["branding_assets"], "fixtures": [list(x) for x in p.FIXTURES], "nonce": "test-proof", "image": NEW,
                   "asset_bytes": {k: __import__("base64").b64encode(v).decode() for k, v in self.assets.items()}}
        def run(data):
            return subprocess.run([shutil.which("node"), "-e", mock_fetch + p.PROBE_JS, json.dumps(data)],
                                  capture_output=True, timeout=10, env={"PATH": "/usr/bin:/bin"})
        good = run(payload)
        self.assertEqual(good.returncode, 0, good.stderr.decode())
        proof = json.loads(good.stdout)
        self.assertEqual(proof["checks"], p.PROBE_CHECKS)
        self.assertEqual(proof["asset_hashes"], self.policy["branding_assets"])
        tampered = copy.deepcopy(payload)
        # The mock server faithfully returns this altered ciphertext, so only
        # actual independent AES-GCM authentication catches the bad fixture.
        tampered["fixtures"][0][1] = tampered["fixtures"][0][1][:-1] + "A"
        self.assertNotEqual(run(tampered).returncode, 0)
        changed_artwork = copy.deepcopy(payload)
        changed_artwork["assets"][next(iter(changed_artwork["assets"]))] = "0" * 64
        self.assertNotEqual(run(changed_artwork).returncode, 0)


if __name__ == "__main__":
    unittest.main()
