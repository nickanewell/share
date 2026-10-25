#!/usr/bin/env python3
"""App-only promotion engine. Not an installer; requires reviewed root policy.

No candidate script runs on the host. Candidate containers receive no host mounts,
Docker socket, production secrets or production-cache connectivity. A separate,
pinned trusted Node container decrypts independent legacy/new fixtures inside the
candidate network namespace; exhaustive crypto/browser gates remain in CI. This
module never discovers or downloads a release.
"""

import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DOCKER = "/usr/bin/docker"
SYSTEMCTL = "/usr/bin/systemctl"
COMPOSE = "/etc/rival-share/compose.json"
STATE = "/var/lib/rival-share-update"
REDIS = "redis:7.4.11-alpine@sha256:57e4255cc971b1c8d6f8a6ca283ac01bc3ecdd914273ef6bfaede87aaecd6541"
PROBE_IMAGE = "node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53"
PROBE_CHECKS = ["status", "health", "branding", "text", "legacy-file", "authenticated-file", "one-view", "old-reader-guard"]
PUBLIC_DOCKER_CONFIG = b'{"auths":{"ghcr.io":{}}}'
# Fixed trusted code, never obtained from the candidate or executed on the host.
PROBE_JS = r"""
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const input = JSON.parse(process.argv[1]);
const origin = 'http://127.0.0.1:8000';
async function req(path, method='GET', body, headers={}) {
  assert(path.startsWith('/') && !path.startsWith('//'));
  const response = await fetch(origin + path, {method, body, headers, redirect:'error', signal:AbortSignal.timeout(5000)});
  const chunks=[]; let length=0;
  for await (const chunk of response.body) { length+=chunk.length; assert(length<=5242880); chunks.push(Buffer.from(chunk)); }
  return [response.status, Buffer.concat(chunks)];
}
function open(ciphertext, key) {
  const parts=ciphertext.split('--'); assert.equal(parts.length,3); assert.equal(parts[0],'QUVTLUdDTQ==');
  const iv=Buffer.from(parts[1],'base64'), encrypted=Buffer.from(parts[2],'base64');
  assert.equal(iv.length,12); assert(encrypted.length>=16);
  const cipher=crypto.createDecipheriv('aes-256-gcm',key,iv); cipher.setAuthTag(encrypted.subarray(-16));
  return Buffer.concat([cipher.update(encrypted.subarray(0,-16)),cipher.final()]);
}
(async()=>{
  const [code, data]=await req('/api/status/'); assert.equal(code,200);
  const status=JSON.parse(data); assert.equal(status.file_format_version,2);
  const observed={}; for(const [key,value] of Object.entries(input.expected)) { assert.equal(status[key],value); observed[key]=status[key]; }
  assert.equal((await req('/api/live/'))[0],200);
  const hashes={};
  for(const [path,digest] of Object.entries(input.assets)) {
    const [code,bytes]=await req('/'+path.replace(/^packages\/frontend\/static\//,'')); assert.equal(code,200);
    hashes[path]=crypto.createHash('sha256').update(bytes).digest('hex'); assert.equal(hashes[path],digest);
  }
  const key=Buffer.alloc(32,1);
  for(const [kind,contents,guarded] of input.fixtures) {
    const meta=JSON.stringify({type:kind});
    const [code,created]=await req('/api/notes/','POST',JSON.stringify({contents,meta,views:1}),{'Content-Type':'application/json'});
    assert.equal(code,200); const id=JSON.parse(created).id; assert(/^[A-Za-z0-9]{1,256}$/.test(id));
    const path='/api/notes/'+id;
    if(guarded) { assert.equal((await req(path,'DELETE'))[0],426); assert.equal((await req(path))[0],200); }
    const [readCode,replyBytes]=await req(path,'DELETE',undefined,{'X-Cryptgeon-File-Format':'2'});
    assert.equal(readCode,200); const reply=JSON.parse(replyBytes); assert.deepEqual(reply,{meta,contents});
    assert.equal((await req(path))[0],404);
    if(kind==='text') assert.equal(open(reply.contents,key).toString(),'Synthetic deployment check');
    else if(!guarded) { const files=JSON.parse(reply.contents); assert.equal(files[0].name,'synthetic.txt'); assert.equal(open(files[0].contents,key).toString(),'abc'); }
    else {
      const derived=Buffer.from(crypto.hkdfSync('sha256',key,Buffer.from('cryptgeon-files'),Buffer.from('cryptgeon-files/v2'),32));
      const frame=open(JSON.parse(reply.contents).ciphertext,derived), n=frame.readUInt32BE();
      assert.deepEqual(JSON.parse(frame.subarray(4,4+n)),{format:'cryptgeon-files',version:2,files:[{name:'synthetic.txt',type:'text/plain',size:3}]});
      assert.equal(frame.subarray(4+n).toString(),'abc');
    }
  }
  process.stdout.write(JSON.stringify({format:'rival-share-stage-probe',version:1,status:'passed',nonce:input.nonce,
    image:input.image,observed,asset_hashes:hashes,checks:['status','health','branding','text','legacy-file','authenticated-file','one-view','old-reader-guard']}));
})().catch(()=>{process.stderr.write('Trusted stage probe failed\n');process.exitCode=1;});
"""
ASSETS = {
    "packages/frontend/static/favicon.png", "packages/frontend/static/logo-light.svg",
    "packages/frontend/static/logo-dark.svg", "packages/frontend/static/branding/rival-it-master-lockup.png",
    "packages/frontend/static/branding/rival-it-master-mark.png",
}
IDENTITY = {
    "repository": "nickanewell/share", "signer_workflow": "nickanewell/share/.github/workflows/automatic-release.yml",
    "allowed_major": 2, "file_format_version": 2, "compose_file": COMPOSE,
    "app_service": "app", "app_container": "share-app", "redis_container": "share-redis",
    "production_origin": "https://share.rivalit.ai", "local_origin": "http://127.0.0.1:8000", "state_dir": STATE,
}
POLICY_KEYS = set(IDENTITY) | {"enabled", "allowed_control_commit", "repository_id", "branding_sha256", "security_contract_sha256", "branding_assets"}
STATUS_KEYS = ("max_size", "max_views", "max_expiration", "allow_advanced", "allow_files")
ENV_KEYS = {"SIZE_LIMIT", "MAX_VIEWS", "MAX_EXPIRATION", "ALLOW_ADVANCED", "ALLOW_FILES", "THEME_FAVICON"}


FIXTURES = [('text', 'QUVTLUdDTQ==--AgICAgICAgICAgIC--VK+nPSIytZSw7NitLMuty8/Qv5vL0uUUvuz5AOSV1HxmglrBB/QOx4tl', False), ('file', '[{"name":"synthetic.txt","size":3,"type":"text/plain","contents":"QUVTLUdDTQ==--AgICAgICAgICAgIC--ZrSqMGv4XeDmGVqkK/qf9BsyXA=="}]', False), ('file', '{"format":"cryptgeon-files","version":2,"ciphertext":"QUVTLUdDTQ==--AgICAgICAgICAgIC--JmBZCVPWteFvvx9HfIGJT+x89hlQOfoSQylIL/tvuFEqRFMUfHMU4cX1A1dd19l/JhxpoUUxFTJ4LwRgphgZfmqjSMJoAODf/PbmGfD9XT01XBwOwWjaJeJMVIPfX1pUZKQjdeU/UAjMP0d6EDKyqmbKq9ap0XjY0rT0UDYZ5A=="}', True)]

class PromotionError(RuntimeError):
    pass


class CommandError(PromotionError):
    def __init__(self, message, uncertain=False):
        super().__init__(message)
        self.uncertain = uncertain


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PromotionError("Duplicate JSON key")
        result[key] = value
    return result


def read_json(path, limit=1048576):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise PromotionError("JSON input exceeds its bound")
    return json.loads(data, object_pairs_hook=unique)


def trusted_path(path, directory=False):
    """Every ancestor must be a real root-owned non-writable-by-others directory."""
    path = Path(path)
    if not path.is_absolute():
        raise PromotionError("Trusted paths must be absolute")
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        final = part == path
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise PromotionError("Untrusted ownership/mode or symlink in privileged path")
        if (not final or directory) and not stat.S_ISDIR(info.st_mode):
            raise PromotionError("Privileged parent is not a directory")
        if final and not directory and not stat.S_ISREG(info.st_mode):
            raise PromotionError("Privileged input is not a regular file")


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise PromotionError("Unexpected host-policy schema")
    for key, expected in IDENTITY.items():
        if policy[key] != expected or type(policy[key]) is not type(expected):
            raise PromotionError("Host policy changes a fixed deployment identity: " + key)
    if type(policy["enabled"]) is not bool:
        raise PromotionError("enabled must be a boolean")
    for key, length in (("allowed_control_commit", 40), ("branding_sha256", 64), ("security_contract_sha256", 64)):
        value = policy[key]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value) or set(value) == {"0"}:
            raise PromotionError("Review and replace the placeholder policy identity: " + key)
    if not isinstance(policy["repository_id"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", policy["repository_id"]):
        raise PromotionError("A reviewed numeric GitHub repository ID is required")
    assets = policy["branding_assets"]
    if not isinstance(assets, dict) or set(assets) != ASSETS or any(not isinstance(v, str) or not re.fullmatch(r"[0-9a-f]{64}", v) for v in assets.values()):
        raise PromotionError("Exactly the approved branding asset hashes are required")
    return policy


def version(tag):
    match = re.fullmatch(r"v?(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})", tag or "")
    if not match:
        raise PromotionError("Expected an ordinary stable release version")
    return tuple(map(int, match.groups()))


def atomic_bytes(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".update-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


class Commands:
    def __init__(self, state):
        # Do not read a user's Docker context, credential helper, env file or SSH configuration.
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(state / "empty-home"),
                    "DOCKER_CONFIG": str(state / "docker"), "DOCKER_HOST": "unix:///var/run/docker.sock",
                    "COMPOSE_DISABLE_ENV_FILE": "1"}

    def __call__(self, args, timeout=60):
        try:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=timeout, env=self.env, check=False)
        except subprocess.TimeoutExpired:
            raise CommandError("Fixed maintenance command timed out; inspect its outcome before retry", uncertain=True)
        if result.returncode:
            raise CommandError("Fixed maintenance command failed (exit %s); output suppressed to protect configuration" % result.returncode)
        if len(result.stdout) > 2097152:
            raise CommandError("Fixed maintenance command response exceeded its bound")
        return result.stdout.decode("utf-8").strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http(origin, path, method="GET", body=None, headers=None, limit=5242880):
    url = urllib.parse.urlsplit(origin)
    if url.query or url.fragment or url.username or url.password or url.path not in ("", "/"):
        raise PromotionError("Probe origin must not carry a path, credentials or query")
    if origin not in ("https://share.rivalit.ai", "http://127.0.0.1:8000") and not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", origin):
        raise PromotionError("Probe destination is outside the approved origins")
    if not path.startswith("/") or path.startswith("//"):
        raise PromotionError("Probe path must be origin-relative")
    request = urllib.request.Request(origin + path, data=body, method=method, headers=headers or {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise PromotionError("Probe response exceeded its bound")
        return response.code, data


def get_status(request, origin):
    code, data = request(origin, "/api/status/", limit=16384)
    if code != 200:
        raise PromotionError("Status endpoint is unhealthy")
    status = json.loads(data, object_pairs_hook=unique)
    if status.get("file_format_version") != 2:
        raise PromotionError("The new-format reader/capability gate is required for safe promotion and rollback")
    version(status.get("version"))
    for key in STATUS_KEYS:
        if key not in status:
            raise PromotionError("Status is missing the production configuration contract")
    return status


def probe(request, origin, expected, assets=None, shares=False):
    if shares and origin in ("https://share.rivalit.ai", "http://127.0.0.1:8000"):
        raise PromotionError("Host probes never create production shares")
    status = get_status(request, origin)
    for key in (*STATUS_KEYS, "version"):
        if status.get(key) != expected.get(key):
            raise PromotionError("Status/configuration compatibility check failed: " + key)
    if request(origin, "/api/live/", limit=16384)[0] != 200:
        raise PromotionError("Cache health check failed")
    for path, digest in (assets or {}).items():
        code, data = request(origin, "/" + path.removeprefix("packages/frontend/static/"))
        if code != 200 or hashlib.sha256(data).hexdigest() != digest:
            raise PromotionError("Branding asset does not match the approved contract")
    if shares:
        # Public, synthetic ciphertext fixtures exercise opaque storage and the
        # old-reader guard. Decryption/tamper/CLI/browser checks remain CI gates.
        fixtures = FIXTURES
        for kind, contents, guarded in fixtures:
            meta = json.dumps({"type": kind}, separators=(",", ":"))
            payload = json.dumps({"contents": contents, "meta": meta, "views": 1}).encode()
            code, data = request(origin, "/api/notes/", "POST", payload, {"Content-Type": "application/json"}, 16384)
            result = json.loads(data) if code == 200 else {}
            note_id = result.get("id")
            if not isinstance(note_id, str) or not re.fullmatch(r"[A-Za-z0-9]{1,256}", note_id):
                raise PromotionError("Synthetic share creation failed")
            path = "/api/notes/" + note_id
            if guarded and (request(origin, path, "DELETE", limit=16384)[0] != 426 or request(origin, path, limit=16384)[0] != 200):
                raise PromotionError("An old reader consumed or could consume a protected file")
            code, data = request(origin, path, "DELETE", headers={"X-Cryptgeon-File-Format": "2"}, limit=16384)
            if code != 200 or json.loads(data) != {"meta": meta, "contents": contents} or request(origin, path, limit=16384)[0] != 404:
                raise PromotionError("Synthetic one-view share round trip failed")
    return status


def load_policy(path, apply=False):
    path = Path(path)
    if apply:
        for name in ("controller.py", "promote.py", "provenance.py"):
            trusted_path(Path(__file__).resolve().with_name(name))
        trusted_path(path)
    policy = validate_policy(read_json(path, 65536))
    if apply:
        if not policy["enabled"] or os.geteuid() != 0:
            raise PromotionError("Explicit activation and root are required")
        trusted_path(policy["compose_file"])
        trusted_path(policy["state_dir"], directory=True)
        if Path(policy["compose_file"]).stat().st_mode & 0o077:
            raise PromotionError("Authoritative Compose must be private mode 0600")
    return policy


def validate_compose(config):
    if not isinstance(config, dict) or set(config.get("services", {})) != {"app", "redis"}:
        raise PromotionError("Only the observed two-service deployment is supported")
    app, redis = config["services"]["app"], config["services"]["redis"]
    if app.get("build") or not isinstance(app.get("image"), str) or not re.fullmatch(r"(?:sha256:[0-9a-f]{64}|ghcr\.io/nickanewell/share@sha256:[0-9a-f]{64})", app["image"]):
        raise PromotionError("Production app must use an immutable reviewed image identity")
    for service in (app, redis):
        if any(service.get(k) for k in ("privileged", "devices", "cap_add", "network_mode", "pid", "ipc", "extends", "env_file")):
            raise PromotionError("Unexpected privileged or externally sourced Compose configuration")
        if service.get("container_name") not in (None, "share-app", "share-redis"):
            raise PromotionError("Unexpected production container identity")
    if app.get("command") or app.get("entrypoint"):
        raise PromotionError("Custom app commands require separate staging review")
    if app.get("container_name") != "share-app" or redis.get("container_name") != "share-redis":
        raise PromotionError("Unexpected service/container identity")
    if app.get("scale", 1) != 1 or app.get("deploy", {}).get("replicas", 1) != 1:
        raise PromotionError("The note-lock contract supports one production backend only")
    if app.get("volumes") or redis.get("ports"):
        raise PromotionError("Candidate app mounts and published Redis ports are not supported")
    for mount in redis.get("volumes", []):
        if not isinstance(mount, dict) or mount.get("type") != "volume":
            raise PromotionError("Only Docker-managed Redis storage is supported")
    if config.get("include") or config.get("secrets") or config.get("configs"):
        raise PromotionError("Unreviewed Compose include/config/secret sources")


def package_maintenance_gate(commands, reboot_marker=Path("/run/reboot-required")):
    if reboot_marker.exists():
        return "guest-reboot-required"
    output = commands([SYSTEMCTL, "show", "--property=ActiveState", "--value", "apt-daily.service", "apt-daily-upgrade.service"])
    # systemctl may separate multiple unit blocks with an empty line.
    states = [line for line in output.splitlines() if line]
    if len(states) != 2 or any(state not in {"active", "activating", "reloading", "deactivating", "inactive", "failed"} for state in states):
        raise PromotionError("Unable to establish package-maintenance state")
    if any(state != "inactive" for state in states):
        return "package-maintenance-active-or-needs-review"
    return None


class Promoter:
    def __init__(self, policy, commands, request=http, verifier=None, trust=trusted_path, sleep=time.sleep, maintenance_gate=package_maintenance_gate):
        self.policy = validate_policy(policy)
        self.run, self.request, self.trust, self.sleep = commands, request, trust, sleep
        self.verifier = verifier
        self.maintenance_gate = maintenance_gate
        self.path, self.state_dir = Path(policy["compose_file"]), Path(policy["state_dir"])

    def compose(self, path, *args, project="share", timeout=90):
        return self.run([DOCKER, "compose", "-p", project, "--project-directory", str(self.path.parent), "-f", str(path), *args], timeout=timeout)

    def inspect(self, name):
        template = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}}}'
        return json.loads(self.run([DOCKER, "inspect", name, "--format", template]))

    def save(self, state):
        atomic_bytes(self.state_dir / "state.json", (json.dumps(state, sort_keys=True) + "\n").encode())

    def public_docker_config(self):
        # An empty config directory can trigger Docker's platform-default
        # credential helper. Explicit nonempty anonymous auths suppress that
        # autodetection without storing any credential. Never replace foreign
        # configuration, even when it appears otherwise usable.
        path = self.state_dir / "docker" / "config.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            self.trust(path)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or stream.read(len(PUBLIC_DOCKER_CONFIG) + 1) != PUBLIC_DOCKER_CONFIG:
                    raise PromotionError("Unexpected private Docker configuration; inspect it without overwriting")
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(PUBLIC_DOCKER_CONFIG)
                stream.flush()
                os.fsync(stream.fileno())
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            self.trust(path)

    def healthy(self, image_id, redis_id, expected, app_id, config_bytes):
        for _ in range(12):
            app = self.inspect("share-app")
            if app["image"] != image_id or app["id"] != app_id or self.path.read_bytes() != config_bytes or self.inspect("share-redis")["id"] != redis_id:
                raise PromotionError("Unexpected running image or Redis identity; inspect before further mutation")
            try:
                if not app["running"]:
                    raise PromotionError("App is not running")
                probe(self.request, self.policy["local_origin"], expected)
                probe(self.request, self.policy["production_origin"], expected)
                return
            except (OSError, ValueError, PromotionError):
                self.sleep(2)
        raise PromotionError("App did not recover within the bounded health window")

    def stage_probe(self, container_id, image_id, expected):
        # Join only the isolated candidate's network namespace. Docker internal
        # networks intentionally have no published ports; host probing is unsafe
        # to assume. This trusted Node image/code never comes from the candidate.
        expected = {key: expected[key] for key in (*STATUS_KEYS, "version")}
        nonce = os.urandom(16).hex()
        data = {"expected": expected, "assets": self.policy["branding_assets"], "fixtures": FIXTURES, "nonce": nonce, "image": image_id}
        name = "rival-share-probe-" + nonce
        args = [DOCKER, "run", "--name", name, "--rm", "--init", "--network", "container:" + container_id,
                "--read-only", "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--memory", "256m", "--memory-swap", "256m", "--pids-limit", "64", "--cpus", "1", "--entrypoint", "node",
                PROBE_IMAGE, "-e", PROBE_JS, json.dumps(data, separators=(",", ":"))]
        self.stage_state["pending"]["probe_container"] = name
        self.save(self.stage_state)
        try:
            result = json.loads(self.run(args, timeout=90), object_pairs_hook=unique)
        except CommandError as error:
            if error.uncertain:
                raise CommandError("Probe timed out; inspect owned probe container " + name, uncertain=True) from error
            # A nonzero Docker exit is not proof that --rm completed. Establish
            # absence before allowing the bounded readiness loop to try again.
            remaining = self.run([DOCKER, "ps", "-aq", "--filter", "name=^/" + name + "$"])
            if remaining:
                raise CommandError("Owned probe container remains; inspect before retry: " + name, uncertain=True) from error
            self.stage_state["pending"]["probe_container"] = None
            self.save(self.stage_state)
            raise
        self.stage_state["pending"]["probe_container"] = None
        self.save(self.stage_state)
        wanted = {"format", "version", "status", "nonce", "image", "observed", "asset_hashes", "checks"}
        if not isinstance(result, dict) or set(result) != wanted or result["format"] != "rival-share-stage-probe" or type(result["version"]) is not int or result["version"] != 1 or result["status"] != "passed" or result["nonce"] != nonce or result["image"] != image_id or result["observed"] != expected or result["asset_hashes"] != self.policy["branding_assets"] or result["checks"] != PROBE_CHECKS:
            raise PromotionError("Trusted probe did not return the complete bound status/branding/crypto contract")

    def execute(self, manifest_path, bundle_path, apply=False, expected_upstream_tag=None):
        # Cryptographic verification must precede every Docker/promotion action.
        if self.verifier is None:
            if apply:
                self.trust(Path(__file__).resolve().with_name("provenance.py"))
            from provenance import verify_release
            verifier = verify_release
        else:
            verifier = self.verifier
        release = verifier(manifest_path, bundle_path, self.policy)
        if expected_upstream_tag is not None and release["upstream_tag"] != expected_upstream_tag:
            raise PromotionError("Signed release does not match the discovered release tag")
        if not apply:
            return {"status": "verified-plan-only", "image": release["image"], "upstream_tag": release["upstream_tag"]}
        if not self.policy["enabled"] or os.geteuid() != 0:
            raise PromotionError("Explicit activation and root are required")
        self.trust(self.path)
        self.trust(self.state_dir, directory=True)
        for name in ("empty-home", "docker"):
            folder = self.state_dir / name
            folder.mkdir(mode=0o700, exist_ok=True)
            self.trust(folder, directory=True)
        self.public_docker_config()
        lock_fd = os.open(self.state_dir / "update.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self._locked(release)
        finally:
            os.close(lock_fd)

    def _locked(self, release):
        state_path = self.state_dir / "state.json"
        if state_path.exists():
            self.trust(state_path)
            state = read_json(state_path)
        else:
            state = {"failed_images": [], "pending": None}
        if not isinstance(state, dict) or not isinstance(state.get("failed_images"), list) or len(state["failed_images"]) > 32 or any(not isinstance(x, str) for x in state["failed_images"]):
            raise PromotionError("Invalid protected update state; inspect before proceeding")
        if state.get("pending"):
            raise PromotionError("A previous operation has an uncertain/pending outcome; inspect it manually before retry")
        if release["image"] in state.get("failed_images", []):
            raise PromotionError("This failed release is quarantined; explicit review is required")
        deferred = self.maintenance_gate(self.run)
        if deferred:
            return {"status": "deferred-maintenance", "reason": deferred, "image": release["image"]}
        old_status = get_status(self.request, self.policy["local_origin"])
        if version(release["upstream_tag"])[0] != 2:
            raise PromotionError("Major migration is not eligible")
        floor = max(version(old_status["version"]), version(state.get("last_upstream_tag", "v0.0.0")))
        if version(release["upstream_tag"]) <= floor:
            return {"status": "not-newer", "upstream_tag": release["upstream_tag"]}
        raw = self.path.read_bytes()
        if len(raw) > 1048576:
            raise PromotionError("Authoritative Compose exceeds its bound")
        original = json.loads(raw, object_pairs_hook=unique)
        effective = json.loads(self.compose(self.path, "config", "--format", "json"))
        validate_compose(effective)
        app_before, redis_before = self.inspect("share-app"), self.inspect("share-redis")
        if not app_before["running"] or not redis_before["running"]:
            raise PromotionError("Production must be healthy before starting")
        configured_image = json.loads(self.run([DOCKER, "image", "inspect", effective["services"]["app"]["image"], "--format", "{{json .Id}} "]))
        if configured_image != app_before["image"]:
            raise PromotionError("Configured and running rollback images differ; review before staging")
        self.run([DOCKER, "pull", "--platform", "linux/amd64", release["image"]], timeout=300)
        self.run([DOCKER, "pull", "--platform", "linux/amd64", REDIS], timeout=300)
        self.run([DOCKER, "pull", "--platform", "linux/amd64", PROBE_IMAGE], timeout=300)
        image = json.loads(self.run([DOCKER, "image", "inspect", release["image"], "--format", '{"id":{{json .Id}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}}}']))
        if image["revision"] != release["source_commit"] or not re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"]):
            raise PromotionError("Pulled image does not match its signed source identity")
        expected = dict(old_status, version=release["upstream_tag"].removeprefix("v"))
        work = Path(tempfile.mkdtemp(prefix="stage-", dir=self.state_dir))
        stage = work / "compose.json"
        env = {k: v for k, v in effective["services"]["app"].get("environment", {}).items() if k in ENV_KEYS}
        env["REDIS"] = "redis://redis/"
        staging = {"services": {
                "redis": {"image": REDIS, "command": ["redis-server", "--save", "", "--appendonly", "no"], "tmpfs": ["/data:rw,noexec,nosuid,size=16m,mode=1777"], "user": "999:999", "read_only": True, "mem_limit": "256m", "memswap_limit": "256m", "pids_limit": 64, "cpus": 0.5,
                      "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "restart": "no"},
            "app": {"image": release["image"], "environment": env, "read_only": True,
                        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "tmpfs": ["/tmp:rw,noexec,nosuid,size=16m"], "mem_limit": "1g", "memswap_limit": "1g", "pids_limit": 128, "cpus": 1, "restart": "no"}},
            "networks": {"default": {"internal": True}}}
        atomic_bytes(stage, json.dumps(staging).encode())
        project = "rival-share-candidate"
        if self.compose(stage, "ps", "-aq", project=project):
            raise PromotionError("A candidate project already exists; inspect it instead of replacing it")
        state["pending"] = {"phase": "staging", "image": release["image"], "stage": work.name, "probe_container": None}
        self.stage_state = state
        self.save(state)
        try:
            self.compose(stage, "up", "-d", "--no-build", "--pull", "never", project=project)
            stage_app = self.compose(stage, "ps", "-q", "app", project=project)
            if not re.fullmatch(r"[0-9a-f]{64}", stage_app) or self.inspect(stage_app)["image"] != image["id"]:
                raise PromotionError("Candidate container identity does not match the verified image")
            for attempt in range(15):
                try:
                    self.stage_probe(stage_app, image["id"], expected)
                    break
                except CommandError as error:
                    if error.uncertain or attempt == 14:
                        raise
                    self.sleep(2)
                except (OSError, ValueError, PromotionError):
                    if attempt == 14:
                        raise
                    self.sleep(2)
        except Exception as error:
            if isinstance(error, CommandError) and error.uncertain:
                state["pending"]["phase"] = "staging-uncertain"
            else:
                state["failed_images"] = (state.get("failed_images", []) + [release["image"]])[-32:]
                try:
                    self.compose(stage, "down", project=project)
                    state["pending"] = None
                except Exception:
                    state["pending"] = {"phase": "staging-cleanup-failed-or-uncertain", "image": release["image"], "stage": work.name}
            self.save(state)
            raise PromotionError("Candidate staging failed; production was not changed") from error
        else:
            try:
                self.compose(stage, "down", project=project)
                state["pending"] = None
                self.save(state)
            except Exception as error:
                state["pending"] = {"phase": "staging-cleanup-failed-or-uncertain", "image": release["image"], "stage": work.name}
                self.save(state)
                raise PromotionError("Candidate cleanup failed or is uncertain; production unchanged") from error
        if self.path.read_bytes() != raw or self.inspect("share-redis")["id"] != redis_before["id"] or self.inspect("share-app")["id"] != app_before["id"]:
            raise PromotionError("Production changed during staging; no promotion performed")
        backup = self.state_dir / ("compose-before-" + release["source_commit"] + ".json")
        if backup.exists():
            self.trust(backup)
            if backup.read_bytes() != raw:
                raise PromotionError("Existing backup differs; inspect before proceeding")
        else:
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        candidate = copy.deepcopy(original)
        candidate["services"]["app"]["image"] = release["image"]
        candidate_file = self.state_dir / "compose-candidate.json"
        atomic_bytes(candidate_file, (json.dumps(candidate, indent=2) + "\n").encode())
        normalized = json.loads(self.compose(candidate_file, "config", "--format", "json"))
        compare = copy.deepcopy(effective)
        compare["services"]["app"]["image"] = release["image"]
        if normalized != compare:
            raise PromotionError("Candidate would change settings other than the app image")
        state["pending"] = {"phase": "promotion", "image": release["image"], "backup": backup.name}
        self.save(state)
        candidate_bytes = candidate_file.read_bytes()
        atomic_bytes(self.path, candidate_bytes)
        owned_app_id = None
        try:
            self.compose(self.path, "up", "-d", "--no-deps", "--no-build", "--pull", "never", "app")
            current = self.inspect("share-app")
            if current["image"] != image["id"]:
                raise PromotionError("Activation did not establish the verified candidate identity")
            owned_app_id = current["id"]
            state["pending"]["container_id"] = owned_app_id
            self.save(state)
            self.healthy(image["id"], redis_before["id"], expected, owned_app_id, candidate_bytes)
        except Exception as error:
            if isinstance(error, CommandError) and error.uncertain:
                state["pending"]["phase"] = "promotion-uncertain"
                self.save(state)
                raise PromotionError("Promotion timed out with uncertain outcome; backup retained, no blind retry/rollback") from error
            # A rollback is allowed only while the expected candidate still owns
            # the app slot and production Redis identity is unchanged.
            now_app, now_redis = self.inspect("share-app"), self.inspect("share-redis")
            unchanged_old = owned_app_id is None and now_app["id"] == app_before["id"] and now_app["image"] == app_before["image"]
            owned_candidate = owned_app_id is not None and now_app["id"] == owned_app_id and now_app["image"] == image["id"]
            if not (unchanged_old or owned_candidate) or self.path.read_bytes() != candidate_bytes or now_redis["id"] != redis_before["id"]:
                state["pending"]["phase"] = "unexpected-concurrent-change"
                self.save(state)
                raise PromotionError("Unexpected production identity; inspect before rollback") from error
            atomic_bytes(self.path, raw)
            try:
                self.compose(self.path, "up", "-d", "--no-deps", "--no-build", "--pull", "never", "app")
                rollback = self.inspect("share-app")
                self.healthy(app_before["image"], redis_before["id"], old_status, rollback["id"], raw)
            except Exception as rollback_error:
                state["pending"]["phase"] = "rollback-failed-or-uncertain"
                self.save(state)
                raise PromotionError("App rollback failed or is uncertain; manual recovery required, backup retained") from rollback_error
            state["pending"] = None
            state["failed_images"] = (state.get("failed_images", []) + [release["image"]])[-32:]
            self.save(state)
            raise PromotionError("Candidate failed health checks; previous compatible app/config restored") from error
        state.update(pending=None, last_upstream_tag=release["upstream_tag"], last_image=release["image"], last_source_commit=release["source_commit"])
        self.save(state)
        return {"status": "promoted", "image": release["image"], "upstream_tag": release["upstream_tag"]}


def promote_release(manifest_path, bundle_path, policy, apply=False, expected_upstream_tag=None):
    controller = Promoter(policy, Commands(Path(policy["state_dir"])))
    return controller.execute(manifest_path, bundle_path, apply, expected_upstream_tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("/etc/rival-share/update-policy.json"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="Requires reviewed enabled root-owned policy; otherwise verify/plan only")
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy, args.apply)
        print(json.dumps(promote_release(args.manifest, args.bundle, policy, args.apply), sort_keys=True))
    except (OSError, ValueError, PromotionError) as error:
        parser.exit(1, "Automatic promotion stopped: " + str(error) + "\n")


if __name__ == "__main__":
    main()
