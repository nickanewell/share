#!/usr/bin/env python3
"""Build/test a disposable candidate; never publishes or touches production.

Only the reviewed control checkout supplies the recipe, test harness and this
program. Candidate build/test scripts run in isolated containers, not on the host.
The caller must supply clean, non-overlapping checkouts and a fresh output path.
This Linux Docker gate does not establish provenance; the publisher signs its
exact resulting image identity separately after all required checks pass.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import subprocess
import time


REDIS = 'redis:7.4.11-alpine@sha256:57e4255cc971b1c8d6f8a6ca283ac01bc3ecdd914273ef6bfaede87aaecd6541'
PW = 'mcr.microsoft.com/playwright:v1.64.1-noble@sha256:47b510dd9230bf0b9bfc9b20102241e577ea7a99334ab4c3ca19f19770e9b8ea'
CONTRACTS = ('Dockerfile', '.dockerignore', '.gitattributes', '.lfsconfig', '.github',
             '.upstream-sync.json', 'playwright.config.ts', 'test', 'scripts', 'deploy/automatic',
             'packages/backend/src/lock.rs', 'packages/backend/src/note/routes.rs',
             'packages/backend/src/note/model.rs', 'packages/backend/src/status/mod.rs',
             'packages/cli/src/shared/files.ts', 'packages/cli/src/shared/adapters.ts',
             'packages/cli/src/shared/api.ts', 'packages/cli/src/actions/upload.ts',
             'packages/cli/src/actions/download.ts', 'packages/cli/src/utils/download-files.ts',
             'packages/frontend/src/routes/note/[id]/+page.svelte',
             'packages/frontend/src/lib/ui/NoteResult.svelte', 'packages/frontend/src/lib/ui/FileUpload.svelte')
CHECKS = ('javascript-security', 'frontend-sync', 'frontend-check', 'rust-security',
          'staging-health-format', 'browser-chrome-firefox-webkit')
SHA = re.compile(r'[0-9a-f]{40}\Z')
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
MAX_LOG_BYTES = 16 * 1024 * 1024
RUST_TESTS = (
    'unique_ids_do_not_grow_lock_storage', 'same_note_is_serialized_across_state_clones',
    'colliding_note_ids_are_also_serialized', 'different_shards_progress_independently',
    'version_two_notes_require_the_exact_reader_capability',
    'legacy_text_arrays_and_other_objects_do_not_require_a_new_reader',
    'malformed_object_envelopes_require_an_updated_reader',
    'json_equivalent_format_and_version_values_are_detected',
    'large_ciphertext_is_skipped_while_the_format_is_borrowed',
)


class GateError(RuntimeError):
    pass


def require_node_tests(text):
    # Maintained files currently define 32 Linux security tests. An exit-zero run
    # which silently disables or skips that contract must not authorize release.
    for key, expected in (('tests', 32), ('pass', 32), ('fail', 0), ('skipped', 0)):
        values = re.findall(r'^# ' + key + r' ([0-9]+)$', text, re.MULTILINE)
        if not values or int(values[-1]) != expected:
            raise GateError('JavaScript security contract was not fully executed')


def require_rust_tests(text):
    for name in RUST_TESTS:
        if not re.search(r'^test (?:[A-Za-z_][A-Za-z_0-9]*::)*' + re.escape(name) + r' \.\.\. ok$', text, re.MULTILINE):
            raise GateError('A maintained Rust security regression was not executed: ' + name)
    if not re.search(r'test result: ok\. [0-9]+ passed; 0 failed;', text):
        raise GateError('Rust test result summary is missing')


def require_browser_report(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOG_BYTES:
            raise GateError('Expected a bounded regular Playwright report')
        data = stream.read(MAX_LOG_BYTES + 1)
    if len(data) > MAX_LOG_BYTES:
        raise GateError('Playwright report is too large')
    report = json.loads(data)
    expected_stats = {'expected': 93, 'skipped': 6, 'unexpected': 0, 'flaky': 0}
    if report.get('errors') != [] or any(type(report.get('stats', {}).get(key)) is not int
            or report['stats'][key] != value for key, value in expected_stats.items()):
        raise GateError('The maintained browser contract did not fully pass')
    if {project.get('name') for project in report.get('config', {}).get('projects', [])} != {'chrome', 'firefox', 'safari'}:
        raise GateError('All three maintained browser projects are required')
    security = {name: set() for name in ('chrome', 'firefox', 'safari')}
    pending = list(report.get('suites', []))
    while pending:
        suite = pending.pop()
        pending.extend(suite.get('suites', []))
        for specification in suite.get('specs', []):
            if not specification.get('file', '').endswith('web/file/security.spec.js'):
                continue
            for item in specification.get('tests', []):
                project = item.get('projectName')
                results = item.get('results', [])
                if project not in security or item.get('status') != 'expected' or len(results) != 1 or results[0].get('status') != 'passed':
                    raise GateError('Every cross-browser file security case must execute and pass')
                security[project].add(specification.get('id'))
    if any(None in cases or len(cases) != 9 for cases in security.values()):
        raise GateError('A maintained file security case/browser was skipped or missing')


def source_contract():
    # Resolve only next to this trusted program, never from candidate source.
    path = Path(__file__).with_name('prepare_release.py')
    spec = importlib.util.spec_from_file_location('rival_gate_source_contract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def real_directory(path):
    path = Path(path).absolute()
    if ',' in str(path) or any(ord(char) < 32 for char in str(path)):
        raise GateError('Checkout paths cannot contain Docker mount delimiters/control characters')
    if path != path.resolve(strict=True) or not path.is_dir():
        raise GateError('Checkout paths must be real directories without symlink ancestors')
    return path


def tree(root, relative):
    """Hash an optional maintained contract without following links or devices."""
    start = root / relative
    if not start.exists() and not start.is_symlink():
        return {}
    result = {}
    pending = [start]
    while pending:
        path = pending.pop()
        if path.name == '__pycache__' or path.suffix == '.pyc':
            continue  # Python's ignored local import cache is never a contract.
        if path.relative_to(root).as_posix() == 'test/assets':
            continue  # Only verified control fixtures are mounted; candidate LFS pointers are unused.
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            pending.extend(path.iterdir())
        elif stat.S_ISREG(mode):
            result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            raise GateError('Contract contains a symlink or nonregular file: ' + path.relative_to(root).as_posix())
    return result


def git(root, *args):
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    completed = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                                '-C', str(root), *args], text=True, capture_output=True,
                               timeout=30, check=True, env=env)
    return completed.stdout.strip()


def verify_control_fixtures(control):
    """Validate the maintained fixture bytes against tracked LFS OIDs, if used."""
    for fixture in (control / 'test/assets').rglob('*'):
        if not stat.S_ISREG(fixture.lstat().st_mode):
            if fixture.is_dir() and not fixture.is_symlink():
                continue
            raise GateError('Trusted fixtures must be regular files/directories')
        data = fixture.read_bytes()
        if data.startswith(b'version https://git-lfs.github.com/spec/v1'):
            raise GateError('Unmaterialized Git LFS test fixture: ' + fixture.name)
        relative = fixture.relative_to(control).as_posix()
        tracked = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(control),
                                  'show', 'HEAD:' + relative], check=True, capture_output=True, timeout=30,
                                 env={'PATH': '/usr/local/bin:/usr/bin:/bin',
                                      'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}).stdout
        if tracked.startswith(b'version https://git-lfs.github.com/spec/v1'):
            match = re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n?', tracked)
            if not match or hashlib.sha256(data).hexdigest().encode() != match[1] or len(data) != int(match[2]):
                raise GateError('Trusted fixture does not match its pinned Git LFS identity')


def verify_candidate_build_files(candidate):
    tracked = set(git(candidate, 'ls-files', '-z', '--', 'packages').split('\0')) - {''}
    for path in (candidate / 'packages').rglob('*'):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise GateError('Candidate build files must not contain symlinks/devices')
        with open(path, 'rb') as stream:
            if stream.read(80).startswith(b'version https://git-lfs.github.com/spec/v1'):
                raise GateError('Unmaterialized candidate build asset: ' + path.relative_to(candidate).as_posix())
        if path.relative_to(candidate).as_posix() not in tracked:
            raise GateError('Untracked or ignored package files cannot enter the image')


def preflight(control, candidate, image, output):
    control, candidate = real_directory(control), real_directory(candidate)
    if control == candidate or control in candidate.parents or candidate in control.parents:
        raise GateError('Control and candidate must be separate non-overlapping checkouts')
    output = Path(output).absolute()
    if ',' in str(output) or any(ord(char) < 32 for char in str(output)):
        raise GateError('Output path cannot contain Docker mount delimiters/control characters')
    # Resolve the existing parent only; a new output directory is mandatory.
    if output.parent != output.parent.resolve(strict=True):
        raise GateError('Output parent must not contain symlinks')
    if output.exists() or output.is_symlink():
        raise GateError('Output directory must be fresh')
    if any(output == root or root in output.parents or output in root.parents for root in (control, candidate)):
        raise GateError('Output must be outside both checkouts')
    for relative in CONTRACTS:
        if tree(control, relative) != tree(candidate, relative):
            raise GateError('Candidate changed a maintained recipe/contract: ' + relative)
    for required in ('Dockerfile', '.dockerignore', 'test/security', 'test/web/file/security.spec.js',
                     'deploy/automatic/gate-browser.Dockerfile', 'deploy/automatic/gate.config.cjs'):
        if not (control / required).exists():
            raise GateError('Missing maintained contract: ' + required)
    verify_control_fixtures(control)
    verify_candidate_build_files(candidate)
    contract = source_contract()
    try:
        for root in (control, candidate):
            contract.require_clean(root)
        contract.assert_contract(control, candidate)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise GateError('Maintained contract/clean checkout validation failed: ' + str(error)) from error
    source = git(candidate, 'rev-parse', '--verify', 'HEAD')
    if not SHA.fullmatch(source) or image != 'rival-it-share:gate-' + source:
        raise GateError('Local image tag must identify the exact candidate commit')
    return control, candidate, output, source


class Runner:
    def __init__(self, output):
        self.output = output
        (output / 'docker-config').mkdir(mode=0o700)
        (output / 'home').mkdir(mode=0o700)
        self.env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(output / 'home'),
                    'DOCKER_CONFIG': str(output / 'docker-config'), 'DOCKER_BUILDKIT': '1'}

    def run(self, args, *, timeout, log):
        def bound_log():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES))
        path = self.output / (log + '.log')
        with open(path, 'xb') as stream:
            result = subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=timeout, env=self.env, preexec_fn=bound_log)
        if result.returncode:
            raise GateError(f'{log} failed (exit {result.returncode}); inspect its local log')
        if path.stat().st_size >= MAX_LOG_BYTES:
            raise GateError(log + ' exceeded the bounded log size')
        return path.read_text(errors='replace')


def execute_gate(control, candidate, image, output, *, runner_factory=Runner, sleep=time.sleep):
    control, candidate, output, source = preflight(control, candidate, image, output)
    output.mkdir(mode=0o700)
    runner = runner_factory(output)
    token = 'rival-gate-' + secrets.token_hex(8)
    network, app, cache = token + '-net', token + '-app', token + '-redis'
    client, backend, browser = [image + '-' + name for name in ('client', 'backend', 'browser')]
    checks = []
    owned_containers, network_attempted = [], False
    failure = None

    def run(args, log, timeout=600):
        return runner.run(args, timeout=timeout, log=log)

    def container(name, target, command, log, *, entrypoint, network_mode='none', mounts=(), env=(), timeout=300):
        # Register before launch: a failed/uncertain docker client outcome is still
        # cleaned up by this exact unpredictable name, never an unrelated service.
        owned_containers.append(name)
        args = ['docker', 'run', '--rm', '--name', name, '--init', '--network', network_mode,
                '--label', 'rival.it.gate-id=' + token,
                '--memory=2g', '--cpus=2', '--pids-limit=512', '--shm-size=256m',
                '--cap-drop=ALL', '--security-opt=no-new-privileges']
        for source_path, destination, writable in mounts:
            args += ['--mount', f'type=bind,src={source_path},dst={destination}' + ('' if writable else ',readonly')]
        for variable in env:
            args += ['--env', variable]
        args += ['--entrypoint', entrypoint, target, *command]
        return run(args, log, timeout)

    try:
        run(['docker', 'pull', '--platform=linux/amd64', REDIS], 'pull-redis', 180)
        run(['docker', 'pull', '--platform=linux/amd64', PW], 'pull-browsers', 240)
        for tag, target in ((client, 'client'), (backend, 'backend'), (image, None)):
            args = ['docker', 'build', '--platform=linux/amd64', '--file', str(control / 'Dockerfile'),
                    '--build-arg', 'SOURCE_REVISION=' + source, '--tag', tag]
            if target:
                args += ['--target', target]
            run([*args, str(candidate)], 'build-' + (target or 'release'), 1200)
        node_tests = sorted((control / 'test/security').glob('*.test.mjs'))
        if not node_tests:
            raise GateError('The trusted JavaScript security contract is empty')
        common_mounts = [(control / 'test', '/tmp/test', False)]
        node_output = container(token + '-js', client,
                  ['--test', '--test-reporter=tap', '--test-timeout=30000', *('/tmp/test/security/' + p.name for p in node_tests)],
                  'javascript-security', entrypoint='node', mounts=common_mounts)
        require_node_tests(node_output)
        checks.append('javascript-security')
        container(token + '-sync', client, ['--filter', '@cryptgeon/web', 'exec', 'svelte-kit', 'sync'],
                  'frontend-sync', entrypoint='pnpm')
        checks.append('frontend-sync')
        check_output = container(token + '-check', client,
                  ['--filter', '@cryptgeon/web', 'exec', 'svelte-check', '--tsconfig', 'tsconfig.json'],
                  'frontend-check', entrypoint='pnpm', env=['NO_COLOR=1', 'FORCE_COLOR=0'])
        if 'svelte-check found 0 errors and 0 warnings' not in check_output:
            raise GateError('Frontend typecheck did not report zero errors/warnings')
        checks.append('frontend-check')
        rust_output = container(token + '-rust', backend, ['test', '--release', '--offline', '--locked', '-j1', '--', '--format', 'pretty'],
                  'rust-security', entrypoint='cargo', env=['RUSTFLAGS=-Ctarget-feature=-crt-static', 'CARGO_TERM_COLOR=never'], timeout=600)
        require_rust_tests(rust_output)
        checks.append('rust-security')
        run(['docker', 'build', '--platform=linux/amd64', '--file', str(control / 'deploy/automatic/gate-browser.Dockerfile'),
             '--build-arg', 'CLIENT_IMAGE=' + client, '--tag', browser, str(control / 'deploy/automatic')],
            'build-browser-runner', 300)
        network_attempted = True
        run(['docker', 'network', 'create', '--internal', '--label', 'rival.it.purpose=isolated-release-gate',
             '--label', 'rival.it.gate-id=' + token, network],
            'create-network', 30)
        owned_containers.append(cache)
        run(['docker', 'run', '-d', '--name', cache, '--platform=linux/amd64', '--network', network,
             '--label', 'rival.it.gate-id=' + token,
             '--network-alias', 'redis', '--read-only', '--user', '999:999', '--memory=256m', '--cpus=1',
             '--pids-limit=128', '--cap-drop=ALL', '--security-opt=no-new-privileges',
             '--tmpfs', '/data:rw,noexec,nosuid,size=128m,mode=1777', REDIS,
             'redis-server', '--save', '', '--appendonly', 'no', '--maxmemory', '96mb', '--maxmemory-policy', 'noeviction'],
            'start-cache', 30)
        owned_containers.append(app)
        run(['docker', 'run', '-d', '--name', app, '--platform=linux/amd64', '--network', network,
             '--label', 'rival.it.gate-id=' + token,
             '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--memory=768m', '--cpus=2',
             '--pids-limit=128', '--cap-drop=ALL', '--security-opt=no-new-privileges',
             '--env', 'REDIS=redis://redis/', '--env', 'SIZE_LIMIT=10MiB', image], 'start-app', 30)
        for attempt in range(30):
            try:
                run(['docker', 'exec', app, 'curl', '--fail', '--silent', '--show-error', '--max-time', '2',
                     'http://127.0.0.1:8000/api/live/'], f'health-{attempt}', 5)
                break
            except GateError:
                if attempt == 29:
                    raise GateError('Isolated app did not become healthy')
                sleep(1)
        status = json.loads(run(['docker', 'exec', app, 'curl', '--fail', '--silent', '--show-error', '--max-time', '3',
                                 'http://127.0.0.1:8000/api/status/'], 'staging-status', 10))
        if status.get('file_format_version') != 2 or status.get('max_size') != 10485760 or status.get('allow_files') is not True:
            raise GateError('Isolated candidate changed required file protocol/size behavior')
        checks.append('staging-health-format')
        results = output / 'browser-results'
        # The host output parent remains 0700. Docker root with all capabilities
        # dropped cannot write a runner-owned 0700 bind directory, so grant write
        # access only to this isolated, otherwise inaccessible report subtree.
        results.mkdir(mode=0o700)
        os.chmod(results, 0o777)
        container(token + '-browser', browser,
                  ['node_modules/@playwright/test/cli.js', 'test', '--config=/tmp/gate.config.cjs',
                   '--workers=2', '--max-failures=1'], 'browser-chrome-firefox-webkit', entrypoint='node',
                  network_mode='container:' + app,
                  mounts=[*common_mounts, (control / 'deploy/automatic/gate.config.cjs', '/tmp/gate.config.cjs', False),
                          (results, '/tmp/gate-results', True)],
                  env=['CRYPTGEON_TEST_SERVER=http://127.0.0.1:8000'], timeout=900)
        require_browser_report(results / 'report.json')
        checks.append('browser-chrome-firefox-webkit')
        metadata = json.loads(run(['docker', 'image', 'inspect', image, '--format', '{{json .}}'], 'image-identity', 30))
        image_id = metadata.get('Id', '')
        labels = metadata.get('Config', {}).get('Labels', {})
        if not IMAGE_ID.fullmatch(image_id) or not isinstance(labels, dict) or labels.get('org.opencontainers.image.revision') != source:
            raise GateError('Final image identity does not match candidate source')
        if tuple(checks) != CHECKS:
            raise GateError('Required gate set was not completed')
        result = {'format': 'rival-it-share-gates', 'schema_version': 1, 'source_commit': source,
                  'image': image, 'image_id': image_id, 'passed': True, 'checks': checks}
    except BaseException as error:
        failure = error
    finally:
        cleanup_errors = []
        for index, name in enumerate(reversed(owned_containers)):
            try:
                # An empty successful exact-name query means --rm already removed
                # it; failure to query the daemon is an unresolved cleanup error.
                present = run(['docker', 'container', 'ls', '--all', '--filter', 'name=^/' + name + '$',
                               '--format', '{{.Names}}'], f'cleanup-query-{index}', 15).strip()
                if present:
                    if present != name:
                        raise GateError('Unexpected container identity during cleanup')
                    owner = run(['docker', 'container', 'inspect', name, '--format',
                                 '{{index .Config.Labels "rival.it.gate-id"}}'], f'cleanup-owner-{index}', 15).strip()
                    if owner != token:
                        raise GateError('Refusing to remove a container not owned by this gate')
                    run(['docker', 'rm', '--force', name], f'cleanup-container-{index}', 30)
            except (GateError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        if network_attempted:
            try:
                present = run(['docker', 'network', 'ls', '--filter', 'name=^' + network + '$',
                               '--format', '{{.Name}}'], 'cleanup-network-query', 15).strip()
                if present:
                    if present != network:
                        raise GateError('Unexpected network identity during cleanup')
                    owner = run(['docker', 'network', 'inspect', network, '--format',
                                 '{{index .Labels "rival.it.gate-id"}}'], 'cleanup-network-owner', 15).strip()
                    if owner != token:
                        raise GateError('Refusing to remove a network not owned by this gate')
                    run(['docker', 'network', 'rm', network], 'cleanup-network', 30)
            except (GateError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            failure = GateError('Isolated gate cleanup is incomplete: ' + '; '.join(cleanup_errors))
    if failure:
        raise failure
    # A success record is never written on a failed gate or incomplete cleanup.
    with open(output / 'gates.json', 'x', encoding='utf-8') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(execute_gate(args.control, args.candidate, args.image, args.output), sort_keys=True))
    except (GateError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Candidate gate stopped: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
