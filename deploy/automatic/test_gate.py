"""Offline command-order and isolation checks; no Docker daemon is contacted."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate_gate', HERE / 'gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class FakeRunner:
    def __init__(self, output, source, fail=None):
        self.output, self.source, self.fail = output, source, fail
        self.calls, self.containers, self.networks = [], set(), set()
        self.image_id = 'sha256:' + 'a' * 64
        self.capability = 2
        self.spoof_owner = False
        self.disable_tests = False

    def run(self, args, *, timeout, log):
        self.calls.append((list(args), timeout, log))
        if log == self.fail:
            raise gate.GateError('simulated ' + log + ' failure')
        if args[:3] == ['docker', 'network', 'create']:
            self.networks.add(args[-1])
        if args[:2] == ['docker', 'run']:
            self.containers.add(args[args.index('--name') + 1])
        if args[:3] == ['docker', 'container', 'ls']:
            name = args[args.index('--filter') + 1].removeprefix('name=^/').removesuffix('$')
            return name if name in self.containers else ''
        if args[:3] == ['docker', 'network', 'ls']:
            name = args[args.index('--filter') + 1].removeprefix('name=^').removesuffix('$')
            return name if name in self.networks else ''
        if log.startswith('cleanup-owner-') or log == 'cleanup-network-owner':
            name = args[3]
            return 'unrelated-resource' if self.spoof_owner else name.removesuffix('-net').removesuffix('-redis').removesuffix('-app').removesuffix('-js').removesuffix('-sync').removesuffix('-check').removesuffix('-rust').removesuffix('-browser')
        if args[:3] == ['docker', 'rm', '--force']:
            self.containers.discard(args[-1])
        if args[:3] == ['docker', 'network', 'rm']:
            self.networks.discard(args[-1])
        if log == 'staging-status':
            return json.dumps({'version': '2.9.4', 'file_format_version': self.capability,
                               'max_size': 10485760, 'allow_files': True})
        if log == 'image-identity':
            return json.dumps({'Id': self.image_id, 'Config': {'Labels': {
                'org.opencontainers.image.revision': self.source}}})
        if log == 'javascript-security':
            return '# tests 0\n# pass 0\n# fail 0\n# skipped 0\n' if self.disable_tests else '# tests 32\n# pass 32\n# fail 0\n# skipped 0\n'
        if log == 'frontend-check':
            return 'svelte-check found 0 errors and 0 warnings\n'
        if log == 'rust-security':
            return '\n'.join('test lock::tests::' + name + ' ... ok' for name in gate.RUST_TESTS) + '\ntest result: ok. 9 passed; 0 failed; 0 ignored;\n'
        if log == 'browser-chrome-firefox-webkit':
            report = {'errors': [], 'config': {'projects': [{'name': name} for name in ('chrome', 'firefox', 'safari')]},
                      'stats': {'expected': 93, 'skipped': 6, 'unexpected': 0, 'flaky': 0},
                      'suites': [{'specs': [{'file': 'web/file/security.spec.js', 'id': 'case-' + str(case),
                                            'tests': [{'projectName': name, 'status': 'expected', 'results': [{'status': 'passed'}]}
                                                      for name in ('chrome', 'firefox', 'safari')]} for case in range(9)]}]}
            (self.output / 'browser-results/report.json').write_text(json.dumps(report))
        return ''


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rival-gate-test-')
        self.root = Path(self.temp.name).resolve()
        self.control, self.candidate = self.root / 'control', self.root / 'candidate'
        self.output = self.root / 'gate-output'
        self.control.mkdir()
        files = {
            'Dockerfile': 'FROM pinned-runtime\n',
            '.dockerignore': '*\n!/packages\n',
            '.github/workflows/test.yaml': 'maintained CI\n',
            'playwright.config.ts': 'maintained configuration\n',
            'test/security/cli-download.test.mjs': 'maintained security contract\n',
            'test/security/file-metadata.test.mjs': 'maintained codec contract\n',
            'test/web/file/security.spec.js': 'maintained browser contract\n',
            'test/assets/fixture.bin': 'tracked fixture bytes\n',
            'deploy/automatic/gate-browser.Dockerfile': (HERE / 'gate-browser.Dockerfile').read_text(),
            'deploy/automatic/gate.config.cjs': (HERE / 'gate.config.cjs').read_text(),
            'packages/backend/src/lock.rs': 'maintained backend regression\n',
        }
        for required in gate.source_contract().REQUIRED_CONTRACTS:
            files.setdefault(required, 'maintained tracked contract fixture\n')
        for name, content in files.items():
            path = self.control / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.initialize(self.control)
        shutil.copytree(self.control, self.candidate)
        self.source = gate.git(self.candidate, 'rev-parse', 'HEAD')
        self.image = 'rival-it-share:gate-' + self.source
        self.fake = FakeRunner(self.output, self.source)

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def initialize(root):
        commands = (['init', '--initial-branch=main'], ['add', '.'],
                    ['-c', 'user.name=Offline test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture'])
        for command in commands:
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-C', str(root),
                            *command], check=True, capture_output=True)

    def execute(self):
        return gate.execute_gate(self.control, self.candidate, self.image, self.output,
                                 runner_factory=lambda output: self.fake, sleep=lambda _: None)

    def assert_no_success_record(self):
        self.assertFalse((self.output / 'gates.json').exists())

    def test_success_requires_all_checks_and_records_exact_image_after_cleanup(self):
        result = self.execute()
        self.assertIs(result['passed'], True)
        self.assertEqual(tuple(result['checks']), gate.CHECKS)
        self.assertEqual(result['source_commit'], self.source)
        self.assertEqual(result['image_id'], self.fake.image_id)
        self.assertEqual(json.loads((self.output / 'gates.json').read_text()), result)
        self.assertFalse(self.fake.containers)
        self.assertFalse(self.fake.networks)
        self.assertEqual(self.fake.calls[-1][2], 'cleanup-network')

    def test_staging_has_no_host_ports_or_secrets_and_uses_internal_network(self):
        self.execute()
        commands = {log: args for args, _, log in self.fake.calls}
        self.assertIn('--internal', commands['create-network'])
        for key in ('start-app', 'start-cache'):
            self.assertNotIn('-p', commands[key])
            self.assertNotIn('--publish', commands[key])
            self.assertNotIn('--privileged', commands[key])
            self.assertIn('--cap-drop=ALL', commands[key])
            self.assertIn('--security-opt=no-new-privileges', commands[key])
        self.assertIn(gate.REDIS, commands['start-cache'])
        self.assertIn('--tmpfs', commands['start-cache'])
        self.assertIn('--save', commands['start-cache'])
        self.assertIn('--appendonly', commands['start-cache'])
        for args in commands.values():
            self.assertNotIn('/var/run/docker.sock', ' '.join(args))
            self.assertNotIn('--network=host', args)
            self.assertNotIn('/home/rival/share', ' '.join(args))
            self.assertNotIn('GH_TOKEN', ' '.join(args))

    def test_candidate_code_runs_only_in_containers_with_read_only_harness(self):
        self.execute()
        commands = {log: args for args, _, log in self.fake.calls}
        for name in ('javascript-security', 'frontend-sync', 'frontend-check', 'rust-security'):
            args = commands[name]
            self.assertEqual(args[:2], ['docker', 'run'])
            self.assertEqual(args[args.index('--network') + 1], 'none')
        browser = commands['browser-chrome-firefox-webkit']
        self.assertTrue(browser[browser.index('--network') + 1].startswith('container:rival-gate-'))
        mounts = [browser[i + 1] for i, value in enumerate(browser) if value == '--mount']
        self.assertIn(f'type=bind,src={self.control / "test"},dst=/tmp/test,readonly', mounts)
        self.assertIn(f'type=bind,src={self.control / "deploy/automatic/gate.config.cjs"},dst=/tmp/gate.config.cjs,readonly', mounts)
        build = commands['build-release']
        self.assertEqual(build[build.index('--file') + 1], str(self.control / 'Dockerfile'))
        self.assertEqual(build[-1], str(self.candidate))
        self.assertTrue(all(isinstance(args, list) and timeout <= 1200 for args, timeout, _ in self.fake.calls))

    def test_failing_security_or_browser_gate_never_produces_success(self):
        for failed in ('javascript-security', 'rust-security', 'browser-chrome-firefox-webkit'):
            with self.subTest(failed=failed):
                if self.output.exists():
                    shutil.rmtree(self.output)
                self.fake = FakeRunner(self.output, self.source, fail=failed)
                with self.assertRaisesRegex(gate.GateError, 'simulated'):
                    self.execute()
                self.assert_no_success_record()
                self.assertFalse(self.fake.containers)
                self.assertFalse(self.fake.networks)

    def test_missing_protocol_capability_stops_before_browser_and_cleans_up(self):
        self.fake.capability = 1
        with self.assertRaisesRegex(gate.GateError, 'protocol'):
            self.execute()
        self.assert_no_success_record()
        self.assertNotIn('browser-chrome-firefox-webkit', [log for _, _, log in self.fake.calls])
        self.assertFalse(self.fake.containers)
        self.assertFalse(self.fake.networks)

    def test_exit_zero_but_disabled_security_contract_does_not_authorize_release(self):
        self.fake.disable_tests = True
        with self.assertRaisesRegex(gate.GateError, 'not fully executed'):
            self.execute()
        self.assert_no_success_record()

    def test_rust_and_browser_contracts_reject_missing_cases_even_with_success_summaries(self):
        with self.assertRaisesRegex(gate.GateError, 'not executed'):
            gate.require_rust_tests('test result: ok. 9 passed; 0 failed;\n')
        self.execute()
        report_path = self.output / 'browser-results/report.json'
        report = json.loads(report_path.read_text())
        report['suites'][0]['specs'][0]['tests'][0]['status'] = 'skipped'
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(gate.GateError, 'must execute and pass'):
            gate.require_browser_report(report_path)

    def test_cleanup_control_failure_is_not_treated_as_container_absent(self):
        self.fake.fail = 'cleanup-query-0'
        with self.assertRaisesRegex(gate.GateError, 'cleanup is incomplete'):
            self.execute()
        self.assert_no_success_record()

    def test_wrong_image_identity_never_produces_success(self):
        self.fake.image_id = 'not-a-digest'
        with self.assertRaisesRegex(gate.GateError, 'identity'):
            self.execute()
        self.assert_no_success_record()

    def test_cleanup_never_removes_resources_with_unexpected_owner_label(self):
        self.fake.spoof_owner = True
        with self.assertRaisesRegex(gate.GateError, 'not owned by this gate'):
            self.execute()
        self.assert_no_success_record()
        self.assertFalse(any(args[:3] in (['docker', 'rm', '--force'], ['docker', 'network', 'rm'])
                             for args, _, _ in self.fake.calls))

    def test_modified_contract_dirty_tree_and_existing_output_fail_before_docker(self):
        path = self.candidate / 'test/web/file/security.spec.js'
        original = path.read_bytes()
        path.write_text('candidate disables checks')
        with self.assertRaisesRegex(gate.GateError, 'maintained'):
            self.execute()
        path.write_bytes(original)
        (self.candidate / 'untracked.env').write_text('not a real secret')
        with self.assertRaisesRegex(gate.GateError, 'clean'):
            self.execute()
        (self.candidate / 'untracked.env').unlink()
        self.output.mkdir()
        with self.assertRaisesRegex(gate.GateError, 'fresh'):
            self.execute()
        self.assertEqual(self.fake.calls, [])

    def test_symlink_checkout_or_contract_cannot_escape(self):
        link = self.root / 'candidate-link'
        link.symlink_to(self.candidate, target_is_directory=True)
        with self.assertRaisesRegex(gate.GateError, 'real directories'):
            gate.preflight(self.control, link, self.image, self.output)
        path = self.candidate / 'test/web/file/security.spec.js'
        path.unlink()
        outside = self.root / 'outside'
        outside.write_text('untouched')
        path.symlink_to(outside)
        with self.assertRaisesRegex(gate.GateError, 'symlink'):
            self.execute()
        self.assertEqual(outside.read_text(), 'untouched')
        self.assertEqual(self.fake.calls, [])

    def test_unmaterialized_trusted_fixture_and_candidate_package_asset_stop(self):
        pointer = 'version https://git-lfs.github.com/spec/v1\noid sha256:' + 'a' * 64 + '\nsize 10\n'
        fixture = self.control / 'test/assets/fixture.bin'
        original = fixture.read_bytes()
        fixture.write_text(pointer)
        with self.assertRaisesRegex(gate.GateError, 'Unmaterialized'):
            self.execute()
        fixture.write_bytes(original)
        runtime = self.candidate / 'packages/pointer.dat'
        runtime.write_text(pointer)
        with self.assertRaisesRegex(gate.GateError, 'candidate build asset'):
            self.execute()
        self.assertEqual(self.fake.calls, [])

    def test_image_name_cannot_select_another_registry_or_revision(self):
        for image in ('cupcakearmy/cryptgeon:latest', 'rival-it-share:gate-' + 'f' * 40, '--privileged'):
            with self.subTest(image=image), self.assertRaisesRegex(gate.GateError, 'exact candidate'):
                gate.preflight(self.control, self.candidate, image, self.output)
        self.assertEqual(self.fake.calls, [])

    def test_mount_delimiter_paths_are_rejected_before_docker(self):
        odd = self.root / 'candidate,readonly'
        shutil.copytree(self.candidate, odd)
        with self.assertRaisesRegex(gate.GateError, 'delimiters'):
            gate.preflight(self.control, odd, self.image, self.output)
        with self.assertRaisesRegex(gate.GateError, 'delimiters'):
            gate.preflight(self.control, self.candidate, self.image, self.root / 'out,side')
        self.assertEqual(self.fake.calls, [])

    def test_ignored_environment_file_cannot_be_included_in_the_image(self):
        # Git's normal "clean" status omits ignored files, but Docker COPY would
        # include packages/** under the maintained build-context rules.
        (self.candidate / '.git/info/exclude').write_text('*.env\n')
        ignored = self.candidate / 'packages/local.env'
        ignored.write_text('SYNTHETIC_VALUE=must-not-enter-image\n')
        with self.assertRaisesRegex(gate.GateError, 'ignored package files'):
            self.execute()
        self.assertEqual(self.fake.calls, [])

    def test_docker_runner_does_not_inherit_tokens_remote_daemon_or_credentials(self):
        self.output.mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {'GH_TOKEN': 'synthetic-never-copy',
                                         'DOCKER_HOST': 'tcp://unapproved.invalid:2375'}):
            runner = gate.Runner(self.output)
            with mock.patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as execute:
                runner.run(['docker', 'version'], timeout=1, log='mock-runner')
        env = execute.call_args.kwargs['env']
        self.assertNotIn('GH_TOKEN', env)
        self.assertNotIn('GITHUB_TOKEN', env)
        self.assertNotIn('DOCKER_HOST', env)
        self.assertNotIn('DOCKER_CONTEXT', env)
        self.assertEqual(env['DOCKER_CONFIG'], str(self.output / 'docker-config'))
        self.assertEqual(list((self.output / 'docker-config').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
