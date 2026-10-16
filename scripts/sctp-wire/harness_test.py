"""Exercise cleanup's Docker boundary with current and foreign resources."""
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import unittest


DOCKER = '''#!/usr/bin/env python3
import json, os, pathlib, signal, sys, time
args = sys.argv[1:]
with pathlib.Path(os.environ['DOCKER_TRACE']).open('a') as trace:
    trace.write(' '.join(args) + '\\n')
run = os.environ.get('run', 'wire')
failure = [arg.replace('{run}', run).replace('{out}', os.environ.get('DOCKER_OUT', ''))
           for arg in json.loads(os.environ.get('DOCKER_FAIL', '[]'))]
if args == failure:
    sys.exit(47)
hang = json.loads(os.environ.get('DOCKER_HANG', '[]'))
if args == hang:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
send_signal = json.loads(os.environ.get('DOCKER_SIGNAL_COMMAND', '[]'))
if args == send_signal:
    marker = pathlib.Path(os.environ['DOCKER_OUT']) / 'signal-sent'
    if not marker.exists():
        marker.touch()
        os.kill(int(os.environ['RUNNER_PID']), int(os.environ['CLEANUP_SIGNAL']))
        time.sleep(.1)
if args[0] == 'inspect':
    if args[-1] in (run + '-server', run + '-client', run + '-build'):
        owner = os.environ['RESOURCE_OWNER']
        if owner == 'current':
            owner = 'another-run' if args[-1].endswith('-server') else run
        print(owner)
    else:
        sys.exit(1)
elif args[0] == 'exec':
    if os.environ.get('run') and args[2:4] == ['test', '-s']:
        sys.exit(0 if args[-1].endswith('.pid') else 1)
    sys.exit(1)
elif args[0] == 'cp':
    if args[1] == run + '-server:/tmp/server.log':
        pathlib.Path(args[2]).write_text('current server log')
    else:
        sys.exit(1)
elif args[:2] == ['network', 'inspect']:
    if os.environ.get('run'):
        print(run if os.environ['NETWORK_OWNER'] == 'current' else 'another-run')
    else:
        sys.exit(1)
elif args[:2] == ['ps', '-aq'] and os.environ.get('run'):
    print(run + '-export')
'''


class CleanupTest(unittest.TestCase):
    def run_harness(self, command, env, timeout=15):
        with subprocess.Popen(command, env=env, start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True) as proc:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                stdout, stderr = proc.communicate(timeout=5)
                self.fail(f'harness exceeded {timeout}s: {stderr}')
            return subprocess.CompletedProcess(command, proc.returncode,
                                               stdout, stderr)

    def cleanup(self, directory, owner):
        root = pathlib.Path(directory)
        docker = root / 'docker'
        docker.write_text(DOCKER)
        docker.chmod(0o755)
        trace = root / 'docker.trace'
        harness = pathlib.Path(__file__).with_name('harness.sh').resolve()
        env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                   DOCKER_TRACE=str(trace), RESOURCE_OWNER=owner)
        proc = self.run_harness(['bash', '-euc', '''
source "$1"
run=wire
client=wire-client
server=wire-server
builder=wire-build
network=wire-net
out=$2
cleanup_attempts=1
wire_cleanup
''', 'bash', str(harness), str(root)], env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return trace.read_text()

    def test_refreshes_server_log_in_reused_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'server-server.log'
            log.write_text('stale server log')
            self.cleanup(directory, 'wire')
            self.assertEqual(log.read_text(), 'current server log')

    def test_leaves_foreign_resources_and_artifacts_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / 'server-server.log'
            log.write_text('previous evidence')
            trace = self.cleanup(directory, 'another-run')
            self.assertEqual(log.read_text(), 'previous evidence')
            for command in ('exec ', 'cp ', 'rm '):
                self.assertNotIn(command, trace)


    def assert_scenario_survives_cleanup_failures(self, status, exit_early):
        failures = [
            ['inspect', '-f', '{{index .Config.Labels "harness"}}', '{run}-client'],
            ['exec', '{run}-client', 'sh', '-c',
             'kill -"$1" "$(cat "/tmp/$2.pid")"', 'sh', 'INT', 'capture'],
            ['cp', '{run}-client:/tmp/wire.pcapng', '{out}/client-wire.pcapng'],
            ['rm', '-f', '-v', '{run}-client'],
            ['network', 'rm', '{run}-net'],
            ['rm', '-f', '-v', '{run}-export'],
            ['ps', '-aq', '--filter', 'label=harness={run}'],
        ]
        for command, kind, field in (
                (['ps', '-a'], 'label', '{{.Names}}'),
                (['volume', 'ls'], 'label', '{{.Name}}'),
                (['network', 'ls'], 'label', '{{.Name}}'),
                (['ps', '-a'], 'name', '{{.Names}}'),
                (['volume', 'ls'], 'name', '{{.Name}}'),
                (['network', 'ls'], 'name', '{{.Name}}')):
            value = 'harness={run}' if kind == 'label' else '{run}'
            failures.append(command + ['--filter', f'{kind}={value}',
                                       '--format', field])
        for failure in failures:
            with self.subTest(command=failure), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                docker = root / 'docker'
                docker.write_text(DOCKER)
                docker.chmod(0o755)
                trace = root / 'docker.trace'
                harness = pathlib.Path(__file__).with_name('harness.sh').resolve()
                env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                           DOCKER_TRACE=str(trace), RESOURCE_OWNER='current',
                           DOCKER_FAIL=json.dumps(failure), DOCKER_OUT=str(root),
                           NETWORK_OWNER='current' if failure[:2] == ['network', 'rm'] else 'another-run',
                           SCENARIO_STATUS=str(status),
                           EXIT_EARLY='true' if exit_early else 'false')
                proc = self.run_harness(['bash', '-euc', '''
source "$1"
scenario=cleanup
variant=basic
output=$2
TMPDIR=$2
cleanup_attempts=0
export run
wire_build() { :; }
wire_start() { :; }
wire_scenario() {
 result=$SCENARIO_STATUS
 if [[ $EXIT_EARLY == true ]]; then exit "$result"; fi
}
wire_collect() { :; }
wire_analyze() { :; }
wire_run
''', 'bash', str(harness), str(root)], env)
                run = (root / 'run-id').read_text().strip()
                commands = trace.read_text().splitlines()
                with self.subTest(behaviour='scenario status'):
                    self.assertEqual(proc.returncode, status, proc.stderr)
                with self.subTest(behaviour='scratch removed'):
                    self.assertEqual(list(root.glob('sctp-wire-build.*')), [])
                with self.subTest(behaviour='later inventories attempted'):
                    self.assertIn(
                        f'network ls --filter name={run} --format {{{{.Name}}}}',
                        commands)
                with self.subTest(behaviour='foreign resources untouched'):
                    for command in commands:
                        if command.startswith(('exec ', 'cp ', 'rm ', 'network rm ')):
                            self.assertNotIn(run + '-server', command)
                            if env['NETWORK_OWNER'] == 'another-run':
                                self.assertNotIn(run + '-net', command)
                with self.subTest(behaviour='later removals attempted'):
                    self.assertIn(f'rm -f -v {run}-build', commands)
                    if failure[:2] != ['ps', '-aq']:
                        self.assertIn(f'rm -f -v {run}-export', commands)

    def test_successful_scenario_survives_cleanup_failures(self):
        self.assert_scenario_survives_cleanup_failures(0, False)

    def test_failed_scenario_survives_cleanup_failures(self):
        self.assert_scenario_survives_cleanup_failures(23, False)

    def test_successful_exit_survives_cleanup_failures(self):
        self.assert_scenario_survives_cleanup_failures(0, True)

    def test_failed_exit_survives_cleanup_failures(self):
        self.assert_scenario_survives_cleanup_failures(23, True)


    def assert_exit_cleanup_finishes(self, status, command, mode='trap',
                                    cleanup_signal=None, default_handlers=False):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            docker = root / 'docker'
            docker.write_text(DOCKER)
            docker.chmod(0o755)
            trace = root / 'docker.trace'
            rig = root / 'scratch'
            rig.mkdir()
            harness = pathlib.Path(__file__).with_name('harness.sh').resolve()
            env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                       DOCKER_TRACE=str(trace), RESOURCE_OWNER='current',
                       NETWORK_OWNER='another-run', DOCKER_OUT=str(root),
                       SCENARIO_STATUS=str(status), EXIT_MODE=mode,
                       DEFAULT_HANDLERS='true' if default_handlers else 'false',
                       SCTP_WIRE_CLEANUP_TIMEOUT='.5s',
                       SCTP_WIRE_CLEANUP_KILL_AFTER='.2s')
            if cleanup_signal is None:
                env['DOCKER_HANG'] = json.dumps(command)
            else:
                env['DOCKER_SIGNAL_COMMAND'] = json.dumps(command)
                env['CLEANUP_SIGNAL'] = str(cleanup_signal)
            started = time.monotonic()
            proc = self.run_harness(['bash', '-uc', '''
source "$1"
export run=wire
export RUNNER_PID=$$
client=wire-client
server=wire-server
builder=wire-build
network=wire-net
out=$2
rig=$2/scratch
cleanup_attempts=0
trap 'wire_exit EXIT; status=$?
 if [[ -n ${CLEANUP_SIGNAL:-} ]]; then kill -"$CLEANUP_SIGNAL" "$$"; fi
 exit "$status"' EXIT
if [[ $DEFAULT_HANDLERS != true ]]; then trap 'exit 130' INT TERM; fi
trap -p INT TERM > "$out/signals-before"
if [[ $EXIT_MODE == trap ]]; then exit "$SCENARIO_STATUS"; fi
(exit "$SCENARIO_STATUS")
wire_exit
status=$?
trap - EXIT
trap -p INT TERM > "$out/signals-after"
printf 'returned' > "$out/explicit-returned"
exit "$status"
''', 'bash', str(harness), str(root)], env, timeout=8)
            self.assertLess(time.monotonic() - started, 8)
            self.assertEqual(proc.returncode, status, proc.stderr)
            self.assertFalse(rig.exists())
            commands = trace.read_text().splitlines()
            self.assertIn(' '.join(command), commands)
            self.assertIn('rm -f -v wire-build', commands)
            self.assertIn('network ls --filter name=wire --format {{.Name}}',
                          commands)
            for invocation in commands:
                if invocation.startswith(('exec ', 'cp ', 'rm ', 'network rm ')):
                    self.assertNotIn('wire-server', invocation)
                    self.assertNotIn('wire-net', invocation)
            if cleanup_signal is not None:
                self.assertTrue((root / 'signal-sent').exists())
            if mode == 'explicit':
                self.assertTrue((root / 'explicit-returned').exists())
                self.assertEqual((root / 'signals-after').read_text(),
                                 (root / 'signals-before').read_text())

    def test_exit_cleanup_finishes_after_inventory_timeout(self):
        for status in (0, 23):
            with self.subTest(status=status):
                self.assert_exit_cleanup_finishes(
                    status, ['ps', '-aq', '--filter', 'label=harness=wire'])

    def test_exit_cleanup_finishes_after_removal_timeout(self):
        for status in (0, 23):
            with self.subTest(status=status):
                self.assert_exit_cleanup_finishes(
                    status, ['rm', '-f', '-v', 'wire-client'])

    def test_exit_cleanup_preserves_status_during_signals(self):
        command = ['inspect', '-f', '{{index .Config.Labels "harness"}}',
                   'wire-client']
        for cleanup_signal in (signal.SIGINT, signal.SIGTERM):
            for mode, default_handlers in (('trap', False), ('explicit', False),
                                           ('explicit', True)):
                with self.subTest(signal=cleanup_signal, mode=mode,
                                  default_handlers=default_handlers):
                    self.assert_exit_cleanup_finishes(
                        23, command, mode, cleanup_signal, default_handlers)


if __name__ == '__main__':
    unittest.main()
