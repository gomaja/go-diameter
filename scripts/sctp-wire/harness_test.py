"""Exercise readiness and cleanup at the Docker boundary."""
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import unittest


DOCKER = '''#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys, time
args = sys.argv[1:]
with pathlib.Path(os.environ['DOCKER_TRACE']).open('a') as trace:
    trace.write(' '.join(args) + '\\n')
run = os.environ.get('run', 'wire')
failure = [arg.replace('{run}', run).replace('{out}', os.environ.get('DOCKER_OUT', ''))
           for arg in json.loads(os.environ.get('DOCKER_FAIL', '[]'))]
if args == failure:
    sys.exit(47)
hang = [arg.replace('{run}', run)
        for arg in json.loads(os.environ.get('DOCKER_HANG', '[]'))]
if args == hang:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(1)
if os.environ.get('DOCKER_READINESS'):
    config = json.loads(os.environ['DOCKER_READINESS'])
    root = pathlib.Path(os.environ['DOCKER_OUT'])
    state_file = root / 'readiness.json'
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    def event(message):
        with pathlib.Path(os.environ['DOCKER_TRACE']).open('a') as trace:
            trace.write(message + '\\n')
    if args[0] == 'exec':
        pos = 1
        detached = False
        while args[pos].startswith('-'):
            if args[pos] == '-d':
                detached = True
                pos += 1
            elif args[pos] == '-e':
                pos += 2
            else:
                sys.exit(2)
        peer = args[pos]
        command = args[pos + 1:]
        if detached:
            event('START ' + peer + ' ' + ' '.join(command))
            sys.exit(0)
        path = command[-1]
        child = 'capture' if path == '/tmp/capture.log' else config.get('child', 'server')
        if path.endswith('.exit'):
            child = pathlib.Path(path).stem
        key = peer + '-' + child
        polls = state.get(key, 0)
        if command[:2] in (['test', '-e'], ['test', '-s']):
            if path.endswith('.exit') and child == config.get('child') and config['mode'] == 'exit':
                sys.exit(0 if polls else 1)
            if path.endswith('.exit'):
                finished = config.get('scenario') and (state.get('killed') if child == 'initial' else state.get('restarted'))
                sys.exit(0 if finished else 1)
            sys.exit(0)
        if command[0] == 'cat':
            print('child diagnostic: ' + peer + ' ' + pathlib.Path(path).stem)
            sys.exit(0)
        if path in ('/proc/net/sctp/eps', '/tmp/capture.log'):
            port = command[command.index('-v') + 1].split('=')[1] if command[0] == 'awk' else 'capture'
            child = 'alternate' if port == '4868' else ('capture' if port == 'capture' else 'server')
            key = peer + '-' + child
            polls = state.get(key, 0) + 1
            state[key] = polls
            state_file.write_text(json.dumps(state))
            ready = config['mode'] == 'ready' and polls >= 3
            fixture = root / (key + '.fixture')
            if port == 'capture':
                text = 'Capturing on eth0\\n'
                if ready:
                    text += ' ** (tshark:7) 12:34:56 [Main MESSAGE] -- Capture started.\\n'
            else:
                text = ' ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS\\n'
                text += '0000 0000 2 10 0 9999 ' + port + ' 42 10.0.0.1\\n'
                if ready:
                    text += '0000 0000 2 10 0 ' + port + ' 0 43 10.0.0.1\\n'
            fixture.write_text(text)
            result = subprocess.run(command[:-1] + [str(fixture)], check=False).returncode
            event(('READY ' if result == 0 else 'PENDING ') + peer + ' ' + child + ' ' + port)
            sys.exit(result)
        if command[:2] == ['sh', '-c'] and 'kill -KILL' in command[2]:
            state['killed'] = True
        if command[0] in ('/wire', '/sctp-tls-restart.test'):
            state['restarted'] = True
        state_file.write_text(json.dumps(state))
        sys.exit(0)
    if args[0] == 'cp':
        pathlib.Path(args[2]).write_text('137\\n' if args[1].endswith('initial.exit') else '0\\n')
    elif args[0] == 'inspect':
        print('10.0.0.1' if args[-1] == 'wire-server' else '10.0.0.2')
    sys.exit(0)
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


class ReadinessTest(unittest.TestCase):
    run_harness = CleanupTest.run_harness

    def run_ready(self, directory, body, config, scenario=None,
                  overrides=None, timeout=4):
        root = pathlib.Path(directory)
        docker = root / 'docker'
        docker.write_text(DOCKER)
        docker.chmod(0o755)
        trace = root / 'docker.trace'
        harness = pathlib.Path(__file__).with_name('harness.sh').resolve()
        env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                   DOCKER_TRACE=str(trace), DOCKER_OUT=str(root),
                   DOCKER_READINESS=json.dumps(config),
                   SCTP_WIRE_READY_TIMEOUT={'never': '1', 'exit': '2'}.get(config['mode'], '20'),
                   TMPDIR=str(root))
        env.update(overrides or {})
        if scenario:
            runner = harness.parents[2] / {
                'peer': 'diam/peer/testdata/sctprestart/run.sh',
                'sm': 'diam/sm/testdata/sctprestart/run.sh',
                'tls': 'diam/testdata/sctptlsrestart/run.sh',
            }[scenario]
            text = runner.read_text()
            env['SCENARIO_FUNCTION'] = text[text.index('wire_scenario() {'):text.rindex('\nwire_run')]
        proc = self.run_harness(['bash', '-euc', '''
source "$1"
client=wire-client
server=wire-server
network=wire-net
run=wire
image_id=image
rig=$2
out=$2
binary=peer
wire_path=/wire
sip=10.0.0.1
cip=10.0.0.2
variant=changed-apps
server_port=3868
client_port=43868
''' + body, 'bash', str(harness), str(root)], env, timeout=timeout)
        return proc, trace.read_text() if trace.exists() else ''

    def assert_wait(self, kind, mode):
        child, port = ('server', '3868') if kind == 'listener' else ('capture', 'capture')
        with tempfile.TemporaryDirectory() as directory:
            command = ('wire_wait_listener wire-server server 3868' if kind == 'listener'
                       else 'wire_wait_capture wire-server')
            proc, trace = self.run_ready(
                directory, command + '\nprintf "DIAL\n" >> "$DOCKER_TRACE"\n',
                dict(mode=mode, child=child))
            if mode == 'ready':
                self.assertEqual(proc.returncode, 0, proc.stderr)
                events = [line for line in trace.splitlines()
                          if line.startswith(('PENDING ', 'READY ', 'DIAL'))]
                self.assertEqual(events, [f'PENDING wire-server {child} {port}'] * 2 +
                                 [f'READY wire-server {child} {port}', 'DIAL'])
            else:
                self.assertNotEqual(proc.returncode, 0)
                self.assertNotIn('DIAL', trace)
                self.assertIn('wire-server', proc.stderr)
                self.assertIn(child, proc.stderr)
                if kind == 'listener':
                    self.assertIn('3868', proc.stderr)
                self.assertIn('child diagnostic: wire-server ' + child, proc.stderr)
                if mode == 'exit':
                    self.assertIn('exited', proc.stderr)
                    self.assertNotIn('timed out', proc.stderr)
                    self.assertEqual(trace.count('PENDING '), 1)
                else:
                    self.assertIn('timed out', proc.stderr)
                    self.assertIn('after 1s', proc.stderr)

    def test_listener_ready_after_polls(self):
        self.assert_wait('listener', 'ready')

    def test_listener_child_exits_first(self):
        self.assert_wait('listener', 'exit')

    def test_listener_never_ready(self):
        self.assert_wait('listener', 'never')

    def test_capture_ready_after_polls(self):
        self.assert_wait('capture', 'ready')

    def test_capture_child_exits_first(self):
        self.assert_wait('capture', 'exit')

    def test_capture_never_ready(self):
        self.assert_wait('capture', 'never')

    def test_wire_start_waits_for_both_captures(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, trace = self.run_ready(directory, '''
wire_start
printf 'SCENARIO\n' >> "$DOCKER_TRACE"
''', dict(mode='ready'))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            for peer in ('wire-server', 'wire-client'):
                self.assertIn(f'READY {peer} capture capture', trace)
                self.assertLess(trace.index(f'READY {peer} capture capture'),
                                trace.index('SCENARIO'))
            # Start both captures before waiting for either.
            self.assertLess(trace.index('START wire-client'),
                            trace.index('READY wire-server'))

    def test_hanging_probes_prevent_scenario_dialing(self):
        probes = [
            ['exec', 'wire-client', 'test', '-e', '/tmp/alternate.exit'],
            ['exec', 'wire-client', 'awk', '-v', 'port=4868',
             'NR > 1 && $6 == port { found=1 } END { exit !found }',
             '/proc/net/sctp/eps'],
        ]
        for probe in probes:
            with self.subTest(probe=probe), tempfile.TemporaryDirectory() as directory:
                started = time.monotonic()
                proc, trace = self.run_ready(directory, '''
eval "$SCENARIO_FUNCTION"
wire_scenario
''', dict(mode='ready', scenario=True), 'peer', overrides=dict(
                    DOCKER_HANG=json.dumps(probe), SCTP_WIRE_READY_TIMEOUT='1',
                    SCTP_WIRE_READY_KILL_AFTER='.2s'), timeout=4)
                self.assertLess(time.monotonic() - started, 4)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn('timed out after 1s', proc.stderr)
                self.assertIn('wire-client', proc.stderr)
                self.assertIn('alternate', proc.stderr)
                self.assertIn('4868', proc.stderr)
                self.assertIn('child diagnostic: wire-client alternate', proc.stderr)
                self.assertIn(' '.join(probe), trace)
                self.assertIn('START wire-client', trace)
                self.assertNotIn('START wire-server', trace)
                self.assertNotIn('/tmp/initial.log', trace)

    def test_hanging_log_retrieval_preserves_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            probe = ['exec', 'wire-server', 'cat', '/tmp/server.log']
            proc, trace = self.run_ready(directory, '''
wire_wait_listener wire-server server 3868
printf 'DIAL\n' >> "$DOCKER_TRACE"
''', dict(mode='exit', child='server'), overrides=dict(
                DOCKER_HANG=json.dumps(probe), SCTP_WIRE_READY_TIMEOUT='2',
                SCTP_WIRE_READY_KILL_AFTER='.2s'), timeout=8)
            self.assertLess(time.monotonic() - started, 8)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn('wire-server: server exited', proc.stderr)
            self.assertIn('3868', proc.stderr)
            self.assertIn(' '.join(probe), trace)
            self.assertNotIn('DIAL', trace)

    def test_failing_wait_runs_exit_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            proc, trace = self.run_ready(directory, '''
scenario=readiness
variant=basic
output=$2/evidence
cleanup_attempts=0
export run
wire_build() { :; }
wire_start() { :; }
wire_scenario() {
 wire_wait_listener "$server" server 3868
 docker exec -d "$client" /wire -mode client
}
wire_run
''', dict(mode='never', child='server'), overrides=dict(
                DOCKER_HANG=json.dumps(
                    ['exec', '{run}-server', 'test', '-e', '/tmp/server.exit']),
                SCTP_WIRE_READY_TIMEOUT='1', SCTP_WIRE_READY_KILL_AFTER='.2s',
                SCTP_WIRE_CLEANUP_TIMEOUT='.5s',
                SCTP_WIRE_CLEANUP_KILL_AFTER='.2s'), timeout=4)
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            self.assertIn('timed out after 1s', proc.stderr)
            self.assertNotIn('START ', trace)
            root = pathlib.Path(directory)
            run = (root / 'evidence/run-id').read_text().strip()
            self.assertIn(f'network ls --filter name={run}', trace)
            self.assertEqual(list(root.glob('sctp-wire-build.*')), [])

    def test_scenarios_wait_before_dialing(self):
        for scenario in ('peer', 'sm', 'tls'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                proc, trace = self.run_ready(directory, '''
sleep() { printf 'SLEEP %s\n' "$*" >> "$DOCKER_TRACE"; }
eval "$SCENARIO_FUNCTION"
wire_scenario
''', dict(mode='ready', scenario=True), scenario)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                events = [line for line in trace.splitlines()
                          if line.startswith(('START ', 'READY '))]
                ready = 'READY wire-server server ' + ('5868' if scenario == 'tls' else '3868')
                self.assertIn(ready, events)
                initial = next(line for line in events if line.startswith('START ')
                               and '/tmp/initial.log' in line)
                self.assertLess(events.index(ready), events.index(initial))
                if scenario == 'peer':
                    alternate = 'READY wire-client alternate 4868'
                    self.assertIn(alternate, events)
                    server = next(line for line in events if line.startswith('START ')
                                  and '/tmp/server.log' in line)
                    self.assertLess(events.index(alternate), events.index(server))


if __name__ == '__main__':
    unittest.main()
