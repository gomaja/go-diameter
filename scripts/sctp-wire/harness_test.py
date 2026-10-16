"""Exercise cleanup's Docker boundary with current and foreign resources."""
import os
import pathlib
import subprocess
import tempfile
import unittest


DOCKER = '''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ['DOCKER_TRACE']).open('a') as trace:
    trace.write(' '.join(args) + '\\n')
if args[0] == 'inspect':
    if args[-1] in ('wire-server', 'wire-client'):
        print(os.environ['RESOURCE_OWNER'])
    else:
        sys.exit(1)
elif args[0] == 'exec':
    sys.exit(1)
elif args[0] == 'cp':
    if args[1] == 'wire-server:/tmp/server.log':
        pathlib.Path(args[2]).write_text('current server log')
    else:
        sys.exit(1)
elif args[:2] == ['network', 'inspect']:
    sys.exit(1)
'''


class CleanupTest(unittest.TestCase):
    def cleanup(self, directory, owner):
        root = pathlib.Path(directory)
        docker = root / 'docker'
        docker.write_text(DOCKER)
        docker.chmod(0o755)
        trace = root / 'docker.trace'
        harness = pathlib.Path(__file__).with_name('harness.sh').resolve()
        env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}',
                   DOCKER_TRACE=str(trace), RESOURCE_OWNER=owner)
        subprocess.run(['bash', '-euc', '''
source "$1"
run=wire
client=wire-client
server=wire-server
builder=wire-build
network=wire-net
out=$2
cleanup_attempts=1
wire_cleanup
''', 'bash', str(harness), str(root)], env=env, check=True)
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


if __name__ == '__main__':
    unittest.main()
