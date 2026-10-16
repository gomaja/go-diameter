"""Check the tshark process boundary without requiring packet capture."""
import pathlib
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch


class TsharkExportTest(unittest.TestCase):
    def test_uses_recorded_image_and_read_only_evidence(self):
        export = runpy.run_path(str(pathlib.Path(__file__).with_name('tshark.py')))['tshark']
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory)
            (out / 'run-id').write_text('sctp-wire-synthetic')
            (out / 'image-id.txt').write_text('sha256:synthetic-image\n')
            completed = subprocess.CompletedProcess([], 0, 'packets', 'diagnostic')
            with patch('subprocess.run', return_value=completed) as run:
                self.assertIs(export(out, 'client.pcapng', '-Y', 'sctp', '-T', 'fields'), completed)
            args = run.call_args.args[0]
            self.assertIn('sha256:synthetic-image', args)
            self.assertIn(f'type=bind,src={out},dst=/evidence,readonly', args)
            self.assertIn('harness=sctp-wire-synthetic', args)
            self.assertEqual(args[-6:], ['-r', '/evidence/client.pcapng', '-Y', 'sctp', '-T', 'fields'])
            self.assertTrue(run.call_args.kwargs['check'])

    def test_standalone_analysis_defaults_to_shared_image(self):
        export = runpy.run_path(str(pathlib.Path(__file__).with_name('tshark.py')))['tshark']
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory)
            (out / 'run-id').write_text('sctp-wire-synthetic')
            with patch('subprocess.run') as run:
                export(out, 'server.pcapng', '-T', 'jsonraw')
            self.assertIn('sctp-wire-tools:go1.27.2', run.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
