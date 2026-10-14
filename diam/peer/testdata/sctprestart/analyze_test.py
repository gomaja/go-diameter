#!/usr/bin/env python3
"""Exercise analyzer exit status with synthetic tshark output and server logs."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


FIELDS = ['frame.number', 'frame.time_epoch', 'ip.src', 'sctp.chunk_type',
          'sctp.srcport', 'sctp.dstport', 'diameter.flags.T',
          'diameter.Session-Id', 'diameter.User-Name', 'sctp.data_sid',
          'diameter.cmd.code', 'diameter.flags.request', 'diameter.hopbyhopid',
          'diameter.endtoendid', 'diameter.Result-Code', 'diameter.Origin-Host',
          'diameter.Auth-Application-Id', 'diameter.Origin-State-Id']


def event(generation, watchdog, eligible, host='client1.example'):
    return (f'PEER_EVENT peer={{Host:DiameterIdentity{{{host}}},Padding:1 '
            f'Realm:DiameterIdentity{{example}},Padding:1 Applications:[4] '
            f'State:R-Open Generation:{generation} Watchdog:{watchdog} '
            f'Eligible:{str(eligible).lower()}}} reason=<nil>')


def fixture():
    """Hand-selected identifiers and packet order; no analyzer helpers used."""
    rows = []

    def packet(chunk='0', request='', command='', hop='', end='', result='',
               src='3868', dst='43868', host='server.example', **extra):
        row = dict.fromkeys(FIELDS, '')
        row.update({'frame.number': str(len(rows) + 1),
                    'frame.time_epoch': str(len(rows) + 1),
                    'ip.src': '192.0.2.2' if src == '43868' else '192.0.2.1',
                    'sctp.chunk_type': chunk, 'sctp.srcport': src,
                    'sctp.dstport': dst, 'diameter.cmd.code': command,
                    'diameter.flags.request': request, 'diameter.hopbyhopid': hop,
                    'diameter.endtoendid': end, 'diameter.Result-Code': result,
                    'diameter.Origin-Host': host})
        row.update(extra)
        rows.append(row)

    packet(chunk='1')
    packet(request='1', command='280', hop='0x00000001', end='0x10000001')
    packet(request='1', command='272', hop='0x00000002', end='0x10000002',
           **{'diameter.flags.T': '0', 'diameter.Session-Id': 'synthetic;1',
              'diameter.User-Name': 'synthetic-payload'})
    packet(chunk='6')
    for chunk in ['1', '2', '10', '11']:
        packet(chunk=chunk)
    packet(request='1', command='257', hop='0x81000002', end='0x82000002',
           src='43868', dst='3868', host='client1.example',
           **{'diameter.Origin-State-Id': '2'})
    packet(request='0', command='257', hop='0x81000002', end='0x82000002', result='2001')
    packet(request='1', command='272', hop='0x00000003', end='0x10000002', dst='4868',
           **{'diameter.flags.T': '1', 'diameter.Session-Id': 'synthetic;1',
              'diameter.User-Name': 'synthetic-payload'})
    packet(request='1', command='280', hop='0x81000102', end='0x82000102',
           src='43868', dst='3868', host='client1.example')
    packet(request='0', command='280', hop='0x81000102', end='0x82000102', result='2001')
    log = [event(1, 'OKAY', True), 'SOCKET_ACCEPT', 'PHYSICAL_ACCEPT',
           'ACCEPT_HOOK generation=1', 'ACCEPT_CLEANUP retired',
           'TRANSPORT_READ index=3 bytes=0 restart=true head=',
           'RESTART_HOOK old_generation=1 new_generation=2',
           'ACCEPT_HOOK generation=2',
           'TRANSPORT_READ index=4 bytes=20 restart=false '
           'head=0100008080000101000000008100000282000002',
           event(2, 'REOPEN', False),
           'OLD_CLOSE_FENCE closed_match=true new_closed=false',
           'SEND_DONE result=2001']
    for n in range(1, 4):
        hop, end = f'0x{16 + n:08x}', f'0x{32 + n:08x}'
        packet(request='1', command='280', hop=hop, end=end)
        packet(request='0', command='280', hop=hop, end=end, result='2001',
               src='43868', dst='3868', host='client1.example')
        log.extend([f'TRANSPORT_READ index={4 + 2*n} bytes=20 restart=false '
                    f'head=010000480000011800000000{hop[2:]}{end[2:]}',
                    f'TRANSPORT_READ index={5 + 2*n} bytes=52 restart=false head=0000010c',
                    event(2, 'OKAY' if n == 3 else 'REOPEN', n == 3)])
    return rows, log


class AnalyzerRecoveryTest(unittest.TestCase):
    def analyze(self, rows, log):
        # Only the external tshark invocation is replaced. The actual CLI,
        # packet parsing, state checks, and resulting exit code run unchanged.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            out = root / 'watchdog'
            out.mkdir()
            (out / 'run-id').write_text('synthetic-recovery')
            (out / 'server.log').write_text('\n'.join(log) + '\n')
            (out / 'iptables.txt').write_text(' 1 100 DROP 132\n')
            (root / 'packets.tsv').write_text('\n'.join(
                '\t'.join(row[field] for field in FIELDS) for row in rows) + '\n')
            request = bytes.fromhex('0100001c80000110000000040000000110000002') + b'payload'
            retry = bytearray(request)
            retry[4] |= 0x10
            retry[12:16] = bytes.fromhex('00000003')
            (root / 'raw.json').write_text(json.dumps([
                {'_source': {'layers': {'diameter_raw': [data.hex()]}}}
                for data in (request, retry)]))
            docker = root / 'docker'
            docker.write_text('#!/usr/bin/env python3\nimport pathlib, sys\n'
                              'root = pathlib.Path(__file__).parent\n'
                              'name = "raw.json" if "jsonraw" in sys.argv else "packets.tsv"\n'
                              'sys.stdout.write((root / name).read_text())\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}')
            return subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('analyze.py')), str(out)],
                                  text=True, capture_output=True, env=env)

    def test_accepts_third_matching_new_generation_dwa(self):
        rows, log = fixture()
        result = self.analyze(rows, log)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_pre_restart_okay_when_renewed_generation_stays_reopen(self):
        rows, log = fixture()
        log[-1] = event(2, 'REOPEN', False)
        result = self.analyze(rows, log)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('renewed generation did not become eligible', result.stderr)

    def test_rejects_eligibility_before_each_of_three_answers(self):
        for count, index in enumerate((9, 14, 17)):
            with self.subTest(before_answer=count):
                rows, log = fixture()
                log[index] = event(2, 'OKAY', True)
                result = self.analyze(rows, log)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('eligible before third matching DWA', result.stderr)

    def test_other_peer_or_old_generation_cannot_supply_recovery(self):
        for replacement in (event(2, 'OKAY', True, 'alternate.example'),
                            event(1, 'OKAY', True)):
            with self.subTest(replacement=replacement):
                rows, log = fixture()
                log[-1] = replacement
                result = self.analyze(rows, log)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('renewed generation did not become eligible', result.stderr)

    def test_requires_ineligible_snapshot_after_first_two_answers(self):
        for index in (14, 17):
            with self.subTest(index=index):
                rows, log = fixture()
                log[index] = event(1, 'REOPEN', False)
                result = self.analyze(rows, log)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('ineligible snapshot missing after recovery DWA', result.stderr)

    def test_capture_dwa_requires_ordered_transport_delivery(self):
        rows, log = fixture()
        log[15] = log[15].replace('0000001200000022', '00000012000000ff')
        result = self.analyze(rows, log)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('matching recovery DWA transport read missing', result.stderr)

    def test_answers_must_follow_probes_on_renewed_association(self):
        for change in ('before_probe', 'wrong_peer', 'wrong_direction'):
            with self.subTest(change=change):
                rows, log = fixture()
                if change == 'before_probe':
                    rows[-1]['frame.number'] = rows[-2]['frame.number']
                elif change == 'wrong_peer':
                    rows[-1]['diameter.Origin-Host'] = 'alternate.example'
                else:
                    rows[-1]['sctp.srcport'], rows[-1]['sctp.dstport'] = '3868', '43868'
                result = self.analyze(rows, log)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('recovery DWA mismatch', result.stderr)

    def test_third_answer_requires_complete_transport_delivery(self):
        rows, log = fixture()
        log[-2], log[-1] = log[-1], log[-2]
        result = self.analyze(rows, log)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('eligible before third matching DWA', result.stderr)

    def test_first_snapshot_after_third_answer_must_be_eligible(self):
        rows, log = fixture()
        log[-1] = event(2, 'REOPEN', False)
        log.append(event(2, 'OKAY', True))
        result = self.analyze(rows, log)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('renewed generation did not become eligible', result.stderr)


if __name__ == '__main__':
    unittest.main()
