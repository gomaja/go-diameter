"""Literal wire trees distinguish an offer from an unrecognized report."""
import copy
import json
import os
import pathlib
import runpy
import subprocess
import sys
import tempfile
import unittest


MODULE = runpy.run_path(str(pathlib.Path(__file__).with_name('prsctp.py')))


def packet(frame, src, dst, chunk_type, parameters, tag='0x00000001'):
    source = '192.0.2.2' if src in ('43868', '43869', '4868') else '192.0.2.1'
    destination = '192.0.2.1' if source == '192.0.2.2' else '192.0.2.2'
    chunk = {'sctp.chunk_type': chunk_type, 'sctp.init_initiate_tag': tag}
    chunk.update(parameters)
    return {'_source': {'layers': {
        'frame': {'frame.number': str(frame)},
        'ip': {'ip.src': source, 'ip.dst': destination},
        'sctp': {'sctp.srcport': src, 'sctp.dstport': dst,
                 'sctp.verification_tag': tag, 'chunk': chunk}}}}


def offer():
    return {'Forward TSN supported parameter': {'sctp.parameter_type': '0xc000'}}


def report():
    return {'Unrecognized parameter parameter': {
        'sctp.parameter_type': '0x0008', **offer()}}


def fixture(port='3868', raw='43868'):
    return [packet(1, raw, port, '1', offer()),
            packet(2, port, raw, '2', report()),
            packet(10, raw, port, '1', offer(), tag='0x00000002'),
            packet(11, port, raw, '2', offer(), tag='0x00000002')]


class PartialReliabilityTest(unittest.TestCase):
    def check(self, packets, ports=('3868',), raw='43868', prsctp_enable=1):
        MODULE['assert_default_off'](packets, ports, raw, prsctp_enable)

    def test_restart_answer_follows_sysctl(self):
        for enabled, parameters, message in [
                (1, offer(), None),
                (1, report(), "Linux now answers restarts from the listener's setting"),
                (0, report(), None),
                (0, offer(), 'restart.*offers Forward-TSN-Supported')]:
            with self.subTest(enabled=enabled, parameters=parameters):
                packets = fixture()
                packets[-1] = packet(11, '3868', '43868', '2', parameters, tag='0x00000002')
                if message:
                    with self.assertRaisesRegex(AssertionError, message):
                        self.check(packets, prsctp_enable=enabled)
                else:
                    self.check(packets, prsctp_enable=enabled)

    def test_capture_requires_restart_answer(self):
        with self.assertRaisesRegex(AssertionError, 'no raw-client restart answer'):
            self.check(fixture()[:2])

    def test_retransmitted_handshake_init_is_not_restart(self):
        packets = fixture()[:2]
        packets.extend([packet(3, '43868', '3868', '1', offer()),
                        packet(4, '3868', '43868', '2', report())])
        with self.assertRaisesRegex(AssertionError, 'no raw-client restart answer'):
            self.check(packets)
        self.check(packets + fixture()[2:])

    def test_capture_requires_handshake_answer(self):
        packets = fixture()
        packets.pop(1)
        with self.assertRaisesRegex(AssertionError, 'no matching INIT ACK'):
            self.check(packets)

    def test_requires_valid_sysctl_file(self):
        for text in (None, '', '2', 'on', '0 1'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                out = pathlib.Path(directory)
                if text is not None:
                    (out / 'prsctp_enable').write_text(text)
                with self.assertRaisesRegex(AssertionError, 'prsctp_enable'):
                    MODULE['read_prsctp_enable'](out)

    def test_accepts_nested_report_in_each_rig(self):
        for port, raw, ports in [('3868', '43868', ('3868', '4868')),
                                 ('3868', '43868', ('3868',)),
                                 ('5868', '43869', ('5868',))]:
            with self.subTest(ports=ports, raw=raw):
                self.check(fixture(port, raw), ports, raw)

    def test_rejects_listener_offer_even_when_also_reported(self):
        packets = fixture()
        packets[1]['_source']['layers']['sctp']['chunk'].update(offer())
        with self.assertRaisesRegex(AssertionError, 'frame 2 offers'):
            self.check(packets)

    def test_requires_nested_forward_tsn_in_matching_ack(self):
        for parameters in ({}, {'Unrecognized parameter parameter': {
                'sctp.parameter_type': '0x0008', 'IPv4 address parameter': {
                    'sctp.parameter_type': '0x0005'}}},
                {'Unrelated container': offer()}):
            with self.subTest(parameters=parameters):
                packets = fixture()
                packets[1] = packet(2, '3868', '43868', '2', parameters)
                with self.assertRaisesRegex(AssertionError, 'does not report'):
                    self.check(packets)

    def test_checks_manager_dialer_and_alternate_listener(self):
        packets = fixture() + [packet(3, '60013', '4868', '1', {}),
                               packet(4, '4868', '60013', '2', {})]
        self.check(packets, ('3868', '4868'))
        for index in (4, 5):
            with self.subTest(index=index):
                changed = copy.deepcopy(packets)
                changed[index]['_source']['layers']['sctp']['chunk'].update(offer())
                with self.assertRaisesRegex(AssertionError, 'offers'):
                    self.check(changed, ('3868', '4868'))

    def test_manager_source_port_can_equal_raw_client_port(self):
        packets = fixture() + [packet(3, '43868', '4868', '1', {}),
                               packet(4, '4868', '43868', '2', {})]
        self.check(packets, ('3868', '4868'))
        packets[4]['_source']['layers']['sctp']['chunk'].update(offer())
        with self.assertRaisesRegex(AssertionError, 'frame 3 offers'):
            self.check(packets, ('3868', '4868'))

    def test_raw_client_must_offer(self):
        packets = fixture()
        packets[0]['_source']['layers']['sctp']['chunk'].pop('Forward TSN supported parameter')
        with self.assertRaisesRegex(AssertionError, 'raw client did not offer'):
            self.check(packets)

    def test_requires_raw_offer_and_go_diameter_handshake(self):
        for packets in ([], fixture()[:1], fixture()[1:]):
            with self.subTest(packets=packets):
                with self.assertRaises(AssertionError):
                    self.check(packets)

    def test_ack_matches_addresses_ports_tag_and_frame(self):
        for field, value in [('sctp.verification_tag', '0x00000002'),
                             ('sctp.dstport', '43869'), ('ip.src', '192.0.2.9'),
                             ('frame.number', '0')]:
            with self.subTest(field=field):
                packets = fixture()
                layers = packets[1]['_source']['layers']
                layers[field.split('.')[0]][field] = value
                with self.assertRaisesRegex(AssertionError, 'no matching INIT ACK'):
                    self.check(packets)

    def test_each_analyzer_rejects_offer_and_missing_report(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        for script, port, raw in [
                ('diam/peer/testdata/sctprestart/analyze.py', '3868', '43868'),
                ('diam/sm/testdata/sctprestart/analyze.py', '3868', '43868'),
                ('diam/testdata/sctptlsrestart/analyze.py', '5868', '43869')]:
            for parameters, message in [(offer(), 'offers Forward-TSN-Supported'),
                                         ({}, 'does not report Forward-TSN-Supported')]:
                with self.subTest(script=script, parameters=parameters), tempfile.TemporaryDirectory() as directory:
                    out = pathlib.Path(directory)
                    (out / 'run-id').write_text('synthetic-prsctp')
                    (out / 'prsctp_enable').write_text('1\n')
                    packets = fixture(port, raw)
                    packets[1] = packet(2, port, raw, '2', parameters)
                    (out / 'packets.json').write_text(json.dumps(packets))
                    docker = out / 'docker'
                    docker.write_text('#!/usr/bin/env python3\nimport pathlib, sys\n'
                                      'sys.stdout.write(pathlib.Path(__file__).with_name("packets.json").read_text())\n')
                    docker.chmod(0o755)
                    env = dict(os.environ, PATH=f'{out}:{os.environ["PATH"]}')
                    result = subprocess.run([sys.executable, str(root / script), str(out)],
                                            text=True, capture_output=True, env=env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)

    def test_repeated_keys_cannot_hide_a_direct_offer(self):
        packet_text = json.dumps(fixture()[1])
        packet_text = packet_text.replace('"chunk": {',
            '"chunk": {"sctp.chunk_type":"2",'
            '"Forward TSN supported parameter":{"sctp.parameter_type":"0xc000"}},'
            '"chunk": {', 1)
        decoded = json.loads('[' + json.dumps(fixture()[0]) + ',' + packet_text + ']',
                             object_pairs_hook=MODULE['_pairs'])
        with self.assertRaisesRegex(AssertionError, 'offers'):
            self.check(decoded)


if __name__ == '__main__':
    unittest.main()
