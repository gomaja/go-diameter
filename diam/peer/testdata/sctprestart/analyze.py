#!/usr/bin/env python3
import csv
import json
import pathlib
import re
import subprocess
import sys


def assert_watchdog_recovery(rows, log, cer, cea):
    """Correlate RFC 3539 Appendix A REOPEN recovery with ordered delivery."""
    hook = re.search(r'RESTART_HOOK .*old_generation=(\d+) new_generation=(\d+)', log)
    assert hook and int(hook[2]) > int(hook[1]), 'renewed generation marker missing'
    generation = int(hook[2])
    host = cer['diameter.Origin-Host']
    cer_read = re.search(r'TRANSPORT_READ index=(\d+) bytes=20.*restart=false.*'
                         r'head=0100[0-9a-f]{20}' + cer['diameter.hopbyhopid'][2:] +
                         cer['diameter.endtoendid'][2:], log)
    assert cer_read and hook.end() < cer_read.start(), 'renewed CER transport read missing'
    probes = [row for row in rows if row['diameter.cmd.code'] == '280' and
              row['diameter.flags.request'] == '1' and
              (row['sctp.srcport'], row['sctp.dstport'], row['ip.src']) ==
              (cer['sctp.dstport'], cer['sctp.srcport'], cea['ip.src']) and
              int(row['frame.number']) > int(cea['frame.number'])]
    assert len(probes) >= 3, 'fewer than three recovery watchdog probes'
    delivered = []
    reply_frames = []
    for probe in probes[:3]:
        replies = [row for row in rows if row['diameter.cmd.code'] == '280' and
                   row['diameter.flags.request'] == '0' and
                   row['diameter.hopbyhopid'] == probe['diameter.hopbyhopid'] and
                   row['diameter.endtoendid'] == probe['diameter.endtoendid']]
        assert len(replies) == 1, 'recovery DWA mismatch'
        reply = replies[0]
        assert (reply['diameter.Result-Code'] == '2001' and
                reply['diameter.Origin-Host'] == host and
                (reply['sctp.srcport'], reply['sctp.dstport'], reply['ip.src']) ==
                (cer['sctp.srcport'], cer['sctp.dstport'], cer['ip.src']) and
                int(reply['frame.number']) > int(probe['frame.number'])), 'recovery DWA mismatch'
        if reply_frames:
            assert reply_frames[-1] < int(probe['frame.number']), 'recovery probes overlap'
        reply_frames.append(int(reply['frame.number']))
        reads = []
        for marker in re.finditer(r'TRANSPORT_READ index=(\d+) bytes=20.*restart=false.*'
                                  r'head=([0-9a-f]{40})\b', log):
            header = bytes.fromhex(marker[2])
            if (header[0] == 1 and not header[4] & 0x80 and
                    int.from_bytes(header[5:8], 'big') == 280 and header[8:12] == bytes(4) and
                    header[12:16].hex() == probe['diameter.hopbyhopid'][2:] and
                    header[16:20].hex() == probe['diameter.endtoendid'][2:]):
                reads.append(marker)
        assert len(reads) == 1, 'matching recovery DWA transport read missing'
        previous = delivered[-1] if delivered else cer_read
        assert (reads[0].start() > previous.end() and
                int(reads[0][1]) > int(previous[1])), 'recovery DWA transport order mismatch'
        header = bytes.fromhex(reads[0][2])
        body_size = int.from_bytes(header[1:4], 'big') - 20
        bodies = [marker for marker in re.finditer(
            r'TRANSPORT_READ index=(\d+) bytes=(\d+).*restart=false', log)
            if int(marker[1]) == int(reads[0][1]) + 1 and
            int(marker[2]) == body_size and marker.start() > reads[0].end()]
        assert body_size > 0 and len(bodies) == 1, 'complete recovery DWA transport read missing'
        delivered.append(bodies[0])

    snapshots = []
    for marker in re.finditer(r'PEER_EVENT peer=\{Host:DiameterIdentity\{([^}]+)\}.*'
                              r'State:(\S+) Generation:(\d+) Watchdog:(\w+) Eligible:(true|false)', log):
        if marker[1] == host and int(marker[3]) == generation and marker.start() > cer_read.end():
            snapshots.append(marker)
    assert not any(marker[5] == 'true' and marker.start() < delivered[2].end()
                   for marker in snapshots), 'renewed generation eligible before third matching DWA'
    boundaries = [cer_read, *delivered]
    for index in range(3):
        assert any(boundaries[index].end() < marker.start() < boundaries[index + 1].start() and
                   marker[2] == 'R-Open' and marker[4] == 'REOPEN' and marker[5] == 'false'
                   for marker in snapshots), f'ineligible snapshot missing after recovery DWA {index}'
    after_third = [marker for marker in snapshots if marker.start() > delivered[2].end()]
    assert (after_third and after_third[0][2] == 'R-Open' and
            after_third[0][4] == 'OKAY' and after_third[0][5] == 'true'), \
        'renewed generation did not become eligible after third matching DWA'
    print(f'PASS: {host} generation {generation} remained ineligible through two matching DWA; '
          f'eligible after third, capture frames={reply_frames}, '
          f'transport completion reads={[int(marker[1]) for marker in delivered]}.')


out = pathlib.Path(sys.argv[1]).resolve()
image = 'i81-wire-tools:go1.27.2'
run_id = (out / 'run-id').read_text().strip()
fields = ['frame.number', 'frame.time_epoch', 'ip.src', 'sctp.chunk_type', 'sctp.srcport', 'sctp.dstport', 'diameter.flags.T', 'diameter.Session-Id', 'diameter.User-Name', 'sctp.data_sid', 'diameter.cmd.code', 'diameter.flags.request', 'diameter.hopbyhopid', 'diameter.endtoendid', 'diameter.Result-Code', 'diameter.Origin-Host', 'diameter.Auth-Application-Id', 'diameter.Origin-State-Id']
cmd = ['docker', 'run', '--rm', '--label', f'harness={run_id}', '--mount', f'type=bind,src={out},dst=/evidence,readonly', image, 'tshark', '-r', '/evidence/client.pcapng', '-Y', 'sctp', '-T', 'fields']
for field in fields:
    cmd.extend(['-e', field])
result = subprocess.run(cmd, text=True, capture_output=True, check=True)
(out / 'packets.tsv').write_text(result.stdout)
(out / 'tshark-errors.txt').write_text(result.stderr)
rows = [dict(zip(fields, row)) for row in csv.reader(result.stdout.splitlines(), delimiter='\t')]
server_cmd = [arg.replace('/evidence/client.pcapng', '/evidence/server.pcapng') for arg in cmd]
server_result = subprocess.run(server_cmd, text=True, capture_output=True, check=True)
(out / 'server-packets.tsv').write_text(server_result.stdout)
server_rows = [dict(zip(fields, row)) for row in csv.reader(server_result.stdout.splitlines(), delimiter='\t')]
assert any(row['sctp.chunk_type'] == '6' for row in server_rows), 'ABORT did not reach receiver capture point'

all_rows = rows
rows = [row for row in rows if '3868' in (row['sctp.srcport'], row['sctp.dstport'])]
cer = next(row for row in rows if row['diameter.hopbyhopid'] == '0x81000002' and row['diameter.flags.request'] == '1')
cea = [row for row in rows if row['diameter.hopbyhopid'] == '0x81000002' and row['diameter.flags.request'] == '0']
assert len([row for row in rows if row['sctp.chunk_type'] == '1']) == 2, 'restart INIT missing'
restart_init = [row for row in rows if row['sctp.chunk_type'] == '1'][1]
handshake = [row['sctp.chunk_type'] for row in rows if int(restart_init['frame.number']) <= int(row['frame.number']) < int(cer['frame.number'])]
assert handshake == ['1', '2', '10', '11'], f'incomplete restart handshake: {handshake}'
assert any(row['sctp.chunk_type'] == '6' for row in rows), 'sender capture contains no ABORT'
log = (out / 'server.log').read_text()
if 'SOCKET_ACCEPT' in log:
    assert log.count('SOCKET_ACCEPT') == 1, 'listener accepted a replacement socket'
assert log.count('PHYSICAL_ACCEPT') == 1, 'physical association replaced instead of renewed'
restart = re.search(r'TRANSPORT_READ index=(\d+).*restart=true', log)
new_data = re.search(r'TRANSPORT_READ index=(\d+).*restart=false.*head=0100[0-9a-f]+8100000282000002', log)
assert re.search(r'\s[1-9]\d*\s+\d+\s+DROP\s+132', (out / 'iptables.txt').read_text()), 'ABORT receiver INPUT drop counter is zero'
for file in out.glob('cleanup-*.txt'):
    assert not file.read_text().strip(), f'leaked Docker resource: {file}'
if not cea:
    print(f'FAIL: restart handshake frames {restart_init["frame.number"]}..{int(cer["frame.number"])-1}; CER frame {cer["frame.number"]}; no matching CEA; physical accepts=1.')
    sys.exit(1)
assert restart, 'ordered transport restart marker missing'
assert new_data, 'new CER receive missing'
assert int(restart[1]) < int(new_data[1]), 'restart delivered after new CER data'
assert cer['diameter.cmd.code'] == '257', 'new request is not CER'
assert cer['diameter.Origin-Host'] == ('client2.example' if out.name == 'changed-identity' else 'client1.example') and cer['diameter.Origin-State-Id'] == '2', 'fresh peer identity/state missing'
assert len(cea) == 1, 'duplicate CEA'
answer = cea[0]
assert answer['diameter.cmd.code'] == '257' and answer['diameter.Result-Code'] == '2001' and answer['diameter.endtoendid'] == cer['diameter.endtoendid'], 'CEA content mismatch'
delay = float(answer['frame.time_epoch']) - float(cer['frame.time_epoch'])
assert 0 <= delay < 4, f'CEA late: {delay}'
assert 'retired' in log and 'PEER_EVENT' in log, 'Manager retirement event missing'
assert log.count('RESTART_HOOK') == 1, 'restart hook missing'
assert log.count('ACCEPT_HOOK') == 2, 'accepted generations did not receive distinct admission'
assert log.count('ACCEPT_CLEANUP') >= 1, 'old acceptance cleanup missing'
assert 'closed_match=true' in log and 'OLD_CLOSE_FENCE' in log and 'new_closed=false' in log, 'generation fencing missing'
dwr = [row for row in rows if row['diameter.cmd.code'] == '280' and row['diameter.hopbyhopid'] == '0x81000102' and row['diameter.flags.request'] == '1']
dwa = [row for row in rows if row['diameter.cmd.code'] == '280' and row['diameter.hopbyhopid'] == '0x81000102' and row['diameter.flags.request'] == '0']
assert len(dwr) == len(dwa) == 1 and dwa[0]['diameter.endtoendid'] == '0x82000102' and dwa[0]['diameter.Result-Code'] == '2001', 'renewed generation did not answer DWR after old Close'
if out.name == 'changed-apps':
    assert cer['diameter.Auth-Application-Id'] == '16777251' and 'Applications:[16777251]' in log, 'changed applications were not freshly admitted'
if out.name in ('alternate-stream', 'fragment'):
    assert cer['sctp.data_sid'] == '0x0005', 'new CER sent on wrong stream'
if out.name == 'watchdog':
    assert any(row['diameter.cmd.code'] == '280' and row['diameter.flags.request'] == '1' and int(row['frame.number']) < int(restart_init['frame.number']) for row in rows), 'old pending DWR was not transmitted'
if out.name == 'fragment':
    assert 'OLD_FRAGMENT stream=3 bytes=10' in (out / 'initial.log').read_text(), 'old fragment was not sent'
    assert any(row['sctp.chunk_type'] == '0' and row['sctp.data_sid'] == '0x0003' and int(row['frame.number']) < int(restart_init['frame.number']) for row in rows), 'old fragment missing on wire'
# RFC 6733 §5.5.4: retransmission preserves end-to-end identity and payload.
requests = [r for r in all_rows if r['diameter.cmd.code'] == '272' and r['diameter.flags.request'] == '1']
assert len(requests) == 2, f'expected original plus one failover request, got {len(requests)}'
original, retry = requests
assert int(retry['frame.number']) > int(restart_init['frame.number']), 'pending request failed over before association restart'
assert original['sctp.dstport'] == '43868' and retry['sctp.dstport'] == '4868', 'request did not fail over to alternate peer'
assert original['diameter.flags.T'] == '0' and retry['diameter.flags.T'] == '1', 'T bit not set exclusively on retransmission'
assert original['diameter.endtoendid'] == retry['diameter.endtoendid'], 'end-to-end changed on failover'
assert original['diameter.hopbyhopid'] != retry['diameter.hopbyhopid'], 'hop-by-hop not freshly allocated'
for key in ('diameter.Session-Id', 'diameter.User-Name'):
    assert original[key] == retry[key] and original[key], f'{key} payload changed or absent'
raw_cmd = cmd[:cmd.index('-Y')] + ['-Y', 'diameter.cmd.code == 272 && diameter.flags.request == 1', '-T', 'jsonraw', '-j', 'diameter']
raw = subprocess.run(raw_cmd, text=True, capture_output=True, check=True)
(out / 'request-raw.json').write_text(raw.stdout)
wire = [bytes.fromhex(p['_source']['layers']['diameter_raw'][0]) for p in json.loads(raw.stdout)]
assert len(wire) == 2 and wire[0][20:] == wire[1][20:], 'complete serialized AVP payload changed on retry'
assert wire[0][:4] == wire[1][:4] and wire[0][5:12] == wire[1][5:12], 'request version, length, command or application changed'
if out.name == 'deadline':
    done = re.search(r'SEND_DONE elapsed=([0-9.]+)s error=.*timeout=true', log)
    assert done and 7.8 <= float(done[1]) < 8.8, 'original request deadline was restarted during failover'
else:
    assert re.search(r'SEND_DONE .*result=2001', log), 'logical request did not complete via alternate'
if out.name == 'watchdog':
    assert_watchdog_recovery(rows, log, cer, answer)
print(f'PASS: failover preserved E2E={original["diameter.endtoendid"]}, Session-Id and payload; HBH {original["diameter.hopbyhopid"]} -> {retry["diameter.hopbyhopid"]}, T 0 -> 1.')
print(f'PASS: restart handshake frames {restart_init["frame.number"]}..{int(cer["frame.number"])-1}; CER {cer["frame.number"]}, CEA {answer["frame.number"]} Result2001 R0 matching ids in {delay:.6f}s. Runtime restart {restart[1]} before DATA {new_data[1]}, physical accepts=1, generations=2, old fences pass.')
