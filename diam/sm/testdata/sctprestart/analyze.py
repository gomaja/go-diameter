#!/usr/bin/env python3
import csv
import pathlib
import re
import subprocess
import sys

out = pathlib.Path(sys.argv[1]).resolve()
image = 'i81-wire-tools:go1.27.2'
run_id = (out / 'run-id').read_text().strip()
fields = ['frame.number', 'frame.time_epoch', 'ip.src', 'sctp.chunk_type', 'sctp.data_sid', 'diameter.cmd.code', 'diameter.flags.request', 'diameter.hopbyhopid', 'diameter.endtoendid', 'diameter.Result-Code', 'diameter.Origin-Host', 'diameter.Auth-Application-Id', 'diameter.Origin-State-Id']
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
assert cer['diameter.Origin-Host'] == 'client2.example' and cer['diameter.Origin-State-Id'] == '2', 'fresh peer identity/state missing'
assert len(cea) == 1, 'duplicate CEA'
answer = cea[0]
assert answer['diameter.cmd.code'] == '257' and answer['diameter.Result-Code'] == '2001' and answer['diameter.endtoendid'] == cer['diameter.endtoendid'], 'CEA content mismatch'
delay = float(answer['frame.time_epoch']) - float(cer['frame.time_epoch'])
assert 0 <= delay < 4, f'CEA late: {delay}'
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
print(f'PASS: restart handshake frames {restart_init["frame.number"]}..{int(cer["frame.number"])-1}; CER {cer["frame.number"]}, CEA {answer["frame.number"]} Result2001 R0 matching ids in {delay:.6f}s. Runtime restart {restart[1]} before DATA {new_data[1]}, physical accepts=1, generations=2, old fences pass.')
