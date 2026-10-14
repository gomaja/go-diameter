import csv,pathlib,re,subprocess,sys
out=pathlib.Path(sys.argv[1]).resolve()
run=(out/'run-id').read_text().strip()
fields=['frame.number','frame.time_epoch','ip.src','sctp.chunk_type','sctp.srcport','sctp.dstport']
rows=[]
for role in ['client','server']:
 cmd=['docker','run','--rm','--label',f'harness={run}','--mount',f'type=bind,src={out},dst=/evidence,readonly','i81-wire-tools:go1.27.2','tshark','-r',f'/evidence/{role}-wire.pcapng','-Y','sctp','-T','fields']
 for f in fields:cmd+=['-e',f]
 proc=subprocess.run(cmd,text=True,capture_output=True,check=True)
 (out/f'{role}-packets.tsv').write_text(proc.stdout)
 parsed=[dict(zip(fields,row)) for row in csv.reader(proc.stdout.splitlines(),delimiter='\t')]
 assert any('6' in r['sctp.chunk_type'].split(',') for r in parsed),'ABORT absent at capture point'
 if role=='client':rows=parsed
init=[r for r in rows if '1' in r['sctp.chunk_type'].split(',')]
assert len(init)==2,init
start=int(init[1]['frame.number']);ip=init[1]['ip.src']
new=[r for r in rows if int(r['frame.number'])>=start]
control=[v for r in new for v in r['sctp.chunk_type'].split(',') if v in ['1','2','10','11']]
assert control==['1','2','10','11'],control
assert not [r for r in new if r['ip.src']==ip and '0' in r['sctp.chunk_type'].split(',')],'restarted peer sent DATA'
assert re.search(r'\s[1-9]\d*\s+\d+\s+DROP\s+132',(out/'iptables.txt').read_text()),'receiver INPUT ABORT counter zero'
log=(out/'server-server.log').read_text()
print(f'WIRE: real restart handshake starts frame {start}; INIT/INIT ACK/COOKIE ECHO/COOKIE ACK; no client DATA afterward; receiver INPUT drop positive.')
if 'TLS_RESTART_CLOSED' in log:
 assert 'TLS_UNDERLYING type=*diam.SCTPConn' in log
 assert 'old_write_fenced=true physical_accepts=1 successors=0' in log
 assert not [r for r in new if r['ip.src']!=ip and '0' in r['sctp.chunk_type'].split(',')],'old TLS records written after restart'
 print('PASS: built-in TLS has restart adapter; old connection closed without stale TLS DATA or successor.')
else:
 assert 'TLS_UNDERLYING type=*sctp.Conn' in log
 assert 'swallowed restart notification; old connection remains open' in log
 print('EXPECTED FAIL: raw SCTP beneath TLS swallowed restart and retained old connection.')
 sys.exit(1)
