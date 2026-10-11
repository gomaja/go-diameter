# Built-in SCTP/TLS restart

The optional `linux && !386 && sctptlsrestart` tests exercise
`Server.ListenAndServeTLS` in two privileged Docker containers on a dedicated
bridge. The server completes a real TLS 1.3 handshake and CER/CEA. Its client
sets zero-timeout SO_LINGER and is killed and reaped; server INPUT drops ABORT.
A separate client establishes SCTP from the same source port without sending
DATA. The old TLS connection must close, fence writes and finish dispatch
without creating another generation. Missing SCTP fails the explicit harness.

Build `i81-wire-tools:go1.27.2` with `diam/sm/testdata/sctprestart/Dockerfile`,
then run from the repository root with Docker, Bash and Python 3:

```sh
mkdir -p /path/to/scratch/temp
TMPDIR=/path/to/scratch/temp \
  bash diam/testdata/sctptlsrestart/run.sh "$PWD" /path/to/scratch/evidence
```

The runner copies source into an internal throwaway tree, mounts no host Go
cache, saves both namespace captures/logs/source hashes, joins explicit child
PIDs and removes its containers/network. Its tshark analyzer requires a second INIT/INIT ACK/COOKIE ECHO/COOKIE ACK,
positive receiver INPUT drop, and no DATA from the restarted client. A successful
server also must emit no stale TLS DATA after the restart; the runner checks
client success and the killed initial client's exit 137.
The normal Linux suite also runs `TestBuiltInSCTPTLSListenerUsesRestartAdapter`
through real SCTP/TLS to check adapter placement beneath the TLS record layer.

RFC 9260 §5.2.4 covers association restart and RFC 9846 §6.2 covers failure
closure. This tests the listener composition; it does not establish universal
kernel ordering, queued DATA purge or application failover policy.
