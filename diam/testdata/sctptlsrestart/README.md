# Built-in SCTP/TLS restart

The optional `linux && !386 && sctptlsrestart` tests exercise
`Server.ListenAndServeTLS` in two privileged Docker containers on a dedicated
bridge. The server completes a real TLS 1.3 handshake and CER/CEA. Its client
sets zero-timeout SO_LINGER and is killed and reaped; server INPUT drops ABORT.
A separate client establishes SCTP from the same source port without sending
DATA. The old TLS connection must close, fence writes and finish dispatch
without creating another generation. Missing SCTP fails the explicit harness.

The runner requires Docker, Bash and Python 3. It uses
`scripts/sctp-wire/harness.sh`, the shared Dockerfile and tshark exporter.
It independently builds `sctp-wire-tools:go1.27.2` if absent and verifies it
otherwise; no sm or peer run is required first. `SCTP_WIRE_IMAGE` selects
another tag, including a fresh tag for an independent first run. Compilation,
peers and tshark use the immutable image ID recorded in the evidence.

Invoke the runner from any directory using its path. Both arguments remain
required: `source checkout` and `output directory`. There is one TLS scenario
and evidence goes directly into the output directory. For example, from the
repository root:

```sh
mkdir -p /path/to/scratch/temp
TMPDIR=/path/to/scratch/temp \
  bash diam/testdata/sctptlsrestart/run.sh "$PWD" /path/to/scratch/evidence
```

The runner copies source into an internal throwaway tree, mounts no host Go
cache, saves both namespace captures/logs/source hashes, joins explicit child
PIDs and removes its containers/network. Artifacts are copied out as the calling
user; privileged peers bind only the test binary. Every run uses unique
`sctp-wire-*` container/network names and a `sctp-wire-build.*` temporary
directory. Cleanup touches only resources labeled for that run. Docker CLI
configuration stays in the temporary directory. Set `TMPDIR` to choose its
location; no files are written outside that directory and the output directory.

Its tshark analyzer requires a second INIT/INIT ACK/COOKIE ECHO/COOKIE ACK,
positive receiver INPUT drop, and no DATA from the restarted client. A successful
server also must emit no stale TLS DATA after the restart; the runner checks
client success and the killed initial client's exit 137.
The normal Linux suite also runs `TestBuiltInSCTPTLSListenerUsesRestartAdapter`
through real SCTP/TLS to check adapter placement beneath the TLS record layer.

RFC 9260 §5.2.4 covers association restart and RFC 9846 §6.2 covers failure
closure. This tests the listener composition; it does not establish universal
kernel ordering, queued DATA purge or application failover policy.
