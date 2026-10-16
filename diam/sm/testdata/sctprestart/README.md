# Accepted SCTP restart on the wire

This optional harness builds the `sctprestart` tagged peer program and runs it
in two privileged Linux Docker containers. It requires Docker with SCTP support,
Bash and Python 3. Missing SCTP or tshark support fails the run; it never skips.
The image pins Go 1.27.2 and installs tshark, iptables and iproute2. Each run owns
a dedicated labeled Docker bridge, joins its children, copies captures out,
and removes its containers and network. It mounts no host Go cache.

All three restart scenarios use `scripts/sctp-wire/harness.sh`, its shared
Dockerfile, and its tshark exporter. Each runner builds
`sctp-wire-tools:go1.27.2` when absent and verifies it when present; no other
scenario needs to run first. `SCTP_WIRE_IMAGE` selects another tag, including a
fresh tag for an independent first run. A run records the immutable image ID
and uses it for compilation, peers and later analysis. Python 3 runs the local
analyzer; only tshark runs in an analysis container.

Invoke the runner from any directory using its path. The arguments remain
`[source checkout] [output root] [variant]`; source defaults to this checkout,
variant to `basic`, and output to a unique `sctp-wire-sm-evidence-*` directory
under `${TMPDIR:-/tmp}`. Evidence is placed in the variant subdirectory.
For example, from the repository root:

```sh
bash diam/sm/testdata/sctprestart/run.sh "$PWD" /path/to/evidence/sm basic
```

The optional `sctprestart` tagged `TestAcceptedSCTPRestartWire` entry point
invokes the same runner. Run it inside a Linux Docker container with the Docker
CLI and socket available. Mount the checkout and `TMPDIR` at their original
absolute host paths so sibling containers can bind them. The test removes its
own temporary evidence; use the standalone runner to retain captures.

Compilation copies source into the builder's writable container layer. No
host Go cache is mounted, and build artifacts are copied out as the calling
user. Privileged peers bind only the fixture binary. Every run uses unique
`sctp-wire-*` container/network names and a `sctp-wire-build.*` temporary
directory; cleanup touches only that run's labeled resources. Docker CLI
configuration stays in the temporary directory. Set `TMPDIR` to choose its
location; the runner writes only there and in its output directory.

The client binds source port 43868, completes CER/CEA, sets SO_LINGER enabled
with zero timeout, and is killed and reaped. The server drops client ABORT on
INPUT while both namespaces capture packets. A separate process restarts on
the same source address/port and requires a successful matching CEA within
four seconds. This bound matches the reported peer's wait; it is not a Diameter
protocol timer. RFC 9260 §5.2.4 governs the SCTP restart; RFC 6733 §§5.3 and
5.6–5.6.1 govern fresh Diameter admission for the replacement generation.

The capture assertion requires the renewed INIT/INIT ACK/COOKIE ECHO/COOKIE ACK,
CER command 257 with R=1, and CEA command 257 with R=0, Result-Code 2001 and matching
Hop-by-Hop/End-to-End IDs. A SACK alone fails. The server must have one physical
acceptance and two accepted generations. The read observer logs the ordered
transport restart marker before the new CER bytes; the new Conn has fresh
context, old acceptance cleanup runs, old writes match `net.ErrClosed`, and
old Close leaves the new generation open. The observer forwards all multistream
operations and `ResetForRestart` to the product adapter; no dependency is patched.

To compare with the original defect using the exact same harness:

```sh
mkdir -p /path/to/scratch/baseline-source
git archive 49b6c8c | tar -x -C /path/to/scratch/baseline-source
bash diam/sm/testdata/sctprestart/run.sh \
  /path/to/scratch/baseline-source /path/to/evidence/baseline basic
```

The runner copies the tagged peer into a throwaway source tree inside its build
container, so a baseline lacking the helper is supported. The expected failure
is `FAIL phase=2 CEA ... i/o timeout`, with the second CER present on the wire
and no matching CEA. `analyze.py /path/to/evidence/baseline/basic` independently
checks the capture and exits nonzero for that missing answer.

Repeat the fixed run with `changed-apps`, `alternate-stream`, `watchdog`, and
`fragment` as the third argument. Changed-apps changes peer Origin-Host,
Origin-State-Id, and Auth-Application-Id from 4 to 16777251; the handshake hook
records fresh negotiated metadata. Alternate-stream sends the new CER on
stream 5. Watchdog enables Twinit=6 seconds and waits nine seconds before
restart, leaving an old DWR unanswered. Fragment sends an incomplete ten-byte
Diameter header on stream 3, then sends the new CER on stream 5 after restart.

The fragment variant covers application framing, not SCTP fragmented DATA or
kernel partial delivery. The harness does not construct bundled COOKIE
ECHO/DATA because go-sctp Config.Dial waits for association establishment.
Observed read ordering applies to the kernel recorded in the evidence, not all
kernels. It does not prove retention/purge of kernel-queued outbound DATA,
Manager failover policy, dialed restart, or every protocol lifecycle race.
