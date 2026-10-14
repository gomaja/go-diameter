# Accepted SCTP restart on the wire

This optional harness builds the `sctprestart` tagged peer program and runs it
in two privileged Linux Docker containers. It requires Docker with SCTP support,
Bash and Python 3. Missing SCTP or tshark support fails the run; it never skips.
The image pins Go 1.27.2 and installs tshark, iptables and iproute2. Each run owns
a dedicated labeled Docker bridge, joins its children, copies captures out,
and removes its containers and network. It mounts no host Go cache.

Run from the repository root, writing evidence outside the checkout:

```sh
bash diam/sm/testdata/sctprestart/run.sh "$PWD" /tmp/i81-wire-fixed basic
```

The optional Go test entry point also runs inside Docker. Mount the repository
and a throwaway scratch directory at their original absolute host paths: the
Docker daemon must see those paths when the runner starts its peers. For example,
using a scratch directory chosen outside the checkout:

```sh
export I81_WIRE_SCRATCH=/absolute/path/to/scratch/i81-wire-test
mkdir -p "$I81_WIRE_SCRATCH"
docker run --rm --label harness=i81-wire-orchestrator \
  --mount "type=bind,src=$PWD,dst=$PWD,readonly" \
  --mount "type=bind,src=$I81_WIRE_SCRATCH,dst=$I81_WIRE_SCRATCH" \
  --mount type=bind,src=/usr/bin/docker,dst=/usr/bin/docker,readonly \
  --mount type=bind,src=/usr/libexec/docker/cli-plugins/docker-buildx,dst=/usr/libexec/docker/cli-plugins/docker-buildx,readonly \
  --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
  -e TMPDIR="$I81_WIRE_SCRATCH" -w "$PWD" i81-wire-tools:go1.27.2 \
  go test -tags=sctprestart ./diam/sm \
    -run '^TestAcceptedSCTPRestartWire$' -count=1 -v -timeout 3m
```

Build `i81-wire-tools:go1.27.2` with the Dockerfile in this directory first. The
Docker CLI and buildx paths above are the installed paths used for validation;
adjust those mounts if the local installation differs. The test's temporary
directory is removed by Go. Use the standalone runner to retain packet captures.

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
mkdir -p /tmp/i81-wire-baseline-source
git archive 49b6c8c | tar -x -C /tmp/i81-wire-baseline-source
bash diam/sm/testdata/sctprestart/run.sh \
  /tmp/i81-wire-baseline-source /tmp/i81-wire-baseline basic
```

The runner copies the tagged peer into a throwaway source tree inside its build
container, so a baseline lacking the helper is supported. The expected failure
is `FAIL phase=2 CEA ... i/o timeout`, with the second CER present on the wire
and no matching CEA. `analyze.py /tmp/i81-wire-baseline/basic` independently
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
