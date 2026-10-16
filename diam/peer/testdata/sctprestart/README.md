This local SCTP restart harness runs `peer.Manager` against two privileged Linux containers. The alternate peer runs in the primary client's namespace; captures on both `eth0` interfaces cover both associations. No SCTP socket runs on the host. The Go driver is excluded from ordinary package discovery by `testdata` and requires the `sctprestart` build tag.

The runner requires Docker with SCTP support, Bash and Python 3. It uses
`scripts/sctp-wire/harness.sh`, the shared Dockerfile and tshark exporter.
Every runner independently builds `sctp-wire-tools:go1.27.2` when absent or
verifies it when present, then records and uses its immutable image ID. No sm
run is required first. Set `SCTP_WIRE_IMAGE` to select a different or fresh tag.
Python 3 runs the package-local analyzer; tshark runs in the recorded image.

Invoke the runner from any directory using its path. Arguments remain
`[source checkout] [output root] [variant]`, with this checkout, a unique
`sctp-wire-peer-evidence-*` directory under `${TMPDIR:-/tmp}`, and `basic`
as defaults. For example, from the repository root:

```sh
diam/peer/testdata/sctprestart/run.sh "$PWD" /path/to/evidence/peer basic
```

The third argument selects `basic`, `changed-identity`, `changed-apps`, `alternate-stream`, `fragment`, `watchdog`, or `deadline`. Each run writes evidence under a subdirectory named for that variant. Pass a frozen source checkout as the first argument to compare baseline and changed implementations; the builder overlays only this driver onto that checkout. The driver compiles against the public Manager APIs on both versions.

Every variant checks the SCTP INIT, INIT ACK, COOKIE ECHO, COOKIE ACK restart sequence, a fresh CER and exactly one matching successful CEA, transport restart notification before fresh CER delivery, one physical socket acceptance, separate generation admissions, and old-write and old-close fences. The restart reuses the primary source address and port 43868. Killing the original client with SO_LINGER set to zero emits ABORT; receiver INPUT drops it while sender and receiver captures prove it reached the network. SCTP chunk types are defined in RFC 9260 section 3; association restart follows section 5.2.4 and socket notification ordering is observable at the RFC 6458 section 6.1.1 boundary.

An application request remains unanswered at the primary. Retirement must retransmit it to the live alternate. Analysis checks T=1 only on retransmission, fresh Hop-by-Hop, preserved End-to-End, and identical complete serialized AVP payload, including the application Session-Id (RFC 6733 section 5.5.4). The normal alternate answers successfully. The deadline variant delays that answer beyond the original eight-second logical deadline; completion must still occur at the original deadline despite a three-second delay before restart.

Identity and application variants change the replacement CER. The stream variant sends it on SCTP stream 5. Fragment sends an incomplete old Diameter header on stream 3 before restart and then a complete replacement CER on stream 5. Watchdog waits for an unanswered old-generation probe before restarting; the replacement answers three new-generation probes and reaches OKAY from REOPEN (RFC 3539 Appendix A). Every variant also sends its own post-restart DWR and verifies a matching DWA with Result-Code 2001 (RFC 6733 section 5.5.1).

Watchdog analysis uses the replacement CER's host and the restart hook's new generation. For this variant, the retained peer's Manager generation and accepted connection generation both advance from 1 to 2. Each of the first three server probes must have exactly one successful matching DWA on the renewed association, with the peer's identity and both request identifiers preserved. Captured DWA packets must correlate with ordered server header and complete body reads.

The harness wrapper forwards each message synchronously to Manager. After `ServeDIAM` returns from protocol commit, it reads `Manager.Peers()` and records a `RECOVERY_CHECKPOINT` containing the processed CER/DWA command, both identifiers, connection generation and peer snapshot. A TCP control connection on server port 3869 delivers that checkpoint to the client. The client waits for the CER checkpoint before answering recovery probes, and for each DWA checkpoint before sending the next DWA. The analyzer requires REOPEN/ineligible at admission and after DWA 1 and 2, then OKAY/eligible after DWA 3 (RFC 3539 section 3.4.1 and Appendix A). Every checkpoint must match the corresponding captured message and precede the next answer's delivery. Asynchronous `OnPeerEvent` callbacks do not establish recovery boundaries; delayed, missing or queued recovery callbacks cannot affect this check. Initial admission and the alternate peer cannot satisfy recovery. No additional Manager accessor is required.

Run the analyzer's synthetic packet/log regression suite from the repository root:

```sh
python3 -B -m unittest discover -s diam/peer/testdata/sctprestart -p '*_test.py' -v
```

These tests execute the analyzer CLI with synthetic tshark output. They check its acceptance and rejection boundaries; the live two-container watchdog run supplies packet capture evidence.

Missing Docker, SCTP support, tshark, captures, restart evidence, or assertions fails the command. Evidence includes packet tables, raw application request bytes, captures and SHA-256 hashes, logs, build and dependency versions, image identity, kernel version, and receiver drop counters. Run-specific containers and networks are labeled, removed on every exit path, and checked by label and name. No volumes are created.

Compilation copies source into the builder's writable
container layer and mounts no host Go caches. Artifacts are copied out as the
calling user; privileged peers bind only the binary. Container/network names
use unique `sctp-wire-*` prefixes and temporary directories use
`sctp-wire-build.*`. Docker CLI configuration stays in that temporary
directory. Set `TMPDIR` to choose its location; no files are written outside
that directory and the output directory.

The harness does not test TLS, dialed association renewal, packet loss/reordering, or peer state election races. Unit and scripted transport tests cover those policy and concurrency cases. Its packet checks and observed generations establish a real accepted SCTP association restart, not a fresh listener connection.
