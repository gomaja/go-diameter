#!/usr/bin/env bash
# Scenario commands and timings; shared lifecycle lives in scripts/sctp-wire.
set -euo pipefail
harness=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$harness/../../.." && pwd)
# shellcheck source=scripts/sctp-wire/harness.sh
source "$root/scripts/sctp-wire/harness.sh"
scenario=tls
variant=basic
source=$(realpath "$1")
output=$(realpath -m "$2")
fixture=
build=(test -c -tags=sctptlsrestart -o /out/sctp-tls-restart.test ./diam)
binary=sctp-tls-restart.test
wire_path=/sctp-tls-restart.test
server_port=5868
client_port=43869
capture_suffix=-wire
cleanup_attempts=30
analyze_on_failure=true
hashes=(diam/server.go diam/network_sctp.go diam/accepted_generation.go diam/server_sctp_tls_restart_wire_test.go)

wire_scenario() {
docker exec -d -e SCTP_TLS_RESTART_SERVER_ADDR="$sip:5868" "$server" sh -c '/sctp-tls-restart.test -test.run "^TestBuiltInSCTPTLSRestartWireServer$" -test.v -test.timeout 20s >/tmp/server.log 2>&1 & pid=$!; echo "$pid" >/tmp/server.pid; wait "$pid"; echo "$?" >/tmp/server.exit'
sleep .5
docker exec -d -e SCTP_TLS_RESTART_SERVER_ADDR="$sip:5868" -e SCTP_TLS_RESTART_CLIENT_ADDR="$cip:43869" -e SCTP_TLS_RESTART_PHASE=initial "$client" sh -c '/sctp-tls-restart.test -test.run "^TestBuiltInSCTPTLSRestartWireClient$" -test.v -test.timeout 20s >/tmp/initial.log 2>&1 & pid=$!; echo "$pid" >/tmp/initial.pid; wait "$pid"; echo "$?" >/tmp/initial.exit'
for ((i=0;i<100;i++)); do if docker exec "$client" test -s /tmp/sctp-tls-restart-client-ready; then break; fi; sleep .1; done
docker exec "$client" test -s /tmp/sctp-tls-restart-client-ready
docker exec "$server" test -s /tmp/sctp-tls-restart-admitted
docker exec "$client" sh -c 'kill -KILL "$(cat /tmp/initial.pid)"'
for ((i=0;i<30;i++)); do if docker exec "$client" test -s /tmp/initial.exit; then break; fi; sleep .1; done
docker exec "$client" test -s /tmp/initial.exit
docker cp "$client:/tmp/initial.exit" "$out/initial.exit" >/dev/null
if [[ $(cat "$out/initial.exit") != 137 ]]; then echo "initial client was not killed and reaped" >&2; exit 1; fi
sleep .15
set +e
docker exec -e SCTP_TLS_RESTART_SERVER_ADDR="$sip:5868" -e SCTP_TLS_RESTART_CLIENT_ADDR="$cip:43869" -e SCTP_TLS_RESTART_PHASE=restart "$client" /sctp-tls-restart.test -test.run '^TestBuiltInSCTPTLSRestartWireClient$' -test.v -test.timeout 12s > "$out/restart.log" 2>&1
client_result=$?
set -e
for ((i=0;i<50;i++)); do if docker exec "$server" test -s /tmp/server.exit; then break; fi; sleep .1; done
docker exec "$server" test -s /tmp/server.exit
docker cp "$server:/tmp/server.exit" "$out/server.exit" >/dev/null
result=$(cat "$out/server.exit")
printf '%s\n' "$client_result" > "$out/restart.exit"
}

wire_run
