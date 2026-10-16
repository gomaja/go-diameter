#!/usr/bin/env bash
# Scenario commands and timings; shared lifecycle lives in scripts/sctp-wire.
set -euo pipefail
harness=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$harness/../../../.." && pwd)
# shellcheck source=scripts/sctp-wire/harness.sh
source "$root/scripts/sctp-wire/harness.sh"
scenario=sm
variant=${3:-basic}
case "$variant" in basic|changed-apps|alternate-stream|watchdog|fragment) ;; *) echo "unknown variant: $variant" >&2; exit 2 ;; esac
source=$(cd "${1:-$harness/../../../..}" && pwd)
output=${2:-${TMPDIR:-/tmp}/sctp-wire-sm-evidence-$(date +%s)-$$}
output=$output/$variant
fixture=diam/sm/testdata/sctprestart/main.go
build=(build -tags=sctprestart -o /out/peer ./diam/sm/testdata/sctprestart)
binary=peer
wire_path=/wire
server_port=3868
client_port=43868
capture_suffix=
cleanup_attempts=10
analyze_on_failure=false
hashes=(diam/server.go diam/accepted_generation.go diam/network_sctp.go diam/sm/sm.go diam/sm/accepted_watchdog.go)

wire_scenario() {
watchdog=false
if [[ $variant == watchdog ]]; then watchdog=true; fi
docker exec -d "$server" sh -c '/wire -mode server -addr "$1" -watchdog="$2" >/tmp/server.log 2>&1 & server_pid=$!; printf "%s\n" "$server_pid" >/tmp/server.pid; wait "$server_pid"; printf "%s\n" "$?" >/tmp/server.exit' sh "$sip:3868" "$watchdog"
sleep 1
fragment=false
if [[ $variant == fragment ]]; then fragment=true; fi
docker exec -d "$client" sh -c '/wire -mode client -addr "$1" -local "$2" -phase 1 -fragment="$3" >/tmp/initial.log 2>&1 & initial_pid=$!; printf "%s\n" "$initial_pid" >/tmp/initial.pid; wait "$initial_pid"; printf "%s\n" "$?" >/tmp/initial.exit' sh "$sip:3868" "$cip:43868" "$fragment"
for ((i=0;i<100;i++)); do
 if docker exec "$client" test -s /tmp/initial-ready; then break; fi
 sleep .1
done
docker exec "$client" test -s /tmp/initial-ready
if [[ $variant == watchdog ]]; then sleep 9; fi
docker exec "$client" sh -c 'kill -KILL "$(cat /tmp/initial.pid)"'
for ((i=0;i<30;i++)); do if docker exec "$client" test -s /tmp/initial.exit; then break; fi; sleep .1; done
docker exec "$client" test -s /tmp/initial.exit
sleep .2
app=4
stream=0
if [[ $variant == changed-apps ]]; then app=16777251; fi
if [[ $variant == alternate-stream || $variant == fragment ]]; then stream=5; fi
set +e
docker exec "$client" /wire -mode client -addr "$sip:3868" -local "$cip:43868" -phase 2 -stream "$stream" -app "$app" > "$out/restarted.log" 2>&1
result=$?
set -e
printf '%s\n' "$result" > "$out/restart.exit"
sleep .5
}

wire_run
