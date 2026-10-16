#!/usr/bin/env bash
# Scenario commands and timings; shared lifecycle lives in scripts/sctp-wire.
set -euo pipefail
harness=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$harness/../../../.." && pwd)
# shellcheck source=scripts/sctp-wire/harness.sh
source "$root/scripts/sctp-wire/harness.sh"
scenario=peer
variant=${3:-basic}
case "$variant" in basic|changed-identity|changed-apps|alternate-stream|watchdog|fragment|deadline) ;; *) echo "unknown variant: $variant" >&2; exit 2 ;; esac
source=$(cd "${1:-$harness/../../../..}" && pwd)
output=${2:-${TMPDIR:-/tmp}/sctp-wire-peer-evidence-$(date +%s)-$$}
output=$output/$variant
fixture=diam/peer/testdata/sctprestart/main.go
build=(build -tags=sctprestart -o /out/peer ./diam/peer/testdata/sctprestart)
binary=peer
wire_path=/wire
server_port=3868
client_port=43868
capture_suffix=
cleanup_attempts=10
analyze_on_failure=true
hashes=(diam/server.go diam/accepted_generation.go diam/network_sctp.go diam/peer/manager.go diam/peer/actor.go diam/peer/session.go diam/peer/renewal.go diam/peer/watchdog.go diam/peer/send.go diam/peer/testdata/sctprestart/main.go go.mod go.sum)

wire_scenario() {
watchdog=false
if [[ $variant == watchdog ]]; then watchdog=true; fi
request_timeout=12s
answer_delay=0s
if [[ $variant == watchdog ]]; then request_timeout=40s; fi
if [[ $variant == deadline ]]; then request_timeout=8s; answer_delay=10s; fi
docker exec -d "$client" sh -c '/wire -mode alternate -addr "$1" -answer-delay="$2" >/tmp/alternate.log 2>&1 & alternate_pid=$!; printf "%s\n" "$alternate_pid" >/tmp/alternate.pid; wait "$alternate_pid"; printf "%s\n" "$?" >/tmp/alternate.exit' sh "$cip:4868" "$answer_delay"
sleep .5
docker exec -d "$server" sh -c '/wire -mode server -addr "$1" -watchdog="$2" -alternate "$3" -request-timeout="$4" >/tmp/server.log 2>&1 & server_pid=$!; printf "%s\n" "$server_pid" >/tmp/server.pid; wait "$server_pid"; printf "%s\n" "$?" >/tmp/server.exit' sh "$sip:3868" "$watchdog" "$cip:4868" "$request_timeout"
sleep 1
fragment=false
if [[ $variant == fragment ]]; then fragment=true; fi
docker exec -d "$client" sh -c '/wire -mode client -addr "$1" -local "$2" -phase 1 -fragment="$3" -watchdog="$4" >/tmp/initial.log 2>&1 & initial_pid=$!; printf "%s\n" "$initial_pid" >/tmp/initial.pid; wait "$initial_pid"; printf "%s\n" "$?" >/tmp/initial.exit' sh "$sip:3868" "$cip:43868" "$fragment" "$watchdog"
for ((i=0;i<100;i++)); do
 if docker exec "$client" test -s /tmp/initial-ready; then break; fi
 sleep .1
done
docker exec "$client" test -s /tmp/initial-ready
if [[ $variant == watchdog ]]; then
 for ((i=0;i<120;i++)); do
  if docker exec "$client" test -s /tmp/watchdog-ready; then break; fi
  sleep .1
 done
 docker exec "$client" test -s /tmp/watchdog-ready
fi
if [[ $variant == deadline ]]; then sleep 3; fi
docker exec "$client" sh -c 'kill -KILL "$(cat /tmp/initial.pid)"'
for ((i=0;i<30;i++)); do if docker exec "$client" test -s /tmp/initial.exit; then break; fi; sleep .1; done
docker exec "$client" test -s /tmp/initial.exit
sleep .2
app=4
stream=0
host=client1.example
if [[ $variant == changed-identity ]]; then host=client2.example; fi
if [[ $variant == changed-apps ]]; then app=16777251; fi
if [[ $variant == alternate-stream || $variant == fragment ]]; then stream=5; fi
set +e
docker exec "$client" /wire -mode client -addr "$sip:3868" -local "$cip:43868" -phase 2 -stream "$stream" -app "$app" -host "$host" -watchdog="$watchdog" > "$out/restarted.log" 2>&1
result=$?
set -e
printf '%s\n' "$result" > "$out/restart.exit"
if [[ $variant == deadline ]]; then sleep 6; else sleep .5; fi
}

wire_run
