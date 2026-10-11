#!/usr/bin/env bash
set -euo pipefail
harness=$(cd "$(dirname "$0")" && pwd)
source=$(realpath "$1")
out=$(realpath -m "$2")
mkdir -p "$out"
rig=$(mktemp -d "${TMPDIR:-/tmp}/i81-f4-build.XXXXXX")
run=i81-f4-${rig##*.}
network=$run-net
server=$run-server
client=$run-client
cleanup(){
 for peer in "$client" "$server"; do
  for child in initial server capture; do
   signal=TERM; [[ $child == initial ]] && signal=KILL; [[ $child == capture ]] && signal=INT
   if docker exec "$peer" test -s "/tmp/$child.pid" >/dev/null 2>&1; then
    docker exec "$peer" sh -c 'test -s "/tmp/$2.exit" || kill -"$1" "$(cat "/tmp/$2.pid")"' sh "$signal" "$child" >/dev/null 2>&1 || true
    for ((i=0;i<30;i++)); do if docker exec "$peer" test -s "/tmp/$child.exit" >/dev/null 2>&1; then break; fi; sleep .1; done
   fi
  done
  for file in server.log initial.log capture.log capture.exit initial.exit server.exit wire.pcapng; do
   docker cp "$peer:/tmp/$file" "$out/${peer##*-}-$file" >/dev/null 2>&1 || true
  done
 done
 docker rm -f -v "$client" "$server" >/dev/null 2>&1 || true
 docker network rm "$network" >/dev/null 2>&1 || true
 docker ps -a --filter "label=harness=$run" --format '{{.Names}}' > "$out/cleanup-containers.txt"
 docker network ls --filter "label=harness=$run" --format '{{.Name}}' > "$out/cleanup-networks.txt"
 python3 -c 'import shutil,sys;shutil.rmtree(sys.argv[1])' "$rig"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
printf '%s\n' "$run" > "$out/run-id"
mkdir "$rig/out"
docker run --rm --label "harness=$run" --mount "type=bind,src=$source,dst=/source,readonly" --mount "type=bind,src=$rig/out,dst=/out" i81-wire-tools:go1.27.2 sh -c 'cp -a /source /tmp/build; cd /tmp/build; sha256sum diam/server.go diam/network_sctp.go diam/accepted_generation.go diam/server_sctp_tls_restart_wire_test.go >/out/source-hashes.txt; go test -c -tags=sctptlsrestart -o /out/f4.test ./diam' > "$out/build.log" 2>&1
cp "$rig/out/source-hashes.txt" "$out/source-hashes.txt"
docker network create --label "harness=$run" "$network" >/dev/null
for peer in "$server" "$client"; do docker run -d --privileged --label "harness=$run" --name "$peer" --network "$network" --mount "type=bind,src=$rig/out/f4.test,dst=/f4.test,readonly" i81-wire-tools:go1.27.2 sleep infinity >/dev/null; done
sip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
cip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client")
docker exec "$server" iptables -I INPUT -p sctp -s "$cip" --sport 43869 --dport 5868 -m sctp --chunk-types any ABORT -j DROP
for peer in "$server" "$client"; do docker exec -d "$peer" sh -c 'tshark -i eth0 -f sctp -w /tmp/wire.pcapng >/tmp/capture.log 2>&1 & pid=$!; echo "$pid" >/tmp/capture.pid; wait "$pid"; echo "$?" >/tmp/capture.exit'; done
sleep 1
docker exec -d -e F4_SERVER_ADDR="$sip:5868" "$server" sh -c '/f4.test -test.run "^TestBuiltInSCTPTLSRestartWireServer$" -test.v -test.timeout 20s >/tmp/server.log 2>&1 & pid=$!; echo "$pid" >/tmp/server.pid; wait "$pid"; echo "$?" >/tmp/server.exit'
sleep .5
docker exec -d -e F4_SERVER_ADDR="$sip:5868" -e F4_CLIENT_ADDR="$cip:43869" -e F4_PHASE=initial "$client" sh -c '/f4.test -test.run "^TestBuiltInSCTPTLSRestartWireClient$" -test.v -test.timeout 20s >/tmp/initial.log 2>&1 & pid=$!; echo "$pid" >/tmp/initial.pid; wait "$pid"; echo "$?" >/tmp/initial.exit'
for ((i=0;i<100;i++)); do if docker exec "$client" test -s /tmp/f4-client-ready; then break; fi; sleep .1; done
docker exec "$client" test -s /tmp/f4-client-ready
docker exec "$server" test -s /tmp/f4-admitted
docker exec "$client" sh -c 'kill -KILL "$(cat /tmp/initial.pid)"'
for ((i=0;i<30;i++)); do if docker exec "$client" test -s /tmp/initial.exit; then break; fi; sleep .1; done
docker exec "$client" test -s /tmp/initial.exit
docker cp "$client:/tmp/initial.exit" "$out/initial.exit" >/dev/null
if [[ $(cat "$out/initial.exit") != 137 ]]; then echo "initial client was not killed and reaped" >&2; exit 1; fi
sleep .15
set +e
docker exec -e F4_SERVER_ADDR="$sip:5868" -e F4_CLIENT_ADDR="$cip:43869" -e F4_PHASE=restart "$client" /f4.test -test.run '^TestBuiltInSCTPTLSRestartWireClient$' -test.v -test.timeout 12s > "$out/restart.log" 2>&1
client_result=$?
set -e
for ((i=0;i<50;i++)); do if docker exec "$server" test -s /tmp/server.exit; then break; fi; sleep .1; done
docker exec "$server" test -s /tmp/server.exit
docker cp "$server:/tmp/server.exit" "$out/server.exit" >/dev/null
result=$(cat "$out/server.exit")
printf '%s\n' "$client_result" > "$out/restart.exit"
docker exec "$server" iptables -nvxL INPUT > "$out/iptables.txt"
docker exec "$server" uname -a > "$out/kernel.txt"
docker inspect "$server" --format '{{.Image}}' > "$out/image-id.txt"
cleanup
trap - EXIT
cat "$out/server-server.log" "$out/restart.log"
if [[ $client_result != 0 ]]; then exit "$client_result"; fi
set +e
python3 "$harness/analyze.py" "$out" > "$out/assertions.txt" 2>&1
analysis_result=$?
set -e
printf '%s\n' "$analysis_result" > "$out/assertions.exit"
cat "$out/assertions.txt"
if [[ $result == 0 ]]; then result=$analysis_result; fi
exit "$result"
