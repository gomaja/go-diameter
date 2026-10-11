#!/usr/bin/env bash
# Every SCTP socket and packet capture runs in isolated privileged containers.
set -euo pipefail
harness=$(cd "$(dirname "$0")" && pwd)
source=$(cd "${1:-$harness/../../../..}" && pwd)
variant=${3:-basic}
case "$variant" in basic|changed-apps|alternate-stream|watchdog|fragment) ;; *) echo "unknown variant: $variant" >&2; exit 2 ;; esac
rig=$(mktemp -d "${TMPDIR:-/tmp}/i81-wire-build.XXXXXX")
trap 'rm -rf "$rig"' EXIT
name=retained
binary=peer
out=$(realpath -m "${2:-/tmp/i81-wire-evidence-$(date +%s)-$$}/$variant")
mkdir -p "$out"
run=i81-wire-${name}-${variant}-${rig##*.}
network=$run-net
server=$run-server
client=$run-client
builder=$run-build

cleanup(){
 for peer in "$client" "$server"; do
  for child in capture initial server; do
   signal=TERM
   if [[ $child == capture ]]; then signal=INT; fi
   if [[ $child == initial ]]; then signal=KILL; fi
   if docker exec "$peer" test -s "/tmp/$child.pid" >/dev/null 2>&1; then
    if ! docker exec "$peer" test -s "/tmp/$child.exit" >/dev/null 2>&1; then
     docker exec "$peer" sh -c 'kill -"$1" "$(cat "/tmp/$2.pid")"' sh "$signal" "$child" >/dev/null 2>&1 || true
     for ((i=0;i<10;i++)); do
      if docker exec "$peer" test -s "/tmp/$child.exit" >/dev/null 2>&1; then break; fi
      sleep .1
     done
    fi
   fi
  done
  role=${peer##*-}
  for file in wire.pcapng capture.log server.log initial.log; do
   destination=$out/$role-$file
   if [[ ! -e $destination ]]; then docker cp "$peer:/tmp/$file" "$destination" >/dev/null 2>&1 || true; fi
  done
 done
 docker rm -f -v "$client" "$server" "$builder" >/dev/null 2>&1 || true
 docker network rm "$network" >/dev/null 2>&1 || true
 docker ps -a --filter "label=harness=$run" --format '{{.Names}}' > "$out/cleanup-containers.txt"
 docker volume ls --filter "label=harness=$run" --format '{{.Name}}' > "$out/cleanup-volumes.txt"
 docker network ls --filter "label=harness=$run" --format '{{.Name}}' > "$out/cleanup-networks.txt"
 docker ps -a --filter "name=$run" --format '{{.Names}}' > "$out/cleanup-name.txt"
 rm -rf "$rig"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
printf '%s\n' "$run" > "$out/run-id"
cp "$harness/Dockerfile" "$rig/Dockerfile"
DOCKER_CONFIG="$rig/docker-config" docker build -t i81-wire-tools:go1.27.2 "$rig" > "$out/image-build.log" 2>&1
mkdir -p "$rig/out"
docker run --rm --name "$builder" --label "harness=$run" \
 --mount "type=bind,src=$source,dst=/source,readonly" \
 --mount "type=bind,src=$harness,dst=/harness,readonly" \
 --mount "type=bind,src=$rig/out,dst=/out" \
 i81-wire-tools:go1.27.2 sh -c 'cp -a /source /tmp/build; mkdir -p /tmp/build/diam/sm/testdata/sctprestart; cp /harness/main.go /tmp/build/diam/sm/testdata/sctprestart/main.go; cd /tmp/build; for f in diam/server.go diam/accepted_generation.go diam/network_sctp.go diam/sm/sm.go diam/sm/accepted_watchdog.go; do if test -f "$f"; then sha256sum "$f"; fi; done > /out/source-hashes.txt; go build -tags=sctprestart -o /out/peer ./diam/sm/testdata/sctprestart' > "$out/build.log" 2>&1

cp "$rig/out/source-hashes.txt" "$out/source-hashes.txt"

docker network create --label "harness=$run" "$network" >/dev/null
for peer in "$server" "$client"; do
 docker run -d --privileged --label "harness=$run" --name "$peer" --network "$network" --mount "type=bind,src=$rig/out/$binary,dst=/wire,readonly" i81-wire-tools:go1.27.2 sleep infinity >/dev/null
done
sip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
cip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client")
docker exec "$server" iptables -I INPUT -p sctp -s "$cip" --sport 43868 --dport 3868 -m sctp --chunk-types any ABORT -j DROP
for peer in "$server" "$client"; do
 docker exec -d "$peer" sh -c 'tshark -i eth0 -f sctp -w /tmp/wire.pcapng >/tmp/capture.log 2>&1 & capture_pid=$!; printf "%s\n" "$capture_pid" >/tmp/capture.pid; wait "$capture_pid"; printf "%s\n" "$?" >/tmp/capture.exit'
done
sleep 1
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
for peer in "$server" "$client"; do
 docker exec "$peer" sh -c 'kill -INT "$(cat /tmp/capture.pid)"'
 for ((i=0;i<30;i++)); do if docker exec "$peer" test -s /tmp/capture.exit; then break; fi; sleep .1; done
 docker exec "$peer" test -s /tmp/capture.exit
 docker cp "$peer:/tmp/wire.pcapng" "$out/${peer##*-}.pcapng" >/dev/null
 docker cp "$peer:/tmp/capture.log" "$out/${peer##*-}-capture.log" >/dev/null
 docker cp "$peer:/tmp/capture.exit" "$out/${peer##*-}-capture.exit" >/dev/null
done
docker cp "$server:/tmp/server.log" "$out/server.log" >/dev/null
docker cp "$client:/tmp/initial.log" "$out/initial.log" >/dev/null
docker cp "$client:/tmp/initial.exit" "$out/initial.exit" >/dev/null
docker exec "$server" iptables -nvxL INPUT > "$out/iptables.txt"
docker exec "$server" uname -a > "$out/kernel.txt"
docker exec "$server" /usr/local/go/bin/go version > "$out/go-version.txt"
docker exec "$server" /usr/local/go/bin/go version -m /wire > "$out/binary-build.txt"
docker inspect "$server" --format '{{.Image}}' > "$out/image-id.txt"
docker exec "$server" tshark --version > "$out/tshark-version.txt"
docker exec "$server" sh -c 'kill -TERM "$(cat /tmp/server.pid)"'
for ((i=0;i<30;i++)); do if docker exec "$server" test -s /tmp/server.exit; then break; fi; sleep .1; done
docker exec "$server" test -s /tmp/server.exit
printf '%s\n' "run=$run restart_exit=$result output=$out"
cat "$out/restarted.log"
cleanup
trap - EXIT
if [[ "$result" == 0 ]]; then
 "$harness/analyze.py" "$out" > "$out/assertions.txt" 2>&1 || result=$?
 cat "$out/assertions.txt"
fi
exit "$result"
