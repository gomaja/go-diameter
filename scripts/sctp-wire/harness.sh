#!/usr/bin/env bash
# Shared lifecycle for the package-local SCTP wire scenarios.
# The caller supplies build arguments, source hashes, ports and wire_scenario.
# Variables are shared with the sourcing scenario.
# shellcheck disable=SC2034,SC2154

wire_wait() {
 local peer=$1 child=$2 attempts=$3 i
 for ((i=0; i<attempts; i++)); do
  if docker exec "$peer" test -s "/tmp/$child.exit" >/dev/null 2>&1; then return 0; fi
  sleep .1
 done
 docker exec "$peer" test -s "/tmp/$child.exit"
}

wire_stop() {
 local peer=$1 child=$2 signal=$3 attempts=$4
 if docker exec "$peer" test -s "/tmp/$child.pid" >/dev/null 2>&1; then
  if ! docker exec "$peer" test -s "/tmp/$child.exit" >/dev/null 2>&1; then
   docker exec "$peer" sh -c 'kill -"$1" "$(cat "/tmp/$2.pid")"' sh "$signal" "$child"
   wire_wait "$peer" "$child" "$attempts"
  fi
 fi
}

wire_cleanup() {
 local peer child signal file destination resource
 for peer in "$client" "$server"; do
  # Never stop or remove a resource owned by another run.
  [[ $(docker inspect -f '{{index .Config.Labels "harness"}}' "$peer" 2>/dev/null) == "$run" ]] || continue
  for child in capture initial server alternate; do
   signal=TERM
   if [[ $child == capture ]]; then signal=INT; fi
   if [[ $child == initial ]]; then signal=KILL; fi
   wire_stop "$peer" "$child" "$signal" "$cleanup_attempts" >/dev/null 2>&1 || true
  done
  for file in wire.pcapng capture.log capture.exit server.log server.exit initial.log initial.exit alternate.log alternate.exit; do
   destination=$out/${peer##*-}-$file
   docker cp "$peer:/tmp/$file" "$destination" >/dev/null 2>&1 || true
  done
 done
 for resource in "$client" "$server" "$builder"; do
  if [[ $(docker inspect -f '{{index .Config.Labels "harness"}}' "$resource" 2>/dev/null) == "$run" ]]; then
   docker rm -f -v "$resource" >/dev/null 2>&1 || true
  fi
 done
 if [[ $(docker network inspect -f '{{index .Labels "harness"}}' "$network" 2>/dev/null) == "$run" ]]; then
  docker network rm "$network" >/dev/null 2>&1 || true
 fi
 # This also reaps a tshark export interrupted during analysis.
 while IFS= read -r resource; do
  [[ -n $resource ]] || continue
  docker rm -f -v "$resource" >/dev/null 2>&1 || true
 done < <(docker ps -aq --filter "label=harness=$run")
 docker ps -a --filter "label=harness=$run" --format '{{.Names}}' > "$out/cleanup-containers.txt"
 docker volume ls --filter "label=harness=$run" --format '{{.Name}}' > "$out/cleanup-volumes.txt"
 docker network ls --filter "label=harness=$run" --format '{{.Name}}' > "$out/cleanup-networks.txt"
 docker ps -a --filter "name=$run" --format '{{.Names}}' > "$out/cleanup-name.txt"
 docker volume ls --filter "name=$run" --format '{{.Name}}' > "$out/cleanup-name-volumes.txt"
 docker network ls --filter "name=$run" --format '{{.Name}}' > "$out/cleanup-name-networks.txt"
}

wire_exit() {
 wire_cleanup
 rm -rf "$rig"
}

wire_build() {
 local tools=$root/scripts/sctp-wire image=${SCTP_WIRE_IMAGE:-sctp-wire-tools:go1.27.2}
 # Builder state stays in the run's scratch directory; the caller's Docker
 # context and credentials stay in effect for every command.
 mkdir -p "$rig/buildx" "$rig/out"
 if ! docker image inspect "$image" > "$out/image-build.log" 2>&1; then
  BUILDX_CONFIG=$rig/buildx docker build -t "$image" "$tools" >> "$out/image-build.log" 2>&1
 fi
 image_id=$(docker image inspect -f '{{.Id}}' "$image")
 printf '%s\n' "$image_id" > "$out/image-id.txt"
 printf '%s\n' "$image" > "$out/image-ref.txt"
 # Compile in the container's writable layer; only read-only source is bound.
 # docker cp returns caller-owned artifacts, leaving no root-owned host files.
 docker create --name "$builder" --label "harness=$run" \
  --mount "type=bind,src=$source,dst=/source,readonly" \
  --mount "type=bind,src=$harness,dst=/harness,readonly" \
  "$image_id" sh -eu -c '
   fixture=$1; hash_count=$2; binary=$3; shift 3
   cp -a /source /tmp/build
   cd /tmp/build
   if test -n "$fixture"; then mkdir -p "$(dirname "$fixture")"; cp /harness/main.go "$fixture"; fi
   mkdir /out
   while test "$hash_count" -gt 0; do
    if test -f "$1"; then sha256sum "$1"; fi
    shift; hash_count=$((hash_count-1))
   done > /out/source-hashes.txt
   go "$@"
   go version > /out/go-version.txt
   go version -m "/out/$binary" > /out/binary-build.txt
  ' sh "$fixture" "${#hashes[@]}" "$binary" "${hashes[@]}" "${build[@]}" > "$out/build.log" 2>&1
 docker start -a "$builder" >> "$out/build.log" 2>&1
 docker cp "$builder:/out/." "$rig/out" >/dev/null
 cp "$rig/out/source-hashes.txt" "$rig/out/go-version.txt" "$rig/out/binary-build.txt" "$out/"
}

wire_start() {
 local peer
 docker network create --label "harness=$run" "$network" >/dev/null
 for peer in "$server" "$client"; do
  docker run -d --privileged --label "harness=$run" --name "$peer" --network "$network" \
   --mount "type=bind,src=$rig/out/$binary,dst=$wire_path,readonly" "$image_id" sleep infinity >/dev/null
 done
 sip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
 cip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client")
 # RFC 9260 §5.2.4.1 (Errata 7387) describes the retained-association restart.
 # Receiver INPUT keeps the stale ABORT visible in both namespace captures.
 docker exec "$server" iptables -I INPUT -p sctp -s "$cip" --sport "$client_port" --dport "$server_port" -m sctp --chunk-types any ABORT -j DROP
 for peer in "$server" "$client"; do
  docker exec -d "$peer" sh -c 'tshark -i eth0 -f sctp -w /tmp/wire.pcapng >/tmp/capture.log 2>&1 & pid=$!; printf "%s\n" "$pid" >/tmp/capture.pid; wait "$pid"; printf "%s\n" "$?" >/tmp/capture.exit'
 done
 sleep 1
}

wire_collect() {
 local peer
 for peer in "$server" "$client"; do
  wire_stop "$peer" capture INT 30
  docker exec "$peer" test -s /tmp/capture.exit
  docker cp "$peer:/tmp/wire.pcapng" "$out/${peer##*-}$capture_suffix.pcapng" >/dev/null
  docker cp "$peer:/tmp/capture.log" "$out/${peer##*-}-capture.log" >/dev/null
  docker cp "$peer:/tmp/capture.exit" "$out/${peer##*-}-capture.exit" >/dev/null
 done
 docker cp "$server:/tmp/server.log" "$out/server.log" >/dev/null
 docker cp "$client:/tmp/initial.log" "$out/initial.log" >/dev/null
 docker cp "$client:/tmp/initial.exit" "$out/initial.exit" >/dev/null
 if [[ $scenario == peer ]]; then docker cp "$client:/tmp/alternate.log" "$out/alternate.log" >/dev/null; fi
 docker exec "$server" iptables -nvxL INPUT > "$out/iptables.txt"
 docker exec "$server" uname -a > "$out/kernel.txt"
 docker exec "$server" tshark --version > "$out/tshark-version.txt"
 wire_stop "$server" server TERM 30
 docker exec "$server" test -s /tmp/server.exit
}

wire_analyze() {
 local analysis_result=0
 if [[ $scenario == tls ]]; then
  cat "$out/server-server.log" "$out/restart.log"
  if [[ $client_result != 0 ]]; then result=$client_result; return; fi
 else
  printf '%s\n' "run=$run restart_exit=$result output=$out"
  cat "$out/restarted.log"
 fi
 if [[ $result == 0 || $analyze_on_failure == true ]]; then
  python3 -B "$harness/analyze.py" "$out" > "$out/assertions.txt" 2>&1 || analysis_result=$?
  cat "$out/assertions.txt"
  if [[ $scenario == tls ]]; then printf '%s\n' "$analysis_result" > "$out/assertions.exit"; fi
  if [[ $result == 0 || $scenario == peer ]]; then
   if [[ $analysis_result != 0 ]]; then result=$analysis_result; fi
  fi
 fi
 if [[ $scenario == peer ]]; then sha256sum "$out"/*.pcapng > "$out/capture-sha256.txt"; fi
}

wire_run() {
 out=$(realpath -m "$output")
 mkdir -p "$out"
 rig=$(mktemp -d "${TMPDIR:-/tmp}/sctp-wire-build.XXXXXXXXXX")
 run=sctp-wire-${scenario}-${variant}-${rig##*.}
 network=$run-net
 server=$run-server
 client=$run-client
 builder=$run-build
 trap wire_exit EXIT
 trap 'exit 130' INT TERM
 printf '%s\n' "$run" > "$out/run-id"
 wire_build
 wire_start
 wire_scenario
 wire_collect
 wire_cleanup
 # Keep the trap through analysis so interruption also reaps tshark containers.
 wire_analyze
 wire_exit
 trap - EXIT
 exit "$result"
}
