#!/usr/bin/env bash
# Copyright 2013-2015 go-diameter authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# check.sh runs, on this machine, every check that gates a change. CI runs
# only what cannot run here: the tests on macOS.
#
#   scripts/check.sh            every check
#   scripts/check.sh vet lint   the named checks
#
# Checks, in order: format test race vet lint vuln windows secrets codeql.
#
# Requirements:
#   - Linux with the sctp kernel module loaded. The tests, which open SCTP
#     sockets, run in Docker containers of the official golang images, each
#     in its own network namespace; nothing opens SCTP sockets on the host.
#   - Docker, and network access for the images, the Go toolchains and the
#     vulnerability database.
#   - The CodeQL CLI on PATH or in $(go env GOPATH)/bin. Staticcheck,
#     golangci-lint, govulncheck and gitleaks run with go run at the versions
#     pinned below.
#   - WSL with interop enabled, for the Windows tests.
#
# Environment:
#   GO_STABLE, GO_OLDSTABLE  toolchains to test with (default: the two
#                            supported releases go.dev lists)
#   BASE                     ref for the whitespace check (default origin/main)
#   SKIP                     comma-separated checks to skip; they are reported
set -uo pipefail

checks=(format test race vet lint vuln windows secrets codeql)

# Pinned tools. go run builds each with the stable toolchain, so the
# analysers read whatever that toolchain compiles; a binary built with an
# older Go cannot load a newer standard library. Staticcheck 2026.2.1 cannot
# read Go 1.27.2 export data; this go-tools commit can.
staticcheck=honnef.co/go/tools/cmd/staticcheck@452d5bb86b45416c35891262f6a11dbd6a970117
golangci_lint=github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
govulncheck=golang.org/x/vuln/cmd/govulncheck@v1.9.0
gitleaks=github.com/zricethezav/gitleaks/v8@v8.30.1

root=$(git rev-parse --show-toplevel) || exit 1
cd "$root" || exit 1
PATH="$PATH:$(go env GOPATH)/bin"
export PATH

selected=("$@")
if [ ${#selected[@]} -eq 0 ]; then
	selected=("${checks[@]}")
fi
for c in "${selected[@]}"; do
	if [[ " ${checks[*]} " != *" $c "* ]]; then
		echo "unknown check $c; checks: ${checks[*]}" >&2
		exit 2
	fi
done

if [ -z "${GO_STABLE:-}" ] || [ -z "${GO_OLDSTABLE:-}" ]; then
	# go.dev lists the supported releases, newest first, once per file.
	mapfile -t releases < <(curl -fsSL 'https://go.dev/dl/?mode=json' |
		grep -oE '"version": *"go[0-9.]+"' | grep -oE 'go[0-9.]+' | awk '!seen[$0]++')
	GO_STABLE=${GO_STABLE:-${releases[0]:-}}
	GO_OLDSTABLE=${GO_OLDSTABLE:-${releases[1]:-}}
fi
if [ -z "$GO_STABLE" ] || [ -z "$GO_OLDSTABLE" ]; then
	echo "cannot read the supported Go releases from go.dev; set GO_STABLE and GO_OLDSTABLE" >&2
	exit 1
fi
export GOTOOLCHAIN=$GO_STABLE

work=$(mktemp -d "${TMPDIR:-/tmp}/go-diameter-check.XXXXXX") || exit 1
trap 'rm -rf "$work/codeql-db"' EXIT

modules=(. oteldiam)

need() {
	command -v "$1" >/dev/null && return 0
	echo "$1 not found: $2" >&2
	return 1
}

sctp_loaded() {
	[ -e /proc/net/sctp/snmp ] && return 0
	echo "the sctp kernel module is not loaded: sudo modprobe sctp" >&2
	return 1
}

# in_container runs a command in each module of the repository, in a
# container of the official golang image for Go version $1. Containers share
# the host kernel, and so its sctp module, but get their own network
# namespace. They run as the invoking user and reuse the host's module and
# build caches, so nothing they write is owned by root.
in_container() {
	local version=${1#go} m
	shift
	need docker "install Docker" || return 1
	for m in "${modules[@]}"; do
		docker run --rm --user "$(id -u):$(id -g)" \
			-e HOME=/tmp -e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false \
			-e GOCACHE=/gocache -e GOMODCACHE=/gomodcache \
			-v "$root:/src" -w "/src/$m" \
			-v "$(go env GOCACHE):/gocache" -v "$(go env GOMODCACHE):/gomodcache" \
			"golang:$version-bookworm" "$@" || return 1
	done
}

# in_modules runs a command in each module of the repository.
in_modules() {
	local m
	for m in "${modules[@]}"; do
		(cd "$m" && "$@") || return 1
	done
}

check_format() {
	local unformatted base file status
	# Tracked files and new ones not yet added, so the check holds before a
	# commit too.
	unformatted=$(git ls-files -z --cached --others --exclude-standard '*.go' |
		while IFS= read -r -d '' file; do
			if [ -f "$file" ]; then
				printf '%s\0' "$file"
			fi
		done | xargs -0 -r "$(go env GOROOT)/bin/gofmt" -l) || return 1
	if [ -n "$unformatted" ]; then
		printf 'not gofmt-formatted:\n%s\n' "$unformatted"
		return 1
	fi
	# Check tracked changes since BASE, then each untracked file. Read-only
	# diffs cover new files without writing an index or repository objects.
	base=$(git merge-base "${BASE:-origin/main}" HEAD) || return 1
	git diff --check "$base" || return 1
	git ls-files -z --others --exclude-standard |
		while IFS= read -r -d '' file; do
			git diff --no-index --check -- /dev/null "$file"
			status=$?
			# A no-index diff returns 1 for different content even when clean.
			[ "$status" -le 1 ] || return 1
		done
}

check_test() {
	sctp_loaded || return 1
	local v
	for v in "$GO_STABLE" "$GO_OLDSTABLE"; do
		echo "== $v"
		in_container "$v" go test ./... -count=1 -timeout 900s || return 1
	done
}

check_race() {
	sctp_loaded || return 1
	in_container "$GO_STABLE" go test ./... -race -count=1 -timeout 900s
}

check_vet() {
	in_modules go vet ./... || return 1
	local t
	for t in linux/386 linux/arm linux/s390x linux/mips darwin/amd64 darwin/arm64 windows/amd64; do
		echo "== $t"
		GOOS=${t%/*} GOARCH=${t#*/} CGO_ENABLED=0 go vet ./... || return 1
	done
}

check_lint() {
	go run "$staticcheck" ./... && go run "$golangci_lint" run ./...
}

check_vuln() {
	# Vulnerabilities the code can reach, then every vulnerable module
	# version required, reachable or not. Module mode needs a directory with
	# Go files, so it starts from one.
	in_modules go run "$govulncheck" ./... || return 1
	go run "$govulncheck" -C diam -scan module &&
		go run "$govulncheck" -C oteldiam -scan module
}

check_windows() {
	if ! grep -qs '^enabled' /proc/sys/fs/binfmt_misc/WSLInterop; then
		echo "the Windows tests need WSL with interop enabled" >&2
		return 1
	fi
	local temp
	temp=$(cmd.exe /c 'echo %TEMP%' 2>/dev/null | tr -d '\r') || return 1
	temp=$(wslpath "$temp")/go-diameter-check || return 1
	mkdir -p "$temp" || return 1
	# A test binary on the Linux file system takes about a minute to start
	# on Windows; one on the Windows file system starts at once.
	GOOS=windows GOARCH=amd64 GOTMPDIR=$temp go test ./... -short -count=1
}

check_secrets() {
	go run "$gitleaks" git --redact --exit-code 1 --no-banner .
}

check_codeql() {
	need codeql "install a CodeQL bundle from https://github.com/github/codeql-action/releases" || return 1
	local db=$work/codeql-db results=$work/codeql.csv
	codeql database create "$db" --language=go --source-root . --overwrite --quiet || return 1
	codeql database analyze "$db" \
		codeql/go-queries:codeql-suites/go-security-extended.qls \
		codeql/go-queries:codeql-suites/go-security-and-quality.qls \
		--format=csv --output="$results" --quiet || return 1
	if [ -s "$results" ]; then
		echo "CodeQL results:"
		cat "$results"
		return 1
	fi
}

summary=()
failed=0
for c in "${selected[@]}"; do
	if [[ ",${SKIP:-}," == *",$c,"* ]]; then
		summary+=("SKIP  $c")
		continue
	fi
	echo "==> $c"
	start=$SECONDS
	"check_$c" 2>&1 | tee "$work/$c.log"
	if [ "${PIPESTATUS[0]}" -eq 0 ]; then
		summary+=("PASS  $c  $((SECONDS - start))s")
	else
		summary+=("FAIL  $c  $((SECONDS - start))s  $work/$c.log")
		failed=1
	fi
done

echo
echo "Go $GO_STABLE and $GO_OLDSTABLE"
printf '%s\n' "${summary[@]}"
if [ "$failed" -ne 0 ]; then
	exit 1
fi
rm -rf "$work"
