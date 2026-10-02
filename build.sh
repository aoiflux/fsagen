#!/usr/bin/env bash
# build.sh builds every release binary for fsagen into dist/, then writes the
# checksums. Run ./build.sh --help for the one argument it takes.
#
# Set NO_COLOR to turn the colours off. build.ps1 is the PowerShell twin and
# writes a byte-identical SHA256SUMS for the same version and toolchain.
set -euo pipefail

readonly APP=fsagen
# Every platform a release ships for. The gate additionally compiles freebsd,
# which is vetted but not published.
readonly TARGETS=(
	windows/amd64 windows/arm64
	linux/amd64   linux/arm64
	darwin/amd64  darwin/arm64
)

CDPATH='' cd -- "$(dirname -- "$0")"
readonly ROOT=$PWD
readonly DIST=$ROOT/dist

if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
	BOLD='' DIM='' RED='' GREEN='' YELLOW='' CYAN='' RESET=''
else
	BOLD=$'\033[1m' DIM=$'\033[2m' RED=$'\033[31m' GREEN=$'\033[32m'
	YELLOW=$'\033[33m' CYAN=$'\033[36m' RESET=$'\033[0m'
fi
readonly BOLD DIM RED GREEN YELLOW CYAN RESET

die() { printf '%s\n' "  ${RED}${BOLD}error${RESET} $*" >&2; exit 1; }
rule() { printf '  %s%s%s\n' "$DIM" "$(printf '%68s' '' | tr ' ' -)" "$RESET"; }
field() { printf '  %s%-10s%s %s\n' "$DIM" "$1" "$RESET" "$2"; }
note() { printf '  %s%-10s%s %s! %s%s\n' "$DIM" '' "$RESET" "$YELLOW" "$1" "$RESET"; }
heading() { printf '\n  %s%s%s\n' "$BOLD" "$1" "$RESET"; }
ok() { printf '%s%-4s%s' "$GREEN" OK "$RESET"; }
bad() { printf '%s%-4s%s' "$RED" FAIL "$RESET"; }

size_of() { stat -c %s -- "$1" 2>/dev/null || stat -f %z -- "$1"; }
human() { awk -v b="$1" 'BEGIN { printf "%.1f MiB", b / 1048576 }'; }
secs() { awk -v ms="$1" 'BEGIN { printf "%.1f", ms / 1000 }'; }

now_ms() {
	local n
	n=$(date +%s%N 2>/dev/null) || n=''
	case "$n" in
	'' | *N) echo $(( $(date +%s) * 1000 )) ;;
	*) echo $(( n / 1000000 )) ;;
	esac
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -- "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 -- "$1" | cut -d' ' -f1
	else
		openssl dgst -sha256 -- "$1" | awk '{ print $NF }'
	fi
}

usage() {
	cat <<'EOF'
Usage: ./build.sh [version]

Builds every release binary into dist/ and writes SHA256SUMS.

  version      the version to build, such as v0.1.0. It names every file and is
               stamped into the binaries, so fsagen --version reports it too.
               Defaults to git describe, which is what a test build wants.

  -h, --help   print this and exit

  NO_COLOR     set it in the environment to turn the colours off
EOF
}

given=''
case "${1:-}" in
-h | --help) usage; exit 0 ;;
-*) die "unknown option $1 (./build.sh --help)" ;;
*) given=${1:-} ;;
esac
[ "$#" -le 1 ] || die "one version at most, such as ./build.sh v0.1.0"

# A version names every file and goes inside the binaries, so it has to be one
# Go accepts as a module version: v, three numbers, an optional prerelease.
version_ok() { printf '%s' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; }

command -v go >/dev/null 2>&1 || die "go is not on PATH"
[ -f "$ROOT/go.mod" ] || die "no go.mod in $ROOT"

if [ -n "$given" ]; then
	version_ok "$given" || die "version must look like v1.2.3 or v1.2.3-rc.1, not '$given'"
	VERSION=$given ORIGIN=given
else
	VERSION=$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null) || VERSION=''
	[ -n "$VERSION" ] || VERSION=dev
	ORIGIN='git describe'
fi
readonly VERSION ORIGIN

# Stamping a version the commit does not carry is how a release ends up
# promising bytes it was not built from. It stays allowed, because test builds
# want it; it does not stay quiet.
TAG=$(git -C "$ROOT" describe --tags --exact-match 2>/dev/null) || TAG=''
DIRTY=''
[ -z "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ] || DIRTY=yes
readonly TAG DIRTY

# The stamped variable is named after the module, so reading that path from
# go.mod is what stops a module rename leaving behind a -X that hits nothing.
MODULE=$(go list -m 2>/dev/null) || die "cannot read the module path (go list -m failed)"
readonly STAMP=$MODULE/runinfo.version

HOST_OS=$(go env GOOS)
HOST_ARCH=$(go env GOARCH)
readonly HOST_OS HOST_ARCH

# A binary's name carries its version and platform, so several releases can sit
# in one directory without colliding.
artifact() {
	local ext=''
	[ "$1" = windows ] && ext=.exe
	printf '%s_%s_%s_%s%s' "$APP" "$VERSION" "$1" "$2" "$ext"
}

printf '\n  %s%s release build%s\n' "$BOLD$CYAN" "$APP" "$RESET"
rule
field version "$VERSION  ${DIM}($ORIGIN)${RESET}"
if [ -z "$TAG" ]; then
	note "no tag on this commit: fine for a test build, not for a release"
elif [ "$TAG" != "${VERSION%-dirty}" ]; then
	note "this commit is tagged $TAG, so these binaries claim a version they are not"
fi
[ -z "$DIRTY" ] || note "uncommitted changes: --version will report +modified"
field toolchain "$(go env GOVERSION)"
field output "$DIST"
field targets "${#TARGETS[@]}  ${DIM}(windows, linux, darwin x amd64, arm64)${RESET}"

# Clearing the contents rather than the directory itself keeps this working
# when another process holds the directory open, which on Windows is easy.
mkdir -p -- "$DIST" || die "cannot create $DIST"
find "$DIST" -mindepth 1 -delete || die "cannot clear $DIST"

started=$(now_ms)
built=()
failed=()
heading building
for target in "${TARGETS[@]}"; do
	goos=${target%/*} goarch=${target#*/}
	name=$(artifact "$goos" "$goarch")
	t0=$(now_ms)
	# -trimpath keeps the build host's paths out of the binary and -X puts the
	# version in; the revision printed beside it is Go's own VCS stamping.
	if log=$(CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
		go build -trimpath -ldflags "-X $STAMP=$VERSION" -o "$DIST/$name" . 2>&1); then
		printf '    %s  %-14s %-52s %9s  %5ss\n' "$(ok)" "$target" "$name" \
			"$(human "$(size_of "$DIST/$name")")" "$(secs $(( $(now_ms) - t0 )) )"
		built+=("$name")
	else
		printf '    %s  %-14s %sbuild failed%s\n' "$(bad)" "$target" "$RED" "$RESET"
		printf '%s\n' "$log" | sed 's/^/          /'
		failed+=("$target")
	fi
done

# Every later step reads the built list, so stop here rather than expand it empty.
if [ "${#built[@]}" -eq 0 ]; then
	printf '\n'
	rule
	printf '  %s%sfailed%s  all %d targets\n\n' "$BOLD" "$RED" "$RESET" "${#TARGETS[@]}"
	exit 1
fi

heading checksums
sums=$DIST/SHA256SUMS
: >"$sums"
while IFS= read -r name; do
	printf '%s  %s\n' "$(sha256_of "$DIST/$name")" "$name" >>"$sums"
done < <(printf '%s\n' "${built[@]}" | LC_ALL=C sort)
printf '    %s  %-14s %s%d entries, verify with: sha256sum -c SHA256SUMS%s\n' \
	"$(ok)" SHA256SUMS "$DIM" "${#built[@]}" "$RESET"

heading "smoke test"
host_artifact=$DIST/$(artifact "$HOST_OS" "$HOST_ARCH")
if [ ! -x "$host_artifact" ]; then
	printf '    %s%-4s%s  %s%s is not a release target, nothing to run%s\n' \
		"$YELLOW" skip "$RESET" "$DIM" "$HOST_OS/$HOST_ARCH" "$RESET"
else
	reported=$("$host_artifact" --version) || die "$(basename "$host_artifact") --version failed"
	printf '    %s  %-14s %s%s%s\n' "$(ok)" "$HOST_OS/$HOST_ARCH" "$DIM" "$reported" "$RESET"
	# -X is silently ignored when the variable it names has moved, so the
	# binary itself has to confirm the version these files are named after.
	case "$reported" in
	*"$APP $VERSION "*) ;;
	*) die "built as $VERSION, but the binary reports: $reported" ;;
	esac
fi

total=0
for name in "${built[@]}"; do total=$(( total + $(size_of "$DIST/$name") )); done

printf '\n'
rule
if [ "${#failed[@]}" -eq 0 ]; then
	printf '  %s%sdone%s  %d/%d targets, %s total, %ss\n' "$BOLD" "$GREEN" "$RESET" \
		"${#built[@]}" "${#TARGETS[@]}" "$(human "$total")" "$(secs $(( $(now_ms) - started )) )"
	printf '  %sthis script checks nothing but --version; for the tests run: go run ./tools/gate%s\n\n' "$DIM" "$RESET"
else
	printf '  %s%sfailed%s  %d of %d targets: %s\n\n' "$BOLD" "$RED" "$RESET" \
		"${#failed[@]}" "${#TARGETS[@]}" "${failed[*]}"
	exit 1
fi
