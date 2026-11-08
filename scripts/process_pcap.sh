#!/usr/bin/env bash
# Process one existing capture without modifying raw input or previous logs.
set -euo pipefail

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 1 ]]; then
    printf 'Usage: %s data/raw/pcap/sample.pcap\n' "$0" >&2
    exit 2
fi

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
raw_dir=$(realpath -e -- "$project_root/data/raw/pcap")
input=$(realpath -e -- "$1") || fail "Input does not exist: $1"
[[ -f "$input" && -r "$input" && -s "$input" ]] || fail "Input must be a readable, non-empty file."
[[ "$input" == "$raw_dir/"* ]] || fail "Input must be inside $raw_dir (including resolved symlinks)."
command -v docker >/dev/null || fail "Docker is required."

# Official Zeek LTS image, verified as Zeek 9.0.1; digest prevents tag drift.
image=${ZEEK_IMAGE:-zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0}
docker info >/dev/null || fail "Cannot access the Docker daemon."
mkdir -p -- "$project_root/data/zeek"
output=$(mktemp -d "$project_root/data/zeek/run-XXXXXXXX")
printf 'Zeek output directory: %s\n' "$output"

if ! docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,source=$input,target=/input/capture.pcap,readonly" \
    --mount "type=bind,source=$output,target=/output" \
    --workdir /output \
    "$image" zeek -r /input/capture.pcap LogAscii::use_json=T; then
    fail "Zeek processing failed; any partial output remains in $output."
fi

if [[ -s "$output/dns.log" ]]; then
    printf 'DNS JSON log: %s/dns.log\n' "$output"
else
    printf 'Zeek completed, but no non-empty dns.log was produced.\n' >&2
    printf 'Check that the capture contains complete, readable plaintext DNS traffic with valid checksums.\n' >&2
fi
