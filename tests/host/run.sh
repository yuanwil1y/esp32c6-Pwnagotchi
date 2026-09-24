#!/usr/bin/env bash
# Phase 1.5 host regression tests: compile the PRODUCTION radio sources
# (ieee80211_parser.c, rx_path.c, obs_cache.c, hopper_policy.c) directly
# against small mock environments and run every test binary, plain and
# under ASan+UBSan. No test re-implements production logic.
#
# A crashing binary does not mask the others: every binary runs, the
# failed ones are collected, and the script exits non-zero at the end.
set -uo pipefail
cd "$(dirname "$0")"

CC=${CC:-cc}
CFLAGS="-std=c11 -Wall -Wextra -Werror -O1 -g"
INC="-I../../components/radio/include -I../../components/world/include -I."
PROD="../../components/radio/ieee80211_parser.c ../../components/radio/rx_path.c ../../components/radio/obs_cache.c ../../components/radio/hopper_policy.c ../../components/world/world.c"
COMMON="runner.c mock_io.c"
SUITES="test_parser test_rx_path test_rx_hostile test_obs_cache test_hopper test_world"

mkdir -p build

overall=0

run_suite() {
    local tag=$1 extra=$2
    for t in $SUITES; do
        # shellcheck disable=SC2086
        if ! "$CC" $CFLAGS $extra $INC -o "build/${t}_${tag}" \
                "${t}.c" $COMMON $PROD; then
            echo "BUILD FAILED: ${t} (${tag})"
            overall=1
            continue
        fi
        if "./build/${t}_${tag}"; then
            :
        else
            echo "SUITE FAILED: ${t} (${tag})"
            overall=1
        fi
    done
}

echo "== host tests (plain) =="
run_suite plain ""

echo "== host tests (ASan+UBSan) =="
run_suite asan "-fsanitize=address,undefined -fno-sanitize-recover=all"

if [ "$overall" -ne 0 ]; then
    echo "HOST TESTS FAILED"
    exit 1
fi
echo "ALL HOST TESTS PASSED"
