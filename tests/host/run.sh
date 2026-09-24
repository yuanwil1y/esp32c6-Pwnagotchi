#!/usr/bin/env bash
# Phase 1.5 host regression tests: compile the PRODUCTION radio sources
# (ieee80211_parser.c, rx_path.c, eapol_parser.c, pcap_serializer.c,
#  obs_cache.c,
#  hopper_policy.c) directly
# against small mock environments and run every test binary, plain and
# under ASan+UBSan. No test re-implements production logic.
#
# A crashing binary does not mask the others: every binary runs, the
# failed ones are collected, and the script exits non-zero at the end.
set -uo pipefail
cd "$(dirname "$0")"

CC=${CC:-cc}
CFLAGS="-std=c11 -Wall -Wextra -Werror -O1 -g"
INC="-I../../components/radio/include -I../../components/world/include -I../../components/storage/include -I."
PROD="../../components/radio/ieee80211_parser.c ../../components/radio/rx_path.c ../../components/radio/eapol_parser.c ../../components/radio/pcap_serializer.c ../../components/radio/obs_cache.c ../../components/radio/hopper_policy.c ../../components/world/world.c ../../components/storage/sd_logger_core.c ../../components/storage/capture_serial_protocol.c"
COMMON="runner.c mock_io.c"
SUITES="test_parser test_rx_path test_rx_hostile test_obs_cache test_hopper test_world test_data_addrs test_world_sta test_security test_mgmt_tx test_eapol test_pcap test_sd_logger test_capture_serial_protocol"

mkdir -p build

overall=0

run_suite() {
    local tag=$1 extra=$2
    for t in $SUITES; do
        local suite_defs=""
        if [ "$t" = "test_sd_logger" ]; then
            suite_defs="-pthread -DSD_LOGGER_MAX_FILE_BYTES=2048 -DSD_LOGGER_SESSION_MAX_BYTES=8192 -DSD_LOGGER_MAX_FILE_AGE_US=1000000"
        fi
        # shellcheck disable=SC2086
        if ! "$CC" $CFLAGS $extra $suite_defs $INC -o "build/${t}_${tag}" \
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

echo "== capture export host protocol tests =="
python3 test_capture_serial_export.py || overall=1

if [ "$overall" -ne 0 ]; then
    echo "HOST TESTS FAILED"
    exit 1
fi
echo "ALL HOST TESTS PASSED"
