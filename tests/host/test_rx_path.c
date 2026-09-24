/* Phase 1.5 host regression tests: rx_path RX front-end core (production
 * code) driven through the mock queue environment.
 *
 * Ownership contract under test:
 *   free pool -> (callback holds exactly one slot) -> rx queue -> consumer
 *   -> release -> free pool.  A slot is never leaked (rx_state errors,
 *   pool-empty, enqueue-failure paths) and never returned twice.  At rest
 *   all RADIO_PACKET_POOL_SIZE slots are back in the free pool; at any
 *   time free + queued + in-flight == RADIO_PACKET_POOL_SIZE.
 */
#include "rx_path.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mock_io.h"
#include "runner.h"

static uint8_t g_payload[64];

static void t_good_frame_flow(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};
    rx_frame_view_t v = mock_view_mgmt_clean(g_payload, sizeof(g_payload));
    v.rx_timestamp_us = UINT64_C(0x100000123); /* injected monotonic clock */
    rx_path_on_frame(&g_mock_io_ops, &st, &v);

    CHECK(st.rx_total == 1);
    CHECK(st.rx_queued == 1);
    CHECK(st.rx_state_errors == 0);
    CHECK(mock_queued_count(&m) == 1);
    CHECK(mock_free_count(&m) == RADIO_PACKET_POOL_SIZE - 1);
    CHECK(st.rx_total == st.rx_state_errors + st.rx_misc +
                             st.rx_dropped_pool + st.rx_dropped_queue +
                             st.rx_queued);

    /* Consumer: pop, inspect, release. */
    radio_packet_t *pkt = NULL;
    CHECK(mock_rx_pop(&m, &pkt));
    CHECK(pkt->length == sizeof(g_payload));
    CHECK(pkt->orig_length == sizeof(g_payload));
    CHECK(pkt->channel == 6);
    CHECK(pkt->rssi == -50);
    CHECK(pkt->rx_timestamp_us == UINT64_C(0x100000123));
    CHECK(memcmp(pkt->data, g_payload, sizeof(g_payload)) == 0);

    rx_capture_view_t capture;
    CHECK(rx_path_make_capture_view(pkt, &capture));
    CHECK(capture.mac_bytes == pkt->data);
    CHECK(capture.captured_mac_length == sizeof(g_payload) - 4);
    CHECK(capture.original_mac_length == sizeof(g_payload) - 4);
    CHECK(capture.original_mac_length_valid);
    CHECK(capture.rx_timestamp_us == UINT64_C(0x100000123));
    CHECK(capture.rx_channel == 6 && capture.rssi == -50);
    CHECK(capture.fcs_policy ==
          RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW);
    CHECK(!capture.capture_truncated);

    rx_path_slot_release(&g_mock_io_ops, &st, pkt);
    CHECK(st.rx_processed == 1);
    CHECK(mock_all_free(&m));
}

/* The callback-provided clock value survives arbitrary queue residence,
 * including a value beyond UINT32_MAX, and a recycled pool slot receives
 * the next frame's independent timestamp. */
static void t_timestamp_copy_delay_and_slot_reuse(void)
{
    mock_io_t m;
    mock_init(&m);
    rx_path_stats_t st = {0};

    rx_frame_view_t v = mock_view_mgmt_clean(g_payload, sizeof(g_payload));
    v.rx_timestamp_us = UINT64_C(0x100000123);
    rx_path_on_frame(&g_mock_io_ops, &st, &v);
    const uint64_t callback_time = v.rx_timestamp_us;
    /* Simulate time advancing before the consumer dequeues this packet. */
    v.rx_timestamp_us = UINT64_C(0x200000456);

    radio_packet_t *first = NULL;
    CHECK(mock_rx_pop(&m, &first));
    const int first_slot = mock_slot_index(&m, first);
    CHECK(first_slot >= 0);
    CHECK(first->rx_timestamp_us == callback_time);
    rx_path_slot_release(&g_mock_io_ops, &st, first);
    CHECK(mock_all_free(&m));

    v.rx_timestamp_us = UINT64_C(0x100000000); /* > 32-bit microseconds */
    rx_path_on_frame(&g_mock_io_ops, &st, &v);
    radio_packet_t *second = NULL;
    CHECK(mock_rx_pop(&m, &second));
    CHECK(mock_slot_index(&m, second) == first_slot); /* same reused slot */
    CHECK(second->rx_timestamp_us == UINT64_C(0x100000000));
    rx_path_slot_release(&g_mock_io_ops, &st, second);
    CHECK(mock_all_free(&m));
    CHECK(mock_free_count(&m) == RADIO_PACKET_POOL_SIZE);
    CHECK(mock_queued_count(&m) == 0);
    CHECK(mock_inflight_count(&m) == 0);
    CHECK(st.rx_queued == 2 && st.rx_processed == 2);
}

static void t_packet_pool_memory_budget(void)
{
    CHECK(offsetof(radio_packet_t, data) == 7);
    CHECK(offsetof(radio_packet_t, rx_timestamp_us) == 520);
    CHECK(sizeof(radio_packet_t) == 528);
    CHECK(sizeof(radio_packet_t) * RADIO_PACKET_POOL_SIZE == 12672);
}

static void t_drop_accounting(void)
{
    mock_io_t m;
    mock_init(&m);
    mock_set_rx_capacity(&m, 1);

    rx_path_stats_t st = {0};

    /* Injected alloc failure: counted, no slot touched. */
    m.fail_next_alloc = true;
    rx_frame_view_t v = mock_view_mgmt_clean(g_payload, 16);
    rx_path_on_frame(&g_mock_io_ops, &st, &v);
    CHECK(st.rx_dropped_pool == 1);
    CHECK(mock_all_free(&m));

    /* Queue full: slot allocated, returned, counted. */
    rx_path_on_frame(&g_mock_io_ops, &st, &v); /* fills the queue */
    rx_path_on_frame(&g_mock_io_ops, &st, &v); /* queue full */
    CHECK(st.rx_dropped_queue == 1);
    CHECK(st.rx_queued == 1);
    CHECK(mock_queued_count(&m) == 1);
    CHECK(mock_free_count(&m) == RADIO_PACKET_POOL_SIZE - 1);
    CHECK(m.double_returns == 0);

    /* Accounting identity. */
    CHECK(st.rx_total == st.rx_state_errors + st.rx_misc +
                             st.rx_dropped_pool + st.rx_dropped_queue +
                             st.rx_queued);

    /* Drain. */
    radio_packet_t *pkt = NULL;
    while (mock_rx_pop(&m, &pkt)) {
        rx_path_slot_release(&g_mock_io_ops, &st, pkt);
    }
    CHECK(mock_all_free(&m));
}

/* Phase 1.5 issue 1: error frames (rx_state != 0) must not take a slot at
 * all; more error frames than pool slots must not exhaust the pool. */
static void t_state_errors_never_leak_slots(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    rx_frame_view_t err = mock_view_mgmt_clean(g_payload, 32);
    err.rx_state = 7; /* driver-reported error (non-zero, non-public) */

    /* More error frames than pool slots: every one is counted and none
     * may leak a slot. */
    for (int i = 0; i < RADIO_PACKET_POOL_SIZE + 6; i++) {
        rx_path_on_frame(&g_mock_io_ops, &st, &err);
    }
    CHECK(st.rx_total == (uint32_t)(RADIO_PACKET_POOL_SIZE + 6));
    CHECK(st.rx_state_errors == (uint32_t)(RADIO_PACKET_POOL_SIZE + 6));
    CHECK(st.rx_queued == 0);
    CHECK(mock_free_count(&m) == RADIO_PACKET_POOL_SIZE);
    CHECK(mock_all_free(&m));

    /* Normal frames are still processed after the error storm. */
    rx_frame_view_t good = mock_view_mgmt_clean(g_payload, 32);
    rx_path_on_frame(&g_mock_io_ops, &st, &good);
    CHECK(st.rx_queued == 1);

    radio_packet_t *pkt = NULL;
    CHECK(mock_rx_pop(&m, &pkt));
    CHECK(pkt->length == 32);
    rx_path_slot_release(&g_mock_io_ops, &st, pkt);
    CHECK(mock_all_free(&m));

    /* Identity still holds. */
    CHECK(st.rx_total == st.rx_state_errors + st.rx_misc +
                             st.rx_dropped_pool + st.rx_dropped_queue +
                             st.rx_queued);
}

/* Phase 1.5 issue 2: MISC frames are counted and returned WITHOUT any
 * payload access and without parser/queue work, even when the driver
 * reports a non-zero sig_len for them (its payload is zero length per the
 * IDF v5.4 contract; a defensive core must not trust the length). */
static void t_misc_whitelist_no_payload_access(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    /* Adapter-contract view: MISC with sig_len > 0 but payload_len == 0
     * (the adapter must not vouch for MISC payload bytes). */
    uint8_t sentinel[64];
    memset(sentinel, 0xA5, sizeof(sentinel));
    rx_frame_view_t misc = mock_view_mgmt_clean(sentinel, 0);
    misc.type = 3; /* WIFI_PKT_MISC */
    misc.sig_len = 100;
    misc.payload = sentinel;
    misc.payload_len = 0;

    rx_path_on_frame(&g_mock_io_ops, &st, &misc);

    CHECK(st.rx_total == 1);
    CHECK(st.rx_misc == 1);
    CHECK(st.rx_queued == 0);
    CHECK(mock_queued_count(&m) == 0);
    CHECK(mock_all_free(&m));
    /* Accounting: the MISC frame must not vanish from the totals. */
    CHECK(st.rx_total == st.rx_state_errors + st.rx_misc +
                             st.rx_dropped_pool + st.rx_dropped_queue +
                             st.rx_queued);
}

/* Phase 1.5 issue 2 (defense in depth): even if a buggy adapter passes a
 * payload_len for MISC, the core must refuse to read it. */
static void t_misc_defensive_even_with_bogus_payload_len(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    /* Adapter-contract view: MISC with sig_len > 0 but payload_len == 0
     * (the adapter must not vouch for MISC payload bytes). The sentinel
     * backs the whole bogus length so a pre-fix core reads in-bounds and
     * the test fails on assertions, not on memory safety. */
    static uint8_t sentinel[128];
    memset(sentinel, 0xA5, sizeof(sentinel));
    rx_frame_view_t misc = mock_view_mgmt_clean(sentinel, 0);
    misc.type = 3; /* WIFI_PKT_MISC */
    misc.sig_len = 100;
    misc.payload = sentinel;
    misc.payload_len = 100; /* bogus: MISC payload is zero length */

    rx_path_on_frame(&g_mock_io_ops, &st, &misc);

    CHECK(st.rx_misc == 1);
    CHECK(st.rx_queued == 0);
    CHECK(mock_all_free(&m));
}

/* Whitelisted frame with zero payload: counted, queued, metadata only. */
static void t_zero_payload_mgmt_queued_and_counted(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    rx_frame_view_t v = mock_view_mgmt_clean(NULL, 0);
    v.sig_len = 0;

    rx_path_on_frame(&g_mock_io_ops, &st, &v);
    CHECK(st.rx_total == 1);
    CHECK(st.rx_no_payload == 1);
    CHECK(st.rx_queued == 1);

    radio_packet_t *pkt = NULL;
    CHECK(mock_rx_pop(&m, &pkt));
    CHECK(pkt->length == 0);
    rx_path_slot_release(&g_mock_io_ops, &st, pkt);
    CHECK(mock_all_free(&m));
}

/* Oversized frame: copied at the 512-byte bound and counted truncated. */
static void t_oversized_truncated_at_bound(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    static uint8_t big[600];
    memset(big, 0x77, sizeof(big));
    rx_frame_view_t v = mock_view_mgmt_clean(big, sizeof(big));

    rx_path_on_frame(&g_mock_io_ops, &st, &v);
    CHECK(st.rx_queued == 1);
    CHECK(st.rx_truncated == 1);

    radio_packet_t *pkt = NULL;
    CHECK(mock_rx_pop(&m, &pkt));
    CHECK(pkt->length == RADIO_PACKET_MAX_LEN);
    CHECK(pkt->orig_length == sizeof(big));
    rx_path_slot_release(&g_mock_io_ops, &st, pkt);
    CHECK(mock_all_free(&m));
}

/* rx_path_parse_length: min(captured, orig - 4) with underflow guard;
 * the FCS must never enter the parse window, in the complete-frame case
 * nor in the partially-captured-FCS case. */
static void t_parse_length_contract(void)
{
    radio_packet_t p = {0};

    /* orig 0..4: no FCS assumption, no underflow. */
    p.length = 0; p.orig_length = 0;
    CHECK(rx_path_parse_length(&p) == 0);
    p.length = 2; p.orig_length = 2;
    CHECK(rx_path_parse_length(&p) == 2);
    p.length = 3; p.orig_length = 3;
    CHECK(rx_path_parse_length(&p) == 3);
    p.length = 4; p.orig_length = 4;
    CHECK(rx_path_parse_length(&p) == 0);

    /* Complete copy: exactly the FCS removed. */
    p.length = 511; p.orig_length = 511;
    CHECK(rx_path_parse_length(&p) == 507);
    p.length = 512; p.orig_length = 512;
    CHECK(rx_path_parse_length(&p) == 508);

    /* Copy bound: 513-byte frame stored as 512 -> 3 partial FCS bytes at
     * the tail must be excluded (parse window 509). */
    p.length = 512; p.orig_length = 513;
    CHECK(rx_path_parse_length(&p) == 509);

    /* 514-byte frame stored as 512 -> 2 partial FCS bytes excluded. */
    p.length = 512; p.orig_length = 514;
    CHECK(rx_path_parse_length(&p) == 510);

    /* 513-byte copy bound: 600-byte frame stored as 512, capture deep in
     * the MAC body -> full copy is the window. */
    p.length = 512; p.orig_length = 600;
    CHECK(rx_path_parse_length(&p) == 512);

    CHECK(rx_path_parse_length(NULL) == 0);
}

static void t_capture_view_fcs_and_body_truncation(void)
{
    radio_packet_t p = {0};
    rx_capture_view_t v;

    /* Original lengths below an FCS cannot be decremented into a bogus
     * uint16_t MAC length. */
    p.length = 3;
    p.orig_length = 3;
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == 3);
    CHECK(!v.original_mac_length_valid);
    CHECK(v.original_mac_length == 0);
    CHECK(!v.capture_truncated);

    p.length = 4;
    p.orig_length = 4;
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == 0);
    CHECK(v.original_mac_length_valid && v.original_mac_length == 0);
    CHECK(!v.capture_truncated); /* only FCS, no MAC bytes */

    p.length = 511;
    p.orig_length = 511;
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == 507);
    CHECK(v.original_mac_length == 507);
    CHECK(!v.capture_truncated);

    p.length = 512;
    p.orig_length = 512;
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == 508);
    CHECK(v.original_mac_length == 508);
    CHECK(!v.capture_truncated);

    p.length = 512;
    p.orig_length = 513; /* only one FCS byte was missed */
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == 509);
    CHECK(v.original_mac_length == 509);
    CHECK(!v.capture_truncated);

    p.orig_length = 514; /* two FCS bytes missed */
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == 510);
    CHECK(v.original_mac_length == 510);
    CHECK(!v.capture_truncated);

    p.orig_length = 600; /* capture ends in the MAC body */
    CHECK(rx_path_make_capture_view(&p, &v));
    CHECK(v.captured_mac_length == RADIO_PACKET_MAX_LEN);
    CHECK(v.original_mac_length == 596);
    CHECK(v.capture_truncated);
}

int main(void)
{
    test_register("rx_good_frame_flow", t_good_frame_flow);
    test_register("rx_timestamp_copy_delay_and_slot_reuse",
                  t_timestamp_copy_delay_and_slot_reuse);
    test_register("rx_packet_pool_memory_budget", t_packet_pool_memory_budget);
    test_register("rx_drop_accounting", t_drop_accounting);
    test_register("rx_state_errors_never_leak_slots",
                  t_state_errors_never_leak_slots);
    test_register("rx_misc_whitelist_no_payload_access",
                  t_misc_whitelist_no_payload_access);
    test_register("rx_misc_defensive_even_with_bogus_payload_len",
                  t_misc_defensive_even_with_bogus_payload_len);
    test_register("rx_zero_payload_mgmt_queued_and_counted",
                  t_zero_payload_mgmt_queued_and_counted);
    test_register("rx_oversized_truncated_at_bound",
                  t_oversized_truncated_at_bound);
    test_register("rx_parse_length_contract", t_parse_length_contract);
    test_register("rx_capture_view_fcs_and_body_truncation",
                  t_capture_view_fcs_and_body_truncation);
    return test_run_all();
}
