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
    CHECK(memcmp(pkt->data, g_payload, sizeof(g_payload)) == 0);

    rx_path_slot_release(&g_mock_io_ops, &st, pkt);
    CHECK(st.rx_processed == 1);
    CHECK(mock_all_free(&m));
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

int main(void)
{
    test_register("rx_good_frame_flow", t_good_frame_flow);
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
    return test_run_all();
}
