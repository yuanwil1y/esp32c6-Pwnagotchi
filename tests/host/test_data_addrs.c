/* Phase 2B host regression tests: data frame address extraction
 * (production parser code). Covers the four DS combinations, header
 * length math (QoS / four-address / HT control), bounds checks and
 * protocol guards. */
#include "ieee80211_parser.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

/* ---------------- frame builder ---------------- */

typedef struct {
    uint8_t buf[64];
    uint16_t len;
} data_frame_t;

/* Data frame with the given FC bytes; addresses filled with distinct,
 * recognizable patterns: addr1=0xA1.., addr2=0xB2.., addr3=0xC3..,
 * addr4=0xD4... */
static void data_init(data_frame_t *f, uint8_t fc0, uint8_t fc1,
                      uint16_t len)
{
    memset(f, 0, sizeof(*f));
    f->buf[0] = fc0;
    f->buf[1] = fc1;
    f->buf[2] = 0x3C; /* duration */
    for (int i = 0; i < 6; i++) {
        f->buf[IEEE80211_DATA_ADDR1_OFF + i] = (uint8_t)(0xA0 + i + 0x10);
        f->buf[IEEE80211_DATA_ADDR2_OFF + i] = (uint8_t)(0xB0 + i + 0x10);
        f->buf[IEEE80211_DATA_ADDR3_OFF + i] = (uint8_t)(0xC0 + i + 0x10);
        f->buf[IEEE80211_DATA_ADDR4_OFF + i] = (uint8_t)(0xD0 + i + 0x10);
    }
    f->buf[22] = 0x10; /* sequence */
    f->len = len;
}

static void t_four_ds_combinations(void)
{
    ieee80211_data_addrs_t a;

    /* ToDS=1 FromDS=0: OK. */
    data_frame_t f;
    data_init(&f, 0x08, 0x01, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_OK);
    CHECK(a.to_ds && !a.from_ds);
    CHECK(a.header_len == 24);
    CHECK(a.addr1[0] == 0xB0 && a.addr1[5] == 0xB5); /* 0xA0 + i + 0x10 */
    CHECK(a.addr2[0] == 0xC0);
    CHECK(a.addr3[0] == 0xD0);
    static const uint8_t zero[6] = {0};
    CHECK(memcmp(a.addr4, zero, 6) == 0); /* no addr4 without WDS */

    /* ToDS=0 FromDS=1: OK. */
    data_init(&f, 0x08, 0x02, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_OK);
    CHECK(!a.to_ds && a.from_ds);

    /* ToDS=0 FromDS=0: AMBIGUOUS (IBSS / direct), addresses still valid. */
    data_init(&f, 0x08, 0x00, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_AMBIGUOUS);

    /* ToDS=1 FromDS=1: WDS, four addresses present. */
    data_init(&f, 0x08, 0x03, 30);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_WDS);
    CHECK(a.four_addr);
    CHECK(a.header_len == 30);
    CHECK(a.addr4[0] == 0xE0);
}

static void t_header_length_math(void)
{
    ieee80211_data_addrs_t a;
    data_frame_t f;

    /* Plain data: 24. */
    data_init(&f, 0x08, 0x01, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.header_len == 24);

    /* QoS Data (subtype 8): 24 + 2. */
    data_init(&f, 0x88, 0x01, 26);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.qos && a.header_len == 26);

    /* QoS Null (subtype 12): still QoS. */
    data_init(&f, 0xC8, 0x01, 26);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.qos && a.header_len == 26);

    /* Null (subtype 4): no QoS. */
    data_init(&f, 0x48, 0x02, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(!a.qos && a.header_len == 24);

    /* Strictly ordered non-QoS data does not carry HT Control. */
    data_init(&f, 0x08, 0x81, 28);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.header_len == 24);

    data_init(&f, 0x08, 0x81, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.header_len == 24);

    /* Four address + QoS: 24 + 6 + 2. */
    data_init(&f, 0x88, 0x03, 32);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.header_len == 32);

    /* Four address + QoS + order: 24 + 6 + 2 + 4. */
    data_init(&f, 0x88, 0x83, 36);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.header_len == 36);
}

static void t_short_headers_rejected(void)
{
    ieee80211_data_addrs_t a;
    data_frame_t f;

    /* One byte short of the base header. */
    data_init(&f, 0x08, 0x01, 23);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_TOO_SHORT);

    /* WDS header cut inside addr4. */
    data_init(&f, 0x08, 0x03, 29);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_TOO_SHORT);

    /* QoS header cut. */
    data_init(&f, 0x88, 0x01, 25);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_TOO_SHORT);

    /* QoS+HT control cut. */
    data_init(&f, 0x88, 0x81, 29);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_TOO_SHORT);

    /* Degenerate lengths. */
    data_init(&f, 0x08, 0x01, 2);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    data_init(&f, 0x08, 0x01, 0);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(!ieee80211_parse_data_addresses(NULL, 24, &a));
}

static void t_protocol_guards(void)
{
    ieee80211_data_addrs_t a;
    data_frame_t f;

    /* Nonzero protocol version. */
    data_init(&f, 0x09, 0x01, 24);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_BAD_PROTOCOL);

    /* Management frame must be refused by the data parser. */
    data_init(&f, 0x80, 0x00, 24);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_BAD_PROTOCOL);

    /* Control frame likewise. */
    data_init(&f, 0xB4, 0x00, 24);
    CHECK(!ieee80211_parse_data_addresses(f.buf, f.len, &a));
}

static void t_protected_frame_header_visible(void)
{
    ieee80211_data_addrs_t a;
    data_frame_t f;

    /* Protected bit only affects the (encrypted) body: the MAC header
     * stays parseable and mappable. */
    data_init(&f, 0x08, 0x41, 24);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_OK);
    CHECK(a.protected_frame);

    data_init(&f, 0x88, 0x43, 32);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_WDS);
    CHECK(a.protected_frame && a.qos && a.four_addr);
}

static void t_broadcast_multicast_parsed_but_unfiltered(void)
{
    ieee80211_data_addrs_t a;
    data_frame_t f;

    /* Broadcast destination: the parser reports it verbatim; filtering
     * is the world's job (regression guard for layer separation). */
    data_init(&f, 0x08, 0x02, 24);
    memset(&f.buf[IEEE80211_DATA_ADDR1_OFF], 0xFF, 6);
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_OK);
    for (int i = 0; i < 6; i++) {
        CHECK(a.addr1[i] == 0xFF);
    }

    /* Multicast (I/G bit) destination. */
    data_init(&f, 0x08, 0x02, 24);
    f.buf[IEEE80211_DATA_ADDR1_OFF] = 0x01;
    f.buf[IEEE80211_DATA_ADDR1_OFF + 5] = 0x05;
    CHECK(ieee80211_parse_data_addresses(f.buf, f.len, &a));
    CHECK(a.status == IEEE80211_DATA_ADDRS_OK);
    CHECK(a.addr1[0] == 0x01);
}

int main(void)
{
    test_register("data_addrs_four_ds_combinations", t_four_ds_combinations);
    test_register("data_addrs_header_length_math", t_header_length_math);
    test_register("data_addrs_short_headers_rejected", t_short_headers_rejected);
    test_register("data_addrs_protocol_guards", t_protocol_guards);
    test_register("data_addrs_protected_frame_header_visible", t_protected_frame_header_visible);
    test_register("data_addrs_broadcast_multicast_parsed_but_unfiltered", t_broadcast_multicast_parsed_but_unfiltered);
    return test_run_all();
}
