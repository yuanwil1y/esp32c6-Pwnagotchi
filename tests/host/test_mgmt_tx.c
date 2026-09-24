/* Regression tests for direction-safe client management observations. */
#include "ieee80211_parser.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

static const uint8_t BSSID[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t STA[6] = {0x52, 0x60, 0x70, 0x80, 0x90, 0x01};

static uint16_t put_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    return 2;
}

static void make_mgmt(uint8_t *frame, uint8_t subtype,
                      const uint8_t receiver[6], const uint8_t transmitter[6],
                      const uint8_t bssid[6], uint16_t body_len)
{
    memset(frame, 0, 64);
    frame[0] = (uint8_t)(subtype << 4);
    memcpy(&frame[4], receiver, 6);
    memcpy(&frame[10], transmitter, 6);
    memcpy(&frame[16], bssid, 6);
    (void)body_len;
}

static void t_auth_request_vs_ap_response(void)
{
    uint8_t frame[64];
    uint8_t source[6] = {0};

    make_mgmt(frame, IEEE80211_MGMT_AUTH, BSSID, STA, BSSID, 6);
    put_le16(&frame[24], 3); /* auth algorithm */
    put_le16(&frame[26], 2); /* no parity-based direction assumption */
    put_le16(&frame[28], 0); /* successful request status */
    CHECK(ieee80211_parse_client_mgmt_tx(frame, 30, source));
    CHECK(memcmp(source, STA, 6) == 0);

    /* An AP authentication response has the AP as transmitter. */
    make_mgmt(frame, IEEE80211_MGMT_AUTH, STA, BSSID, BSSID, 6);
    put_le16(&frame[24], 3);
    put_le16(&frame[26], 3);
    put_le16(&frame[28], 0);
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
}

static void t_auth_fixed_body_and_request_status(void)
{
    uint8_t frame[64];
    uint8_t source[6] = {0};
    make_mgmt(frame, IEEE80211_MGMT_AUTH, BSSID, STA, BSSID, 6);
    put_le16(&frame[24], 0);
    put_le16(&frame[26], 1);
    put_le16(&frame[28], 1); /* failure status cannot be a client request */
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 29, source));
    put_le16(&frame[28], 0);
    put_le16(&frame[26], 0);
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
}

static void t_assoc_request_and_response(void)
{
    uint8_t frame[64];
    uint8_t source[6] = {0};

    make_mgmt(frame, IEEE80211_MGMT_ASSOC_REQ, BSSID, STA, BSSID, 4);
    CHECK(ieee80211_parse_client_mgmt_tx(frame, 28, source));
    CHECK(memcmp(source, STA, 6) == 0);
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 27, source));

    make_mgmt(frame, IEEE80211_MGMT_ASSOC_RESP, STA, BSSID, BSSID, 6);
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));

    make_mgmt(frame, IEEE80211_MGMT_REASSOC_REQ, BSSID, STA, BSSID, 10);
    CHECK(ieee80211_parse_client_mgmt_tx(frame, 34, source));
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 33, source));
}

static void t_invalid_or_ambiguous_headers_rejected(void)
{
    uint8_t frame[64];
    uint8_t source[6] = {0};
    make_mgmt(frame, IEEE80211_MGMT_AUTH, BSSID, STA, BSSID, 6);
    put_le16(&frame[26], 1);

    frame[0] |= 0x01; /* nonzero protocol version */
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
    frame[0] &= (uint8_t)~0x01;

    frame[1] |= 0x01; /* ToDS */
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
    frame[1] &= (uint8_t)~0x01;

    frame[1] |= 0x40; /* protected */
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
    frame[1] &= (uint8_t)~0x40;

    frame[1] |= 0x04; /* More Fragments */
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
    frame[1] &= (uint8_t)~0x04;

    frame[16] ^= 0x02; /* addr3 not the receiver BSSID */
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, source));
    CHECK(!ieee80211_parse_client_mgmt_tx(frame, 30, NULL));
    CHECK(!ieee80211_parse_client_mgmt_tx(NULL, 30, source));
}

int main(void)
{
    test_register("mgmt_auth_request_vs_ap_response", t_auth_request_vs_ap_response);
    test_register("mgmt_auth_fixed_body_and_status", t_auth_fixed_body_and_request_status);
    test_register("mgmt_assoc_request_and_response", t_assoc_request_and_response);
    test_register("mgmt_invalid_or_ambiguous_rejected", t_invalid_or_ambiguous_headers_rejected);
    return test_run_all();
}
