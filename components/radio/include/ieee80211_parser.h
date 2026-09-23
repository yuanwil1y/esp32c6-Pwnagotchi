#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * Phase 1B 802.11 Frame Control classification.
 *
 * Pure functions over raw frame bytes: no globals, no allocation, no logging.
 * The caller (radio_rx_task, a normal FreeRTOS task) owns all counters.
 * Never called from the promiscuous RX callback.
 */

/* Bit masks over the 16-bit Frame Control assembled little-endian. */
#define IEEE80211_FC_PROTOCOL_MASK     0x0003
#define IEEE80211_FC_TYPE_MASK         0x000C
#define IEEE80211_FC_SUBTYPE_MASK      0x00F0
#define IEEE80211_FC_TODS_MASK         0x0100
#define IEEE80211_FC_FROMDS_MASK       0x0200
#define IEEE80211_FC_MOREFRAG_MASK     0x0400
#define IEEE80211_FC_RETRY_MASK        0x0800
#define IEEE80211_FC_PWRMGT_MASK       0x1000
#define IEEE80211_FC_MOREDATA_MASK     0x2000
#define IEEE80211_FC_PROTECTED_MASK    0x4000
#define IEEE80211_FC_ORDER_MASK        0x8000

#define IEEE80211_FC_TYPE_SHIFT        2
#define IEEE80211_FC_SUBTYPE_SHIFT     4

/* Raw 2-bit Frame Control type values (independent of the enum above). */
#define IEEE80211_FC_TYPE_VALUE_MGMT   0
#define IEEE80211_FC_TYPE_VALUE_CTRL   1
#define IEEE80211_FC_TYPE_VALUE_DATA   2
#define IEEE80211_FC_TYPE_VALUE_EXT    3

typedef enum {
    IEEE80211_TYPE_MGMT,
    IEEE80211_TYPE_CTRL,
    IEEE80211_TYPE_DATA,
    IEEE80211_TYPE_EXT,
    IEEE80211_TYPE_UNKNOWN,
} ieee80211_frame_type_t;

/* Subtype nibble values as shifted out of the Frame Control. */

/* Management (type 0). */
enum {
    IEEE80211_MGMT_ASSOC_REQ     = 0,
    IEEE80211_MGMT_ASSOC_RESP    = 1,
    IEEE80211_MGMT_REASSOC_REQ   = 2,
    IEEE80211_MGMT_REASSOC_RESP  = 3,
    IEEE80211_MGMT_PROBE_REQ     = 4,
    IEEE80211_MGMT_PROBE_RESP    = 5,
    IEEE80211_MGMT_BEACON        = 8,
    IEEE80211_MGMT_ATIM          = 9,
    IEEE80211_MGMT_DISASSOC      = 10,
    IEEE80211_MGMT_AUTH          = 11,
    IEEE80211_MGMT_DEAUTH        = 12,
    IEEE80211_MGMT_ACTION        = 13,
    IEEE80211_MGMT_ACTION_NO_ACK = 14,
};

/* Control (type 1), 802.11-2007 and later subtype layout. */
enum {
    IEEE80211_CTRL_BAR        = 8,
    IEEE80211_CTRL_BA         = 9,
    IEEE80211_CTRL_PS_POLL    = 10,
    IEEE80211_CTRL_RTS        = 11,
    IEEE80211_CTRL_CTS        = 12,
    IEEE80211_CTRL_ACK        = 13,
    IEEE80211_CTRL_CF_END     = 14,
    IEEE80211_CTRL_CF_END_ACK = 15,
};

/* Data (type 2). */
enum {
    IEEE80211_DATA_DATA             = 0,
    IEEE80211_DATA_DATA_CFACK       = 1,
    IEEE80211_DATA_DATA_CFPOLL      = 2,
    IEEE80211_DATA_DATA_CFACK_CFPOLL= 3,
    IEEE80211_DATA_NULL             = 4,
    IEEE80211_DATA_CFACK            = 5,
    IEEE80211_DATA_CFPOLL           = 6,
    IEEE80211_DATA_CFACK_CFPOLL     = 7,
    IEEE80211_DATA_QOS_DATA         = 8,
    IEEE80211_DATA_QOS_DATA_CFACK   = 9,
    IEEE80211_DATA_QOS_DATA_CFPOLL  = 10,
    IEEE80211_DATA_QOS_DATA_CFACK_CFPOLL = 11,
    IEEE80211_DATA_QOS_NULL         = 12,
};

/* Decoded Frame Control fields. */
typedef struct {
    uint8_t protocol_version;
    uint8_t type;
    uint8_t subtype;

    bool to_ds;
    bool from_ds;
    bool more_fragments;
    bool retry;
    bool power_mgmt;
    bool more_data;
    bool protected_frame;
    bool order;
} ieee80211_fc_t;

typedef struct {
    ieee80211_fc_t fc;
    ieee80211_frame_type_t type;
    bool valid;
} ieee80211_frame_info_t;

/*
 * Parse the Frame Control from the first bytes of a raw 802.11 frame.
 * Returns false (and touches nothing) for NULL args or length < 2, the
 * minimum needed to read the two Frame Control bytes. Never reads past
 * `length` bytes and performs no pointer casts onto the frame buffer.
 */
bool ieee80211_parse(const uint8_t *frame, uint16_t length,
                     ieee80211_frame_info_t *out);
