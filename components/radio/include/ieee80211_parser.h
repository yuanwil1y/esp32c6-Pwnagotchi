#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Phase 1B: 802.11 Frame Control classification.
 * Phase 1C: management frame fixed fields + Information Element walk for
 *           beacon / probe request / probe response.
 *
 * Pure functions over raw frame bytes: no globals, no allocation, no logging.
 * The caller (radio_rx_task, a normal FreeRTOS task) owns all counters and
 * caches. Never called from the promiscuous RX callback.
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

/* --- Phase 1C: management frame layout and Information Elements. --- */

#define IEEE80211_MGMT_HDR_LEN       24  /* FC + dur + addr1/2/3 + seq */
#define IEEE80211_BEACON_FIXED_LEN   12  /* timestamp(8) + interval(2) + cap(2) */

/* Offsets inside the management header. */
#define IEEE80211_MGMT_ADDR2_OFF     10  /* SA */
#define IEEE80211_MGMT_ADDR3_OFF     16  /* BSSID for beacon / probe resp */

/* Fixed-field offsets after the management header (beacon / probe resp). */
#define IEEE80211_BEACON_INTERVAL_OFF  (IEEE80211_MGMT_HDR_LEN + 8)
#define IEEE80211_BEACON_CAP_OFF       (IEEE80211_MGMT_HDR_LEN + 10)

/* Information Element IDs used in Phase 1C. */
#define IEEE80211_IE_SSID            0
#define IEEE80211_IE_DS_PARAM        3
#define IEEE80211_IE_RSN             48
#define IEEE80211_IE_VENDOR          221

/* Old WPA vendor specific signature: OUI 00:50:F2, type 01. */
#define IEEE80211_WPA_OUI            0x0050F2
#define IEEE80211_WPA_OUI_TYPE       0x01

#define IEEE80211_SSID_MAX_LEN       32
#define IEEE80211_SSID_BUF_LEN       (IEEE80211_SSID_MAX_LEN + 1)

/* Capability Information bits. */
#define IEEE80211_CAP_PRIVACY        0x0010

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

/* Coarse security classification from presence flags only. */
typedef enum {
    IEEE80211_SEC_OPEN = 0,
    IEEE80211_SEC_PRIVACY,
    IEEE80211_SEC_WPA,
    IEEE80211_SEC_RSN,
    IEEE80211_SEC_UNKNOWN,
} ieee80211_security_t;

/*
 * Phase 2 security description. The IE walk fills the presence flags and,
 * for legally structured RSN / WPA vendor IEs, the decoded suites (Phase
 * 2C; Phase 2A fills presence only). Bit masks keep the struct small and
 * merge-friendly. `*_valid` means "this IE was fully parsed and its
 * structure was legal"; presence without validity means the IE existed
 * but was malformed or cut by the capture - never authoritative.
 */

/* Cipher suite type codes (RSN OUI 00:0F:AC; WPA uses 00:50:F2). */
#define IEEE80211_CIPHER_USE_GROUP    (1u << 0)   /* type 0 */
#define IEEE80211_CIPHER_WEP40        (1u << 1)   /* type 1 */
#define IEEE80211_CIPHER_TKIP         (1u << 2)   /* type 2 */
#define IEEE80211_CIPHER_CCMP128      (1u << 3)   /* type 4 */
#define IEEE80211_CIPHER_WEP104       (1u << 4)   /* type 5 */
#define IEEE80211_CIPHER_BIP_CMAC128  (1u << 5)   /* type 6 */
#define IEEE80211_CIPHER_GCMP128      (1u << 6)   /* type 8 */
#define IEEE80211_CIPHER_GCMP256      (1u << 7)   /* type 9 */
#define IEEE80211_CIPHER_CCMP256      (1u << 8)   /* type 10 */
#define IEEE80211_CIPHER_BIP_GMAC128  (1u << 9)   /* type 11 */
#define IEEE80211_CIPHER_BIP_GMAC256  (1u << 10)  /* type 12 */
#define IEEE80211_CIPHER_BIP_CMAC256  (1u << 11)  /* type 13 */
#define IEEE80211_CIPHER_UNKNOWN      (1u << 15)

/* AKM suite type codes. */
#define IEEE80211_AKM_802_1X          (1u << 0)   /* type 1 */
#define IEEE80211_AKM_PSK             (1u << 1)   /* type 2 */
#define IEEE80211_AKM_FT_802_1X       (1u << 2)   /* type 3 */
#define IEEE80211_AKM_FT_PSK          (1u << 3)   /* type 4 */
#define IEEE80211_AKM_1X_SHA256       (1u << 4)   /* type 5 */
#define IEEE80211_AKM_PSK_SHA256      (1u << 5)   /* type 6 */
#define IEEE80211_AKM_SAE             (1u << 6)   /* type 8 */
#define IEEE80211_AKM_FT_SAE          (1u << 7)   /* type 9 */
#define IEEE80211_AKM_1X_SUITE_B      (1u << 8)   /* type 11 */
#define IEEE80211_AKM_1X_SUITE_B_192  (1u << 9)   /* type 12 */
#define IEEE80211_AKM_FT_1X_SHA384    (1u << 10)  /* type 13 */
#define IEEE80211_AKM_FILS_SHA256     (1u << 11)  /* type 14 */
#define IEEE80211_AKM_FILS_SHA384     (1u << 12)  /* type 15 */
#define IEEE80211_AKM_OWE             (1u << 13)  /* type 18 */
#define IEEE80211_AKM_FT_PSK_SHA384   (1u << 14)  /* type 19 */
#define IEEE80211_AKM_UNKNOWN         (1u << 15)

typedef struct {
    bool rsn_present;   /* RSN IE (48) seen at all */
    bool wpa_present;   /* WPA vendor IE (221, OUI 00:50:F2 type 01) seen */
    bool rsn_valid;     /* RSN IE fully parsed with legal structure */
    bool wpa_valid;     /* WPA vendor IE fully parsed with legal structure */
    bool privacy;       /* capability PRIVACY bit (header-verified) */

    uint16_t version;   /* version field of the last fully valid parse */

    uint16_t group;     /* group cipher mask (exactly one bit when valid) */
    uint16_t pairwise;  /* pairwise cipher mask */
    uint16_t akm;       /* AKM suite mask */

    bool mfp_capable;   /* RSN capabilities MFPC */
    bool mfp_required;  /* RSN capabilities MFPR */
    bool caps_present;  /* RSN capabilities field present AND complete */
} ieee80211_security_desc_t;

/*
 * Beacon / probe response observation. rx_channel and rssi come from the
 * ESP-IDF RX metadata and are filled in by the caller after parsing.
 * advertised_channel comes from the DS Parameter Set IE (0 when absent or
 * invalid) and is deliberately stored separately from rx_channel.
 *
 * Phase 1.5 observation status:
 * - malformed_ie       : structurally illegal frame content (declared IE
 *                        body runs past a COMPLETE frame end, trailing
 *                        garbage in a complete body, illegal SSID length,
 *                        bad DS Parameter length)
 * - ie_walk_incomplete : the capture (not the air) ended inside the IE
 *                        area, so the tail cannot be judged; NOT evidence
 *                        of a bad frame
 * - dup_critical_ie    : a critical IE (SSID or DS Parameter) appeared
 *                        more than once; only the first occurrence is used
 * - complete           : true only when the whole MAC body was present in
 *                        the capture and the walk finished cleanly with no
 *                        malformed, incomplete or duplicated critical IEs.
 *                        Only complete observations may carry negative
 *                        evidence (e.g. "no RSN IE seen").
 */
typedef struct {
    uint8_t bssid[6];

    char ssid[IEEE80211_SSID_BUF_LEN];
    uint8_t ssid_len;
    bool hidden_ssid;

    int8_t rssi;            /* caller: RX metadata */
    uint8_t rx_channel;     /* caller: RX metadata */

    uint8_t advertised_channel;
    bool ds_param_present;

    uint16_t beacon_interval;
    uint16_t capability;

    bool privacy;
    bool rsn_present;
    bool wpa_vendor_present;

    /* Phase 2: structured security knowledge (presence level in 2A,
     * full suite parsing in 2C). Mirrors the flags above; kept separate
     * so the Phase 1.5 presence classification stays byte-compatible. */
    ieee80211_security_desc_t sec;

    uint16_t ie_count;
    bool malformed_ie;

    /* Phase 1.5 status fields. */
    bool ie_walk_incomplete;
    bool dup_critical_ie;
    bool complete;
} ieee80211_ap_observation_t;

/* Probe request observation; rssi/rx_channel filled in by the caller.
 * Status fields have the same meaning as in the AP observation. */
typedef struct {
    uint8_t source[6];

    char ssid[IEEE80211_SSID_BUF_LEN];
    uint8_t ssid_len;
    bool wildcard_ssid;

    int8_t rssi;
    uint8_t rx_channel;

    uint16_t ie_count;
    bool malformed_ie;

    /* Phase 1.5 status fields. */
    bool ie_walk_incomplete;
    bool dup_critical_ie;
    bool complete;
} ieee80211_probe_req_observation_t;

/*
 * Parse options: `capture_truncated` tells the parser that the buffer ends
 * because the capture was cut (radio_packet_t.length < orig_length), not
 * because the frame ended. The walk then reports ie_walk_incomplete
 * instead of malformed_ie for the cut tail. Phase 1.5: always fill this
 * struct (designated initializers keep unknown fields safe).
 */
typedef struct {
    bool capture_truncated;
} ieee80211_parse_opts_t;

/*
 * Parse the Frame Control from the first bytes of a raw 802.11 frame.
 * Returns false (and touches nothing) for NULL args or length < 2, the
 * minimum needed to read the two Frame Control bytes. Never reads past
 * `length` bytes and performs no pointer casts onto the frame buffer.
 */
bool ieee80211_parse(const uint8_t *frame, uint16_t length,
                     ieee80211_frame_info_t *out);

/*
 * Parse a beacon or probe response body: BSSID (address 3), the fixed
 * timestamp/interval/capability fields, then a strictly bounds-checked IE
 * walk extracting SSID (0), DS Parameter channel (3), RSN presence (48) and
 * WPA vendor presence (221, OUI 00:50:F2 type 01). Requires at least the
 * 24-byte management header plus the 12 fixed bytes; returns false below
 * that without touching `out` beyond zeroing it. Malformed IEs stop the
 * walk, set malformed_ie, and are not an error return. `opts` may be NULL
 * for "capture not truncated".
 */
bool ieee80211_parse_beacon_or_probe_resp(const uint8_t *frame, uint16_t length,
                                          const ieee80211_parse_opts_t *opts,
                                          ieee80211_ap_observation_t *out);

/*
 * Parse a probe request: source address (address 2) plus the IE walk for
 * the requested SSID. SSID length 0 is a wildcard probe, not hidden AP.
 * Requires the 24-byte management header. `opts` may be NULL.
 */
bool ieee80211_parse_probe_request(const uint8_t *frame, uint16_t length,
                                   const ieee80211_parse_opts_t *opts,
                                   ieee80211_probe_req_observation_t *out);

/* Coarse security from observation flags: RSN > WPA > PRIVACY > OPEN. */
ieee80211_security_t ieee80211_classify_security(const ieee80211_ap_observation_t *obs);

const char *ieee80211_security_name(ieee80211_security_t sec);

/* Format "AA:BB:CC:DD:EE:FF". out_size must be >= 18. */
void ieee80211_format_mac(const uint8_t mac[6], char *out, size_t out_size);

/*
 * Copy ssid into out replacing non-printable bytes with '.' and always
 * NUL-terminating. out_size is the full buffer size including terminator;
 * the copy is truncated to fit. Raw SSID bytes are never printable-safe and
 * must never be printed with %s directly.
 */
void ieee80211_ssid_to_printable(const char *ssid, uint8_t ssid_len,
                                 char *out, size_t out_size);

/* --- Phase 2B: data frame address extraction ------------------------- */

/* Offsets inside the data frame header. */
#define IEEE80211_DATA_HDR_BASE_LEN  24  /* FC+dur+addr1..3+seq */
#define IEEE80211_DATA_ADDR1_OFF     4
#define IEEE80211_DATA_ADDR2_OFF     10
#define IEEE80211_DATA_ADDR3_OFF     16
#define IEEE80211_DATA_ADDR4_OFF     24

typedef enum {
    IEEE80211_DATA_ADDRS_OK = 0,        /* ToDS ^ FromDS: mappable      */
    IEEE80211_DATA_ADDRS_TOO_SHORT,    /* header not fully captured     */
    IEEE80211_DATA_ADDRS_BAD_PROTOCOL, /* not a plain data frame / ver  */
    IEEE80211_DATA_ADDRS_WDS,          /* ToDS & FromDS: 4-address      */
    IEEE80211_DATA_ADDRS_AMBIGUOUS,    /* no DS bits: IBSS / direct     */
} ieee80211_data_addrs_status_t;

/*
 * Bounds-checked extraction of the data frame address fields. The minimum
 * header length is computed FROM the Frame Control: 24 bytes + 6 (both DS
 * bits: addr4) + 2 (QoS subtype) + 4 (order bit: HT control). Protected
 * bodies are irrelevant: the MAC header stays plaintext and no body byte
 * is ever read here.
 *
 * Returns true when the header was fully present and structurally valid
 * (status OK, WDS or AMBIGUOUS - all three carry verified addresses);
 * false for NULL args, TOO_SHORT and BAD_PROTOCOL, in which case `out`
 * only has `status` set. WDS and AMBIGUOUS are deliberately NOT mapped to
 * infrastructure roles: the caller must skip ordinary AP<->STA inference
 * for them (see docs/PHASE2_WORLD_MODEL.md for the DS mapping table).
 */
typedef struct {
    ieee80211_data_addrs_status_t status;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t addr4[6]; /* zero unless both DS bits set */
    uint16_t header_len;  /* minimum header incl. QoS / HT control */
    bool to_ds;
    bool from_ds;
    bool qos;
    bool four_addr;
    bool protected_frame;
} ieee80211_data_addrs_t;

bool ieee80211_parse_data_addresses(const uint8_t *frame, uint16_t length,
                                    ieee80211_data_addrs_t *out);
