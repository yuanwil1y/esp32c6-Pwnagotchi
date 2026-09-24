#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "rx_path.h"

/* EAPOL packet-type values from IEEE 802.1X / Wireshark packet-eapol.h. */
enum {
    EAPOL_PACKET_EAP = 0,
    EAPOL_PACKET_START = 1,
    EAPOL_PACKET_LOGOFF = 2,
    EAPOL_PACKET_KEY = 3,
};

typedef enum {
    EAPOL_OBS_NOT_APPLICABLE = 0,
    EAPOL_OBS_NOT_EAPOL,
    EAPOL_OBS_COMPLETE,
    EAPOL_OBS_TRUNCATED,
    EAPOL_OBS_MALFORMED,
    EAPOL_OBS_UNSUPPORTED,
} eapol_observation_status_t;

typedef enum {
    EAPOL_UNSUPPORTED_NONE = 0,
    EAPOL_UNSUPPORTED_PROTECTED,
    EAPOL_UNSUPPORTED_NULL_DATA,
    EAPOL_UNSUPPORTED_NO_DS,
    EAPOL_UNSUPPORTED_WDS,
    EAPOL_UNSUPPORTED_MESH,
    EAPOL_UNSUPPORTED_AMSDU,
    EAPOL_UNSUPPORTED_FRAGMENT,
    EAPOL_UNSUPPORTED_SUBTYPE,
    EAPOL_UNSUPPORTED_VERSION,
    EAPOL_UNSUPPORTED_PACKET_TYPE,
    EAPOL_UNSUPPORTED_KEY_DESCRIPTOR,
    EAPOL_UNSUPPORTED_KEY_MIC_LAYOUT,
} eapol_unsupported_reason_t;

typedef enum {
    EAPOL_DIRECTION_UNKNOWN = 0,
    EAPOL_DIRECTION_STA_TO_AP,
    EAPOL_DIRECTION_AP_TO_STA,
} eapol_direction_t;

typedef enum {
    EAPOL_KEY_CLASS_UNKNOWN = 0,
    EAPOL_KEY_CLASS_PAIRWISE,
    EAPOL_KEY_CLASS_GROUP,
} eapol_key_class_t;

/*
 * Value-only parser output. It contains no pointer into rx_capture_view_t or
 * the packet pool and is safe to copy beyond rx_path_slot_release(). The
 * MAC addresses are set only when three-address DS mapping and valid
 * unicast addresses make the role unambiguous.
 */
typedef struct {
    eapol_observation_status_t status;
    eapol_unsupported_reason_t unsupported_reason;
    eapol_direction_t direction;
    eapol_key_class_t key_class;
    uint64_t rx_timestamp_us;
    uint8_t rx_channel;
    int8_t rssi;
    uint8_t eapol_type;
    uint8_t eapol_version;
    uint8_t key_descriptor_type;
    uint8_t key_descriptor_version;
    bool raw_eapol_frame;       /* strict LLC/SNAP EtherType 0x888e seen */
    bool partial_eapol_candidate; /* capture cut after matching SNAP prefix */
    bool eapol_header_present;
    bool eapol_body_complete;   /* declared body is captured and in bounds */
    bool complete_key;          /* supported descriptor + all bounds valid */
    bool unsupported_mac_layout;
    bool bssid_valid;
    bool sta_valid;
    uint8_t bssid[6];
    uint8_t sta[6];
} eapol_observation_t;

/* Fixed-size, saturating statistics and the latest value observation only. */
typedef struct {
    uint32_t raw_eapol_frames;
    uint32_t complete_eapol_envelopes;
    uint32_t complete_key_frames;
    uint32_t truncated_eapol_frames;
    uint32_t malformed_eapol_frames;
    uint32_t unsupported_eapol_frames;
    uint32_t unsupported_mac_layout_frames;
    uint32_t eap_packet_frames;
    uint32_t start_frames;
    uint32_t logoff_frames;
    uint32_t key_frames;
    uint32_t unknown_key_descriptors;
    uint32_t pairwise_key_frames;
    uint32_t group_key_frames;
    bool last_observation_valid;
    eapol_observation_t last_observation;
} eapol_stats_t;

/* Parse one captured MAC frame. Returns false only for invalid arguments. */
bool eapol_parse_frame(const rx_capture_view_t *frame,
                       eapol_observation_t *out);

/* Update fixed counters from one parser result; saturates instead of wrap. */
void eapol_stats_record(eapol_stats_t *stats,
                        const eapol_observation_t *observation);
