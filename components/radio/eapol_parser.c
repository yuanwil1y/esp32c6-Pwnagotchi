#include "eapol_parser.h"

#include "ieee80211_parser.h"

#include <stddef.h>
#include <string.h>

#define LLC_SNAP_LEN                 8u
#define EAPOL_HEADER_LEN             4u
#define EAPOL_KEY_FIXED_PREFIX_LEN   77u
#define EAPOL_KEY_MIC_LEN_V1_TO_V3   16u
#define EAPOL_KEY_DATA_LEN_FIELD     (EAPOL_KEY_FIXED_PREFIX_LEN + EAPOL_KEY_MIC_LEN_V1_TO_V3)
#define EAPOL_KEY_DATA_OFFSET        (EAPOL_KEY_DATA_LEN_FIELD + 2u)
#define IEEE80211_QOS_AMSDU_MASK     0x0080u
#define IEEE80211_QOS_MESH_MASK      0x0100u

static const uint8_t s_llc_snap_eapol[LLC_SNAP_LEN] = {
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
};

typedef enum {
    SNAP_NOT_EAPOL = 0,
    SNAP_IS_EAPOL,
    SNAP_PREFIX_ONLY,
} snap_match_t;

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

static bool mac_is_unicast(const uint8_t mac[6])
{
    uint8_t nonzero = 0;
    for (size_t i = 0; i < 6; ++i) {
        nonzero |= mac[i];
    }
    return nonzero != 0 && (mac[0] & 0x01u) == 0;
}

static void set_short_status(eapol_observation_t *out,
                             const rx_capture_view_t *frame,
                             uint32_t required_mac_length)
{
    /* The driver's original length lets us distinguish a capture cut from
     * a frame whose complete MAC body is intrinsically too short. */
    if (frame->original_mac_length_valid &&
        required_mac_length > frame->original_mac_length) {
        out->status = EAPOL_OBS_MALFORMED;
    } else {
        out->status = frame->capture_truncated ? EAPOL_OBS_TRUNCATED
                                               : EAPOL_OBS_MALFORMED;
    }
}

static snap_match_t match_eapol_snap(const uint8_t *bytes, uint16_t length)
{
    const uint16_t n = length < LLC_SNAP_LEN ? length : LLC_SNAP_LEN;
    if (n == 0 || memcmp(bytes, s_llc_snap_eapol, n) != 0) {
        return SNAP_NOT_EAPOL;
    }
    return length < LLC_SNAP_LEN ? SNAP_PREFIX_ONLY : SNAP_IS_EAPOL;
}

static void set_reliable_direction(eapol_observation_t *out,
                                   const ieee80211_data_addrs_t *addrs)
{
    if (addrs->status != IEEE80211_DATA_ADDRS_OK) {
        return;
    }

    if (addrs->to_ds) {
        out->direction = EAPOL_DIRECTION_STA_TO_AP;
        if (mac_is_unicast(addrs->addr1)) {
            memcpy(out->bssid, addrs->addr1, sizeof(out->bssid));
            out->bssid_valid = true;
        }
        if (mac_is_unicast(addrs->addr2)) {
            memcpy(out->sta, addrs->addr2, sizeof(out->sta));
            out->sta_valid = true;
        }
    } else if (addrs->from_ds) {
        out->direction = EAPOL_DIRECTION_AP_TO_STA;
        if (mac_is_unicast(addrs->addr2)) {
            memcpy(out->bssid, addrs->addr2, sizeof(out->bssid));
            out->bssid_valid = true;
        }
        if (mac_is_unicast(addrs->addr1)) {
            memcpy(out->sta, addrs->addr1, sizeof(out->sta));
            out->sta_valid = true;
        }
    }

    if (out->bssid_valid && out->sta_valid &&
        memcmp(out->bssid, out->sta, sizeof(out->bssid)) == 0) {
        memset(out->bssid, 0, sizeof(out->bssid));
        memset(out->sta, 0, sizeof(out->sta));
        out->bssid_valid = false;
        out->sta_valid = false;
        out->direction = EAPOL_DIRECTION_UNKNOWN;
    }
}

static void parse_key(eapol_observation_t *out, const uint8_t *body,
                      uint16_t body_length)
{
    if (body_length < 1) {
        out->status = EAPOL_OBS_MALFORMED;
        return;
    }

    out->key_descriptor_type = body[0];
    if (out->key_descriptor_type != 2 && out->key_descriptor_type != 254) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_KEY_DESCRIPTOR;
        return;
    }

    if (body_length < 3) {
        out->status = EAPOL_OBS_MALFORMED;
        return;
    }

    const uint16_t key_info = read_be16(&body[1]);
    out->key_descriptor_version = (uint8_t)(key_info & 0x0007u);

    /* Descriptor version 0 is AKM-defined: its MIC field can vary by AKM
     * (including 0, 16, 24, or 32 bytes). The parser has no negotiated AKM,
     * so it deliberately does not guess the following key-data offset. */
    if (out->key_descriptor_version < 1 || out->key_descriptor_version > 3) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_KEY_MIC_LAYOUT;
        return;
    }

    if (body_length < EAPOL_KEY_DATA_OFFSET) {
        out->status = EAPOL_OBS_MALFORMED;
        return;
    }

    const uint16_t key_data_length = read_be16(&body[EAPOL_KEY_DATA_LEN_FIELD]);
    const uint16_t key_data_available =
        (uint16_t)(body_length - EAPOL_KEY_DATA_OFFSET);
    if (key_data_length > key_data_available) {
        out->status = EAPOL_OBS_MALFORMED;
        return;
    }

    out->key_class = (key_info & 0x0008u) != 0
                         ? EAPOL_KEY_CLASS_PAIRWISE
                         : EAPOL_KEY_CLASS_GROUP;
    out->complete_key = true;
    out->status = EAPOL_OBS_COMPLETE;
}

bool eapol_parse_frame(const rx_capture_view_t *frame,
                       eapol_observation_t *out)
{
    if (frame == NULL || out == NULL) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->status = EAPOL_OBS_NOT_APPLICABLE;
    out->rx_timestamp_us = frame->rx_timestamp_us;
    out->rx_channel = frame->rx_channel;
    out->rssi = frame->rssi;

    if (frame->mac_bytes == NULL || !frame->original_mac_length_valid ||
        frame->fcs_policy !=
            RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW ||
        frame->captured_mac_length > RADIO_PACKET_MAX_LEN ||
        frame->captured_mac_length > frame->original_mac_length ||
        frame->capture_truncated !=
            (frame->captured_mac_length < frame->original_mac_length)) {
        out->status = EAPOL_OBS_MALFORMED;
        return true;
    }
    if (frame->captured_mac_length < 2) {
        return true;
    }

    ieee80211_frame_info_t info = {0};
    if (!ieee80211_parse(frame->mac_bytes, frame->captured_mac_length, &info) ||
        info.type != IEEE80211_TYPE_DATA) {
        return true;
    }
    if (info.fc.protocol_version != 0) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_SUBTYPE;
        out->unsupported_mac_layout = true;
        return true;
    }

    const uint8_t subtype = info.fc.subtype;
    const bool qos_data = subtype >= IEEE80211_DATA_QOS_DATA &&
                          subtype <= IEEE80211_DATA_QOS_DATA_CFACK_CFPOLL;
    const bool plain_data = subtype >= IEEE80211_DATA_DATA &&
                            subtype <= IEEE80211_DATA_DATA_CFACK_CFPOLL;
    const bool no_payload = (subtype >= IEEE80211_DATA_NULL &&
                             subtype <= IEEE80211_DATA_CFACK_CFPOLL) ||
                            subtype == IEEE80211_DATA_QOS_NULL;
    if (!plain_data && !qos_data && !no_payload) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_SUBTYPE;
        out->unsupported_mac_layout = true;
        return true;
    }

    ieee80211_data_addrs_t addrs = {0};
    if (!ieee80211_parse_data_addresses(frame->mac_bytes,
                                        frame->captured_mac_length, &addrs)) {
        if (addrs.status == IEEE80211_DATA_ADDRS_TOO_SHORT) {
            set_short_status(out, frame, addrs.header_len);
        } else {
            out->status = EAPOL_OBS_UNSUPPORTED;
            out->unsupported_reason = EAPOL_UNSUPPORTED_SUBTYPE;
            out->unsupported_mac_layout = true;
        }
        return true;
    }

    set_reliable_direction(out, &addrs);

    /* Null and QoS Null have a valid MAC/QoS header but no MSDU payload. */
    if (no_payload) {
        out->status = EAPOL_OBS_NOT_EAPOL;
        out->unsupported_reason = EAPOL_UNSUPPORTED_NULL_DATA;
        return true;
    }

    if (addrs.protected_frame) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_PROTECTED;
        out->unsupported_mac_layout = true;
        return true; /* encrypted body is never searched for plaintext */
    }

    const uint16_t qos_offset = (uint16_t)(IEEE80211_DATA_HDR_BASE_LEN +
                                           (addrs.four_addr ? 6u : 0u));
    if (qos_data) {
        const uint16_t qos_control = read_le16(&frame->mac_bytes[qos_offset]);
        if ((qos_control & IEEE80211_QOS_MESH_MASK) != 0) {
            out->status = EAPOL_OBS_UNSUPPORTED;
            out->unsupported_reason = EAPOL_UNSUPPORTED_MESH;
            out->unsupported_mac_layout = true;
            return true;
        }
        if ((qos_control & IEEE80211_QOS_AMSDU_MASK) != 0) {
            out->status = EAPOL_OBS_UNSUPPORTED;
            out->unsupported_reason = EAPOL_UNSUPPORTED_AMSDU;
            out->unsupported_mac_layout = true;
            return true;
        }
    }

    const uint8_t fragment_number = (uint8_t)(frame->mac_bytes[22] & 0x0fu);
    if (info.fc.more_fragments || fragment_number != 0) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_FRAGMENT;
        out->unsupported_mac_layout = true;

        /* Only fragment zero contains the MSDU LLC header. Check just its
         * complete SNAP marker so a genuine EAPOL fragment is counted, but
         * never interpret/reassemble its incomplete EAPOL body. */
        if (fragment_number == 0 && frame->captured_mac_length >= addrs.header_len) {
            const uint16_t available =
                (uint16_t)(frame->captured_mac_length - addrs.header_len);
            const snap_match_t fragment_snap =
                match_eapol_snap(&frame->mac_bytes[addrs.header_len], available);
            out->raw_eapol_frame = fragment_snap == SNAP_IS_EAPOL;
            out->partial_eapol_candidate =
                fragment_snap == SNAP_PREFIX_ONLY && frame->capture_truncated;
            if (out->partial_eapol_candidate) {
                out->status = EAPOL_OBS_TRUNCATED;
            }
        }
        return true;
    }

    const uint16_t body_offset = addrs.header_len;
    const uint16_t body_available =
        (uint16_t)(frame->captured_mac_length - body_offset);
    const snap_match_t snap = match_eapol_snap(&frame->mac_bytes[body_offset],
                                               body_available);

    if (addrs.status == IEEE80211_DATA_ADDRS_WDS ||
        addrs.status == IEEE80211_DATA_ADDRS_AMBIGUOUS) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = addrs.status == IEEE80211_DATA_ADDRS_WDS
                                      ? EAPOL_UNSUPPORTED_WDS
                                      : EAPOL_UNSUPPORTED_NO_DS;
        out->unsupported_mac_layout = true;
        out->raw_eapol_frame = snap == SNAP_IS_EAPOL;
        return true;
    }

    if (snap == SNAP_NOT_EAPOL) {
        out->status = EAPOL_OBS_NOT_EAPOL;
        return true;
    }
    if (snap == SNAP_PREFIX_ONLY) {
        out->partial_eapol_candidate = frame->capture_truncated;
        out->status = out->partial_eapol_candidate ? EAPOL_OBS_TRUNCATED
                                                   : EAPOL_OBS_NOT_EAPOL;
        return true;
    }

    out->raw_eapol_frame = true;
    const uint16_t eapol_offset = (uint16_t)(body_offset + LLC_SNAP_LEN);
    const uint16_t eapol_available =
        (uint16_t)(frame->captured_mac_length - eapol_offset);
    if (eapol_available < EAPOL_HEADER_LEN) {
        set_short_status(out, frame, (uint32_t)eapol_offset + EAPOL_HEADER_LEN);
        return true;
    }

    const uint8_t *eapol = &frame->mac_bytes[eapol_offset];
    out->eapol_header_present = true;
    out->eapol_version = eapol[0];
    out->eapol_type = eapol[1];
    const uint16_t eapol_body_length = read_be16(&eapol[2]);
    const uint16_t eapol_body_available =
        (uint16_t)(eapol_available - EAPOL_HEADER_LEN);
    if (eapol_body_length > eapol_body_available) {
        set_short_status(out, frame,
                         (uint32_t)eapol_offset + EAPOL_HEADER_LEN +
                             eapol_body_length);
        return true;
    }
    out->eapol_body_complete = true;

    if (out->eapol_version < 1 || out->eapol_version > 3) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_VERSION;
        return true;
    }

    if (out->eapol_type > EAPOL_PACKET_KEY) {
        out->status = EAPOL_OBS_UNSUPPORTED;
        out->unsupported_reason = EAPOL_UNSUPPORTED_PACKET_TYPE;
        return true;
    }

    if ((out->eapol_type == EAPOL_PACKET_START ||
         out->eapol_type == EAPOL_PACKET_LOGOFF) && eapol_body_length != 0) {
        out->status = EAPOL_OBS_MALFORMED;
        return true;
    }

    if (out->eapol_type != EAPOL_PACKET_KEY) {
        out->status = EAPOL_OBS_COMPLETE;
        return true;
    }

    parse_key(out, &eapol[EAPOL_HEADER_LEN], eapol_body_length);
    return true;
}

static void sat_inc(uint32_t *value)
{
    if (*value != UINT32_MAX) {
        ++*value;
    }
}

void eapol_stats_record(eapol_stats_t *stats,
                        const eapol_observation_t *observation)
{
    if (stats == NULL || observation == NULL) {
        return;
    }

    if (observation->unsupported_mac_layout) {
        sat_inc(&stats->unsupported_mac_layout_frames);
    }
    if (!observation->raw_eapol_frame) {
        if (observation->partial_eapol_candidate) {
            sat_inc(&stats->truncated_eapol_frames);
            stats->last_observation = *observation;
            stats->last_observation_valid = true;
        }
        return;
    }

    sat_inc(&stats->raw_eapol_frames);
    stats->last_observation = *observation;
    stats->last_observation_valid = true;

    if (observation->eapol_header_present) {
        switch (observation->eapol_type) {
        case EAPOL_PACKET_EAP:
            sat_inc(&stats->eap_packet_frames);
            break;
        case EAPOL_PACKET_START:
            sat_inc(&stats->start_frames);
            break;
        case EAPOL_PACKET_LOGOFF:
            sat_inc(&stats->logoff_frames);
            break;
        case EAPOL_PACKET_KEY:
            sat_inc(&stats->key_frames);
            break;
        default:
            break;
        }
    }

    if (observation->eapol_body_complete &&
        observation->eapol_version >= 1 && observation->eapol_version <= 3 &&
        observation->eapol_type <= EAPOL_PACKET_KEY) {
        sat_inc(&stats->complete_eapol_envelopes);
    }
    if (observation->complete_key) {
        sat_inc(&stats->complete_key_frames);
        if (observation->key_class == EAPOL_KEY_CLASS_PAIRWISE) {
            sat_inc(&stats->pairwise_key_frames);
        } else if (observation->key_class == EAPOL_KEY_CLASS_GROUP) {
            sat_inc(&stats->group_key_frames);
        }
    }
    if (observation->eapol_type == EAPOL_PACKET_KEY &&
        observation->unsupported_reason == EAPOL_UNSUPPORTED_KEY_DESCRIPTOR) {
        sat_inc(&stats->unknown_key_descriptors);
    }
    switch (observation->status) {
    case EAPOL_OBS_TRUNCATED:
        sat_inc(&stats->truncated_eapol_frames);
        break;
    case EAPOL_OBS_MALFORMED:
        sat_inc(&stats->malformed_eapol_frames);
        break;
    case EAPOL_OBS_UNSUPPORTED:
        sat_inc(&stats->unsupported_eapol_frames);
        break;
    default:
        break;
    }
}
