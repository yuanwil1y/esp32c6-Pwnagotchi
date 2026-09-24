#include "ieee80211_parser.h"

#include <stddef.h>
#include <string.h>

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

bool ieee80211_parse(const uint8_t *frame, uint16_t length,
                     ieee80211_frame_info_t *out)
{
    if (frame == NULL || out == NULL || length < 2) {
        return false;
    }

    /* Byte-by-byte little-endian assembly: no struct overlay and no
     * alignment or endianness assumptions on the frame buffer. */
    const uint16_t fc = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);

    out->fc.protocol_version = (uint8_t)(fc & IEEE80211_FC_PROTOCOL_MASK);
    out->fc.type = (uint8_t)((fc & IEEE80211_FC_TYPE_MASK) >> IEEE80211_FC_TYPE_SHIFT);
    out->fc.subtype = (uint8_t)((fc & IEEE80211_FC_SUBTYPE_MASK) >> IEEE80211_FC_SUBTYPE_SHIFT);

    out->fc.to_ds = (fc & IEEE80211_FC_TODS_MASK) != 0;
    out->fc.from_ds = (fc & IEEE80211_FC_FROMDS_MASK) != 0;
    out->fc.more_fragments = (fc & IEEE80211_FC_MOREFRAG_MASK) != 0;
    out->fc.retry = (fc & IEEE80211_FC_RETRY_MASK) != 0;
    out->fc.power_mgmt = (fc & IEEE80211_FC_PWRMGT_MASK) != 0;
    out->fc.more_data = (fc & IEEE80211_FC_MOREDATA_MASK) != 0;
    out->fc.protected_frame = (fc & IEEE80211_FC_PROTECTED_MASK) != 0;
    out->fc.order = (fc & IEEE80211_FC_ORDER_MASK) != 0;

    switch (out->fc.type) {
    case IEEE80211_FC_TYPE_VALUE_MGMT:
        out->type = IEEE80211_TYPE_MGMT;
        break;
    case IEEE80211_FC_TYPE_VALUE_CTRL:
        out->type = IEEE80211_TYPE_CTRL;
        break;
    case IEEE80211_FC_TYPE_VALUE_DATA:
        out->type = IEEE80211_TYPE_DATA;
        break;
    case IEEE80211_FC_TYPE_VALUE_EXT:
        out->type = IEEE80211_TYPE_EXT;
        break;
    default:
        out->type = IEEE80211_TYPE_UNKNOWN;
        break;
    }

    out->valid = true;
    return true;
}

/*
 * Strict IE walk over frame[ie_start .. length). Semantics (Phase 1.5):
 *
 * - two header bytes must exist and the declared 2+len body must fit
 *   inside the frame; when it does not because the CAPTURE was cut
 *   (capture_truncated), the tail is marked ie_walk_incomplete - it
 *   cannot be judged and is NOT evidence of a bad frame. The same
 *   violation in a COMPLETE body is malformed_ie.
 * - a leftover byte in a complete body is trailing garbage (malformed);
 *   with a truncated capture it is just an unknowable tail (incomplete).
 * - the SSID IE and the DS Parameter IE are "critical": the FIRST
 *   occurrence wins, further occurrences set dup_critical_ie and are
 *   ignored (they cannot poison fields already parsed).
 * - SSID: length > 32 is malformed and not stored; all-zero bytes are
 *   the hidden-SSID representation, stored as ssid_len = 0.
 * - DS Parameter: only length == 1 is well-formed (other lengths are
 *   malformed); only channel values 1..14 are written into
 *   advertised_channel, anything else is ignored (rx_channel stays
 *   independent).
 */
typedef struct {
    bool ssid_seen;
    bool ds_seen;
} ie_walk_state_t;

static void walk_information_elements(const uint8_t *frame, uint16_t length,
                                      uint16_t ie_start, bool capture_truncated,
                                      ie_walk_state_t *st,
                                      ieee80211_ap_observation_t *ap_out,
                                      ieee80211_probe_req_observation_t *probe_out)
{
    uint32_t pos = ie_start;

    while (length - pos >= 2) {
        const uint8_t id = frame[pos];
        const uint8_t ie_len = frame[pos + 1];

        if ((uint32_t)ie_len > (uint32_t)(length - pos - 2)) {
            if (capture_truncated) {
                if (ap_out != NULL) {
                    ap_out->ie_walk_incomplete = true;
                }
                if (probe_out != NULL) {
                    probe_out->ie_walk_incomplete = true;
                }
            } else {
                if (ap_out != NULL) {
                    ap_out->malformed_ie = true;
                }
                if (probe_out != NULL) {
                    probe_out->malformed_ie = true;
                }
            }
            return;
        }

        const uint8_t *data = &frame[pos + 2];

        switch (id) {
        case IEEE80211_IE_SSID:
            if (ie_len > IEEE80211_SSID_MAX_LEN) {
                /* Illegal SSID length: structural, regardless of capture. */
                if (ap_out != NULL) {
                    ap_out->malformed_ie = true;
                }
                if (probe_out != NULL) {
                    probe_out->malformed_ie = true;
                }
                return;
            }
            if (st->ssid_seen) {
                if (ap_out != NULL) {
                    ap_out->dup_critical_ie = true;
                }
                if (probe_out != NULL) {
                    probe_out->dup_critical_ie = true;
                }
                break; /* first occurrence wins */
            }
            st->ssid_seen = true;

            /* All-zero bytes are the hidden-SSID representation. */
            bool all_zero = true;
            for (uint8_t k = 0; k < ie_len; k++) {
                if (data[k] != 0x00) {
                    all_zero = false;
                    break;
                }
            }

            if (ap_out != NULL) {
                if (all_zero) {
                    ap_out->ssid_len = 0;
                    ap_out->ssid[0] = '\0';
                    ap_out->hidden_ssid = true;
                } else {
                    memcpy(ap_out->ssid, data, ie_len);
                    ap_out->ssid[ie_len] = '\0';
                    ap_out->ssid_len = ie_len;
                    ap_out->hidden_ssid = ie_len == 0;
                }
            }
            if (probe_out != NULL) {
                if (all_zero) {
                    probe_out->ssid_len = 0;
                    probe_out->ssid[0] = '\0';
                    probe_out->wildcard_ssid = true;
                } else {
                    memcpy(probe_out->ssid, data, ie_len);
                    probe_out->ssid[ie_len] = '\0';
                    probe_out->ssid_len = ie_len;
                    probe_out->wildcard_ssid = ie_len == 0;
                }
            }
            break;
        case IEEE80211_IE_DS_PARAM:
            if (ie_len != 1) {
                /* DS Parameter Set is exactly one octet. */
                if (ap_out != NULL) {
                    ap_out->malformed_ie = true;
                }
                if (probe_out != NULL) {
                    probe_out->malformed_ie = true;
                }
                return;
            }
            if (st->ds_seen) {
                if (ap_out != NULL) {
                    ap_out->dup_critical_ie = true;
                }
                break; /* first occurrence wins */
            }
            st->ds_seen = true;
            if (ap_out != NULL) {
                if (data[0] >= 1 && data[0] <= 14) {
                    ap_out->advertised_channel = data[0];
                    ap_out->ds_param_present = true;
                }
                /* Out-of-range values: not written; advertised_channel
                 * stays 0 and rx_channel remains independent. */
            }
            break;
        case IEEE80211_IE_RSN:
            if (ap_out != NULL) {
                ap_out->rsn_present = true;
                ap_out->sec.rsn_present = true; /* suite decode: Phase 2C */
            }
            break;
        case IEEE80211_IE_VENDOR:
            /* WPA vendor signature needs at least OUI(3) + type(1). */
            if (ap_out != NULL && ie_len >= 4 &&
                data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 &&
                data[3] == IEEE80211_WPA_OUI_TYPE) {
                ap_out->wpa_vendor_present = true;
                ap_out->sec.wpa_present = true; /* suite decode: Phase 2C */
            }
            break;
        default:
            break;
        }

        pos += 2u + ie_len;
        if (ap_out != NULL) {
            ap_out->ie_count++;
        }
        if (probe_out != NULL) {
            probe_out->ie_count++;
        }
    }

    /* Leftover byte(s) after the walk. */
    if (length - pos > 0) {
        if (capture_truncated) {
            if (ap_out != NULL) {
                ap_out->ie_walk_incomplete = true;
            }
            if (probe_out != NULL) {
                probe_out->ie_walk_incomplete = true;
            }
        } else {
            /* Trailing garbage in a complete body. */
            if (ap_out != NULL) {
                ap_out->malformed_ie = true;
            }
            if (probe_out != NULL) {
                probe_out->malformed_ie = true;
            }
        }
    }
}

bool ieee80211_parse_beacon_or_probe_resp(const uint8_t *frame, uint16_t length,
                                          const ieee80211_parse_opts_t *opts,
                                          ieee80211_ap_observation_t *out)
{
    if (frame == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    if (length < IEEE80211_MGMT_HDR_LEN + IEEE80211_BEACON_FIXED_LEN) {
        return false;
    }

    /* Conservative deep-parse guards: a nonzero protocol version, the
     * order bit (an HT control field follows the FC: a variable header
     * this parser does not model) and fragmented bodies are rejected
     * before any fixed-field or IE read. */
    ieee80211_frame_info_t fc_info = {0};
    if (!ieee80211_parse(frame, 2, &fc_info) ||
        fc_info.fc.protocol_version != 0 ||
        fc_info.fc.order || fc_info.fc.more_fragments) {
        return false;
    }

    memcpy(out->bssid, &frame[IEEE80211_MGMT_ADDR3_OFF], sizeof(out->bssid));

    /* Timestamp (8 bytes) is deliberately skipped, not stored. */
    out->beacon_interval = read_le16(&frame[IEEE80211_BEACON_INTERVAL_OFF]);
    out->capability = read_le16(&frame[IEEE80211_BEACON_CAP_OFF]);
    out->privacy = (out->capability & IEEE80211_CAP_PRIVACY) != 0;
    out->sec.privacy = out->privacy;

    const bool capture_truncated = opts != NULL && opts->capture_truncated;
    ie_walk_state_t st = {0};
    walk_information_elements(frame, length,
                              IEEE80211_MGMT_HDR_LEN + IEEE80211_BEACON_FIXED_LEN,
                              capture_truncated, &st, out, NULL);

    /* A truncated capture never yields a complete observation, even when
     * the walk reached a clean boundary: IEs after the cut are unknowable. */
    if (capture_truncated) {
        out->ie_walk_incomplete = true;
    }
    out->complete = !out->malformed_ie && !out->ie_walk_incomplete &&
                    !out->dup_critical_ie;
    return true;
}

bool ieee80211_parse_probe_request(const uint8_t *frame, uint16_t length,
                                   const ieee80211_parse_opts_t *opts,
                                   ieee80211_probe_req_observation_t *out)
{
    if (frame == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    if (length < IEEE80211_MGMT_HDR_LEN) {
        return false;
    }

    /* Same deep-parse guards as the beacon path. */
    ieee80211_frame_info_t fc_info = {0};
    if (!ieee80211_parse(frame, 2, &fc_info) ||
        fc_info.fc.protocol_version != 0 ||
        fc_info.fc.order || fc_info.fc.more_fragments) {
        return false;
    }

    memcpy(out->source, &frame[IEEE80211_MGMT_ADDR2_OFF], sizeof(out->source));

    const bool capture_truncated = opts != NULL && opts->capture_truncated;
    ie_walk_state_t st = {0};
    walk_information_elements(frame, length, IEEE80211_MGMT_HDR_LEN,
                              capture_truncated, &st, NULL, out);

    if (capture_truncated) {
        out->ie_walk_incomplete = true;
    }
    out->complete = !out->malformed_ie && !out->ie_walk_incomplete &&
                    !out->dup_critical_ie;
    return true;
}

ieee80211_security_t ieee80211_classify_security(const ieee80211_ap_observation_t *obs)
{
    if (obs == NULL) {
        return IEEE80211_SEC_UNKNOWN;
    }
    if (obs->rsn_present) {
        return IEEE80211_SEC_RSN;
    }
    if (obs->wpa_vendor_present) {
        return IEEE80211_SEC_WPA;
    }
    if (obs->privacy) {
        return IEEE80211_SEC_PRIVACY;
    }
    return IEEE80211_SEC_OPEN;
}

const char *ieee80211_security_name(ieee80211_security_t sec)
{
    switch (sec) {
    case IEEE80211_SEC_RSN:
        return "RSN";
    case IEEE80211_SEC_WPA:
        return "WPA";
    case IEEE80211_SEC_PRIVACY:
        return "PRIVACY";
    case IEEE80211_SEC_OPEN:
        return "OPEN";
    default:
        return "UNKNOWN";
    }
}

bool ieee80211_parse_data_addresses(const uint8_t *frame, uint16_t length,
                                    ieee80211_data_addrs_t *out)
{
    if (frame == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    ieee80211_frame_info_t info = {0};
    if (!ieee80211_parse(frame, length, &info)) {
        out->status = IEEE80211_DATA_ADDRS_TOO_SHORT;
        return false;
    }
    if (info.fc.protocol_version != 0 || info.type != IEEE80211_TYPE_DATA) {
        out->status = IEEE80211_DATA_ADDRS_BAD_PROTOCOL;
        return false;
    }

    out->to_ds = info.fc.to_ds;
    out->from_ds = info.fc.from_ds;
    out->qos = (info.fc.subtype & 0x08) != 0;
    out->four_addr = info.fc.to_ds && info.fc.from_ds;
    out->protected_frame = info.fc.protected_frame;

    /* Minimum header length strictly derived from the Frame Control; the
     * capture must hold every byte of it before any address is read. */
    uint32_t hdr = IEEE80211_DATA_HDR_BASE_LEN;
    if (out->four_addr) {
        hdr += 6; /* addr4 */
    }
    if (out->qos) {
        hdr += 2; /* QoS control */
    }
    if (info.fc.order) {
        hdr += 4; /* HT control */
    }
    out->header_len = (uint16_t)hdr;

    if (length < out->header_len) {
        out->status = IEEE80211_DATA_ADDRS_TOO_SHORT;
        return false;
    }

    memcpy(out->addr1, &frame[IEEE80211_DATA_ADDR1_OFF], sizeof(out->addr1));
    memcpy(out->addr2, &frame[IEEE80211_DATA_ADDR2_OFF], sizeof(out->addr2));
    memcpy(out->addr3, &frame[IEEE80211_DATA_ADDR3_OFF], sizeof(out->addr3));
    if (out->four_addr) {
        memcpy(out->addr4, &frame[IEEE80211_DATA_ADDR4_OFF], sizeof(out->addr4));
    }

    if (out->four_addr) {
        out->status = IEEE80211_DATA_ADDRS_WDS;
    } else if (!out->to_ds && !out->from_ds) {
        out->status = IEEE80211_DATA_ADDRS_AMBIGUOUS;
    } else {
        out->status = IEEE80211_DATA_ADDRS_OK;
    }
    return true;
}

void ieee80211_format_mac(const uint8_t mac[6], char *out, size_t out_size)
{
    static const char hex[] = "0123456789ABCDEF";

    if (out == NULL || out_size < 18) {
        return;
    }

    for (int i = 0; i < 6; i++) {
        out[i * 3 + 0] = hex[(mac[i] >> 4) & 0x0F];
        out[i * 3 + 1] = hex[mac[i] & 0x0F];
        out[i * 3 + 2] = ':';
    }
    out[17] = '\0';
}

void ieee80211_ssid_to_printable(const char *ssid, uint8_t ssid_len,
                                 char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }

    size_t n = ssid_len;
    if (n > out_size - 1) {
        n = out_size - 1;
    }

    for (size_t i = 0; i < n; i++) {
        const char c = ssid[i];
        out[i] = (c >= 0x20 && c <= 0x7E) ? c : '.';
    }
    out[n] = '\0';
}
