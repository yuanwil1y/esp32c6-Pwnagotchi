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
 * INTERMEDIATE Phase 1.5 commit: the parse opts / status plumbing is in
 * place, but the walk below still has the pre-1.5 semantics on purpose so
 * the regression tests can demonstrate the defects:
 *   - a 1-byte tail in a COMPLETE body is silently ignored (no malformed),
 *   - a tail cut by a truncated capture is reported malformed instead of
 *     ie_walk_incomplete,
 *   - SSID all-zero bytes are stored as a name instead of hidden,
 *   - a duplicate SSID IE overwrites the first one,
 *   - DS Parameter with an out-of-range channel value is still accepted,
 *   - no protocol-version / order-bit / fragment guards on deep parse.
 * The Phase 1.5 fixes land in later commits and flip the tests without
 * changing them.
 */

/*
 * Strict IE walk over frame[ie_start .. length). For each element requires
 * two header bytes to exist and 2+len bytes to fit inside the frame; a
 * violation marks the observation malformed and stops the walk safely.
 */
static void walk_information_elements(const uint8_t *frame, uint16_t length,
                                      uint16_t ie_start, bool capture_truncated,
                                      ieee80211_ap_observation_t *ap_out,
                                      ieee80211_probe_req_observation_t *probe_out)
{
    uint32_t pos = ie_start;

    while (length - pos >= 2) {
        const uint8_t id = frame[pos];
        const uint8_t ie_len = frame[pos + 1];

        if ((uint32_t)ie_len > (uint32_t)(length - pos - 2)) {
            if (ap_out != NULL) {
                ap_out->malformed_ie = true;
                ap_out->ie_walk_incomplete = capture_truncated;
            }
            if (probe_out != NULL) {
                probe_out->malformed_ie = true;
                probe_out->ie_walk_incomplete = capture_truncated;
            }
            return;
        }

        const uint8_t *data = &frame[pos + 2];

        switch (id) {
        case IEEE80211_IE_SSID:
            if (ie_len > IEEE80211_SSID_MAX_LEN) {
                /* Illegal SSID length: treat as malformed, do not store. */
                if (ap_out != NULL) {
                    ap_out->malformed_ie = true;
                }
                if (probe_out != NULL) {
                    probe_out->malformed_ie = true;
                }
                return;
            }
            if (ap_out != NULL) {
                memcpy(ap_out->ssid, data, ie_len);
                ap_out->ssid[ie_len] = '\0';
                ap_out->ssid_len = ie_len;
                ap_out->hidden_ssid = ie_len == 0;
            }
            if (probe_out != NULL) {
                memcpy(probe_out->ssid, data, ie_len);
                probe_out->ssid[ie_len] = '\0';
                probe_out->ssid_len = ie_len;
                probe_out->wildcard_ssid = ie_len == 0;
            }
            break;
        case IEEE80211_IE_DS_PARAM:
            if (ap_out != NULL && ie_len >= 1) {
                ap_out->advertised_channel = data[0];
                ap_out->ds_param_present = true;
            }
            break;
        case IEEE80211_IE_RSN:
            if (ap_out != NULL) {
                ap_out->rsn_present = true;
            }
            break;
        case IEEE80211_IE_VENDOR:
            /* WPA vendor signature needs at least OUI(3) + type(1). */
            if (ap_out != NULL && ie_len >= 4 &&
                data[0] == 0x00 && data[1] == 0x50 && data[2] == 0xF2 &&
                data[3] == IEEE80211_WPA_OUI_TYPE) {
                ap_out->wpa_vendor_present = true;
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

    /* The walk only exits the loop cleanly; any 1-byte tail is currently
     * ignored here (pre-1.5 behavior, flagged by the Phase 1.5 tests). */
    (void)capture_truncated;
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

    memcpy(out->bssid, &frame[IEEE80211_MGMT_ADDR3_OFF], sizeof(out->bssid));

    /* Timestamp (8 bytes) is deliberately skipped, not stored. */
    out->beacon_interval = read_le16(&frame[IEEE80211_BEACON_INTERVAL_OFF]);
    out->capability = read_le16(&frame[IEEE80211_BEACON_CAP_OFF]);
    out->privacy = (out->capability & IEEE80211_CAP_PRIVACY) != 0;

    const bool capture_truncated = opts != NULL && opts->capture_truncated;
    walk_information_elements(frame, length,
                              IEEE80211_MGMT_HDR_LEN + IEEE80211_BEACON_FIXED_LEN,
                              capture_truncated, out, NULL);

    out->complete = !out->malformed_ie && !out->ie_walk_incomplete &&
                    !capture_truncated;
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

    memcpy(out->source, &frame[IEEE80211_MGMT_ADDR2_OFF], sizeof(out->source));

    const bool capture_truncated = opts != NULL && opts->capture_truncated;
    walk_information_elements(frame, length, IEEE80211_MGMT_HDR_LEN,
                              capture_truncated, NULL, out);

    out->complete = !out->malformed_ie && !out->ie_walk_incomplete &&
                    !capture_truncated;
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
