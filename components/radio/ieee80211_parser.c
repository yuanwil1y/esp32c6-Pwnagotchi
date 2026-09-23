#include "ieee80211_parser.h"

#include <stddef.h>

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
