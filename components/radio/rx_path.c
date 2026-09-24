#include "rx_path.h"

#include <string.h>

/*
 * Phase 1.5 RX front-end core. This is the whole decision flow of the
 * promiscuous RX callback; wifi_sniffer.c only translates the driver
 * structures. Order of operations (also the counter accounting order):
 *
 *   1. rx_total++
 *   2. type whitelist: only MGMT/CTRL/DATA carry payload; MISC and any
 *      unknown type count rx_misc and return WITHOUT touching payload.
 *      IDF v5.4 (esp_wifi_types.h): MISC payload is zero length even when
 *      sig_len is not. The core enforces this defensively, so it holds
 *      even with the MISC promiscuous filter enabled and even if a buggy
 *      adapter passes a non-zero payload_len.
 *   3. rx_state gate: error frames (rx_state != 0, per
 *      esp_wifi_types_native.h) count rx_state_errors and return BEFORE a
 *      slot is allocated - no slot can leak on error frames.
 *   4. slot_alloc failure: rx_dropped_pool++ (no slot held).
 *   5. bounded copy: min(sig_len, RADIO_PACKET_MAX_LEN, payload_len).
 *   6. rx_push failure: slot returned to the free pool, rx_dropped_queue++.
 *   7. rx_queued++, queue occupancy maintained.
 */

void rx_path_on_frame(const rx_path_io_t *io, rx_path_stats_t *stats,
                      const rx_frame_view_t *view)
{
    if (io == NULL || stats == NULL || view == NULL ||
        io->slot_alloc == NULL || io->rx_push == NULL ||
        io->slot_return == NULL || io->lock == NULL || io->unlock == NULL) {
        return;
    }

    io->lock(io->ctx);
    stats->rx_total++;
    io->unlock(io->ctx);

    switch (view->type) {
    case RX_PATH_TYPE_MGMT:
        io->lock(io->ctx);
        stats->rx_management++;
        io->unlock(io->ctx);
        break;
    case RX_PATH_TYPE_CTRL:
        io->lock(io->ctx);
        stats->rx_control++;
        io->unlock(io->ctx);
        break;
    case RX_PATH_TYPE_DATA:
        io->lock(io->ctx);
        stats->rx_data++;
        io->unlock(io->ctx);
        break;
    default:
        /* MISC and unknown types: counted, dropped, payload untouched. */
        io->lock(io->ctx);
        stats->rx_misc++;
        io->unlock(io->ctx);
        return;
    }

    if (view->rx_state != 0) {
        io->lock(io->ctx);
        stats->rx_state_errors++;
        io->unlock(io->ctx);
        return; /* no slot was taken for this frame */
    }

    radio_packet_t *slot = NULL;
    if (!io->slot_alloc(io->ctx, &slot) || slot == NULL) {
        io->lock(io->ctx);
        stats->rx_dropped_pool++;
        io->unlock(io->ctx);
        return;
    }

    const uint16_t orig_len = view->sig_len;
    uint16_t copy_len = orig_len > RADIO_PACKET_MAX_LEN ? RADIO_PACKET_MAX_LEN
                                                        : orig_len;
    if (copy_len > view->payload_len) {
        /* Never read beyond the bytes the adapter vouches for. */
        copy_len = view->payload_len;
    }

    slot->rssi = view->rssi;
    slot->channel = view->channel;
    slot->orig_length = orig_len;
    slot->length = copy_len;
    slot->packet_type = view->type;
    slot->rx_timestamp_us = view->rx_timestamp_us;
    if (copy_len > 0) {
        memcpy(slot->data, view->payload, copy_len);
    }

    if (!io->rx_push(io->ctx, slot)) {
        (void)io->slot_return(io->ctx, slot);
        io->lock(io->ctx);
        stats->rx_dropped_queue++;
        io->unlock(io->ctx);
        return;
    }

    io->lock(io->ctx);
    stats->rx_queued++;
    if (orig_len > RADIO_PACKET_MAX_LEN) {
        stats->rx_truncated++;
    }
    if (copy_len == 0) {
        stats->rx_no_payload++;
    }
    stats->queue_current++;
    if (stats->queue_current > stats->queue_peak) {
        stats->queue_peak = stats->queue_current;
    }
    io->unlock(io->ctx);
}

void rx_path_slot_release(const rx_path_io_t *io, rx_path_stats_t *stats,
                          radio_packet_t *slot)
{
    if (io == NULL || stats == NULL || slot == NULL ||
        io->slot_return == NULL || io->lock == NULL || io->unlock == NULL) {
        return;
    }

    io->lock(io->ctx);
    stats->rx_processed++;
    stats->queue_current--;
    io->unlock(io->ctx);

    (void)io->slot_return(io->ctx, slot);
}

static void rx_path_get_mac_lengths(const radio_packet_t *pkt,
                                    uint16_t *captured_mac_length,
                                    uint16_t *original_mac_length,
                                    bool *original_mac_length_valid,
                                    bool *capture_truncated)
{
    if (captured_mac_length != NULL) {
        *captured_mac_length = 0;
    }
    if (original_mac_length != NULL) {
        *original_mac_length = 0;
    }
    if (original_mac_length_valid != NULL) {
        *original_mac_length_valid = false;
    }
    if (capture_truncated != NULL) {
        *capture_truncated = false;
    }
    if (pkt == NULL) {
        return;
    }

    /* Phase 1.5 orig_length is driver-reported sig_len including FCS.
     * Compute the no-FCS lengths once, in a wide type and only after the
     * underflow guard. If orig_length < 4, retain the bounded copy length
     * for the legacy parser helper but declare original MAC length invalid. */
    uint32_t original_mac = 0;
    uint32_t captured_mac = pkt->length;
    const bool original_valid = pkt->orig_length >= 4;
    if (original_valid) {
        original_mac = (uint32_t)pkt->orig_length - 4u;
        if (captured_mac > original_mac) {
            captured_mac = original_mac;
        }
    }

    if (captured_mac_length != NULL) {
        *captured_mac_length = (uint16_t)captured_mac;
    }
    if (original_mac_length != NULL && original_valid) {
        *original_mac_length = (uint16_t)original_mac;
    }
    if (original_mac_length_valid != NULL) {
        *original_mac_length_valid = original_valid;
    }
    if (capture_truncated != NULL && original_valid) {
        *capture_truncated = captured_mac < original_mac;
    }
}

uint16_t rx_path_parse_length(const radio_packet_t *pkt)
{
    uint16_t captured_mac_length = 0;
    rx_path_get_mac_lengths(pkt, &captured_mac_length, NULL, NULL, NULL);
    return captured_mac_length;
}

bool rx_path_body_truncated(const radio_packet_t *pkt)
{
    bool capture_truncated = false;
    rx_path_get_mac_lengths(pkt, NULL, NULL, NULL, &capture_truncated);
    return capture_truncated;
}

bool rx_path_make_capture_view(const radio_packet_t *pkt,
                               rx_capture_view_t *out)
{
    if (pkt == NULL || out == NULL) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->mac_bytes = pkt->data;
    rx_path_get_mac_lengths(pkt, &out->captured_mac_length,
                            &out->original_mac_length,
                            &out->original_mac_length_valid,
                            &out->capture_truncated);
    if (out->captured_mac_length > RADIO_PACKET_MAX_LEN) {
        out->captured_mac_length = RADIO_PACKET_MAX_LEN;
    }
    if (out->original_mac_length_valid) {
        /* Include the view's own storage bound in its truncation promise. */
        out->capture_truncated =
            out->captured_mac_length < out->original_mac_length;
    }
    out->rx_channel = pkt->channel;
    out->rssi = pkt->rssi;
    out->rx_timestamp_us = pkt->rx_timestamp_us;
    out->fcs_policy = RX_CAPTURE_FCS_DRIVER_LENGTH_INCLUDES_STRIP_FROM_VIEW;
    return true;
}
