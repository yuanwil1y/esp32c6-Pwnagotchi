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

uint16_t rx_path_parse_length(const radio_packet_t *pkt)
{
    if (pkt == NULL) {
        return 0;
    }

    /*
     * MAC body of the pooled copy, i.e. the captured bytes minus the FCS:
     *   parse_len = min(captured, orig - 4)  when orig >= 4
     *   parse_len = captured                 when orig <  4
     * The subtraction happens in the wide type after the orig >= 4 check,
     * so it cannot underflow. A copy cut inside the MAC body keeps the
     * full copy; a copy that only misses (part of) the FCS excludes the
     * FCS bytes. The FCS never reaches the parser in either case.
     */
    uint32_t parse_len = pkt->length;
    if (pkt->orig_length >= 4) {
        const uint32_t body = (uint32_t)pkt->orig_length - 4;
        if (parse_len > body) {
            parse_len = body;
        }
    }
    return (uint16_t)parse_len;
}

bool rx_path_body_truncated(const radio_packet_t *pkt)
{
    if (pkt == NULL) {
        return false;
    }

    /*
     * True when MAC body bytes (not just FCS bytes) were lost. Only then
     * may the parser report its tail as incomplete instead of judging it.
     */
    if (pkt->orig_length < 4) {
        return false;
    }
    return pkt->length < (uint16_t)(pkt->orig_length - 4);
}
