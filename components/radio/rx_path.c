#include "rx_path.h"

#include <string.h>

/*
 * INTERMEDIATE Phase 1.5 commit: this file is the extracted pre-1.5 RX
 * callback flow behind the new rx_path seams, preserving the two defects
 * under review on purpose so the regression tests added in the next commit
 * can demonstrate them failing:
 *   - the rx_state gate runs AFTER slot allocation and does not return the
 *     slot (ownership leak),
 *   - the copy uses sig_len for every packet type, including MISC, whose
 *     payload is zero length per the IDF v5.4 contract.
 * The whitelist/ownership fix lands in the following commit and turns the
 * tests green without any further test changes.
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

    radio_packet_t *slot = NULL;
    if (!io->slot_alloc(io->ctx, &slot) || slot == NULL) {
        io->lock(io->ctx);
        stats->rx_dropped_pool++;
        io->unlock(io->ctx);
        return;
    }

    /* Pre-1.5 defect #1: error frames leak the slot they already hold. */
    if (view->rx_state != 0) {
        io->lock(io->ctx);
        stats->rx_state_errors++;
        io->unlock(io->ctx);
        return;
    }

    /* Pre-1.5 defect #2: sig_len drives the copy for every type, including
     * MISC (zero-length payload). Clamping to payload_len only keeps the
     * copy inside the buffer the adapter actually vouches for; it does not
     * whitelist types yet. */
    const uint16_t orig_len = view->sig_len;
    uint16_t copy_len = orig_len > RADIO_PACKET_MAX_LEN ? RADIO_PACKET_MAX_LEN
                                                        : orig_len;
    if (copy_len > view->payload_len) {
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

    /* Pre-1.5 formula: subtract the FCS only when the copy is complete.
     * Truncated copies keep partial FCS bytes in the parse window; the
     * Phase 1.5 tests fail on exactly this case. */
    if (pkt->length == pkt->orig_length && pkt->length >= 4) {
        return (uint16_t)(pkt->length - 4);
    }
    return pkt->length;
}
