#pragma once

#include <stdbool.h>

#include "radio_types.h"
#include "rx_path.h"

/*
 * Mock environment for the rx_path core: a real radio_packet_t pool of
 * RADIO_PACKET_POOL_SIZE slots plus bookkeeping queues, tracking the
 * ownership state of every slot so leaks, double returns and lost slots
 * are detectable.
 *
 *   slot state: FREE (in free list) / QUEUED (in rx ring) / INFLIGHT
 *   (popped by the simulated consumer, not yet released)
 *
 * Invariant at any quiescent point:
 *   free_count + queued + inflight == RADIO_PACKET_POOL_SIZE
 */

typedef enum {
    MOCK_SLOT_FREE = 0,
    MOCK_SLOT_QUEUED = 1,
    MOCK_SLOT_INFLIGHT = 2,
} mock_slot_state_t;

typedef struct {
    radio_packet_t pool[RADIO_PACKET_POOL_SIZE];
    mock_slot_state_t state[RADIO_PACKET_POOL_SIZE];

    radio_packet_t *free_list[RADIO_PACKET_POOL_SIZE];
    int free_count;

    radio_packet_t *rx_ring[RADIO_PACKET_POOL_SIZE];
    int rx_head;
    int rx_count;
    int rx_capacity; /* queue depth; may be < pool size to model a full queue */

    bool fail_next_alloc;
    bool fail_next_push;
    int double_returns;
    int foreign_returns; /* slot_return of a pointer outside the pool */
} mock_io_t;

/* The io struct the tests pass into rx_path_on_frame(). */
extern const rx_path_io_t g_mock_io_ops;

void mock_init(mock_io_t *m);
void mock_set_rx_capacity(mock_io_t *m, int capacity);

/* Simulated consumer side. */
bool mock_rx_pop(mock_io_t *m, radio_packet_t **out);

/* Bookkeeping checks used by tests. */
int mock_free_count(const mock_io_t *m);
int mock_inflight_count(const mock_io_t *m);
int mock_queued_count(const mock_io_t *m);
int mock_slot_index(const mock_io_t *m, const radio_packet_t *slot);
bool mock_all_free(const mock_io_t *m);

/* Convenience frame builders for rx_frame_view_t. */
rx_frame_view_t mock_view_mgmt_clean(const uint8_t *payload, uint16_t len);
