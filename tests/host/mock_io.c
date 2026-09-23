#include "mock_io.h"

#include <string.h>

static mock_io_t *g_mock; /* tests are single-threaded */

static bool op_alloc(void *ctx, radio_packet_t **out)
{
    mock_io_t *m = *(mock_io_t **)ctx;
    if (m->fail_next_alloc) {
        m->fail_next_alloc = false;
        return false;
    }
    if (m->free_count == 0) {
        return false;
    }
    radio_packet_t *slot = m->free_list[--m->free_count];
    const int idx = mock_slot_index(m, slot);
    if (m->state[idx] != MOCK_SLOT_FREE) {
        return false; /* allocator handed out a non-free slot */
    }
    m->state[idx] = MOCK_SLOT_INFLIGHT; /* owned by the core right now */
    *out = slot;
    return true;
}

static bool op_push(void *ctx, radio_packet_t *slot)
{
    mock_io_t *m = *(mock_io_t **)ctx;
    if (m->fail_next_push) {
        m->fail_next_push = false;
        return false;
    }
    if (m->rx_count >= m->rx_capacity) {
        return false;
    }
    const int idx = mock_slot_index(m, slot);
    if (m->state[idx] != MOCK_SLOT_INFLIGHT) {
        return false; /* pushing a slot the core does not own */
    }
    m->rx_ring[(m->rx_head + m->rx_count) % RADIO_PACKET_POOL_SIZE] = slot;
    m->rx_count++;
    m->state[idx] = MOCK_SLOT_QUEUED;
    return true;
}

static bool op_return(void *ctx, radio_packet_t *slot)
{
    mock_io_t *m = *(mock_io_t **)ctx;
    const int idx = mock_slot_index(m, slot);
    if (idx < 0) {
        m->foreign_returns++;
        return false;
    }
    if (m->state[idx] == MOCK_SLOT_FREE) {
        m->double_returns++;
        return false;
    }
    if (m->state[idx] == MOCK_SLOT_QUEUED) {
        /* Removing a queued slot from the ring (enqueue-fail path). */
        for (int i = 0; i < m->rx_count; i++) {
            const int pos = (m->rx_head + i) % RADIO_PACKET_POOL_SIZE;
            if (m->rx_ring[pos] == slot) {
                for (int j = i; j < m->rx_count - 1; j++) {
                    const int a = (m->rx_head + j) % RADIO_PACKET_POOL_SIZE;
                    const int b = (m->rx_head + j + 1) % RADIO_PACKET_POOL_SIZE;
                    m->rx_ring[a] = m->rx_ring[b];
                }
                m->rx_count--;
                break;
            }
        }
    }
    m->state[idx] = MOCK_SLOT_FREE;
    m->free_list[m->free_count++] = slot;
    return true;
}

static void op_lock(void *ctx)
{
    (void)ctx;
}

static void op_unlock(void *ctx)
{
    (void)ctx;
}

const rx_path_io_t g_mock_io_ops = {
    .ctx = &g_mock,
    .slot_alloc = op_alloc,
    .rx_push = op_push,
    .slot_return = op_return,
    .lock = op_lock,
    .unlock = op_unlock,
};

void mock_init(mock_io_t *m)
{
    memset(m, 0, sizeof(*m));
    g_mock = m;
    for (int i = 0; i < RADIO_PACKET_POOL_SIZE; i++) {
        m->pool[i].packet_type = 0xFF;
        m->free_list[m->free_count++] = &m->pool[i];
        m->state[i] = MOCK_SLOT_FREE;
    }
    m->rx_capacity = RADIO_PACKET_POOL_SIZE;
}

void mock_set_rx_capacity(mock_io_t *m, int capacity)
{
    m->rx_capacity = capacity;
}

bool mock_rx_pop(mock_io_t *m, radio_packet_t **out)
{
    if (m->rx_count == 0) {
        return false;
    }
    radio_packet_t *slot = m->rx_ring[m->rx_head];
    m->rx_head = (m->rx_head + 1) % RADIO_PACKET_POOL_SIZE;
    m->rx_count--;
    m->state[mock_slot_index(m, slot)] = MOCK_SLOT_INFLIGHT;
    *out = slot;
    return true;
}

int mock_free_count(const mock_io_t *m)
{
    return m->free_count;
}

int mock_inflight_count(const mock_io_t *m)
{
    int n = 0;
    for (int i = 0; i < RADIO_PACKET_POOL_SIZE; i++) {
        if (m->state[i] == MOCK_SLOT_INFLIGHT) {
            n++;
        }
    }
    return n;
}

int mock_queued_count(const mock_io_t *m)
{
    return m->rx_count;
}

int mock_slot_index(const mock_io_t *m, const radio_packet_t *slot)
{
    if (slot < &m->pool[0] || slot >= &m->pool[RADIO_PACKET_POOL_SIZE]) {
        return -1;
    }
    return (int)(slot - &m->pool[0]);
}

bool mock_all_free(const mock_io_t *m)
{
    return m->free_count == RADIO_PACKET_POOL_SIZE &&
           m->rx_count == 0 && mock_inflight_count(m) == 0 &&
           m->double_returns == 0 && m->foreign_returns == 0;
}

rx_frame_view_t mock_view_mgmt_clean(const uint8_t *payload, uint16_t len)
{
    rx_frame_view_t v = {0};
    v.type = 0; /* WIFI_PKT_MGMT */
    v.channel = 6;
    v.rssi = -50;
    v.rx_state = 0;
    v.sig_len = len;
    v.payload = payload;
    v.payload_len = len;
    return v;
}
