/* Phase 1.5 host regression tests: channel table builder, error
 * classification and bounded-failure policy (production code). */
#include "hopper_policy.h"

#include <stdio.h>
#include <string.h>

#include "runner.h"

static bool list_is(const uint8_t *got, uint8_t count, int first, int last)
{
    if (count != (uint8_t)(last - first + 1)) {
        return false;
    }
    for (int ch = first; ch <= last; ch++) {
        if (got[ch - first] != (uint8_t)ch) {
            return false;
        }
    }
    return true;
}

static void t_build_from_country(void)
{
    uint8_t list[HOPPER_MAX_CHANNELS];
    uint8_t n = 0;

    /* World-safe default country "01" per IDF: schan=1 nchan=11. */
    CHECK(hopper_build_list_from_country(1, 11, list, HOPPER_MAX_CHANNELS, &n));
    CHECK(list_is(list, n, 1, 11));

    /* e.g. CN: 13 channels. */
    CHECK(hopper_build_list_from_country(1, 13, list, HOPPER_MAX_CHANNELS, &n));
    CHECK(list_is(list, n, 1, 13));

    /* Sub-range: schan=6 nchan=4 -> 6..9. */
    CHECK(hopper_build_list_from_country(6, 4, list, HOPPER_MAX_CHANNELS, &n));
    CHECK(list_is(list, n, 6, 9));

    /* Custom window: 3..7. */
    CHECK(hopper_build_list_from_country(3, 5, list, HOPPER_MAX_CHANNELS, &n));
    CHECK(list_is(list, n, 3, 7));

    /* Invalid tables -> caller applies the 1..11 fallback. */
    CHECK(!hopper_build_list_from_country(0, 11, list, HOPPER_MAX_CHANNELS, &n));
    CHECK(n == 0);
    CHECK(!hopper_build_list_from_country(1, 0, list, HOPPER_MAX_CHANNELS, &n));
    CHECK(!hopper_build_list_from_country(20, 3, list, HOPPER_MAX_CHANNELS, &n));
    /* Overflow guard: computed in int, rejected before narrowing. */
    CHECK(!hopper_build_list_from_country(1, 200, list, HOPPER_MAX_CHANNELS, &n));

    hopper_build_fallback_list(list, HOPPER_MAX_CHANNELS, &n);
    CHECK(list_is(list, n, HOPPER_FALLBACK_FIRST, HOPPER_FALLBACK_LAST));
}

static void t_err_classify(void)
{
    /* Mirrored IDF v5.4 values (esp_err.h / esp_wifi.h). */
    CHECK(hopper_err_classify(0) == HOPPER_ERR_OK);
    CHECK(hopper_err_classify(0x102) == HOPPER_ERR_INVALID_CHANNEL); /* ESP_ERR_INVALID_ARG */
    CHECK(hopper_err_classify(0x3001) == HOPPER_ERR_DRIVER_DEAD);    /* ESP_ERR_WIFI_NOT_INIT */
    CHECK(hopper_err_classify(0x3002) == HOPPER_ERR_DRIVER_DEAD);    /* ESP_ERR_WIFI_NOT_STARTED */
    CHECK(hopper_err_classify(0x107) == HOPPER_ERR_TRANSIENT);       /* ESP_ERR_TIMEOUT */
    CHECK(hopper_err_classify(0x103) == HOPPER_ERR_TRANSIENT);       /* ESP_ERR_INVALID_STATE */
    CHECK(hopper_err_classify(0x300B) == HOPPER_ERR_TRANSIENT);      /* ESP_ERR_WIFI_TIMEOUT */
    CHECK(hopper_err_classify(-1) == HOPPER_ERR_TRANSIENT);
}

static void t_bounded_failure_policy(void)
{
    hopper_channel_health_t h = {0};

    /* Transient failures: bounded retries, then skip for this pass. */
    CHECK(hopper_note_failure(&h, HOPPER_ERR_TRANSIENT) == HOP_ACT_CONTINUE);
    CHECK(hopper_note_failure(&h, HOPPER_ERR_TRANSIENT) == HOP_ACT_CONTINUE);
    CHECK(hopper_note_failure(&h, HOPPER_ERR_TRANSIENT) == HOP_ACT_SKIP_PASS);

    /* Success resets the counter. */
    hopper_note_success(&h);
    CHECK(h.consecutive_transient == 0);
    CHECK(hopper_note_failure(&h, HOPPER_ERR_TRANSIENT) == HOP_ACT_CONTINUE);

    /* Deterministic invalid channel: retire immediately. */
    CHECK(hopper_note_failure(&h, HOPPER_ERR_INVALID_CHANNEL) == HOP_ACT_RETIRE);

    /* Driver dead: stop, never retire-all. */
    CHECK(hopper_note_failure(&h, HOPPER_ERR_DRIVER_DEAD) == HOP_ACT_STOP);
}

static void t_log_throttle(void)
{
    hopper_channel_health_t h = {0};
    h.last_log_ms = 1000;

    CHECK(!hopper_log_due(&h, 2000));
    CHECK(!hopper_log_due(&h, 5999));
    CHECK(hopper_log_due(&h, 6001));
    CHECK(!hopper_log_due(&h, 6100));
    CHECK(hopper_log_due(&h, 11500));
}

int main(void)
{
    test_register("hopper_build_from_country", t_build_from_country);
    test_register("hopper_err_classify", t_err_classify);
    test_register("hopper_bounded_failure_policy", t_bounded_failure_policy);
    test_register("hopper_log_throttle", t_log_throttle);
    return test_run_all();
}
