/* Phase 1.5 hostile-input isolation: frames whose (buggy) handling would
 * read memory the driver does not vouch for. Kept in its own binary so a
 * pre-fix crash cannot mask the other suites' results. */
#include "rx_path.h"

#include <stdio.h>
#include <string.h>

#include "mock_io.h"
#include "runner.h"

/* MISC with a NULL payload but a non-zero payload_len: any payload read
 * faults (plain build segfaults, ASan build reports the error). The
 * whitelist must return before the copy. */
static void t_misc_null_payload_never_read(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    rx_frame_view_t misc = mock_view_mgmt_clean(NULL, 0);
    misc.type = 3; /* WIFI_PKT_MISC */
    misc.sig_len = 100;
    misc.payload = NULL;
    misc.payload_len = 100; /* bogus, and unreadable */

    rx_path_on_frame(&g_mock_io_ops, &st, &misc);

    CHECK(st.rx_misc == 1);
    CHECK(st.rx_queued == 0);
    CHECK(mock_all_free(&m));
}

/* Unknown type value (driver extensions beyond 0..3): same whitelist. */
static void t_unknown_type_never_read(void)
{
    mock_io_t m;
    mock_init(&m);

    rx_path_stats_t st = {0};

    rx_frame_view_t weird = mock_view_mgmt_clean(NULL, 0);
    weird.type = 200; /* out of the known wifi_promiscuous_pkt_type_t set */
    weird.sig_len = 64;
    weird.payload = NULL;
    weird.payload_len = 64;

    rx_path_on_frame(&g_mock_io_ops, &st, &weird);

    CHECK(st.rx_misc == 1);
    CHECK(st.rx_queued == 0);
    CHECK(mock_all_free(&m));
}

int main(void)
{
    test_register("hostile_misc_null_payload_never_read",
                  t_misc_null_payload_never_read);
    test_register("hostile_unknown_type_never_read",
                  t_unknown_type_never_read);
    return test_run_all();
}
