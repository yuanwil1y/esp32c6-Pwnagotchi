#include "capture_serial_protocol.h"

#include <stdio.h>
#include <string.h>

static unsigned s_failed;

#define CHECK(c) do { \
    if (!(c)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        ++s_failed; \
    } \
} while (0)

static void test_known_vector(void)
{
    static const uint8_t bytes[] = { 'a', 'b', 'c' };
    static const char expected[] =
        "!PCAP,DATA,P,0,0,3,352441C2,YWJj\r\n";
    char output[CAPTURE_SERIAL_FRAME_MAX];
    size_t length = 0u;

    CHECK(capture_serial_crc32(bytes, sizeof(bytes)) == UINT32_C(0x352441c2));
    CHECK(capture_serial_encode_data('P', 0u, 0u, bytes, sizeof(bytes),
                                     output, sizeof(output), &length));
    CHECK(length == sizeof(expected) - 1u);
    CHECK(memcmp(output, expected, sizeof(expected) - 1u) == 0);
}

static void test_index_offset_padding(void)
{
    static const uint8_t bytes[] = { 0u, 1u, 2u, 3u };
    char output[CAPTURE_SERIAL_FRAME_MAX + 1u];
    size_t length = 0u;

    CHECK(capture_serial_encode_data('S', 12u, UINT64_C(0x100000005),
                                     bytes, sizeof(bytes), output,
                                     sizeof(output) - 1u, &length));
    output[length] = '\0';
    CHECK(length > 0u);
    static const char prefix[] = "!PCAP,DATA,S,12,4294967301,4,";
    CHECK(strncmp(output, prefix, sizeof(prefix) - 1u) == 0);
    CHECK(strstr(output, "AAECAw==\r\n") != NULL);
}

static void test_max_chunk_and_validation(void)
{
    uint8_t bytes[CAPTURE_SERIAL_CHUNK_MAX];
    char output[CAPTURE_SERIAL_FRAME_MAX];
    char untouched[CAPTURE_SERIAL_FRAME_MAX];
    size_t length = 99u;
    memset(bytes, 0xa5, sizeof(bytes));
    memset(untouched, 0x5a, sizeof(untouched));
    memcpy(output, untouched, sizeof(output));

    CHECK(capture_serial_encode_data('P', 9999u, UINT64_MAX, bytes,
                                     sizeof(bytes), output, sizeof(output),
                                     &length));
    CHECK(length > CAPTURE_SERIAL_CHUNK_MAX &&
          length < CAPTURE_SERIAL_FRAME_MAX);

    memcpy(output, untouched, sizeof(output));
    length = 99u;
    CHECK(!capture_serial_encode_data('X', 0u, 0u, bytes, 1u, output,
                                      sizeof(output), &length));
    CHECK(length == 0u);
    CHECK(memcmp(output, untouched, sizeof(output)) == 0);

    length = 99u;
    CHECK(!capture_serial_encode_data('P', 0u, 0u, bytes,
                                      CAPTURE_SERIAL_CHUNK_MAX + 1u,
                                      output, sizeof(output), &length));
    CHECK(length == 0u);

    length = 99u;
    CHECK(!capture_serial_encode_data('P', 0u, 0u, bytes, 1u, output, 1u,
                                      &length));
    CHECK(length == 0u);
}

int main(void)
{
    test_known_vector();
    test_index_offset_padding();
    test_max_chunk_and_validation();
    if (s_failed != 0u) {
        fprintf(stderr, "%u capture serial protocol test(s) failed\n", s_failed);
        return 1;
    }
    puts("capture serial protocol: all tests passed");
    return 0;
}
