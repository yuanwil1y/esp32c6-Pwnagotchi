#include "capture_serial_protocol.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char s_base64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint32_t capture_serial_crc32(const uint8_t *data, size_t length)
{
    if (data == NULL && length != 0u) {
        return 0u;
    }
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8u; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return crc ^ UINT32_C(0xffffffff);
}

static size_t base64_size(size_t length)
{
    return ((length + 2u) / 3u) * 4u;
}

static size_t encode_base64(const uint8_t *data, size_t length, char *out)
{
    size_t written = 0u;
    for (size_t i = 0; i < length; i += 3u) {
        const size_t remain = length - i;
        const uint32_t a = data[i];
        const uint32_t b = remain > 1u ? data[i + 1u] : 0u;
        const uint32_t c = remain > 2u ? data[i + 2u] : 0u;
        const uint32_t value = (a << 16) | (b << 8) | c;
        out[written++] = s_base64[(value >> 18) & 0x3fu];
        out[written++] = s_base64[(value >> 12) & 0x3fu];
        out[written++] = remain > 1u ? s_base64[(value >> 6) & 0x3fu] : '=';
        out[written++] = remain > 2u ? s_base64[value & 0x3fu] : '=';
    }
    return written;
}

bool capture_serial_encode_data(char file_kind, uint32_t file_index,
                                uint64_t offset, const uint8_t *payload,
                                size_t payload_length, char *output,
                                size_t output_capacity,
                                size_t *output_length)
{
    if (output_length != NULL) {
        *output_length = 0u;
    }
    if ((file_kind != 'P' && file_kind != 'S') || payload == NULL ||
        payload_length == 0u || payload_length > CAPTURE_SERIAL_CHUNK_MAX ||
        output == NULL || output_length == NULL) {
        return false;
    }

    char header[112];
    const int header_len = snprintf(header, sizeof(header),
        "!PCAP,DATA,%c,%" PRIu32 ",%" PRIu64 ",%zu,%08" PRIX32 ",",
        file_kind, file_index, offset, payload_length,
        capture_serial_crc32(payload, payload_length));
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
        return false;
    }
    const size_t encoded_len = base64_size(payload_length);
    const size_t required = (size_t)header_len + encoded_len + 2u;
    if (required > output_capacity) {
        return false;
    }

    memcpy(output, header, (size_t)header_len);
    const size_t actual_encoded = encode_base64(
        payload, payload_length, output + (size_t)header_len);
    if (actual_encoded != encoded_len) {
        return false;
    }
    output[(size_t)header_len + encoded_len] = '\r';
    output[(size_t)header_len + encoded_len + 1u] = '\n';
    *output_length = required;
    return true;
}
