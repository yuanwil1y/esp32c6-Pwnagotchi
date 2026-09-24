#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CAPTURE_SERIAL_CHUNK_MAX 512u
#define CAPTURE_SERIAL_FRAME_MAX 800u

/* Encodes one binary chunk as an ASCII, CRC-protected USB Serial/JTAG line.
 * Output is untouched on validation/capacity failure; *output_length is zero. */
bool capture_serial_encode_data(char file_kind, uint32_t file_index,
                                uint64_t offset, const uint8_t *payload,
                                size_t payload_length, char *output,
                                size_t output_capacity,
                                size_t *output_length);

uint32_t capture_serial_crc32(const uint8_t *data, size_t length);
