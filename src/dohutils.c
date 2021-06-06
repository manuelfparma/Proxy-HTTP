#include <dohutils.h>
#include <errno.h>
#include <logger.h>
#include <stdlib.h>
#include <string.h>

int setup_doh_resources(ConnectionNode *node, int doh_fd) {
	node->data.doh = malloc(sizeof(doh_data));
	if (node->data.doh == NULL)
		goto EXIT;

	node->data.doh->doh_response_buffer = malloc(sizeof(buffer));
	if (node->data.doh->doh_response_buffer == NULL)
		goto FREE_DOH_DATA;

	node->data.doh->doh_response_buffer->data = malloc(MAX_DOH_PACKET_SIZE * SIZE_8);
	if (node->data.doh->doh_response_buffer->data == NULL)
		goto FREE_BUFFER;

	buffer_init(node->data.doh->doh_response_buffer, MAX_DOH_PACKET_SIZE, node->data.doh->doh_response_buffer->data);
	node->data.doh->sock = doh_fd;

	return 0;

FREE_BUFFER:
	free(node->data.doh->doh_response_buffer);
FREE_DOH_DATA:
	free(node->data.doh);
EXIT:
	logger(ERROR, "malloc(): %s", strerror(errno));
	return -1;
}

void read_big_endian_16(uint16_t *dest, uint8_t *src, size_t n) {
	for(size_t j = 0; j < n; j++) {
		*dest = 0;
		for (size_t i = 0; i < SIZE_16; i++) {
			*dest = *dest << 8;
			*dest += (uint16_t) *src;
			src += 1;
		}
		dest += SIZE_16;
	}
}

void read_big_endian_32(uint32_t *dest, uint8_t *src, size_t n) {
	for(size_t j = 0; j < n; j++) {
		*dest = 0;
		for (size_t i = 0; i < SIZE_32; i++) {
			*dest = *dest << 8;
			*dest += (uint32_t) *src;
			src += 1;
		}
		dest += SIZE_32;
	}
}

void write_big_endian_16(uint8_t *dest, uint16_t *src, size_t n) {
	for(size_t j = 0; j < n; j++) {
		*dest = 0;
		for (int i = SIZE_16 - 1; i >= 0; i--) {
			dest[i] = (uint8_t) *src;
			*src = *src >> 8;
		}
		dest += SIZE_16;
		src += SIZE_16;
	}
}

void write_big_endian_32(uint8_t *dest, uint32_t *src, size_t n) {
	for(size_t j = 0; j < n; j++) {
		*dest = 0;
		for (int i = SIZE_32 - 1; i >= 0; i--) {
			dest[i] = (uint8_t) *src;
			*src = *src >> 8;
		}
		dest += SIZE_32;
		src += SIZE_32;
	}
}
