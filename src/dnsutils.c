#include <dnsutils.h>

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
