#include <arpa/inet.h>
#include <errno.h>
#include <limits.h> /* LONG_MIN et al */
#include <netutils.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define NUM_BASE 10

bool parse_ip_address(const char *addr_str, uint16_t port, addr_info *addr) {
	if (inet_pton(AF_INET, addr_str, &addr->in4.sin_addr) == 1) {
		addr->addr.sa_family = AF_INET;
		addr->in4.sin_port = htons(port);
	} else if (inet_pton(AF_INET6, addr_str, &addr->in6.sin6_addr) == 1) {
		addr->addr.sa_family = AF_INET6;
		addr->in6.sin6_port = htons(port);
	} else
		return false;

	return true;
}

bool parse_port(const char *port_str, uint16_t *port) {
	char *end = 0;
	const long service_number = strtol(port_str, &end, NUM_BASE);

	if (end == port_str || *end != '\0' || ((service_number == LONG_MAX || service_number == LONG_MIN) && errno == ERANGE) ||
		service_number < 0 || service_number > USHRT_MAX) {
		return false;
	}

	*port = service_number;

	return true;
}

void read_big_endian_16(uint16_t *dest, uint8_t *src, size_t n) {
	for (size_t j = 0; j < n; j++) {
		*dest = 0;
		for (size_t i = 0; i < SIZE_16; i++) {
			*dest = *dest << 8;
			*dest += (uint16_t)*src;
			src += 1;
		}
		dest += SIZE_16;
	}
}

void read_big_endian_32(uint32_t *dest, uint8_t *src, size_t n) {
	for (size_t j = 0; j < n; j++) {
		*dest = 0;
		for (size_t i = 0; i < SIZE_32; i++) {
			*dest = *dest << 8;
			*dest += (uint32_t)*src;
			src += 1;
		}
		dest += SIZE_32;
	}
}

void read_big_endian_64(uint64_t *dest, uint8_t *src, size_t n) {
	for (size_t j = 0; j < n; j++) {
		*dest = 0;
		for (size_t i = 0; i < SIZE_64; i++) {
			*dest = *dest << 8;
			*dest += (uint64_t)*src;
			src += 1;
		}
		dest += SIZE_64;
	}
}

void write_big_endian_16(uint8_t *dest, uint16_t *src, size_t n) {
	for (size_t j = 0; j < n; j++) {
		*dest = 0;
		for (int i = SIZE_16 - 1; i >= 0; i--) {
			dest[i] = (uint8_t)*src;
			*src = *src >> 8;
		}
		dest += SIZE_16;
		src += SIZE_16;
	}
}

void write_big_endian_32(uint8_t *dest, uint32_t *src, size_t n) {
	for (size_t j = 0; j < n; j++) {
		*dest = 0;
		for (int i = SIZE_32 - 1; i >= 0; i--) {
			dest[i] = (uint8_t)*src;
			*src = *src >> 8;
		}
		dest += SIZE_32;
		src += SIZE_32;
	}
}

void write_big_endian_64(uint8_t *dest, uint64_t *src, size_t n) {
	for (size_t j = 0; j < n; j++) {
		*dest = 0;
		for (int i = SIZE_64 - 1; i >= 0; i--) {
			dest[i] = (uint8_t)*src;
			*src = *src >> 8;
		}
		dest += SIZE_64;
		src += SIZE_64;
	}
}

int strcmp_case_insensitive(char *str1, char *str2) {
	int i = 0, diff;
	for (; str1[i] != '\0' && str2[i] != '\0'; i++) {
		diff = (('A' <= str1[i] && str1[i] <= 'Z') ? str1[i] + 'a' - 'A' : str1[i]) -
			   (('A' <= str2[i] && str2[i] <= 'Z') ? str2[i] + 'a' - 'A' : str2[i]);
		// hago la resta de sus mayusculas para ser case-insensitive
		if (diff != 0) return diff;
	}
	if (str1[i] == '\0' && str2[i] == '\0') {
		return 0;
	} else if (str1[i] == '\0') {
		return -1;
	} else {
		return 1;
	}
}
