// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <buffer.h>
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

uint64_t hton64(uint64_t host_64) {
	uint64_t result = 0;
	uint8_t *aux = (uint8_t *) &result;

	for(int i = SIZE_64 - 1; i >= 0; i--) {
		aux[i] = (uint8_t) host_64;
		host_64 = host_64 >> 8;
	}

	return result;
}

uint64_t ntoh64(uint64_t network_64) {
	uint64_t result = 0;
	uint8_t *aux = (uint8_t *) &network_64;

	for(int i = 0; i < SIZE_64 && (aux + i) != NULL; i++) {
		result = result << 8;
		result += aux[i];
	}

	return result;
}

void copy_from_buffer_to_buffer(buffer *dest, buffer *src) {
	ssize_t bytes_available = dest->limit - dest->write;
	ssize_t bytes_to_copy = src->write - src->read;
	ssize_t bytes_copied = (bytes_available > bytes_to_copy) ? bytes_to_copy : bytes_available;
	strncpy((char *)dest->write, (char *)src->read, bytes_copied);
	buffer_write_adv(dest, bytes_copied);
}
