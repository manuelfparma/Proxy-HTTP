#ifndef PCAMPUTILS_H
#define PCAMPUTILS_H

#include <openssl/sha.h>
#include <stdint.h>
#include <unistd.h>

#define MAX_PCAMP_PACKET_LENGTH 1024
#define PCAMP_HEADER_LENGTH 4
#define MAX_PROXY_CLIENTS 509
#define MIN_PROXY_CLIENTS 0
#define MAX_PROXY_IO_BUFFER_SIZE 65535
#define MIN_PROXY_IO_BUFFER_SIZE 1
#define MAX_DOH_HOSTNAME_LENGTH 255
#define MIN_DOH_HOSTNAME_LENGTH 1
#define MAX_CONFIG_VALUE_SIZE 256
#define PCAMP_IPV4 0
#define PCAMP_IPV6 1

// TODO: Comentar estructuras, enums y funciones

typedef enum { PCAMP_QUERY, PCAMP_CONFIG, PCAMP_METHOD_COUNT } pcamp_method;
typedef enum { PCAMP_REQUEST, PCAMP_RESPONSE } pcamp_op;

typedef enum {
	BUFFER_SIZE_CONFIG,
	MAX_CLIENTS_CONFIG,
	SNIFFING_CONFIG,
	DOH_ADDR_CONFIG,
	DOH_PORT_CONFIG,
	DOH_HOSTNAME_CONFIG,
	PCAMP_CONFIG_TYPE_COUNT
} config_type;

typedef enum {
	TOTAL_CONNECTIONS_QUERY,
	CURRENT_CONNECTIONS_QUERY,
	TOTAL_BYTES_QUERY,
	BYTES_TO_SERVER_QUERY,
	BYTES_TO_CLIENT_QUERY,
	BYTES_VIA_CONNECT_QUERY,
	PCAMP_QUERY_TYPE_COUNT
} query_type;

typedef enum {
	PCAMP_SUCCESS = 0,
	PCAMP_AUTH_ERROR,
	PCAMP_UNSUPPORTED_VERSION,
	PCAMP_UNSUPPORTED_QUERY_TYPE,
	PCAMP_UNSUPPORTED_CONFIG_TYPE,
	PCAMP_INVALID_CONFIG_VALUE,
	PCAMP_BAD_REQUEST,
	PCAMP_INTERNAL_SERVER_ERROR,
	PCAMP_STATUS_CODE_COUNT
} pcamp_status_code;

typedef struct {
	uint8_t version;
	uint8_t flags; // contiene en el bit menos significativo la operacion (current_request (0)/response (1)) y en el siguiente el
				   // metodo (query(0)/config(1))
	uint16_t id;
} pcamp_header;

typedef struct {
	uint8_t query_type;
} pcamp_query_request;

typedef struct {
	uint8_t config_type;
	uint8_t *config_value;
} pcamp_config_request;

typedef struct {
	uint8_t status_code;
	uint8_t query_type;
	uint8_t *response;
} pcamp_query_response;

typedef struct {
	uint8_t status_code;
} pcamp_config_response;

typedef struct {
	uint8_t method;
	uint16_t id;
	unsigned char authorization[SHA256_DIGEST_LENGTH];
	union {
		pcamp_query_request query;
		pcamp_config_request config;
	};
} pcamp_request_info;

void sha256_digest(const void *src, void *dest, size_t bytes);

#endif
