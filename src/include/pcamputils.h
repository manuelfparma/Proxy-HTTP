#ifndef PCAMPUTILS_H
#define PCAMPUTILS_H

#include <openssl/sha.h>
#include <stdint.h>

#define PCAMP_VERSION 1
#define MAX_PCAMP_PACKET_LENGTH 1024
#define MAX_PROXY_CLIENTS 510
#define MIN_PROXY_CLIENTS 0
#define MAX_PROXY_IO_BUFFER_SIZE 65535
#define MIN_PROXY_IO_BUFFER_SIZE 1
#define MAX_DOH_HOSTNAME_LENGTH 255
#define MIN_DOH_HOSTNAME_LENGTH 1
#define PCAMP_IPV4 0
#define PCAMP_IPV6 1

typedef enum { QUERY, CONFIG, METHOD_COUNT } pcamp_method;
typedef enum { REQUEST, RESPONSE } pcamp_op;

typedef enum {
	BUFFER_SIZE_CONFIG,
	MAX_CLIENTS_CONFIG,
	SNIFFING_CONFIG,
	DOH_ADDR_CONFIG,
	DOH_PORT_CONFIG,
	DOH_HOSTNAME_CONFIG,
	CONFIG_TYPE_COUNT
} config_type;

typedef enum {
	TOTAL_CONNECTIONS_QUERY,
	CURRENT_CONNECTIONS_QUERY,
	TOTAL_BYTES_QUERY,
	BYTES_TO_SERVER_QUERY,
	BYTES_TO_CLIENT_QUERY,
	BYTES_VIA_CONNECT_QUERY,
	QUERY_TYPE_COUNT
} query_type;

ssize_t config_value_size[CONFIG_TYPE_COUNT] = {2, 2, 1, 17, 2, 256};

typedef struct {
	uint8_t version;
	uint8_t flags; // contiene en el bit menos significativo la operacion (current_request (0)/response (1)) y en el siguiente el metodo
				   // (query(0)/config(1))
	uint16_t id;
} pcamp_header;

typedef struct {
	unsigned char authorization[SHA256_DIGEST_LENGTH];
	uint8_t query_type;
} pcamp_query_request;

typedef struct {
	unsigned char authorization[SHA256_DIGEST_LENGTH];
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

#endif
