#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netutils.h>
#include <openssl/sha.h>
#include <pcampserver.h>
#include <proxyargs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <logger.h>

// 1 - Abrir socket UDP en select apenas arranca el programa (usar puerto de args)
// 2 - Revisar si hay algo para leer antes de pasar por ConnectionNodes etc.
// 3 - Si hay algo, llamar a func. de handle
// 4 - You're here

extern proxy_arguments args;

static int parse_pcamp_request(uint8_t *request);
static ssize_t prepare_pcamp_response(uint8_t *response_buffer, uint8_t *request_buffer, int status_code);
static bool is_passphrase_correct(uint8_t *hashed_request_pass);
static int resolve_pcamp_query(uint8_t *response_buffer, uint8_t *request_buffer, ssize_t *response_len);
static int resolve_pcamp_config(uint8_t *response_buffer, uint8_t *request_buffer);

static struct {
    uint8_t method;
    uint16_t id;
    union {
        pcamp_query_request query;
        pcamp_config_request config;
    };
} current_request = {0};

static const char *passphrase = "12341234";

int create_pcamp_socket() {
	
	int pcamp_sock = socket(args.management_addr_info.addr.sa_family, SOCK_DGRAM, 0);

	if (pcamp_sock < 0)
		logger(FATAL, "create_pcamp_socket :: socket(): %s", strerror(errno));

	if (fcntl(pcamp_sock, F_SETFL, O_NONBLOCK) < 0){
		close(pcamp_sock);
		logger(FATAL, "create_pcamp_socket :: fcntl(): %s", strerror(errno));
	}

	addr_info management_addr = args.management_addr_info;
	socklen_t len = (management_addr.addr.sa_family == AF_INET6) ? sizeof(management_addr.in6) : sizeof(management_addr.in4);
	
	if (bind(pcamp_sock, &management_addr.addr, len) < 0) {
		close(pcamp_sock);
		logger(FATAL, "create_pcamp_socket :: bind(): %s", strerror(errno));
	}

	return pcamp_sock;
}

int handle_pcamp_request(int fd, fd_set *read_fd_set) { 
	
	if (FD_ISSET(fd, read_fd_set)) {
		memset(&current_request, 0, sizeof(current_request));

		uint8_t status_code;

		uint8_t request_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};
		uint8_t response_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};
		struct sockaddr src_addr;
		socklen_t len;

		ssize_t recv_bytes = recvfrom(fd, request_buffer, MAX_PCAMP_PACKET_LENGTH, 0, &src_addr, &len);

		if (recv_bytes < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				// FIXME: codigo de retorno, manejo de este caso
				return 0;
			
			// FIXME: codigo de retorno, manejo de este caso
			logger(ERROR, "handle_pcamp_request :: recvfrom(): %s", strerror(errno));
			return -1;
		}

		int status_code = parse_pcamp_request(request_buffer);

		ssize_t response_len = prepare_pcamp_response(response_buffer, request_buffer, status_code);
		
		// TODO enviar request
	}
	

	
	return 0; 
}

static int parse_pcamp_request(uint8_t *request) {
	int i = 0;

	if(request[i] != SERVER_PCAMP_VERSION)
		return PCAMP_UNSUPPORTED_VERSION;
	
	i += SIZE_8;

	if(request[i] & 1 != PCAMP_REQUEST)
		return PCAMP_BAD_REQUEST;
	
	current_request.method = (request[i] & 2 >> 1);
	
	i += SIZE_8;
	
	read_big_endian_16(&current_request.id, request + i, 1);

	i += SIZE_16;
	
	if (!is_passphrase_correct(request + i))
		return PCAMP_AUTH_ERROR;
	
	i += SHA256_DIGEST_LENGTH;

	return PCAMP_SUCCESS;
}

static ssize_t prepare_pcamp_response(uint8_t *response_buffer, uint8_t *request_buffer, int status_code) {
	ssize_t response_len = PCAMP_HEADER_LENGTH + SHA256_DIGEST_LENGTH;

	memcpy(response_buffer, request_buffer, response_len);

	response_buffer[response_len] = status_code;
	response_len++;

	if (status_code == PCAMP_SUCCESS) {
		switch (current_request.method) {
			case PCAMP_QUERY:
				status_code = resolve_pcamp_query(response_buffer, request_buffer, &response_len);
				break;
			case PCAMP_CONFIG:
				status_code = resolve_pcamp_config(response_buffer, request_buffer);
				break;
			default:
				break;
		}
	} 

	if (status_code != PCAMP_SUCCESS) {
		// FIXME: codigo de retorno, manejo de este caso
		response_buffer[PCAMP_HEADER_LENGTH + SHA256_DIGEST_LENGTH] = status_code;		// Tengo que cambiar al status de error
		return 1;
	}

	return response_len;
}

static int resolve_pcamp_query(uint8_t *response_buffer, uint8_t *request_buffer, ssize_t *response_len) {
	// TODO: siguiente flujo
	// 1 - Levanto query_type del request_buffer
	// 2 - Copio el query_type al response_buffer
	// 3 - Ejecuto la query (?????????)
	// 4 - Copio el resultado de la query al response_buffer
	// 5 - Retorno del size de lo que escribir
	return PCAMP_INTERNAL_SERVER_ERROR;
}

static int resolve_pcamp_config(uint8_t *response_buffer, uint8_t *request_buffer) {
	size_t request_index = PCAMP_HEADER_LENGTH + SHA256_DIGEST_LENGTH;
	uint8_t config_type = request_buffer[request_index];
	request_index++;

	if (config_type >= PCAMP_CONFIG_TYPE_COUNT)
		return PCAMP_UNSUPPORTED_CONFIG_TYPE;

	uint8_t byte_value;
	uint16_t word_value;
	uint8_t *array_value[MAX_CONFIG_VALUE_SIZE];	

	switch (config_value_size[config_type]) {
		case 1:
			byte_value = request_buffer[request_index];
			break;
		case 2:
			read_big_endian_16(&word_value, request_buffer + request_index, 1);
			break;
		default:
			memcpy(array_value, request_buffer + request_index, config_value_size[config_type]);
			break;
	}

	// TODO: estos cambios (CUIDADO: Las funciones deberian retornar un estado PCAMP_SUCCESS o de error)
	switch (config_type) {
		case BUFFER_SIZE_CONFIG:
			break;
		case MAX_CLIENTS_CONFIG:
			break;
		case SNIFFING_CONFIG:
			break;
		case DOH_ADDR_CONFIG:
			break;
		case DOH_PORT_CONFIG:
			break;
		case DOH_HOSTNAME_CONFIG:
			break;
		default:
			// No deberia pasar
			break;	
	}

	return PCAMP_SUCCESS;
}

static bool is_passphrase_correct(uint8_t *hashed_request_pass) {
	uint8_t hashed_server_pass[SHA256_DIGEST_LENGTH];
	sha256_digest(passphrase, hashed_server_pass, strlen(passphrase));

	return strncmp((char *)hashed_server_pass, (char *)hashed_request_pass, SHA256_DIGEST_LENGTH) == 0;
}
