#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netutils.h>
#include <openssl/sha.h>
#include <pcampserver.h>
#include <pcamputils.h>
#include <proxyargs.h>
#include <string.h>

extern proxy_arguments args;
extern ssize_t query_answer_length[PCAMP_QUERY_TYPE_COUNT];

static int parse_pcamp_request(uint8_t *request);
static bool is_passphrase_correct(uint8_t *hashed_request_pass);
static int resolve_pcamp_query(uint8_t *response_buffer);
static ssize_t prepare_pcamp_query_response(int status_code, uint8_t *query_answer, uint8_t *buffer);
static int resolve_pcamp_config();
static void parse_pcamp_config(uint8_t *request_buffer);

static pcamp_request_info current_request = {0};

static const char *passphrase = "12341234";

int setup_pcamp_socket() {

	int pcamp_sock = socket(args.management_addr_info.addr.sa_family, SOCK_DGRAM, 0);

	if (pcamp_sock < 0) return -1;

	if (fcntl(pcamp_sock, F_SETFL, O_NONBLOCK) < 0) {
		close(pcamp_sock);
		return -1;
	}

	addr_info management_addr = args.management_addr_info;
	socklen_t len = (management_addr.addr.sa_family == AF_INET6) ? sizeof(management_addr.in6) : sizeof(management_addr.in4);

	if (bind(pcamp_sock, &management_addr.addr, len) < 0) {
		close(pcamp_sock);
		return -1;
	}

	return pcamp_sock;
}

int handle_pcamp_request(int fd) {

	memset(&current_request, 0, sizeof(current_request));

	uint8_t request_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};
	uint8_t response_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};
	struct sockaddr src_addr;
	socklen_t src_addr_len;

	ssize_t recv_bytes = recvfrom(fd, request_buffer, MAX_PCAMP_PACKET_LENGTH, 0, &src_addr, &src_addr_len);

	if (recv_bytes < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			// FIXME: codigo de retorno, manejo de este caso
			return 0;

		// FIXME: codigo de retorno, manejo de este caso
		logger(ERROR, "handle_pcamp_request :: recvfrom(): %s", strerror(errno));
		return -1;
	}

	uint8_t status_code = parse_pcamp_request(request_buffer);

	// considerando el header y el status code
	ssize_t response_len = 0;

	if (status_code == PCAMP_SUCCESS) {
		uint8_t query_answer[QUERY_ANSWER_BUFFER_LENGTH] = {0};
		switch (current_request.method) {
			case PCAMP_QUERY:
				current_request.query.query_type = request_buffer[PCAMP_HEADER_LENGTH + SHA256_DIGEST_LENGTH];
				status_code = resolve_pcamp_query(query_answer);
				response_len = prepare_pcamp_query_response(status_code, query_answer, response_buffer);
				break;
			case PCAMP_CONFIG:
				parse_pcamp_config(request_buffer);
				status_code = resolve_pcamp_config();
				response_buffer[PCAMP_HEADER_LENGTH] = status_code;
				response_len = PCAMP_HEADER_LENGTH + 1;
				break;
			default:
				// No debería pasar nunca
				// FIXME: codigo de retorno, manejo de este caso
				return -1;
				break;
		}
	}

	sendto(fd, response_buffer, response_len, 0, &src_addr, src_addr_len);
	// FIXME: codigo de retorno
	return 1;
}

static int parse_pcamp_request(uint8_t *request) {
	int i = 0;

	if (request[i] != SERVER_PCAMP_VERSION) return PCAMP_UNSUPPORTED_VERSION;

	i += SIZE_8;
	if ((request[i] & 1) != PCAMP_REQUEST) return PCAMP_BAD_REQUEST;

	current_request.method = ((request[i] & 2 ) >> 1);

	i += SIZE_8;
	read_big_endian_16(&current_request.id, request + i, 1);

	i += SIZE_16;
	if (!is_passphrase_correct(request + i)) return PCAMP_AUTH_ERROR;

	return PCAMP_SUCCESS;
}

static int resolve_pcamp_query(uint8_t *query_answer) {
	// TODO: siguiente flujo
	// 3 - Ejecuto la query (?????????)
	// 4 - Copio el resultado de la query al query_answer

	switch (current_request.query.query_type) {
		case TOTAL_CONNECTIONS_QUERY:
			break;
		case CURRENT_CONNECTIONS_QUERY:
			break;
		case TOTAL_BYTES_QUERY:
			break;
		case BYTES_TO_SERVER_QUERY:
			break;
		case BYTES_TO_CLIENT_QUERY:
			break;
		case BYTES_VIA_CONNECT_QUERY:
			break;
		default:
			// No debería pasar nunca
			return PCAMP_INTERNAL_SERVER_ERROR;
	}
	return PCAMP_SUCCESS;
}

static ssize_t prepare_pcamp_query_response(int status_code, uint8_t *query_answer, uint8_t *buffer) {
	ssize_t len = 0;

	// version
	buffer[len] = SERVER_PCAMP_VERSION;

	// flags
	len += SIZE_8;
	buffer[len] = (((uint8_t)PCAMP_QUERY) << 1) + PCAMP_RESPONSE;

	// id
	len += SIZE_8;
	write_big_endian_16(buffer + len, &current_request.id, 1);

	len += SIZE_16;
	buffer[len] = status_code;

	len += SIZE_8;

	if (status_code == PCAMP_SUCCESS) {
		ssize_t answer_len = query_answer_length[current_request.query.query_type];
		memcpy(buffer + len, query_answer, answer_len);
		len += answer_len;
	}

	return len;
}

static void parse_pcamp_config(uint8_t *request_buffer) {
	size_t request_index = PCAMP_HEADER_LENGTH + SHA256_DIGEST_LENGTH;

	uint8_t config_type = request_buffer[request_index];
	current_request.config.config_type = config_type;
	request_index++;

	current_request.config.config_value = &request_buffer[request_index];
}

static int resolve_pcamp_config() {
	uint8_t config_type = current_request.config.config_type;

	if (config_type >= PCAMP_CONFIG_TYPE_COUNT) return PCAMP_UNSUPPORTED_CONFIG_TYPE;

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
