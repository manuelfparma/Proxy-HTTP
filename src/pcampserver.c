#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netutils.h>
#include <pcampserver.h>
#include <pcamputils.h>
#include <proxyargs.h>
#include <string.h>

extern proxy_arguments args;
extern proxy_settings settings;
extern connection_header connections;
extern http_dns_request doh_request_template;
extern ssize_t query_answer_length[PCAMP_QUERY_TYPE_COUNT];

static int parse_pcamp_request(uint8_t *request);
static bool is_passphrase_correct(uint8_t *hashed_request_pass);
static int resolve_pcamp_query(uint8_t *query_answer);
static ssize_t prepare_pcamp_query_response(uint8_t *query_answer);
static int resolve_pcamp_config();
static void parse_pcamp_config();
static void copy_response_header();
static bool doh_addr_config();
static void doh_port_config();

static pcamp_request_info current_request = {0};

static uint8_t request_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};
static uint8_t response_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};

static const char *passphrase = "12341234";

int setup_pcamp_sockets(int management_sockets[SOCK_COUNT]) {
	addr_info management_addr;

	for (int i = 0; i < SOCK_COUNT; i++) {
		if (i == IPV4_SOCK) management_addr.in4 = args.management_addr4;
		else if (i == IPV6_SOCK)
			management_addr.in6 = args.management_addr6;

		if (management_addr.addr.sa_family == 0) {
			management_sockets[i] = -1;
			continue;
		}

		management_sockets[i] = socket(management_addr.addr.sa_family, SOCK_DGRAM, 0);

		if (management_sockets[i] < 0) {
			logger(ERROR, "socket() for UDP socket failed: %s", strerror(errno));
			return -1;
		}

		if (setsockopt(management_sockets[i], SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
			logger(INFO, "setsockopt(): %s", strerror(errno));
			return -1;
		}

		if (i == IPV6_SOCK && setsockopt(management_sockets[i], IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0) {
			logger(INFO, "setsockopt(): %s", strerror(errno));
			return -1;
		}

		if (fcntl(management_sockets[i], F_SETFL, O_NONBLOCK) < 0) {
			close(management_sockets[i]);
			return -1;
		}

		socklen_t len = (management_addr.addr.sa_family == AF_INET6) ? sizeof(management_addr.in6) : sizeof(management_addr.in4);

		if (bind(management_sockets[i], &management_addr.addr, len) < 0) {
			close(management_sockets[i]);
			return -1;
		}
	}

	return 0;
}

void handle_pcamp_request(int fd) {

	memset(&current_request, 0, sizeof(current_request));

	struct sockaddr src_addr;
	socklen_t src_addr_len;

	ssize_t recv_bytes = recvfrom(fd, request_buffer, MAX_PCAMP_PACKET_LENGTH, 0, &src_addr, &src_addr_len);

	// Elegimos politica de best effort para casos de errores
	if (recv_bytes < 0) return;

	uint8_t status_code = parse_pcamp_request(request_buffer);

	copy_response_header();

	// considerando el header y el status code
	ssize_t response_len = PCAMP_HEADER_LENGTH + 1;

	if (status_code == PCAMP_SUCCESS) {
		uint8_t query_answer[QUERY_ANSWER_BUFFER_LENGTH] = {0};
		switch (current_request.method) {
			case PCAMP_QUERY:
				current_request.query.query_type = request_buffer[PCAMP_HEADER_LENGTH + SHA256_DIGEST_LENGTH];
				status_code = resolve_pcamp_query(query_answer);
				if (status_code != PCAMP_SUCCESS) break;

				response_len += prepare_pcamp_query_response(query_answer);
				break;
			case PCAMP_CONFIG:
				parse_pcamp_config();
				status_code = resolve_pcamp_config();
				break;
			default:
				// No debería pasar nunca
				return;
		}
	}

	response_buffer[PCAMP_HEADER_LENGTH] = status_code;

	// Elegimos politica de best effort para casos de send que bloquean / dan error
	sendto(fd, response_buffer, response_len, 0, &src_addr, src_addr_len);
}

static int parse_pcamp_request(uint8_t *request) {
	int i = 0;

	if (request[i] != SERVER_PCAMP_VERSION) return PCAMP_UNSUPPORTED_VERSION;

	i += SIZE_8;
	if ((request[i] & 1) != PCAMP_REQUEST) return PCAMP_BAD_REQUEST;

	current_request.method = ((request[i] & 2) >> 1);

	i += SIZE_8;
	current_request.id = ntohs(*(uint16_t *)(request + i));
	//	read_big_endian_16(&current_request.id, request + i, 1);

	i += SIZE_16;
	if (!is_passphrase_correct(request + i)) return PCAMP_AUTH_ERROR;

	return PCAMP_SUCCESS;
}

static int resolve_pcamp_query(uint8_t *query_answer) {
	uint64_t total_bytes;

	switch (current_request.query.query_type) {
		case TOTAL_CONNECTIONS_QUERY:
			*(uint64_t *)query_answer = hton64(connections.statistics.total_connections);
			//			write_big_endian_64(query_answer, &connections.statistics.total_connections, 1);
			break;
		case CURRENT_CONNECTIONS_QUERY:
			*(uint64_t *)query_answer = hton64(connections.current_clients);
			//			write_big_endian_64(query_answer, &connections.current_clients, 1);
			break;
		case TOTAL_BYTES_QUERY:
			total_bytes =
				connections.statistics.total_proxy_to_clients_bytes + connections.statistics.total_proxy_to_origins_bytes;
			*(uint64_t *)query_answer = hton64(total_bytes);
			//			write_big_endian_64(query_answer, &total_bytes, 1);
			break;
		case BYTES_TO_SERVER_QUERY:
			*(uint64_t *)query_answer = hton64(connections.statistics.total_proxy_to_origins_bytes);
			//			write_big_endian_64(query_answer, &connections.statistics.total_proxy_to_origins_bytes, 1);
			break;
		case BYTES_TO_CLIENT_QUERY:
			*(uint64_t *)query_answer = hton64(connections.statistics.total_proxy_to_clients_bytes);
			//			write_big_endian_64(query_answer, &connections.statistics.total_proxy_to_clients_bytes, 1);
			break;
		case BYTES_VIA_CONNECT_QUERY:
			*(uint64_t *)query_answer = hton64(connections.statistics.total_connect_method_bytes);
			//			write_big_endian_64(query_answer, &connections.statistics.total_connect_method_bytes, 1);
			break;
		default:
			return PCAMP_UNSUPPORTED_QUERY_TYPE;
	}
	return PCAMP_SUCCESS;
}

static ssize_t prepare_pcamp_query_response(uint8_t *query_answer) {
	uint8_t *body = response_buffer + PCAMP_HEADER_LENGTH + 1;
	ssize_t body_len = 0;
	body[body_len] = current_request.query.query_type;
	body_len += SIZE_8;

	ssize_t answer_len = query_answer_length[current_request.query.query_type];
	memcpy(body + body_len, query_answer, answer_len);
	body_len += answer_len;

	return body_len;
}

static void parse_pcamp_config() {
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
	// TODO: Validar los config values que llegan
	uint16_t aux;
	switch (config_type) {
		case BUFFER_SIZE_CONFIG:
			aux = ntohs(*(uint16_t *)current_request.config.config_value);
			//			read_big_endian_16(&aux, current_request.config.config_value, 1);
			if (aux == 0) return PCAMP_INVALID_CONFIG_VALUE;

			settings.io_buffer_size = aux;
			break;
		case MAX_CLIENTS_CONFIG:
			aux = ntohs(*(uint16_t *)current_request.config.config_value);
			//			read_big_endian_16(&aux, current_request.config.config_value, 1);
			if (aux > MAX_CLIENTS) return PCAMP_INVALID_CONFIG_VALUE;

			settings.max_clients = ntohs(*(uint16_t *)current_request.config.config_value);
			//			read_big_endian_16(&settings.max_clients, current_request.config.config_value, 1);
			break;
		case SNIFFING_CONFIG:
			if (*current_request.config.config_value != 0 && *current_request.config.config_value != 1)
				return PCAMP_INVALID_CONFIG_VALUE;

			settings.password_dissector = *current_request.config.config_value;
			break;
		case DOH_ADDR_CONFIG:
			if (!doh_addr_config()) return PCAMP_INVALID_CONFIG_VALUE;
			break;
		case DOH_PORT_CONFIG:
			doh_port_config();
			break;
		case DOH_HOSTNAME_CONFIG:
			strcpy(settings.doh_host, (char *)current_request.config.config_value);
			break;
		default:
			return PCAMP_UNSUPPORTED_CONFIG_TYPE;
	}

	return PCAMP_SUCCESS;
}

static bool doh_addr_config() {
	uint16_t port = 0;

	switch (settings.doh_addr_info.addr.sa_family) {
		case AF_INET:
			port = settings.doh_addr_info.in4.sin_port;
			break;
		case AF_INET6:
			port = settings.doh_addr_info.in6.sin6_port;
			break;
	}

	switch (current_request.config.config_value[0]) {
		case PCAMP_IPV4:
			settings.doh_addr_info.addr.sa_family = AF_INET;
			settings.doh_addr_info.in4.sin_addr = *(struct in_addr *)(current_request.config.config_value + 1);
			settings.doh_addr_info.in4.sin_port = port;
			break;
		case PCAMP_IPV6:
			settings.doh_addr_info.addr.sa_family = AF_INET6;
			settings.doh_addr_info.in6.sin6_addr = *(struct in6_addr *)(current_request.config.config_value + 1);
			settings.doh_addr_info.in6.sin6_port = port;
			break;
		default:
			return false;
	}

	return true;
}

static void doh_port_config() {
	switch (settings.doh_addr_info.addr.sa_family) {
		case AF_INET:
			settings.doh_addr_info.in4.sin_port = *(uint16_t *)current_request.config.config_value;
			break;
		case AF_INET6:
			settings.doh_addr_info.in6.sin6_port = *(uint16_t *)current_request.config.config_value;
			break;
	}
}

static bool is_passphrase_correct(uint8_t *hashed_request_pass) {
	uint8_t hashed_server_pass[SHA256_DIGEST_LENGTH];
	sha256_digest(passphrase, hashed_server_pass, strlen(passphrase));

	return strncmp((char *)hashed_server_pass, (char *)hashed_request_pass, SHA256_DIGEST_LENGTH) == 0;
}

static void copy_response_header() {
	response_buffer[0] = SERVER_PCAMP_VERSION;

	uint8_t flags = (current_request.method << 1) + PCAMP_RESPONSE;
	response_buffer[SIZE_8] = flags;

	*(uint16_t *)(response_buffer + 2 * SIZE_8) = htons(current_request.id);
	//	write_big_endian_16(response_buffer + 2 * SIZE_8, &current_request.id, 1);
}
