#include <arpa/inet.h>
#include <errno.h>
#include <logger.h>
#include <netutils.h>
#include <pcampargs.h>
#include <pcampclient.h>
#include <pcamputils.h>
#include <string.h>
#include <ctype.h>

// TODO: 0-	 printear menu de ayuda
// DONE: 1- 	 recibo la IP del proxy por STDIN
// DONE: 2- 	 armar socket
// DONE: 3- 	 pedis por STDIN si quiere configurar o consultar registros de acceso (multiple choice)
// DONE: 4- 	 pedis por STDIN que cosa quiere consultar / configurar
// DONE: 5- 	 pedis parametro de config
// DONE: 6- 	 armas paquete en binario y lo envias
// DONE: 7- 	 loader (print de '.' cada segundo)
// TODO: 8.1-  si no recibis respuesta en 3 seg -> retransmitis
// TODO: 8.2 - a los 10 seg timeout
// TODO: 9 -	 recibis la respuesta, la parseas, y la mostras
// TODO: 10 -  repetir 3

extern ssize_t config_value_length[PCAMP_CONFIG_TYPE_COUNT];
extern ssize_t query_answer_length[PCAMP_QUERY_TYPE_COUNT];

static long get_option(long options_count, char **options_strings, const char *instruction);
static bool is_option_valid(long options_count, char *input, ssize_t read_bytes, long *parsed_option);
static void print_prompt();
static void get_passphrase();
static void get_config_value(config_type type, char *value);
static ssize_t prepare_query_request(query_type type);
static ssize_t prepare_config_request(config_type type, char *value);
static bool parse_buffer_size(char *value);
static bool parse_doh_hostname(char *value, ssize_t bytes);
static bool parse_doh_port(char *value);
static bool parse_doh_addr(char *value);
static bool parse_max_clients(char *value);
static bool parse_sniffing(char *value);
static bool parse_pcamp_response(uint8_t *response, ssize_t recv_bytes);
static bool parse_query_body(uint8_t *body, ssize_t recv_bytes);
static void print_query_response();
static void flush_stdin(const char *buffer, ssize_t recv_bytes);

static addr_info current_addr = {0};
static pcamp_request_info current_request = {0};
static uint16_t current_id = 0;
static uint8_t io_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};
static pcamp_response_info current_response = {0};

int main(const int argc, char **argv) {
	char exit_client;
	setvbuf(stdout, NULL, _IONBF, 0);

	current_addr = parse_pcamp_args(argc, argv);

	printf("======= Proxy Configuration and Monitoring Protocol - Version 1.0 =======\n\n");

	while (1) {
		memset(&current_request, 0, sizeof(current_request));
		memset(&io_buffer, 0, PCAMP_BUFFER_SIZE);

		uint8_t method = get_option(PCAMP_METHOD_COUNT, method_strings, "Select a method:\n");
		current_request.method = method;

		uint8_t type;
		ssize_t packet_size = 0;
		char input[PCAMP_BUFFER_SIZE + 1];
		switch (method) {
			case PCAMP_QUERY:
				type = get_option(PCAMP_QUERY_TYPE_COUNT, query_type_strings, "Select query type:\n");
				get_passphrase();
				packet_size = prepare_query_request(type);
				break;
			case PCAMP_CONFIG:
				type = get_option(PCAMP_CONFIG_TYPE_COUNT, config_type_strings, "Select the configuration you wish to modify:\n");
				get_config_value(type, input);
				get_passphrase();
				packet_size = prepare_config_request(type, input);
				break;
			default:
				// No deberia pasar nunca
				break;
		}

		int server_sock = socket(current_addr.addr.sa_family, SOCK_DGRAM, 0);

		if (server_sock < 0) logger(FATAL, "%s", strerror(errno));

		socklen_t len;
		switch (current_addr.addr.sa_family) {
			case AF_INET:
				len = sizeof(current_addr.in4);
				break;
			case AF_INET6:
				len = sizeof(current_addr.in6);
				break;
		}

		fd_set read_fd_set;
		FD_ZERO(&read_fd_set);
		struct timeval timeout = {PCAMP_CLIENT_TIMEOUT, 0};
		// Wait con prints de '.' y timeouts

		printf("Waiting for response..");
		int ready_fds = 0;
		for (int i = 0; i < PCAMP_CLIENT_MAX_RECV_ATTEMPS && ready_fds == 0; i++) {
			sendto(server_sock, io_buffer, packet_size, 0, &current_addr.addr, len);
			printf(".");
			FD_SET(server_sock, &read_fd_set);
			timeout.tv_sec = PCAMP_CLIENT_TIMEOUT;
			ready_fds = select(server_sock + 1, &read_fd_set, NULL, NULL, &timeout);
		}

		printf("\n");

		if (ready_fds == 0) {
			printf("Timeout expired: no responses were received\n");
			goto EXIT_LABEL;
		}

		uint8_t response[MAX_PCAMP_PACKET_LENGTH] = {0};
		struct sockaddr server_addr;
		socklen_t server_addr_len;
		ssize_t recv_bytes = recvfrom(server_sock, response, MAX_PCAMP_PACKET_LENGTH, 0, &server_addr, &server_addr_len);

		printf("read %ld bytes\n", recv_bytes);

		if (!parse_pcamp_response(response, recv_bytes)) {
			printf("The response received from the server is not valid. Please try again\n");
			goto EXIT_LABEL;
		} else if (current_response.status_code != PCAMP_SUCCESS) {
			printf("%s\n", status_code_strings[current_response.status_code]);
			goto EXIT_LABEL;
		}

		switch (current_response.method) {
			case PCAMP_CONFIG:
				printf("Proxy HTTP configuration modified successfully\n");
				break;
			case PCAMP_QUERY:
				print_query_response();
				break;
		}

	EXIT_LABEL:
		printf("Do you wish to exit? [y/n]\n");
		recv_bytes = read(STDIN_FILENO, &exit_client, 1);
		flush_stdin(&exit_client, recv_bytes);
		switch (tolower(exit_client)) {
			case 'y':
				return 0;
			case 'n':
			default:
				break;
		}
	}

	return 0;
}

static void flush_stdin(const char *buffer, ssize_t recv_bytes) {
	int c = (unsigned char) buffer[recv_bytes-1];
	while (c != '\n' && c != EOF)
		c = getchar();
}

static void get_passphrase() {
	char input[PCAMP_BUFFER_SIZE];

	printf("Enter the passphrase:\n");
	print_prompt();

	ssize_t read_bytes = read(STDIN_FILENO, input, PCAMP_BUFFER_SIZE);
	flush_stdin(input, read_bytes);

	read_bytes--; // Para ignorar el \n

	sha256_digest(input, current_request.authorization, read_bytes);
}

static long get_option(long options_count, char **options_strings, const char *instruction) {
	ssize_t read_bytes;
	char input[PCAMP_BUFFER_SIZE + 1];
	bool is_input_valid = false;
	long parsed_option;

	while (!is_input_valid) {
		printf("%s", instruction);

		for (int i = 0; i < options_count; i++)
			printf("%d - %s\n", i, options_strings[i]);

		print_prompt();

		read_bytes = read(STDIN_FILENO, input, PCAMP_BUFFER_SIZE);
		flush_stdin(input, read_bytes);
		input[--read_bytes] = 0;

		if (is_option_valid(options_count, input, read_bytes, &parsed_option)) is_input_valid = true;
		else
			printf("Invalid option\n");
	}

	return parsed_option;
}

static bool is_option_valid(long options_count, char *input, ssize_t read_bytes, long *parsed_option) {
	ssize_t digit_count = 0;

	long aux = options_count;
	while (aux != 0) {
		digit_count++;
		aux /= 10;
	}

	if (read_bytes != digit_count) return false;

	*parsed_option = strtol(input, NULL, 10);

	if (*parsed_option == 0 && errno == EINVAL) return false;

	return *parsed_option < options_count && *parsed_option >= 0;
}

static void print_prompt() { printf("→ "); }

static void get_config_value(config_type type, char *value) {
	bool is_input_valid = false;

	while (!is_input_valid) {
		printf("Enter new value:\n");
		print_prompt();

		ssize_t read_bytes = read(STDIN_FILENO, value, PCAMP_BUFFER_SIZE);
		flush_stdin(value, read_bytes);
		value[read_bytes-1] = 0;

		switch (type) {
			case BUFFER_SIZE_CONFIG:
				if (parse_buffer_size(value)) is_input_valid = true;
				break;
			case MAX_CLIENTS_CONFIG:
				if (parse_max_clients(value)) is_input_valid = true;
				break;
			case SNIFFING_CONFIG:
				if (parse_sniffing(value)) is_input_valid = true;
				break;
			case DOH_ADDR_CONFIG:
				if (parse_doh_addr(value)) is_input_valid = true;
				break;
			case DOH_PORT_CONFIG:
				if (parse_doh_port(value)) is_input_valid = true;
				break;
			case DOH_HOSTNAME_CONFIG:
				if (parse_doh_hostname(value, read_bytes)) is_input_valid = true;
				break;
			default:
				break;
		}

		if (!is_input_valid) printf("Invalid value\n");
	}
}

static bool parse_buffer_size(char *value) {
	long parsed_buffer_size = strtol(value, NULL, 0);

	if ((parsed_buffer_size == 0 && errno == EINVAL) || parsed_buffer_size < MIN_PROXY_IO_BUFFER_SIZE ||
		parsed_buffer_size > MAX_PROXY_IO_BUFFER_SIZE)
		return false;

	uint16_t aux = parsed_buffer_size;

	current_request.config.config_value = malloc(config_value_length[BUFFER_SIZE_CONFIG]);
	*(uint16_t *)(current_request.config.config_value) = htons(aux);
//	write_big_endian_16(current_request.config.config_value, &aux, 1);

	return true;
}

static bool parse_max_clients(char *value) {
	long parsed_max_clients = strtol(value, NULL, 0);

	if ((parsed_max_clients == 0 && errno == EINVAL) || parsed_max_clients < MIN_PROXY_CLIENTS ||
		parsed_max_clients > MAX_PROXY_CLIENTS)
		return false;

	uint16_t aux = parsed_max_clients;

	current_request.config.config_value = malloc(config_value_length[MAX_CLIENTS_CONFIG]);
	*(uint16_t *)(current_request.config.config_value) = htons(aux);
//	write_big_endian_16(current_request.config.config_value, &aux, 1);

	return true;
}

static bool parse_sniffing(char *value) {
	long parsed_sniffing = strtol(value, NULL, 0);

	if ((parsed_sniffing == 0 && errno == EINVAL) || (parsed_sniffing != 0 && parsed_sniffing != 1)) return false;

	current_request.config.config_value = malloc(config_value_length[SNIFFING_CONFIG]);
	*current_request.config.config_value = parsed_sniffing;

	return true;
}

//	No llamamos a la funcion parse_ip_address de netutils.h porque nos armamos un formato especial
static bool parse_doh_addr(char *value) {
	struct in_addr ipv4;
	struct in6_addr ipv6;
	uint8_t parsed_ip[config_value_length[DOH_ADDR_CONFIG]];

	if (inet_pton(AF_INET, value, &ipv4) == 1) {
		// es ipv4
		parsed_ip[0] = PCAMP_IPV4;
		*(struct in_addr *)(parsed_ip + 1) = ipv4;
	} else if (inet_pton(AF_INET6, value, &ipv6) == 1) {
		// es ipv6
		parsed_ip[0] = PCAMP_IPV6;
		*(struct in6_addr *)(parsed_ip + 1) = ipv6;
	} else
		return false;

	current_request.config.config_value = calloc(config_value_length[DOH_ADDR_CONFIG], SIZE_8);
	memcpy(current_request.config.config_value, parsed_ip, config_value_length[DOH_ADDR_CONFIG]);

	return true;
}

static bool parse_doh_port(char *value) {
	uint16_t aux;

	if (!parse_port(value, &aux)) return false;

	current_request.config.config_value = malloc(config_value_length[DOH_PORT_CONFIG]);
	*(uint16_t *)current_request.config.config_value = htons(aux);
//	write_big_endian_16(current_request.config.config_value, &aux, 1);

	return true;
}

static bool parse_doh_hostname(char *value, ssize_t bytes) {
	if (bytes < MIN_DOH_HOSTNAME_LENGTH || bytes > MAX_DOH_HOSTNAME_LENGTH) return false;

	value[bytes] = 0;

	current_request.config.config_value = calloc(config_value_length[DOH_HOSTNAME_CONFIG], SIZE_8);
	memcpy(current_request.config.config_value, value, bytes);

	return true;
}

static ssize_t prepare_query_request(query_type type) {
	ssize_t i = 0;

	io_buffer[i++] = CLIENT_PCAMP_VERSION;
	io_buffer[i++] = (((uint8_t)(PCAMP_QUERY)) << 1) + PCAMP_REQUEST;

	current_request.id = current_id;
	*(uint16_t *)(io_buffer + i) = htons(current_id);
//	write_big_endian_16(io_buffer + i, &current_id, 1);
	i += 2;
	current_id++;

	memcpy(io_buffer + i, current_request.authorization, SHA256_DIGEST_LENGTH);

	i += SHA256_DIGEST_LENGTH;

	io_buffer[i++] = type;
	current_request.query.query_type = type;

	return i;
}

static ssize_t prepare_config_request(config_type type, char *value) {
	ssize_t i = 0;

	io_buffer[i++] = CLIENT_PCAMP_VERSION;
	io_buffer[i++] = (((uint8_t)(PCAMP_CONFIG)) << 1) + PCAMP_REQUEST;

	current_request.id = current_id;
	*(uint16_t *)(io_buffer + i) = htons(current_id);
//	write_big_endian_16(io_buffer + i, &current_id, 1);
	i += 2;
	current_id++;

	memcpy(io_buffer + i, current_request.authorization, SHA256_DIGEST_LENGTH);

	i += SHA256_DIGEST_LENGTH;

	io_buffer[i++] = type;

	memcpy(io_buffer + i, current_request.config.config_value, config_value_length[type]);
	free(current_request.config.config_value);

	i += config_value_length[type];

	return i;
}

static bool parse_pcamp_response(uint8_t *response, ssize_t recv_bytes) {
	//	Primero veo que tenga suficientes bytes para leer el header + status code
	if (recv_bytes < PCAMP_HEADER_LENGTH + SIZE_8) return false;
	else
		recv_bytes -= PCAMP_HEADER_LENGTH + SIZE_8;

	size_t response_idx = 0;
	uint8_t version = response[response_idx];
	if (version != CLIENT_PCAMP_VERSION) return false;

	response_idx += SIZE_8;
	uint8_t flags = response[response_idx];
	if ((flags & 1) != PCAMP_RESPONSE) return false;

	uint8_t method = (flags >> 1) & 1;
	if (method != current_request.method) return false;
	current_response.method = method;

	response_idx += SIZE_8;
	uint16_t id = ntohs(*(uint16_t *)(response + response_idx));
//	read_big_endian_16(&id, response + response_idx, 1);
	if (id != current_request.id) return false;

	response_idx += SIZE_16;
	uint8_t status_code = response[response_idx];
	current_response.status_code = status_code;

	if (status_code == PCAMP_SUCCESS) {
		response_idx += SIZE_8;

		switch (method) {
			case PCAMP_QUERY:
				if (!parse_query_body(response + response_idx, recv_bytes)) return -1;
				current_response.query.status_code = status_code;
				break;
			case PCAMP_CONFIG:
				//	Como el status_code fue Success, no tengo que hacer nada
				current_response.config.status_code = status_code;
				break;
			default:
				// No deberia pasar nunca
				break;
		}
	}

	return true;
}

static bool parse_query_body(uint8_t *body, ssize_t recv_bytes) {
	//	Necesito como minimo el query_type
	if (recv_bytes <= SIZE_8) return false;

	size_t response_idx = 0;

	uint8_t query_type = body[response_idx];

	if (query_type != current_request.query.query_type) return false;

	current_response.query.query_type = query_type;

	response_idx += SIZE_8;
	recv_bytes -= SIZE_8;

	ssize_t query_answer_size = query_answer_length[query_type];

	if (recv_bytes < query_answer_size) return false;

	current_response.query.response = &body[response_idx];

	return true;
}

static void print_query_response() {
	uint64_t value = 0;
	switch (current_response.query.query_type) {
		case TOTAL_CONNECTIONS_QUERY:
		case CURRENT_CONNECTIONS_QUERY:
		case TOTAL_BYTES_QUERY:
		case BYTES_TO_SERVER_QUERY:
		case BYTES_TO_CLIENT_QUERY:
		case BYTES_VIA_CONNECT_QUERY:
			value = ntoh64(*(uint64_t *)current_response.query.response);
//			read_big_endian_64(&value, current_response.query.response, 1);
			printf("%s: %" PRId64 "\n", query_type_strings[current_response.query.query_type], value);
		default:
			// No debería pasar nunca
			return;
	}
}
