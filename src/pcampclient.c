#include <arpa/inet.h>
#include <errno.h>
#include <logger.h>
#include <netinet/in.h>
#include <netutils.h>
#include <openssl/sha.h>
#include <pcampargs.h>
#include <pcampclient.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// TODO: 0-	 printear menu de ayuda
// DONE: 1- 	 recibo la IP del proxy por STDIN
// DONE: 2- 	 armar socket
// DONE: 3- 	 pedis por STDIN si quiere configurar o consultar registros de acceso (multiple choice)
// DONE: 4- 	 pedis por STDIN que cosa quiere consultar / configurar
// DONE: 5- 	 pedis parametro de config
// TODO: 6- 	 armas paquete en binario y lo envias
// TODO: 7- 	 loader (print de '.' cada segundo)
// TODO: 8.1-  si no recibis respuesta en 3 seg -> retransmitis
// TODO: 8.2 - a los 10 seg timeout
// TODO: 9 -	 recibis la respuesta, la parseas, y la mostras
// TODO: 10 -  repetir 3


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
static void copy_config_value(config_type type, void *value);

static addr_info current_addr = {0};
static pcamp_config_request current_request = {0};
static uint16_t current_id = 0;
static uint8_t io_buffer[MAX_PCAMP_PACKET_LENGTH] = {0};

int main(const int argc, char **argv) {
	current_addr = parse_pcamp_args(argc, argv);

	printf("======= Proxy Configuration and Monitoring Protocol - Version 1.0 =======\n\n ");

	memset(&current_request, 0, sizeof(current_request));
	memset(&io_buffer, 0, PCAMP_BUFFER_SIZE);

	get_passphrase();

	uint8_t method = get_option(METHOD_COUNT, method_strings, "Select a method:\n");

	uint8_t type;
	ssize_t packet_size = 0;
	char input[PCAMP_BUFFER_SIZE + 1];
	switch (method) {
		case QUERY:
			type = get_option(QUERY_TYPE_COUNT, query_type_strings, "Select query type:\n");
			packet_size = prepare_query_request(type);
			break;
		case CONFIG:
			type = get_option(CONFIG_TYPE_COUNT, config_type_strings, "Select the configuration you wish to modify:\n");
			get_config_value(type, input);
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

	sendto(server_sock, io_buffer, packet_size, 0, &current_addr.addr, len);
}

static void get_passphrase() {
	char input[PCAMP_BUFFER_SIZE];

	printf("Please, enter the passphrase:\n");
	print_prompt();

	ssize_t read_bytes = read(STDIN_FILENO, input, PCAMP_BUFFER_SIZE);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, input, read_bytes);
	SHA256_Final(current_request.authorization, &sha256);
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
		input[read_bytes] = 0;

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
		value[read_bytes] = 0;

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
	copy_config_value(BUFFER_SIZE_CONFIG, &aux);

	return true;
}

static bool parse_max_clients(char *value) {
	long parsed_max_clients = strtol(value, NULL, 0);

	if ((parsed_max_clients == 0 && errno == EINVAL) || parsed_max_clients < MIN_PROXY_CLIENTS ||
		parsed_max_clients > MAX_PROXY_CLIENTS)
		return false;

	uint16_t aux = parsed_max_clients;
	copy_config_value(MAX_CLIENTS_CONFIG, &aux);

	return true;
}

static bool parse_sniffing(char *value) {
	long parsed_sniffing = strtol(value, NULL, 0);

	if ((parsed_sniffing == 0 && errno == EINVAL) || (parsed_sniffing != 0 && parsed_sniffing != 1)) return false;

	uint8_t aux = parsed_sniffing;
	copy_config_value(SNIFFING_CONFIG, &aux);

	return true;
}

static bool parse_doh_addr(char *value) {
	struct in_addr ipv4;
	struct in6_addr ipv6;
	uint8_t parsed_ip[config_value_size[DOH_ADDR_CONFIG]];

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

	copy_config_value(DOH_ADDR_CONFIG, parsed_ip);

	return true;
}

static bool parse_doh_port(char *value) {
	long parsed_port = strtol(value, NULL, 0);

	if ((parsed_port == 0 && errno == EINVAL) || parsed_port < 0 || parsed_port > MAX_PORT) return false;

	uint16_t aux = parsed_port;
	copy_config_value(DOH_PORT_CONFIG, &aux);

	return true;
}

static bool parse_doh_hostname(char *value, ssize_t bytes) {
	if (bytes < MIN_DOH_HOSTNAME_LENGTH || bytes > MAX_DOH_HOSTNAME_LENGTH) return false;

	value[bytes] = 0;

	copy_config_value(DOH_HOSTNAME_CONFIG, value);

	return true;
}

static void copy_config_value(config_type type, void *value) {
	size_t value_size = config_value_size[type];
	current_request.config_value = malloc(value_size);

	switch (value_size) {
		case 1:
			//	Casos uint8_t
			*current_request.config_value = *(uint8_t *)value;
			break;
		case 2:
			//	Casos uint16_t
			write_big_endian_16(current_request.config_value, value, 1);
			break;
		case 4:
			//	Casos uint32_t
			write_big_endian_32(current_request.config_value, value, 1);
			break;
		default:
			// Casos array de uint8_t
			memcpy(current_request.config_value, value, value_size);
			break;
	}
}

static ssize_t prepare_query_request(query_type type) {
	ssize_t i = 0;

	io_buffer[i++] = PCAMP_VERSION;
	io_buffer[i++] = (((uint8_t)(QUERY)) << 1) + REQUEST;
	write_big_endian_16(io_buffer + i, &current_id, 1);
	i += 2;
	current_id++;

	memcpy(io_buffer + i, current_request.authorization, SHA256_DIGEST_LENGTH);

	i += SHA256_DIGEST_LENGTH;

	io_buffer[i++] = type;

	return i;
}

static ssize_t prepare_config_request(config_type type, char *value) {
	ssize_t i = 0;

	io_buffer[i++] = PCAMP_VERSION;
	io_buffer[i++] = (((uint8_t)(CONFIG)) << 1) + REQUEST;
	write_big_endian_16(io_buffer + i, &current_id, 1);
	i += 2;
	current_id++;

	memcpy(io_buffer + i, current_request.authorization, SHA256_DIGEST_LENGTH);

	i += SHA256_DIGEST_LENGTH;

	io_buffer[i++] = type;

	memcpy(io_buffer + i, current_request.config_value, config_value_size[type]);
	i += config_value_size[type];

	return i;
}
