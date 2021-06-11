#include <arpa/inet.h>
#include <errno.h>
#include <logger.h>
#include <netinet/in.h>
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
// TODO: 4- 	 pedis por STDIN que cosa quiere consultar / configurar
// TODO: 5- 	 pedis parametro de config
// TODO: 6- 	 armas paquete en binario y lo envias
// TODO: 7- 	 loader (print de '.' cada segundo)
// TODO: 8.1-  si no recibis respuesta en 3 seg -> retransmitis
// TODO: 8.2 - a los 10 seg timeout
// TODO: 9 -	 recibis la respuesta, la parseas, y la mostras
// TODO: 10 -  repetir 3

#define INPUT_BUFFER 1024

static int get_option(long options_count, char **options_strings, const char *instruction);
static bool is_valid_option(long options_count, char *input, ssize_t read_bytes);
static void print_prompt();
static void get_passphrase(unsigned char hash[SHA256_DIGEST_LENGTH]);
static int get_config_type();
static void get_config_value(int type, char *value);
static void prepare_query_request(int type);
static void prepare_config_request(int type, char *value);

static addr_info current_addr = {0};

int main(const int argc, char **argv) {
	current_addr = parse_pcamp_args(argc, argv);

	printf("\033[1:36m ======= Proxy Configuration and Monitoring Protocol - Version 1.0 =======\n\n\033[0m ");

	unsigned char hash[SHA256_DIGEST_LENGTH];
	get_passphrase(hash);

	uint8_t method = get_option(METHOD_COUNT, method_strings, "Select a method:\n");

	uint8_t type;
	switch (method) {
		case QUERY:
			type = get_option(QUERY_TYPE_COUNT, query_type_strings, "Select query type:\n");
			prepare_query_request(type);
			break;
		case CONFIG:
			type = get_option(CONFIG_TYPE_COUNT, config_type_strings, "Select configuration type:\n");
			get_config_value(type, input);
			prepare_config_request(type, input);
			break;
		default:
			break;
	}

	int server_sock = socket(current_addr.addr.sa_family, SOCK_DGRAM, 0);

	if (server_sock < 0) logger(FATAL, "%s", strerror(errno));
}

static void get_passphrase(unsigned char hash[SHA256_DIGEST_LENGTH]) {
	char input[INPUT_BUFFER];

	printf("Please, enter the passphrase:\n");
	print_prompt();

	ssize_t read_bytes = read(STDIN_FILENO, input, INPUT_BUFFER);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, input, read_bytes);
	SHA256_Final(hash, &sha256);
}

static int get_option(long options_count, char **options_strings, const char *instruction) {
	ssize_t read_bytes;
	char input[INPUT_BUFFER + 1];
	bool isInputValid = false;

	while (!isInputValid) {
		// TODO: opción de exit?
		printf(instruction);

		for (int i = 0; i < options_count; i++)
			printf("%d - %s\n", i, options_strings[i]);

		print_prompt();

		read_bytes = read(STDIN_FILENO, input, INPUT_BUFFER);
		input[read_bytes] = 0;

		if (is_valid_option(options_count, input, read_bytes))
			isInputValid = true;
		else
			printf("Invalid option\n");
	}

	return input[0] - '0';
}

static bool is_valid_option(long options_count, char *input, ssize_t read_bytes) {
	ssize_t digit_count = 0;

	long aux = options_count;
	while (aux != 0)  {
		digit_count++;
		aux /= 10;
	}

	if (read_bytes != digit_count)
		return false;

	long parsed_option = strtol(input, NULL, 10);

	if (parsed_option == 0 && errno == EINVAL)
		return false;

	return parsed_option < options_count && parsed_option >= 0;
}

static void print_prompt() { printf("\033[1:32m→ \033[0m"); }

static int get_config_type() {}

static void get_config_value(int type, char *value) {}

static void prepare_query_request(int type) {}

static void prepare_config_request(int type, char *value) {}
