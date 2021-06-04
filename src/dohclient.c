#include "include/dohclient.h"
#include "include/logger.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// TODO: Acordar valor con Octa y Mana
#define MAX_HEADER_VALUE_LENGTH 1024
static const char *DOH_SERVER = "127.0.0.1";
static const uint16_t DOH_PORT = 8053;

static int connect_to_server(char *doh_host, char *doh_port);
static int write_http_request(int fd, char *name);
static size_t prepare_dns_question(dns_question question_info, char *question);
static int prepare_dns_message(char *name, char *dns_message);
static void copy_little_to_big(uint8_t *dest, uint8_t *src, size_t n, size_t data_size);
static void copy_dns_header(void *dest, dns_header dns_header_info);
static int strncmp_case_insensitive(char *s1, char *s2, size_t n);
static int read_http_response(int fd);

static http_dns_request test_request = {.method = "POST",
										.path = "/dns-query",
										.http_version = "1.1",
										.host = "localhost",
										.accept = "application/dns-message",
										.content_type = "application/dns-message",
										.content_length = 0,
										.body = NULL};

static dns_header test_dns_header = {.id = 0, // autoincrementar?
									 .qr = 0,
									 .opcode = 0,
									 .aa = 0,
									 .tc = 0,
									 .rd = 1,
									 .ra = 0,
									 .z = 0,
									 .rcode = 0,
									 .qdcount = 1,
									 .ancount = 0,
									 .nscount = 0,
									 .arcount = 0};

// TODO: Guarda que el type puede variar segun si pide IPv4 o IPv6 (A/AAAA record)
static dns_question test_dns_question = {.name = "www.netflix.com", .class = 1, .type = 1};

int solve_name(char *name, char *doh_host, char *doh_port) {
	// TODO: Malloc de structs de HTTP request, DNS, etc.

	// TODO: Mandarlo al select antes de llegar al connect
	// conectarse al server
	logger(INFO, "connecting to DoH server");
	int dns_sock = connect_to_server(doh_host, doh_port);
	if (dns_sock < 0) {
		logger(ERROR, "connect_to_server(): %s", strerror(errno));
		return -1;
	}

	logger(INFO, "connected to DoH server");

	write_http_request(dns_sock, name);
	return read_http_response(dns_sock);
}

int main() { return solve_name("google.com", "127.0.0.1", "8053"); }

// TODO: cablear host y puerto dinamico
static int connect_to_server(char *doh_host, char *doh_port) {
	struct sockaddr_in dns_addr;

	int dns_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (dns_sock < 0) {
		logger(ERROR, "dns_sock(): %s", strerror(errno));
		return -1;
	}

	dns_addr.sin_family = AF_INET;
	dns_addr.sin_port = htons(DOH_PORT);
	dns_addr.sin_addr.s_addr = inet_addr(DOH_SERVER);

	if (dns_addr.sin_addr.s_addr == (in_addr_t)-1) {
		logger(ERROR, "inet_addr(): %s", strerror(errno));
		return -1;
	}

	if (connect(dns_sock, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) == -1) {
		logger(ERROR, "connect(): %s", strerror(errno));
		return -1;
	}

	return dns_sock;
}

// Funcion que prepara y envia el paquete HTTP con la consulta DNS
static int write_http_request(int fd, char *name) {
	char request[HTTP_PACKET_LENGTH] = {0};
	char dns_message[DNS_MESSAGE_LENGTH] = {0};

	// Copiamos el mensaje de DNS en un buffer
	int dns_message_length = prepare_dns_message(name, dns_message);
	logger(INFO, "DNS message prepared");

	// Copiamos los headers del paquete HTTP en otro buffer
	int http_headers_size =
		sprintf(request, "%s %s HTTP/%s\r\nHost: %s\r\nAccept: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
				test_request.method, test_request.path, test_request.http_version, test_request.host, test_request.accept,
				test_request.content_type, dns_message_length);

	memcpy(request + http_headers_size, dns_message, dns_message_length);
	logger(INFO, "HTTP request prepared");

	logger(INFO, "sending DoH request...");
	int sent_bytes = send(fd, request, http_headers_size + dns_message_length, 0);

	if (sent_bytes < 0) {
		logger(ERROR, "send(): %s", strerror(errno));
		return -1;
	}

	logger(INFO, "DoH request sent");
	return sent_bytes;
}

static int read_http_response(int fd) {
	char response[HTTP_PACKET_LENGTH] = {0};
	// TODO: Pasar a select con socket no bloqueante
	// TODO: Manejar estados para recibir de a chunks

	logger(INFO, "reading DoH response...");
	int recv_bytes = recv(fd, response, HTTP_PACKET_LENGTH, 0);
	if (recv_bytes < 0) {
		logger(ERROR, "recv(): %s", strerror(errno));
		return -1;
	}

	logger(INFO, "DoH response received");

	char *http_200 = "HTTP/1.1 200 OK\r\n";
	int http_200_len = strlen(http_200);

	if (strncmp(response, http_200, http_200_len) != 0) {
		logger(ERROR, "read_http_response(): expected \"HTTP/1.1 200 OK\r\rn\", got \"%.*s\"", http_200_len, http_200);
		return -1;
	}

	logger(INFO, "found HTTP/1.1 200 OK line header");

	char *content_length = "content-length:";
	int content_length_len = strlen(content_length);
	long parsed_length = -1;

	// Comenzamos a buscar matches con "content-length:"

	int i;
	for (i = http_200_len; i < recv_bytes; i++) {
		if (response[i - 2] == '\r' && response[i - 1] == '\n' && tolower(response[i]) == 'c') {
			if (strncmp_case_insensitive(response + i, content_length, content_length_len) == 0) {
				// TODO: Pasar a funcion auxiliar
				// si matcheo, parseamos el valor a partir de ':'
				int j;
				int offset = i + content_length_len; // posicion despues del char ';'

				// TODO: Que pasa con len si sale por j < recv_bytes - 1 pero terminaba con \r\n correctamente?
				for (j = offset; j < recv_bytes - 1 && response[j] != '\r' && response[j + 1] != '\n'; j++)
					;

				if (j == recv_bytes - 1) {
					logger(ERROR, "read_http_response(): unable to parse Content-Length value, response ended unexpectedly");
					return -1;
				}

				// copiamos el valor a un buffer auxiliar
				char length_value[MAX_HEADER_VALUE_LENGTH] = {0};
				int len = j - offset; // Longitud del string del valor del header Content-Length
				strncpy(length_value, response + offset, len);

				parsed_length = strtol(length_value, NULL, 10);
				if (parsed_length == 0 && errno == EINVAL) {
					logger(ERROR, "strtol(): %s", strerror(errno));
					return -1;
				} else {
					i = j; // Guardo posicion de lo ultimo parseado
					break;
				}
			}
		}
	}

	if (parsed_length == -1) {
		logger(ERROR, "read_http_response(): no Content-Length header found");
		return -1;
	}

	logger(INFO, "found Content-Length: %ld", parsed_length);
	
	// Ahora buscamos el comienzo del mensaje DNS
	for (; i < recv_bytes - 3 && response[i] == '\r' && response[i + 1] == '\n' && response[i + 2] == '\r' &&
		   response[i + 3] == '\n';
		 i++)
		;
	
	if (i == recv_bytes - 3) {
		logger(ERROR, "read_http_response(): no body found in HTTP response");
		return -1;
	}

	// Muevo i al comienzo del cuerpo
	i += 4;
	logger(INFO, "found HTTP request body in position %d", i);

	return i;
}

// Funcion que prepara un mensaje DNS completo con headers y question dado un FQDN
// Devuelve la cantidad de bytes que ocupa el mensaje
static int prepare_dns_message(char *name, char *dns_message) {
	// copiamos el header desde el string de template de header
	copy_dns_header(dns_message, test_dns_header);

	char *dns_quest = dns_message + 6 * sizeof(uint16_t);

	test_dns_question.name = name;

	// copiamos la question al buffer
	size_t question_length = prepare_dns_question(test_dns_question, dns_quest);
	test_request.content_length = question_length + sizeof(dns_header);

	return test_request.content_length;
}

// Función uelca los campos de una estructura de DNS question a un buffer y devuelve la cantidad
// de bytes copiados
static size_t prepare_dns_question(dns_question question_info, char *question) {
	size_t n = 0;
	char *label = question_info.name;

	while (*label != 0) {
		// TODO: Verificar que name sea null terminated
		// avanzamos hasta encontrar un punto o hasta que corte el string
		uint8_t i;
		for (i = 0; label[i] != '.' && label[i] != 0; i++)
			;
		// copiamos longitud de la label actual en la question
		question[n++] = i;

		// copiamos la label actual en la question
		memcpy(question + n, label, i);
		n += i;
		label += i;

		// si todavian quedan labels por leer, aumentamos el puntero
		if (*label == '.') label++;
	}
	// null para indicar label de root del dominio
	question[n++] = 0;

	// copiamos QTYPE y QCLASS
	// int copy_size = 2 * sizeof(uint16_t);
	// memcpy(question + n, &question_info.type, copy_size);
	// n += copy_size;

	// Copiamos de little endian a big endian el QTYPE y QCLASS
	copy_little_to_big((uint8_t *)(question + n), (uint8_t *)&question_info.type, 2, sizeof(uint16_t));
	n += 2 * sizeof(uint16_t);

	return n;
}

static void copy_dns_header(void *dest, dns_header dns_header_info) {
	size_t size_16 = sizeof(uint16_t), n = 0;

	copy_little_to_big(dest, (uint8_t *)&dns_header_info.id, 1, size_16);
	n += size_16;

	uint16_t flags = 0; // En esta variable voy a setear los flags
	flags += dns_header_info.qr;
	flags = flags << 4;
	flags += dns_header_info.opcode;
	flags = flags << 1;
	flags += dns_header_info.aa;
	flags = flags << 1;
	flags += dns_header_info.tc;

	flags = flags << 1;
	flags += dns_header_info.rd;
	flags = flags << 1;
	flags += dns_header_info.ra;
	flags = flags << 3;
	flags += dns_header_info.z;
	flags = flags << 4;
	flags += dns_header_info.rcode;

	copy_little_to_big((uint8_t *)dest + n, (uint8_t *)&flags, 1, size_16);

	n += size_16;

	copy_little_to_big((uint8_t *)dest + n, (uint8_t *)&dns_header_info.qdcount, 4, size_16);
}

// Funcion auxiliar que copia informacion almacenada en little endian en formato big endian
// dados una zona de memoria destino, otra de origen, una cantidad de bytes, y el tamaño de los datos a copiar
static void copy_little_to_big(uint8_t *dest, uint8_t *src, size_t n, size_t data_size) {
	for (size_t i = 0; i < n; i++) {
		size_t offset = i * data_size;
		for (size_t j = 0; j < data_size; j++)
			dest[j + offset] = src[(data_size - j - 1) + offset];
	}
}

static int strncmp_case_insensitive(char *s1, char *s2, size_t n) {
	size_t i;
	for (i = 0; i < n && s1[i] != 0 && s2[i] != 0 && tolower(s1[i]) == tolower(s2[i]); i++)
		;
	return n - i;
}
