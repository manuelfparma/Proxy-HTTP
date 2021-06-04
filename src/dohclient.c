#include "include/dohclient.h"
#include "include/logger.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

static const char *DOH_SERVER = "127.0.0.1";
static const uint16_t DOH_PORT = 8053;

static int connect_to_server(char *doh_host, char *doh_port);
static int write_http_request(int fd, char *name);
static size_t prepare_dns_question(dns_question question_info, char *question);
static int prepare_dns_message(char *name, char *dns_message);
static void copy_little_to_big(uint8_t *dest, uint8_t *src, size_t n, size_t data_size);
static void copy_dns_header(void * dest, dns_header dns_header_info);

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
	int dns_sock = connect_to_server(doh_host, doh_port);
	if (dns_sock < 0) {
		logger(ERROR, "connect_to_server(): %s", strerror(errno));
		return -1;
	}

	return write_http_request(dns_sock, name);
}

int main() {
	return solve_name("google.com", "127.0.0.1", "8053");
}

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
	
	// Copiamos los headers del paquete HTTP en otro buffer
	int http_headers_size = sprintf(request, "%s %s HTTP/%s\r\nHost: %s\r\nAccept: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n", test_request.method,
			test_request.path, test_request.http_version, test_request.host, test_request.accept, test_request.content_type, dns_message_length);

	memcpy(request + http_headers_size, dns_message, dns_message_length);
	
	send(fd, request, http_headers_size + dns_message_length, 0);

	return 0;
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
	copy_little_to_big((uint8_t*)(question + n), (uint8_t*)&question_info.type, 2, sizeof(uint16_t));
	n += 2 * sizeof(uint16_t);

	return n;
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

static void copy_dns_header(void * dest, dns_header dns_header_info) {
	size_t size_16 = sizeof(uint16_t), n = 0;

	copy_little_to_big(dest, (uint8_t *) &dns_header_info.id, 1, size_16);
	n += size_16;

	uint16_t flags = 0;		//En esta variable voy a setear los flags
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

	copy_little_to_big((uint8_t *) dest + n, (uint8_t *) &flags, 1, size_16);

	n += size_16;

	copy_little_to_big((uint8_t *) dest + n, (uint8_t *) &dns_header_info.qdcount, 4, size_16);
}
