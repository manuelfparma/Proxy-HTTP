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
static int write_http_request(char *name);
static ssize_t prepare_dns_question(dns_question question_info, char *question);

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

static dns_question test_dns_question = {.name = "www.netflix.com",
										 .class = 1,
										 .type = 1};

int solve_name(char *name, char *doh_host, char *doh_port) {
	// conectarse al server
	if (connect_to_server(host, port) == -1) {
		logger(ERROR, "connect_to_server(): %s", strerror(errno));
		return -1;
	}

	write_http_request(name);
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

	if (dns_addr.sin_addr.s_addr == -1) {
		logger(ERROR, "inet_addr(): %s", strerror(errno));
		return -1;
	}

	if (connect(dns_sock, (struct sockaddr *)dns_addr, sizeof(dns_addr)) == -1) {
		logger(ERROR, "connect(): %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int write_http_request(char *name) {
	char *request[HTTP_PACKET_LENGTH] = {0};
	sprintf(request, "%s %s %s/1.1\r\nHost: %s\r\nAccept: %s\r\nContent-Type: %s\r\nContent-Length: ", test_request.method,
			test_request.path, test_request.http_version);
}

// Funcion que prepara un mensaje DNS completo con headers y question dado un FQDN
// Devuelve la cantidad de bytes que ocupa el mensaje
static int prepare_dns_message(char *name) {
	char *dns_message[DNS_MESSAGE_LENGTH] = {0};
	char *dns_quest = memcpy(dns_message, &test_dns_header, sizeof(dns_header));
	dns_quest += sizeof(dns_header);
	ssize_t n = prepare_dns_question(test_dns_question, dns_quest);
	test_request.content_length = n + sizeof(dns_header);
}

// www.netflix.com -> 3www7netflix3com0
// campus.itba.edu.ar -> 6campus4itba3edu2ar0
//
static ssize_t prepare_dns_question(dns_question question_info, char *question) {
	ssize_t n = 0;
	char *label = question_info.name;

	while (*label != 0) {
		// TODO: Verificar que name sea null terminated
		// avanzamos hasta encontrar un punto o hasta que corte el string
		char i;
		for (i = 0; label[i] != '.' && label[i] == 0; i++)
			;
		// copiamos longitud de la label actual en la question
		question[n++] = i;

		// copiamos la label actual en la question
		memcpy(question + n, label, i);
		n += i;
		label += i;

		// si todavian quedan labels por leer, aumentamos el puntero
		if(*label == '.')
			label++;

	}
	// null termination de labels
	question[n++] = 0;

	// copiamos QTYPE y QCLASS
	int copy_size = 2 * sizeof(uint16_t);
	memcpy(question + n, &question_info.type, copy_size);
	n += copy_size;

	return n;
}
