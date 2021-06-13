#include "dohdata.h"
#include "netutils.h"
#include <dohsender.h>
#include <dohutils.h>
#include <errno.h>
#include <logger.h>
#include <string.h>
#include <sys/socket.h>

static size_t prepare_dns_question(dns_question question_info, uint8_t *question);
static size_t prepare_dns_message(const char *name, uint8_t *dns_message, uint16_t question_type);
static void copy_dns_header(uint8_t *dest, dns_header dns_header_info);

extern http_dns_request doh_request_template;
extern dns_header dns_header_template;

// Funcion que prepara y envia el paquete HTTP con la consulta DNS
void prepare_doh_request(connection_node *node) {
	uint8_t dns_message[DNS_MESSAGE_LENGTH] = {0};
	buffer *request = node->data.doh->doh_buffer;
	char *domain = node->data.parser->request.target.request_target.host_name;
	uint16_t question_type = node->data.doh->question_types[node->data.doh->request_number];

	// Copiamos el mensaje de DNS en un buffer
	size_t dns_message_length = prepare_dns_message(domain, dns_message, question_type);

	// Copiamos los headers del paquete HTTP en otro buffer
	int http_headers_size = sprintf(
		(char *)request->write, "%s %s HTTP/%s\r\nHost: %s\r\nAccept: %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n",
		doh_request_template.method, doh_request_template.path, doh_request_template.http_version, doh_request_template.host,
		doh_request_template.accept, doh_request_template.content_type, dns_message_length);

	buffer_write_adv(request, http_headers_size);

	memcpy(request->write, dns_message, dns_message_length);

	buffer_write_adv(request, (ssize_t) dns_message_length);
}

int send_doh_request(connection_node *node, fd_set *write_fd_set) {
	int doh_sock = node->data.doh->sock;
	buffer *request = node->data.doh->doh_buffer;

	ssize_t sent_bytes = send(doh_sock, request->read, request->write - request->read, 0);

	if (sent_bytes < request->write - request->read) {
		if (sent_bytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
			logger(ERROR, "send_doh_request :: send(): %s", strerror(errno));
			return DOH_SEND_ERROR;
		}
		buffer_read_adv(request, sent_bytes);
		FD_SET(doh_sock, &write_fd_set[BASE]);
		return DOH_SEND_INCOMPLETE;
	}

	buffer_read_adv(request, sent_bytes);
	return DOH_SEND_COMPLETE;
}

// Funcion que prepara un mensaje DNS completo con headers y question dado un FQDN
// Devuelve la cantidad de bytes que ocupa el mensaje
static size_t prepare_dns_message(const char *name, uint8_t *dns_message, uint16_t question_type) {
	// copiamos el header en el mensaje
	copy_dns_header(dns_message, dns_header_template);

	uint8_t *dns_quest = dns_message + 6 * SIZE_16;

	dns_question ip_question = {.name = name, .class = IN_CLASS, .type = question_type};

	size_t question_length = prepare_dns_question(ip_question, dns_quest);

	doh_request_template.content_length = sizeof(dns_header) + question_length;

	return doh_request_template.content_length;
}

// Función uelca los campos de una estructura de DNS question a un buffer y devuelve la cantidad
// de bytes copiados
static size_t prepare_dns_question(dns_question question_info, uint8_t *question) {
	size_t n = 0;
	const char *label = question_info.name;

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

	// Copiamos de little endian a big endian el QTYPE y QCLASS
	write_big_endian_16(question + n, &question_info.type, 1);
	n += SIZE_16;
	write_big_endian_16(question + n, &question_info.class, 1);
	n += SIZE_16;

	return n;
}

static void copy_dns_header(uint8_t *dest, dns_header dns_header_info) {
	size_t n = 0;

	write_big_endian_16(dest, &dns_header_info.id, 1);
	n += SIZE_16;

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

	write_big_endian_16(dest + n, &flags, 1);

	n += SIZE_16;

	write_big_endian_16(dest + n, &dns_header_info.qdcount, 1);
	n += SIZE_16;
	write_big_endian_16(dest + n, &dns_header_info.ancount, 1);
	n += SIZE_16;
	write_big_endian_16(dest + n, &dns_header_info.nscount, 1);
	n += SIZE_16;
	write_big_endian_16(dest + n, &dns_header_info.arcount, 1);
}
