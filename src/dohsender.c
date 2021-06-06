#include <dohsender.h>
#include <dohutils.h>
#include <errno.h>
#include <logger.h>
#include <string.h>
#include <sys/socket.h>

static size_t prepare_dns_question(dns_question question_info, uint8_t *question);
static int prepare_dns_message(char *name, uint8_t *dns_message);
static void copy_dns_header(uint8_t *dest, dns_header dns_header_info);

extern http_dns_request test_request;
extern dns_header test_dns_header;
extern dns_question test_dns_question;

// Funcion que prepara y envia el paquete HTTP con la consulta DNS
ssize_t write_doh_request(int fd, char *domain_name, char *host_name) {
	uint8_t request[HTTP_PACKET_LENGTH] = {0};
	uint8_t dns_message[DNS_MESSAGE_LENGTH] = {0};

	// Copiamos el mensaje de DNS en un buffer
	int dns_message_length = prepare_dns_message(domain_name, dns_message);
	logger(INFO, "DNS message prepared");

	// Copiamos los headers del paquete HTTP en otro buffer
	int http_headers_size =
		sprintf((char *)request, "%s %s HTTP/%s\r\nHost: %s\r\nAccept: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
				test_request.method, test_request.path, test_request.http_version, test_request.host, test_request.accept,
				test_request.content_type, dns_message_length);

	memcpy(request + http_headers_size, dns_message, dns_message_length);
	logger(INFO, "HTTP request prepared");

	logger(INFO, "sending DoH request...");
	ssize_t sent_bytes = send(fd, request, http_headers_size + dns_message_length, 0);

	if (sent_bytes < 0) {
		logger(ERROR, "send(): %s", strerror(errno));
		return -1;
	}

	logger(INFO, "DoH request sent");
	return sent_bytes;
}

// Funcion que prepara un mensaje DNS completo con headers y question dado un FQDN
// Devuelve la cantidad de bytes que ocupa el mensaje
static int prepare_dns_message(char *name, uint8_t *dns_message) {
	// copiamos el header en el mensaje
	copy_dns_header(dns_message, test_dns_header);

	uint8_t *dns_quest = dns_message + 6 * SIZE_16;

	test_dns_question.name = name;

	// copiamos la question al buffer
	size_t question_length = prepare_dns_question(test_dns_question, dns_quest);
	test_request.content_length = question_length + sizeof(dns_header);

	return test_request.content_length;
}

// Función uelca los campos de una estructura de DNS question a un buffer y devuelve la cantidad
// de bytes copiados
static size_t prepare_dns_question(dns_question question_info, uint8_t *question) {
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
