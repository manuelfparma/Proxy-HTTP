// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include "dohdata.h"
#include "netutils.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dohparser.h>
#include <dohutils.h>
#include <errno.h>
#include <logger.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

static int strncmp_case_insensitive(uint8_t *s1, uint8_t *s2, size_t n);
static int parse_dns_header(connection_node *node, uint16_t *qdcount, uint16_t *ancount);
static int parse_dns_answers(connection_node *node, uint16_t ancount);
static void consume_buffer_bytes(connection_node *node, ssize_t count);

extern http_dns_request doh_request_template;
extern dns_header dns_header_template;

// Función que dado un FD de un socket lee de este, esperando una respuesta
// de DoH, y vuelca el mensaje DNS en una esctructura dns_answer.
int read_doh_response(connection_node *node) {
	buffer *buff = node->data.doh->doh_buffer;

	if (!buffer_can_write(buff)) {
		logger(ERROR, "read_doh_reponse(): doh buffer full");
		return -1;
	}

	ssize_t recv_bytes = recv(node->data.doh->sock, buff->write, buff->limit - buff->write, 0);
	if (recv_bytes == 0) {
		logger(INFO, "read_doh_response :: recv(): received EOF from socket %d", node->data.doh->sock);
		return 0;
	}
	if (recv_bytes < 0) {
		logger(ERROR, "recv(): %s", strerror(errno));
		return -1;
	}

	buffer_write_adv(buff, recv_bytes);

	return 1;
}

int parse_doh_status_code(connection_node *node) {
	char *http_200 = "HTTP/1.1 200 OK\r\n";
	long http_200_len = 17;
	buffer *response = node->data.doh->doh_buffer;
	long bytes_to_consume = response->write - response->read;

	if (bytes_to_consume < http_200_len) return DOH_PARSE_INCOMPLETE;

	// Buscamos que haya sido una response exitosa de HTTP
	if (strncmp((char *)response->read, http_200, http_200_len) != 0) {
		logger(ERROR, "read_doh_response(): expected \"HTTP/1.1 200 OK\r\n\", got \"%.*s\"", (int)http_200_len,
			   (char *)response->read);
		return DOH_PARSE_ERROR;
	}

	buffer_read_adv(response,
					http_200_len - 2); // No queremos saltear el \r\n, nos sirve para el matcheo de Content-Length mas tarde
	return DOH_PARSE_COMPLETE;
}

int parse_doh_content_length_header(connection_node *node) {
	char *content_length = "content-length:";
	int content_length_len = 15;
	buffer *response = node->data.doh->doh_buffer;

	while (response->write - response->read >= 3) {
		if (response->read[0] == '\r' && response->read[1] == '\n' && tolower(response->read[2]) == 'c') {
			// Avanzo hasta la 'c'
			buffer_read_adv(response, 2);
			// Si la cantidad de caracteres a consumir es menor al largo del header,
			// ni nos molestamos en continuar
			if (response->write - response->read < content_length_len) return DOH_PARSE_INCOMPLETE;

			if (strncmp_case_insensitive(response->read, (uint8_t *)content_length, content_length_len) == 0) {
				// si matcheo, avanzamos el puntero de lectura hasta despues del ':'
				buffer_read_adv(response, content_length_len);
				return DOH_PARSE_COMPLETE;
			}
		} else
			buffer_read_adv(response, 1);
	}

	return DOH_PARSE_INCOMPLETE;
}

int parse_doh_content_length_value(connection_node *node) {
	buffer *response = node->data.doh->doh_buffer;

	// Estando parados despues del ':' del header Content-Length avanzamos hasta
	// encontrar \r\n, sin incrementar el buffer
	int j;
	for (j = 0; j < response->write - response->read - 1 && !(response->read[j] == '\r' && response->read[j + 1] == '\n'); j++)
		;

	if (j == response->write - response->read - 1) { return DOH_PARSE_INCOMPLETE; }

	// copiamos el valor a un buffer auxiliar
	char length_value[MAX_HEADER_VALUE_LENGTH] = {0};
	strncpy(length_value, (char *)response->read, j);

	long parsed_length = strtol(length_value, NULL, 10); // Extraccion del valor

	if (parsed_length == 0 && errno == EINVAL) {
		logger(ERROR, "parse_doh_content_length_value :: strtol(): %s", strerror(errno));
		return DOH_PARSE_ERROR;
	}

	node->data.doh->response_content_length = parsed_length;

	// Avanzamos el valor del header y el \r\n
	buffer_read_adv(response, j + 2);

	return DOH_PARSE_COMPLETE;
}

int find_http_body(connection_node *node) {
	buffer *response = node->data.doh->doh_buffer;

	// Ahora buscamos el comienzo del mensaje DNS
	for (; response->write - response->read >= 4 &&
		   !(response->read[0] == '\r' && response->read[1] == '\n' && response->read[2] == '\r' && response->read[3] == '\n');
		 buffer_read_adv(response, SIZE_8))
		;

	if (response->write - response->read < 4) { return DOH_PARSE_INCOMPLETE; }

	// Muevo offset al comienzo del cuerpo
	buffer_read_adv(response, 4);

	return DOH_PARSE_COMPLETE;
}

int parse_dns_message(connection_node *node) {
	buffer *message = node->data.doh->doh_buffer;
	// Si todavia no llego el mensaje DNS completo esperamos
	if (message->write - message->read < node->data.doh->response_content_length) return DOH_PARSE_INCOMPLETE;

	uint16_t qdcount, ancount;
	if (parse_dns_header(node, &qdcount, &ancount) == -1) { return DOH_PARSE_ERROR; }

	// Saltamos a la question section y salteamos cada pregunta
	consume_buffer_bytes(node, 3 * SIZE_16);

	for (size_t i = 0; i < qdcount; i++) {
		// Salteamos hasta encontrar el octeto nulo que indica la label raiz en la pregunta
		while (*(message->read) != 0)
			consume_buffer_bytes(node, SIZE_8);

		// Salteamos QTYPE y QCLASS
		consume_buffer_bytes(node, 5 * SIZE_8);
	}

	if (parse_dns_answers(node, ancount) == -1) { return DOH_PARSE_ERROR; }

	// Si quedaron secciones de la respuesta para consumir, no nos interesan
	if (node->data.doh->response_content_length != 0) consume_buffer_bytes(node, node->data.doh->response_content_length);

	return DOH_PARSE_COMPLETE;
}

static int parse_dns_header(connection_node *node, uint16_t *qdcount, uint16_t *ancount) {
	dns_header header_info;
	buffer *message = node->data.doh->doh_buffer;

	// Obtenemos el id y validamos
	header_info.id = ntohs(*(uint16_t *)message->read);

	if (header_info.id != dns_header_template.id) {
		// No es nuestra current_request
		logger(ERROR, "parse_dns_message(): expected id %d, got %d", dns_header_template.id, header_info.id);
		return -1;
	}

	consume_buffer_bytes(node, SIZE_16);

	// Obtenemos el flag QR y validamos
	header_info.qr = (*message->read >> 7);

	if (header_info.qr == (unsigned int)0) {
		// No es una response
		logger(ERROR, "parse_dns_message(): expected a DNS response, got DNS query instead");
		return -1;
	}

	consume_buffer_bytes(node, SIZE_8);

	// Obtenemos el RCODE y validamos
	header_info.rcode = (*message->read & 15);

	if (header_info.rcode == (unsigned int)3) {
		logger(ERROR, "parse_dns_message(): DNS response - no such name (0 results)");
		return -1;
	}
	else if (header_info.rcode != (unsigned int)0) {
		// Hubo error al procesar la query en el servidor DNS
		logger(ERROR, "parse_dns_message(): error in DNS query");
		return -1;
	}

	// Obtenemos la cantidad de preguntas y de respuestas en el mensaje
	consume_buffer_bytes(node, SIZE_8);

	*qdcount = ntohs(*(uint16_t *)message->read);
	consume_buffer_bytes(node, SIZE_16);
	*ancount = ntohs(*(uint16_t *)message->read);

	return 0;
}

static int parse_dns_answers(connection_node *node, uint16_t ancount) {
	// Parseo de answers - RFC 1035 - Sec. 4.1.3.
	bool is_compressed = false;
	buffer *message = node->data.doh->doh_buffer;

	for (size_t i = 0; i < ancount; i++) {
		// Salteamos campo NAME teniendo en cuenta posible compresion - RFC 1035 - Sec. 4.1.4.
		uint8_t label_count;
		do {
			label_count = *message->read;

			//	Checkeamos si estan activados los flags de pointer
			if ((label_count >> 6) == 3) {
				// Es un puntero, por ende saltamos 16 bits y termina la seccion de NAME
				consume_buffer_bytes(node, SIZE_16);
				is_compressed = true;
				break;
			}

			// Si no era puntero avanzamos tantas posiciones como especifica label_count
			do {
				consume_buffer_bytes(node, SIZE_8);
			} while (label_count--);
		} while (*message->read != 0);

		// Si salio del ciclo por encontrar la longitud de la label de root (0x0), avanzamos 1 byte
		if (!is_compressed) consume_buffer_bytes(node, SIZE_8);

		// Aca ya pasamos el name
		// Vemos si coincide el type con el solicitado en la query
		uint16_t type = ntohs(*(uint16_t *)message->read);

		// Vemos lo mismo con class
		consume_buffer_bytes(node, SIZE_16);
		uint16_t class = ntohs(*(uint16_t *)message->read);

		if (class != IN_CLASS) {
			logger(ERROR, "parse_dns_message(): expected class %d record, got class = %d", IN_CLASS, class);
			return -1;
			// Error
		}

		// Avanzamos CLASS y Salteamos TTL
		consume_buffer_bytes(node, 3 * SIZE_16);

		uint16_t rdlength = ntohs(*(uint16_t *)message->read);

		consume_buffer_bytes(node, SIZE_16);

		int ip_family;
		switch (type) {
			case IPV4_TYPE:
				ip_family = AF_INET;
				break;
			case IPV6_TYPE:
				ip_family = AF_INET6;
				break;
			default:
				// Caso de otro type de Answer, la ignoramos
				ip_family = -1;
				break;
		}

		if (ip_family != -1 && add_ip_address(node, ip_family, message->read) == -1) { return -1; }

		consume_buffer_bytes(node, rdlength);
	}

	return 0;
}

static int strncmp_case_insensitive(uint8_t *s1, uint8_t *s2, size_t n) {
	size_t i;
	for (i = 0; i < n && s1[i] != 0 && s2[i] != 0 && tolower(s1[i]) == tolower(s2[i]); i++)
		;
	return n - i;
}

static void consume_buffer_bytes(connection_node *node, ssize_t count) {
	buffer_read_adv(node->data.doh->doh_buffer, count);

	long *content_length = &node->data.doh->response_content_length;
	if (*content_length - count >= 0) node->data.doh->response_content_length -= count;
	else
		logger(ERROR, "consume_buffer_bytes(): content-length already 0, cannot subtract value %ld", count);
}
