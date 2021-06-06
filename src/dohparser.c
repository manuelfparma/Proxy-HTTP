#include <arpa/inet.h>
#include <ctype.h>
#include <dnsutils.h>
#include <dohparser.h>
#include <errno.h>
#include <logger.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

static int strncmp_case_insensitive(uint8_t *s1, uint8_t *s2, size_t n);
static long find_content_length(uint8_t *response, int *match_offset, ssize_t response_length);
static int parse_dns_message(uint8_t *message, long length);

extern http_dns_request test_request;
extern dns_header test_dns_header;
extern dns_question test_dns_question;

// Función que dado un FD de un socket lee de este, esperando una respuesta
// de DoH, y vuelca el mensaje DNS en una esctructura dns_answer.
int read_http_response(int fd) {
	uint8_t response[HTTP_PACKET_LENGTH] = {0};
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

	// Buscamos que haya sido una response exitosa de HTTP
	if (strncmp((char *)response, http_200, http_200_len) != 0) {
		logger(ERROR, "read_http_response(): expected \"HTTP/1.1 200 OK\r\rn\", got \"%.*s\"", http_200_len, http_200);
		return -1;
	}

	logger(INFO, "found HTTP/1.1 200 OK line header");

	// Comenzamos a buscar matches con "content-length:"
	int offset;
	long parsed_length = find_content_length(response + http_200_len, &offset, recv_bytes - http_200_len);

	if (parsed_length == -1) {
		logger(ERROR, "read_http_response(): no Content-Length header found");
		return -1;
	}

	logger(INFO, "found Content-Length: %ld", parsed_length);

	// Como el offset devolvio la diferencia a partir del /r/n de la primera linea y el fin del header Content-Length, le sumo
	// la longitud de la primera linea para que sea un offset absoluto sobre el paquete HTTP
	offset += http_200_len;
	// Ahora buscamos el comienzo del mensaje DNS
	for (; offset < recv_bytes - 3 && !(response[offset] == '\r' && response[offset + 1] == '\n' &&
										response[offset + 2] == '\r' && response[offset + 3] == '\n');
		 offset++)
		;

	if (offset == recv_bytes - 3) {
		logger(ERROR, "read_http_response(): no body found in HTTP response");
		return -1;
	}

	// Muevo offset al comienzo del cuerpo
	offset += 4;
	logger(INFO, "found HTTP request body in position %d", offset);

	// A partir de este offset hay que parsear la response DNS
	parse_dns_message(response + offset, parsed_length);

	return 0;
}

// Funcion auxiliar que recibe un puntero a la respuesta HTTP, su tamaño restante,
// y encuentra y parsea el header "Content-Length"
// En caso exitoso, devuelve la longitud parseada y asigna en match_offset
// el indice donde termina el header. En caso de error devuelve -1
static long find_content_length(uint8_t *response, int *match_offset, ssize_t response_length) {
	char *content_length = "content-length:";
	int content_length_len = strlen(content_length);
	long parsed_length = -1;

	int i;
	for (i = 0; i < response_length; i++) {
		if (response[i - 2] == '\r' && response[i - 1] == '\n' && tolower(response[i]) == 'c') {
			if (strncmp_case_insensitive(response + i, (uint8_t *)content_length, content_length_len) == 0) {
				// si matcheo, parseamos el valor a partir de ':'
				int j;
				int offset = i + content_length_len; // posicion despues del uint8_t ';'

				for (j = offset; j < response_length - 1 && response[j] != '\r' && response[j + 1] != '\n'; j++)
					;

				if (j == response_length - 1) {
					logger(ERROR, "read_http_response(): unable to parse Content-Length value, response ended unexpectedly");
					return -1;
				}

				// copiamos el valor a un buffer auxiliar
				char length_value[MAX_HEADER_VALUE_LENGTH] = {0};
				int len = j - offset; // Longitud del string del valor del header Content-Length
				strncpy(length_value, (char *)response + offset, len);

				parsed_length = strtol(length_value, NULL, 10); // Extraccion del valor
				if (parsed_length == 0 && errno == EINVAL) {
					logger(ERROR, "strtol(): %s", strerror(errno));
					return -1;
				} else {
					i = j; // Guardamos la posicion donde se matcheo
					break;
				}
			}
		}
	}

	*match_offset = i;

	return parsed_length;
}

static int parse_dns_message(uint8_t *message, long length) {
	// Obtenemos el id y validamos
	// TODO: Ver si lo levanta como little endian o big endian
	uint16_t id;
	read_big_endian_16(&id, message, 1);

	if (id != test_dns_header.id) {
		// No es nuestra request
		logger(ERROR, "parse_dns_message(): expected id %d, got %d", test_dns_header.id, id);
		return -1;
	}

	// Obtenemos el flag QR y validamos
	message += SIZE_16;
	uint8_t qr_flag = (*message >> 7);

	if (qr_flag == 0) {
		// No es una response
		logger(ERROR, "parse_dns_message(): expected a DNS response, got DNS query instead");
		return -1;
	}

	// Obtenemos el RCODE y validamos
	message += SIZE_8;
	uint8_t rcode = (*message & 15);

	if (rcode != 0) {
		// Hubo error al procesar la query en el servidor DNS
		logger(ERROR, "parse_dns_message(): error in DNS query");
		return -1;
	}

	// Obtenemos la cantidad de preguntas y de respuestas en el mensaje
	message += SIZE_8;
	uint16_t qdcount;
	uint16_t ancount;

	read_big_endian_16(&qdcount, message, 1);
	message += SIZE_16;
	read_big_endian_16(&ancount, message, 1);

	// Saltamos a la question section y salteamos cada pregunta
	message += 3 * SIZE_16;
	for (size_t i = 0; i < qdcount; i++) {
		// Salteamos hasta encontrar el octeto nulo que indica la label raiz en la pregunta
		while (*message++ != 0)
			;
		// Salteamos QTYPE y QCLASS
		message += 2 * SIZE_16;
	}

	// Parseo de answers - RFC 1035 - Sec. 4.1.3.
	bool is_compressed = false;
	for (size_t i = 0; i < ancount; i++) {
		// Salteamos campo NAME teniendo en cuenta posible compresion - RFC 1035 - Sec. 4.1.4.
		uint8_t label_count;
		do {
			label_count = *message;

			//	Checkeamos si estan activados los flags de pointer
			if ((label_count >> 6) == 3) {
				// Es un puntero, por ende saltamos 16 bits y termina la seccion de NAME
				message += SIZE_16;
				is_compressed = true;
				break;
			}

			// Si no era puntero avanzamos tantas posiciones como especifica label_count
			do {
				message += SIZE_8;
			} while (label_count--);
		} while (*message != 0);

		// Si salio del ciclo por encontrar la longitud de la label de root (0x0), avanzamos 1 byte
		if (!is_compressed) message += SIZE_8;

		// Aca ya pasamos el name
		// Vemos si coincide el type con el solicitado en la query
		uint16_t type;
		read_big_endian_16(&type, message, 1);

		if (type != test_dns_question.type) {
			logger(ERROR, "parse_dns_message(): expected type %d record, got type = %d", test_dns_question.type, type);
			return -1;
			// Error
		}

		// Vemos lo mismo con class
		message += SIZE_16;
		uint16_t class;
		read_big_endian_16(&class, message, 1);

		if (class != test_dns_question.class) {
			logger(ERROR, "parse_dns_message(): expected class %d record, got class = %d", test_dns_question.class, class);
			return -1;
			// Error
		}

		// Avanzamos CLASS y Salteamos TTL
		message += 3 * SIZE_16;

		uint16_t rdlength;
		read_big_endian_16(&rdlength, message, 1);

		message += SIZE_16;

		// s_addr debe estar en Big Endian
		struct in_addr ip_addr;
		ip_addr.s_addr = *((uint32_t *)message);
		logger(INFO, "found IP address %s", inet_ntoa(ip_addr));

		message += rdlength;
	}

	return 0;
}

static int strncmp_case_insensitive(uint8_t *s1, uint8_t *s2, size_t n) {
	size_t i;
	for (i = 0; i < n && s1[i] != 0 && s2[i] != 0 && tolower(s1[i]) == tolower(s2[i]); i++)
		;
	return n - i;
}
