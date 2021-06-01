#include "include/parser.h"
#include <buffer.h>
#include <logger.h>
#include <regex.h>
#include <string.h>

#define METHOD_QTY 5
#define CONNECT_INDEX 0
static const char *methods[METHOD_QTY] = {"CONNECT ", "GET ", "POST ", "PUT ", "DELETE "};
static ConnectionNode *current_connection = {0};

static long parse_method(const char *buff);
static long parse_request_target(const char *buffer);
static long parse_http_version(const char *buffer);
static long parse_header_type(const char *buffer);
static long parse_header_value(const char *buffer);

static void resume_state_machine(const char *buffer) {
	long bytes_consumed = 0, aux;
	while (*buffer != 0) {
		switch (current_connection->parse_state) {
			case METHOD:
				aux = parse_method(buffer);
				break;
			case REQUEST_TARGET:
				aux = parse_request_target(buffer);
				break;
			case HTTP_VERSION:
				aux = parse_http_version(buffer);
				break;
			case HEADER_TYPE:
				aux = parse_header_type(buffer);
				break;
			case HEADER_VALUE:
				aux = parse_header_value(buffer);
				break;
			default:
				// consumir hasta el proximo espacio o CRLF?
		}
		if (aux == -1)
			// TODO: Handle error (octa)
			return;
		bytes_consumed += aux;
		buffer += aux;
	}

	buffer_read_adv(current_connection->data.clientToServerBuffer, bytes_consumed);
}

int parse_request(ConnectionNode *node) {
	// almacenamos una referencia a la conexion actual
	current_connection = node;

	// buffer auxiliar para trabajar con strings null terminated y por ende las librerias de C
	char aux_buffer[BUFFER_SIZE + 1];
	long length = node->data.clientToServerBuffer->write - node->data.clientToServerBuffer->read;
	strncpy(aux_buffer, node->data.clientToServerBuffer->read, length);
	aux_buffer[length + 1] = 0;

	resume_state_machine(aux_buffer);

	return -1;
}

static bool prefix(const char *pre, const char *str) { return strncmp(pre, str, strlen(pre)) == 0; }

static long parse_method(const char *buff) {
	for (int i = 0; i < METHOD_QTY; i++) {
		if (prefix(methods[i], buff)) {

			current_connection->parse_state = REQUEST_TARGET;
			if (i == CONNECT_INDEX) return 0; // TODO: cosas de connect

			return (long)strlen( /
		}
	}

	// Rechazas el request: Start line muy largo
	return -1;
}

static long parse_request_target(const char *buffer) {
	long i;
	switch (buffer[0]) {
		case '/': // path relativo, no nos interesa este campo asi que lo salteamos
			for (i = 1; buffer[i] != 0 && buffer[i] != ' '; i++)
				; // recorremos el buffer hasta encontrar un espacio o hasta que termine
			current_connection->parse_state = HTTP_VERSION;
			break;

		case '*': // para metodos HTTP que no necesitan pedir recursos
			break;

		default: // vemos si es un path absoluto
			regex_t urlRegex;
			regcomp(&urlRegex, "https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}");
			regexec()
	}

	return i;
}

static long parse_http_version(const char *buffer) {
	const char[8	const int strlenst = _ version_1_1 = "HTTP/1.1";

	if (strncmp(version_1_1, buffer, strlen(version_1_1)) == 0) {
		current_connection->parse_state = HEADER_TYPE;
		return (long)strlen(version_1_1);
	} else
		// version no soportada o string invalido
		return -1;
}

static long parse_header_type(const char *buffer) {
	const char[10] type_host = "Host: ";

	if (strncmp(type_host, buffer, strlen(type_host)) == 0) {
		current_connection->parse_state = HEADER_VALUE;
		return (long)strlen(type_host);
	} else
		return -1;
}

static long parse_header_value(const char *buffer) {
	char aux_buffer[256];
	for (int i = 0; buffer[i] != 0 && buffer[i] != '\r' && buffer[i + 1] != 0 && buffer[i + 1] != '\n' && i < 254; i++) {
		if (buffer[i] == ' ')
			// se termino de parsear
			// TODO: Otros caracteres?
			return -1;
		else {
			aux_buffer[i] = buffer[i];
		}
	}
	if (buffer[i] == '\r' && buffer[i + 1] == '\n') {
		// TODO: GUARDAR VALOR
		// Llegue al CRLF, finalizo la maquina de estados
	} else {
		// Finalizo el parseo de este header pero todavia hay mas
	}
}
