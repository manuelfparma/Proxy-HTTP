#include "include/parser.h"
#include <buffer.h>
#include <logger.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define METHOD_QTY 5
#define CONNECT_INDEX 0
static const char *methods[METHOD_QTY] = {"CONNECT ", "GET ", "POST ", "PUT ", "DELETE "};
static ConnectionNode *current_connection = NULL;
char aux_host_name[256] = {0};
static long parse_method(const char *buff);
static long parse_request_target(const char *buffer);
static long parse_http_version(const char *buffer);
static long parse_header_type(const char *buffer);
static long parse_header_value(const char *buffer);

static int resume_state_machine(const char *buffer) {
	long bytes_consumed = 0, aux;
	logger(INFO, "resuming state machine");
	while (*buffer != 0) {
		switch (current_connection->data.parse_state) {
			case METHOD:
				logger(INFO, "Parsing state: METHOD");
				aux = parse_method(buffer);
				break;
			case REQUEST_TARGET:
				logger(INFO, "Parsing state: REQUEST_TARGET");
				aux = parse_request_target(buffer);
				break;
			case HTTP_VERSION:
				logger(INFO, "Parsing state: HTTP_VERSION");
				aux = parse_http_version(buffer);
				break;
			case HEADER_TYPE:
				logger(INFO, "Parsing state: HEADER_TYPE");
				aux = parse_header_type(buffer);
				break;
			case HEADER_VALUE:
				logger(INFO, "Parsing state: HEADER_VALUE");
				aux = parse_header_value(buffer);
				if (aux >= 0) return 0;
				break;
			default:;
				// consumir hasta el proximo espacio o CRLF?
		}
		if (aux == -1) {
			// TODO: Handle error (octa), MEJORAR LOGS, USAR ERRNO?
			logger(ERROR, "Parsing error");
			return -1;
		}
		bytes_consumed += aux;
		buffer += aux;
	}
	logger(INFO, "Header host not received");
	current_connection->data.parse_state = METHOD;
	return 1;
}

int parse_request(ConnectionNode *node, char *host_name) {
	// almacenamos una referencia a la conexion actual
	current_connection = node;

	// buffer auxiliar para trabajar con strings null terminated y por ende las librerias de C
	char aux_buffer[BUFFER_SIZE + 1] = {0};
	long length = node->data.clientToServerBuffer->write - node->data.clientToServerBuffer->read;
	strncpy(aux_buffer, (char *)node->data.clientToServerBuffer->read, length);

	int aux = resume_state_machine(aux_buffer);
	strcpy(host_name, aux_host_name);
	return aux;
}

static bool prefix(const char *pre, const char *str) { return strncmp(pre, str, strlen(pre)) == 0; }

static long parse_method(const char *buff) {
	for (int i = 0; i < METHOD_QTY; i++) {
		if (prefix(methods[i], buff)) {

			current_connection->data.parse_state = REQUEST_TARGET;
			if (i == CONNECT_INDEX) return 0; // TODO: cosas de connect

			return (long)strlen(methods[i]);
		}
	}

	// Rechazas el request: Start line muy largo
	return -1;
}

static long parse_request_target(const char *buffer) {
	long i;
	switch (buffer[0]) {
		case '/': // path relativo, no nos interesa este campo asi que lo salteamos
			for (i = 1; buffer[i] != 0 && buffer[i] != ' '; i++) {};
			if (buffer[i] == 0) return -1;
			// recorremos el buffer hasta encontrar un espacio o hasta que termine
			current_connection->data.parse_state = HTTP_VERSION;
			break;

		case '*': // para metodos HTTP que no necesitan pedir recursos
			break;

		default:; // vemos si es un path absoluto
				  //			regex_t urlRegex;
				  //			if (regcomp(&urlRegex,
				  //"https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}", 0)) { logger() }
				  //
				  //			regexec();
	}

	return i + 1; //se suma 1 por el caracter consumido en el switch
}

static long parse_http_version(const char *buffer) {
	const char *version = "HTTP/1.1\r\n";
	const unsigned long version_length = strlen(version);

	logger(DEBUG, "buffer: %s, length: %zu", buffer, strlen(buffer));
	if (strncmp(version, buffer, version_length) == 0) {
		current_connection->data.parse_state = HEADER_TYPE;
		return (long)version_length;
	} else
		// version no soportada o string invalido
		return -1;
}

static long parse_header_type(const char *buffer) {
	const char *type_host = "Host: ";
	const unsigned long strlen_type_host = strlen(type_host);

	if (strncmp(type_host, buffer, strlen_type_host) == 0) {
		current_connection->data.parse_state = HEADER_VALUE;
		return (long)strlen_type_host;
	} else{
		return -1;
	}
}

// TODO: Magic numbers
static long parse_header_value(const char *buffer) {
	char aux_buffer[256] = {0};
	int i;

	for (i = 0; buffer[i] != 0 && buffer[i] != '\r' && buffer[i + 1] != 0 && buffer[i + 1] != '\n' && i < 254; i++) {
		if (buffer[i] == ' ')
			// TODO: Otros caracteres?
			// error
			return -1;
		else {
			aux_buffer[i] = buffer[i];
		}
	}

	if (buffer[i] == '\r' && buffer[i + 1] == '\n') {
		// Llegue al CRLF, finalizo la maquina de estados
		strncpy(aux_host_name, aux_buffer, i);
		return 0;
	} else {
		// Fin	alizo el parseo de este header pero todavia hay mas}}
		return -1;
	}
}
