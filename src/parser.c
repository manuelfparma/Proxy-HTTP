#include "include/parser.h"
#include <buffer.h>
#include <logger.h>
#include <parser.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define METHOD_QTY 5
#define CONNECT_INDEX 0
static const char *methods[METHOD_QTY] = {"CONNECT ", "GET ", "POST ", "PUT ", "DELETE "};
static ConnectionNode *current_connection = NULL;
char parsed_host_name[URI_MAX_LENGTH + 1];
char parsed_port[PORT_MAX_LENGTH];
static long parse_method(const char *buff);
static long parse_request_target(const char *buffer);
static long parse_http_version(const char *buffer);
static long parse_header_type(const char *buffer);
static long parse_header_value(const char *buffer);
static long parse_header_host_value(const char *buffer);

static int resume_state_machine(const char *buffer) {
	long aux = 1;
	logger(INFO, "resuming state machine");
	while (*buffer != 0 && aux != PARSE_INCOMPLETE) {
		switch (current_connection->data.parser->parse_state) {
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
				break;
			case HEADER_HOST_VALUE:
				logger(INFO, "Parsing state: HEADER_HOST_VALUE");
				aux = parse_header_host_value(buffer);
				break;
			case NO_MORE_HEADERS:
				// TODO: implementar estado final
				return 2;
			default:;
				// consumir hasta el proximo espacio o CRLF?
		}
		if (aux == PARSE_ERROR) {
			// TODO: Handle error (octa), MEJORAR LOGS, USAR ERRNO?
			logger(ERROR, "Parsing error");
			return PARSE_ERROR;
		} else if (aux != PARSE_INCOMPLETE) {
			current_connection->data.parser->current_index += aux;
			buffer += aux;

			// Si el string no esta vacio quiere decir que ya contiene el host name parseado
			if (strlen(parsed_host_name) > 0) return PARSE_OK;
		}
	}
	return PARSE_INCOMPLETE;
}

int parse_request(ConnectionNode *node, char *host_name, char *port) {
	// almacenamos una referencia a la conexion actual
	current_connection = node;

	// variable global donde se guarda el host name
	parsed_host_name[0] = 0;

	// buffer auxiliar para trabajar con strings null terminated y por ende las librerias de C
	char aux_buffer[BUFFER_SIZE + 1] = {0};
	long length =
		(node->data.clientToServerBuffer->write - node->data.clientToServerBuffer->read) - node->data.parser->current_index;
	strncpy(aux_buffer, (char *)node->data.clientToServerBuffer->read + node->data.parser->current_index, length);

	// se resume la ejecucion de la maquina de estados
	int parse = resume_state_machine(aux_buffer);

	// intento de copia
	if (parse == PARSE_OK) {
		strcpy(host_name, parsed_host_name);
		strcpy(port, parsed_port);
	}
	return parse;
}

static bool prefix(const char *pre, const char *str) { return strncmp(pre, str, strlen(pre)) == 0; }

static long parse_method(const char *buff) {
	for (int i = 0; i < METHOD_QTY; i++) {
		if (prefix(methods[i], buff)) {

			current_connection->data.parser->parse_state = REQUEST_TARGET;
			if (i == CONNECT_INDEX) return 0; // TODO: cosas de connect

			return (long)strlen(methods[i]);
		}
	}

	// Rechazas el request: Start line muy largo
	// TODO: Setear errno
	return PARSE_ERROR;
}

static long parse_request_target(const char *buffer) {
	long i;
	switch (buffer[0]) {
		case '/': // path relativo, no nos interesa este campo asi que lo salteamos
			for (i = 1; buffer[i] != 0 && buffer[i] != ' '; i++) {};
			if (buffer[i] == 0) {
				logger(DEBUG, "path relative incomplete");
				return PARSE_INCOMPLETE;
			}
			// recorremos el buffer hasta encontrar un espacio o hasta que termine
			current_connection->data.parser->parse_state = HTTP_VERSION;
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

	return i + 1; // se suma 1 por el caracter consumido en el switch (asi salteamos el caracter ' ')
}

static long parse_http_version(const char *buffer) {
	const char *version = "HTTP/1.1\r\n";
	const unsigned long strlen_version = strlen(version);

	size_t buffer_length = strlen(buffer);
	if (buffer_length >= strlen_version) {

		if (strncmp(version, buffer, strlen_version) == 0) {
			current_connection->data.parser->parse_state = HEADER_TYPE;
			return (long)strlen_version;
		} else
			// version no soportada
			// TODO: Setear errno
			return PARSE_ERROR;
		// todo mejorar octa

	} else if (buffer_length >= 2 && buffer[buffer_length - 2] == '\r' && buffer[buffer_length - 1] == '\n')
		// se parseo la linea, pero no fue un parametro valido
		return PARSE_ERROR;
	else
		// faltan paquetes
		return PARSE_INCOMPLETE;
}

static long parse_header_type(const char *buffer) {
	const char *type_host = "Host: "; // fixme: no es case sensitive
	const unsigned long strlen_type_host = strlen(type_host);

	if (strlen(buffer) >= strlen_type_host && strncmp(type_host, buffer, strlen_type_host) == 0) {
		current_connection->data.parser->parse_state = HEADER_HOST_VALUE;
		return (long)strlen_type_host;
	} else {
		// en caso que sea un header diferente a 'Host: '
		current_connection->data.parser->parse_state = HEADER_VALUE;
		int i;
		// TODO: chequear si luego de un header siempre va espacio
		// nos salteamos el header
		for (i = 0; buffer[i] != 0 && buffer[i] != ' '; i++) {};

		return i + 1;
	}
}

static long parse_header_value(const char *buffer) {
	int i;

	for (i = 0; buffer[i] != 0 && buffer[i] != '\r' && buffer[i + 1] != 0 && buffer[i + 1] != '\n'; i++) {};

	if (buffer[i] == 0 || buffer[i + 1] == 0) { return PARSE_INCOMPLETE; }

	current_connection->data.parser->parse_state = HEADER_TYPE;
	return i + 2;
}

static long parse_header_host_value(const char *buffer) {
	char aux_buffer[URI_MAX_LENGTH + 1] = {0};
	char aux_port_buffer[PORT_MAX_LENGTH + 1] = {0};
	aux_port_buffer[0] = '8';
	aux_port_buffer[1] = '0';
	int i;

	// parseo de host name
	for (i = 0; buffer[i] != 0 && buffer[i + 1] != 0 && buffer[i] != '\r' && buffer[i + 1] != '\n' && i < URI_MAX_LENGTH &&
				buffer[i] != ':';
		 i++) {
		if (buffer[i] == ' ')
			// TODO: Otros caracteres?
			// error
			return PARSE_ERROR;
		else {
			aux_buffer[i] = buffer[i];
		}
	}

	// parseo de puerto
	if (buffer[i] == ':') {
		i++;
		int j;
		for (j = 0; buffer[i] != 0 && buffer[i] != '\r' && buffer[i + 1] != 0 && buffer[i + 1] != '\n' &&
						i < URI_MAX_LENGTH + PORT_MAX_LENGTH;
			 i++, j++) {
			aux_port_buffer[j] = buffer[i];
		}
		aux_port_buffer[j] = 0;
	}

	if (buffer[i] == 0 || buffer[i + 1] == 0) {
		// faltan paquetes
		return PARSE_INCOMPLETE;
	}

	current_connection->data.parser->parse_state = HEADER_TYPE;
	if (buffer[i] == '\r' && buffer[i + 1] == '\n') {
		// Llegue al CRLF, finalizo la maquina de estados
		strncpy(parsed_host_name, aux_buffer, i);
		strncpy(parsed_port, aux_port_buffer, strlen(aux_port_buffer));
		return i + 2;
	} else {
		// Finalizo el parseo de este header pero todavia hay mas}}
		return PARSE_ERROR;
	}
}
