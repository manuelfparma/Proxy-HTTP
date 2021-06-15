// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <base64.h>
#include <buffer.h>
#include <connection.h>
#include <httpparser.h>
#include <logger.h>
#include <netutils.h>
#include <proxyargs.h>
#include <stdlib.h>
#include <string.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))
#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')

extern proxy_arguments args;
extern proxy_settings settings;
http_parser *current_parser;

//----------- PROTOTIPOS DE FUNCIONES AUXILIARES -----------//

// Funcion que copia un string de longitud maxima de bytes a un buffer
static void copy_to_request_buffer(buffer *target, char *source, ssize_t bytes);

// Funcion que copia en el buffer de salida la startline con path relativo y el header 'Host:' en caso de haberse identificado el origin server
static void parse_start_line(char current_char);

// Funcion parsea un header completo buscando informacion relevante(campo 'Host:' o 'Authorization:') y lo copia en el buffer de salida
static void parse_header_line(char current_char);

// Funcion que chequea si hay un puerto, caso contrario setea un default dependiendo del schema indicado
static void check_port();

//----------- PROTOTIPOS DE LAS FUNCIONES DE TRANSICION -----------//

// Funcion que copia en un buffer, determinado por el estado actual, el caracter
static void tr_copy_byte_to_buffer(char current_char);

// Funcion que establece que el request target es relativo
static void tr_solve_relative_request_target(char current_char);

// Funcion que verifica si se esta conectando a un puerto 110 con el metodo CONNECT
static void tr_solve_port_request_target(char current_char);

// Funcion que indica que se resolvio a quien se quiere conectar
static void tr_solve_request_target(char current_char);

// Funcion que se ejecuta cuando se finalizo una linea
static void tr_line_ended(char current_char);

// Funcion que se ejecuta cuando se lee un nuevo header
static void tr_new_header(char current_char);

// Funcion que guarda el tipo del request target de la first line
static void tr_set_http_path_type(char current_char);

// Funcion que guarda el tipo del host
static void tr_set_host_type(char current_char);

// Funcion que guarda la version HTTP del request
static void tr_http_version(char current_char);

// Funcion que resetea el indice auxiliar del parser
static void tr_reset_copy_index(char current_char);

// Funcion que solo consume el caracter
static void tr_adv(char current_char);

// Funcion que se ejecuta al finalizar los headers, realiza el pasaje a la lectura del body
static void tr_headers_ended(char current_char);

// Funcion que chequea si el metodo fue CONNECT y en cuyo caso cambia la ejecucion de la maquina
static void tr_check_method(char current_char);

// Funcion que chequea que el metodo sea OPTIONS
static void tr_check_asterisk_form(char current_char);

// Funcion que maneja los errores
static void tr_parse_error(char current_char);


//----------- ESTRUCTURAS QUE REPRESENTAN LOS NODOS DEL GRAFO -----------//

static const http_parser_state_transition ST_METHOD[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH, .transition = tr_check_method},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_METHOD, .transition = tr_copy_byte_to_buffer}};

static const http_parser_state_transition ST_PATH[5] = {
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_set_http_path_type},
	{.when = '*',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_ASTERISK_FORM,
	 .transition = tr_check_asterisk_form},
	{.when = '[', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_set_http_path_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv4, .transition = tr_set_http_path_type},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SCHEMA, .transition = tr_set_http_path_type},
};

static const http_parser_state_transition ST_ASTERISK_FORM[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error}};

static const http_parser_state_transition ST_PATH_SCHEMA[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SLASHES, .transition = tr_reset_copy_index},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_SCHEMA,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_PATH_SLASHES[4] = {
	{.when = '/', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SLASHES, .transition = tr_adv},
	{.when = '[', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_set_host_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv4, .transition = tr_set_host_type},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_DOMAIN, .transition = tr_set_host_type},
};

static const http_parser_state_transition ST_IPv4[6] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv4, .transition = tr_copy_byte_to_buffer},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_solve_relative_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv4, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv6[7] = {
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_copy_byte_to_buffer},
	{.when = '.',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_IPv6,
	 .transition = tr_copy_byte_to_buffer}, // por si es IPv4-mapped to IPv6
	{.when = ']', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6_END, .transition = tr_reset_copy_index},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv6, .transition = tr_copy_byte_to_buffer},
	{.when = EMPTY, .lower_bound = 'A', .upper_bound = 'F', .destination = PS_IPv6, .transition = tr_copy_byte_to_buffer},
	{.when = EMPTY, .lower_bound = 'a', .upper_bound = 'f', .destination = PS_IPv6, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv6_END[4] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_solve_relative_request_target},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_DOMAIN[4] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_solve_relative_request_target},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_DOMAIN, .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_PORT[4] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_port_request_target},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_solve_relative_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_PORT, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_RELATIVE_PATH[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_HTTP_VERSION[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_adv},
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_http_version},
};

static const http_parser_state_transition ST_HEADER_TYPE[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HEADER_TYPE, .transition = tr_adv},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HEADER_VALUE, .transition = tr_reset_copy_index},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HEADER_TYPE,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_HEADER_VALUE[2] = {
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR, .transition = tr_copy_byte_to_buffer},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HEADER_VALUE,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_CR[2] = {
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_LF, .transition = tr_line_ended},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_LF[2] = {
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR_END, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HEADER_TYPE, .transition = tr_new_header},
};

static const http_parser_state_transition ST_CR_END[2] = {
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_BODY, .transition = tr_headers_ended},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HEADER_VALUE,
	 .transition = tr_copy_byte_to_buffer},
};

//----------- ESTRUCTURAS PARA SABER LAS TRANSICIONES DE CADA NODO -----------//

static const http_parser_state_transition *states[] = {
	ST_METHOD, ST_PATH, ST_ASTERISK_FORM, ST_RELATIVE_PATH, ST_PATH_SCHEMA,	 ST_PATH_SLASHES, ST_IPv4, ST_IPv6,	  ST_IPv6_END,
	ST_DOMAIN, ST_PORT, ST_HTTP_VERSION,  ST_HEADER_TYPE,	ST_HEADER_VALUE, ST_CR,			  ST_LF,   ST_CR_END,
};

static const size_t states_n[] = {
	N(ST_METHOD),		N(ST_PATH),			N(ST_ASTERISK_FORM), N(ST_RELATIVE_PATH), N(ST_PATH_SCHEMA),
	N(ST_PATH_SLASHES), N(ST_IPv4),			N(ST_IPv6),			 N(ST_IPv6_END),	  N(ST_DOMAIN),
	N(ST_PORT),			N(ST_HTTP_VERSION), N(ST_HEADER_TYPE),	 N(ST_HEADER_VALUE),  N(ST_CR),
	N(ST_LF),			N(ST_CR_END),
};

//----------- FUNCIONES AUXILIARES PARA LAS TRANSICIONES -----------//

static void copy_to_request_buffer(buffer *target, char *source, ssize_t bytes) {
	ssize_t bytes_available = (ssize_t)(target->limit - target->write);
	if (bytes > bytes_available) {
		strncpy((char *)target->write, (const char *)source, bytes_available);
		buffer_write_adv(current_parser->data.parsed_request, bytes_available);
	} else {
		strncpy((char *)target->write, (const char *)source, bytes);
		buffer_write_adv(current_parser->data.parsed_request, bytes);
	}
}

static void copy_char_to_request_buffer(buffer *target, char c) {
	if (buffer_can_write(target)) buffer_write(target, (uint8_t)c);
}

static int find_idx(char *array, char c) {
	int idx;
	for (idx = 0; array[idx] != '\0' && array[idx] != c; idx++) {};
	return array[idx] == c ? idx : -1;
}
static void copy_to_request_buffer_request_target() {
	switch (current_parser->request.target.host_type) {
		case IPV4:
			copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.request_target.ip_addr,
								   strlen(current_parser->request.target.request_target.ip_addr));
			break;
		case IPV6:
			copy_char_to_request_buffer(current_parser->data.parsed_request, '[');
			copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.request_target.ip_addr,
								   strlen(current_parser->request.target.request_target.ip_addr));
			copy_char_to_request_buffer(current_parser->data.parsed_request, ']');
			break;
		case DOMAIN:
			copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.request_target.host_name,
								   strlen(current_parser->request.target.request_target.host_name));
			break;
		default:
			tr_parse_error(' ');
			break;
	}
}

static void check_port() {
	if (current_parser->request.target.port[0] == '\0') {
		char *port;
		if (strcmp_case_insensitive("pop3", current_parser->request.schema) == 0) {
			port = "110";
			strcpy(current_parser->request.target.port, port);
		} else if (strcmp_case_insensitive("https", current_parser->request.schema) == 0) {
			port = "433";
			strcpy(current_parser->request.target.port, port);
		} else {
			port = "80";
			strcpy(current_parser->request.target.port, port);
		}
	}
}

static void parse_start_line(char current_char) {
	copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.method,
						   strlen(current_parser->request.method));
	copy_char_to_request_buffer(current_parser->data.parsed_request, ' ');

	if (current_parser->request.target.path_type == ASTERISK_FORM ||
		(current_parser->request.target.path_type == ABSOLUTE && strcmp("OPTIONS", current_parser->request.method) == 0)) {
		copy_char_to_request_buffer(current_parser->data.parsed_request, '*');
	} else {
		copy_char_to_request_buffer(current_parser->data.parsed_request, '/');
		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.relative_path,
							   strlen(current_parser->request.target.relative_path));
	}

	// Hardcodeamos la version para, en el caso ideal, recibir el delimitador null terminated indicando que el servidor termino de
	// enviar sus recursos
	char *http = " HTTP/1.0\r\n";
	copy_to_request_buffer(current_parser->data.parsed_request, http, SPHTTP_1_0_LENGTH);

	if (current_parser->request.target.path_type == ABSOLUTE ||
		current_parser->request.target.path_type == ABSOLUTE_WITH_RELATIVE) {
		// Hardcodeo el header 'Host:' de acuerdo al RFC de HTTP
		char *header_host = "Host: ";
		copy_to_request_buffer(current_parser->data.parsed_request, header_host, HEADER_TYPE_HOST_LENGTH);
		copy_to_request_buffer_request_target();
		copy_char_to_request_buffer(current_parser->data.parsed_request, ':');
		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.port,
							   strlen(current_parser->request.target.port));
		char *cr_lf = "\r\n";
		copy_to_request_buffer(current_parser->data.parsed_request, cr_lf, CR_LF_LENGTH);
	}
}

static int parse_request_target() {
	int idx_port;
	if (current_parser->request.header.value[0] == '[') {
		// CASO IPv6
		int ipv6_length = find_idx(current_parser->request.header.value + 1, ']');
		if (ipv6_length == -1 || ipv6_length > MAX_IP_LENGTH) {
			return -1;
		} else {
			current_parser->request.target.host_type = IPV6;
			strncpy(current_parser->request.target.request_target.ip_addr, current_parser->request.header.value + 1, ipv6_length);
			current_parser->request.target.request_target.ip_addr[ipv6_length] = '\0';
			idx_port = find_idx(current_parser->request.header.value + ipv6_length + 1, ':'); // lo busco a partir del caracter ]
			if (idx_port == -1) {
				check_port();
			} else if (idx_port > MAX_PORT_LENGTH) {
				logger(ERROR, "Port excedeed length in header type Host");
				tr_parse_error(' ');
			} else {
				// almaceno en la estructura el puerto
				strcpy(current_parser->request.target.port,
					   current_parser->request.header.value + ipv6_length + 1 + (idx_port + 1));
			}
		}
	} else {
		// Busco el indice del delimitador entre el path y el puerto, en caso de no existir retorna -1
		idx_port = find_idx(current_parser->request.header.value, ':');
		if (idx_port == -1) {
			check_port();
		} else
			// almaceno en la estructura el puerto
			strcpy(current_parser->request.target.port, current_parser->request.header.value + (idx_port + 1));

		if (IS_DIGIT(current_parser->request.header.value[0])) {
			// CASO IPv4
			current_parser->request.target.host_type = IPV4;
			if (idx_port >= 1) {
				// tiene puerto no default
				strncpy(current_parser->request.target.request_target.ip_addr, current_parser->request.header.value,
						(size_t)idx_port);
				current_parser->request.target.request_target.ip_addr[idx_port] = '\0';
			} else
				strcpy(current_parser->request.target.request_target.ip_addr, current_parser->request.header.value);
		} else {
			// CASO DOMINIO
			current_parser->request.target.host_type = DOMAIN;
			if (idx_port >= 1) {
				// tiene puerto no default
				strncpy(current_parser->request.target.request_target.host_name, current_parser->request.header.value,
						(size_t)idx_port);
				current_parser->request.target.request_target.host_name[idx_port] = '\0';
			} else
				strcpy(current_parser->request.target.request_target.host_name, current_parser->request.header.value);
		}
	}

	return 0;
}

static void parse_header_line(char current_char) {
	char *delimiter = ": ";
	int strcmp_header_type = strcmp_case_insensitive("Host", current_parser->request.header.type);
	if (strcmp_header_type == 0) {
		if (current_parser->data.target_status == NOT_FOUND && current_parser->request.target.path_type != ABSOLUTE) {
			if (parse_request_target() == -1) {
				logger(ERROR, "Request target in header Host invalid");
				tr_parse_error(current_char);
				return;
			}
			current_parser->data.target_status = FOUND;
			goto COPY_HEADER;
		}
		return;
	}
	if (settings.password_dissector) {
		strcmp_header_type = strcmp_case_insensitive("Authorization", current_parser->request.header.type);
		if (strcmp_header_type == 0) {
			if (strncmp("Basic ", current_parser->request.header.value, BASIC_CREDENTIAL_LENGTH) == 0) {
				size_t length = strlen(current_parser->request.header.value + BASIC_CREDENTIAL_LENGTH);
				int base64_decoded_length = -1;
				unsigned char *base64_decoded =
					unbase64(current_parser->request.header.value + BASIC_CREDENTIAL_LENGTH, length, &base64_decoded_length);
				if (base64_decoded == NULL || base64_decoded_length == -1) {
					free(base64_decoded);
					logger(ERROR, "Base64 decoder failed");
					goto COPY_HEADER;
				}
				memcpy(current_parser->request.authorization.value, base64_decoded, base64_decoded_length);
				current_parser->request.authorization.value[base64_decoded_length] = '\0';
				puts(current_parser->request.authorization.value);
				free(base64_decoded);
			} else {
				logger(DEBUG, "Header type Authorization : unknown credentials");
			}
			goto COPY_HEADER;
		}
	}
COPY_HEADER:
	copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.header.type,
						   strlen(current_parser->request.header.type));
	copy_to_request_buffer(current_parser->data.parsed_request, delimiter, strlen(delimiter));
	copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.header.value,
						   strlen(current_parser->request.header.value));
}

//----------- FUNCIONES DE TRANSICION ENTRE LOS ESTADOS -----------//

static void tr_check_asterisk_form(char current_char) {
	if (strcmp("OPTIONS", current_parser->request.method) == 0) tr_set_http_path_type(current_char);
	else
		tr_parse_error(current_char);
}

static void tr_check_method(char current_char) {
	tr_reset_copy_index(current_char);
	if (strcmp("CONNECT", current_parser->request.method) == 0) {
		current_parser->data.parser_state = PS_PATH_SLASHES;
		current_parser->request.target.path_type = ABSOLUTE;
		current_parser->data.request_status = PARSE_CONNECT_METHOD;
	}
}

static void tr_headers_ended(char current_char) {
	tr_copy_byte_to_buffer(current_char);
	current_parser->data.request_status = PARSE_BODY_INCOMPLETE;
}

static void tr_new_header(char current_char) {
	current_parser->data.request_status = PARSE_HEADER_LINE_INCOMPLETE;
	tr_copy_byte_to_buffer(current_char);
}

static void tr_copy_byte_to_buffer(char current_char) {
	size_t *idx = &current_parser->data.copy_index;
	size_t limit = 0;
	char *copy_buffer;
	switch (current_parser->data.parser_state) {
		case PS_METHOD:
			limit = MAX_METHOD_LENGTH;
			copy_buffer = current_parser->request.method;
			break;
		case PS_IPv4:
		case PS_IPv6:
			limit = MAX_IP_LENGTH;
			copy_buffer = current_parser->request.target.request_target.ip_addr;
			break;
		case PS_PATH_SCHEMA:
			limit = MAX_SCHEMA_LENGTH;
			copy_buffer = current_parser->request.schema;
			break;
		case PS_DOMAIN:
			limit = MAX_HOST_NAME_LENGTH;
			copy_buffer = current_parser->request.target.request_target.host_name;
			break;
		case PS_PORT:
			limit = MAX_PORT_LENGTH;
			copy_buffer = current_parser->request.target.port;
			break;
		case PS_ASTERISK_FORM:
		case PS_RELATIVE_PATH:
			limit = MAX_RELATIVE_PATH_LENGTH;
			copy_buffer = current_parser->request.target.relative_path;
			break;
		case PS_HEADER_TYPE:
			limit = MAX_HEADER_TYPE_LENGTH;
			copy_buffer = current_parser->request.header.type;
			break;
		case PS_HEADER_VALUE:
			limit = MAX_HEADER_VALUE_LENGTH;
			copy_buffer = current_parser->request.header.value;
			break;
		case PS_CR:
		case PS_LF:
			// las transiciones cambian el estado pero la informacion se debe llevar a donde corresponda
			switch (current_parser->data.request_status) {
				case PARSE_START_LINE_INCOMPLETE:
					return; // es de la version
				case PARSE_HEADER_LINE_INCOMPLETE:
					// pertenece al header value;
					limit = MAX_HEADER_VALUE_LENGTH;
					copy_buffer = current_parser->request.header.value;
					break;
				default:
					break;
			}
			break;
		case PS_CR_END:
		case PS_BODY:
			copy_char_to_request_buffer(current_parser->data.parsed_request, current_char);
			return;
		default:
			break;
	}

	if (*idx < limit) {
		// no copia espacios al inicio de cualquier valor de interes
		if (*idx != 0 || current_char != ' ') {
			copy_buffer[*idx] = current_char;
			copy_buffer[*idx + 1] = '\0';
			(*idx)++;
		}
	} else {
		tr_parse_error(current_char);
	}
}

static void tr_solve_relative_request_target(char current_char) {
	current_parser->request.target.path_type = ABSOLUTE_WITH_RELATIVE;
	tr_solve_request_target(current_char);
}

static void tr_solve_port_request_target(char current_char) {
	if (current_parser->data.request_status == PARSE_CONNECT_METHOD && strcmp(current_parser->request.target.port, "110") == 0) {
		// sabemos que estamos bajo el protocolo pop3
		current_parser->data.request_status = PARSE_CONNECT_METHOD_POP3;
	}
	tr_solve_request_target(current_char);
}

static void tr_solve_request_target(char current_char) {
	check_port();
	tr_reset_copy_index(current_char);
	current_parser->data.target_status = FOUND;
}

static void tr_line_ended(char current_char) {
	tr_copy_byte_to_buffer(current_char);
	tr_reset_copy_index(current_char);
	switch (current_parser->data.request_status) {
		case PARSE_START_LINE_INCOMPLETE:
			parse_start_line(current_char);
			current_parser->data.request_status = PARSE_START_LINE_COMPLETE;
			break;
		case PARSE_HEADER_LINE_INCOMPLETE:
			parse_header_line(current_char);
			current_parser->data.request_status = PARSE_HEADER_LINE_COMPLETE;
			break;
		default:
			tr_parse_error(current_char);
	}
}

static void tr_set_http_path_type(char current_char) {
	switch (current_char) {
		case '/':
			current_parser->request.target.path_type = RELATIVE;
			break;
		case '*':
			current_parser->request.target.path_type = ASTERISK_FORM;
			break;
		default:
			current_parser->request.target.path_type = ABSOLUTE;
			tr_set_host_type(current_char);
	}
}

static void tr_set_host_type(char current_char) {
	if (current_char == '[') {
		current_parser->request.target.host_type = IPV6;
	} else {
		if (IS_DIGIT(current_char)) {
			current_parser->request.target.host_type = IPV4;
		} else {
			current_parser->request.target.host_type = DOMAIN;
		}
		tr_copy_byte_to_buffer(current_char);
	}
}

static void tr_http_version(char current_char) {
	if ('9' >= current_char && current_char >= '0') {
		if (current_parser->request.version.major == EMPTY_VERSION) {
			current_parser->request.version.major = current_char;
		} else if (current_parser->request.version.minor == EMPTY_VERSION) {
			current_parser->request.version.minor = current_char;
		}
	}
}

static void tr_reset_copy_index(char current_char) {
	current_parser->data.copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_parse_error(char current_char) { current_parser->data.request_status = PARSE_ERROR; }

static void tr_adv(char current_char) {}

//----------- FUNCION QUE REALIZA LA EJECUCION DE LA MAQUINA DE ESTADOS -----------//

int parse_request(http_parser *parser, buffer **read_buffer) {
	current_parser = parser;
	char current_char;
	http_parser_state current_state;

	while (buffer_can_read(*read_buffer) && current_parser->data.request_status != PARSE_ERROR &&
		   current_parser->data.parser_state != PS_END && current_parser->data.request_status != PARSE_BODY_INCOMPLETE) {
		current_char = buffer_read(*read_buffer);
		current_state = current_parser->data.parser_state;
		// logger(DEBUG, "current_char: %c, current_state: %u", current_char, current_state);
		for (size_t i = 0; i < states_n[current_state]; i++) {
			if (states[current_state][i].when != EMPTY) {
				if (current_char == states[current_state][i].when || states[current_state][i].when == (char)ANY) {
					current_parser->data.parser_state = states[current_state][i].destination;
					states[current_state][i].transition(current_char);
					break;
				}
			} else if (states[current_state][i].upper_bound != EMPTY && states[current_state][i].lower_bound != EMPTY) {
				if (states[current_state][i].upper_bound >= current_char &&
					current_char >= states[current_state][i].lower_bound) {
					current_parser->data.parser_state = states[current_state][i].destination;
					states[current_state][i].transition(current_char);
					break;
				}
			} else {
				break;
			}
		}
		if (current_parser->data.target_status == FOUND) {
			// se encontro el destino a conectar, corto la maquina para que se empieze a realizar la conexion
			current_parser->data.target_status = SOLVED;
			return 0;
		}
	}

	if (current_parser->data.request_status == PARSE_BODY_INCOMPLETE) {
		if (current_parser->data.target_status == NOT_FOUND)
			// se terminaron los headers y no se reconocio la uri objetivo
			tr_parse_error(' ');
		else {
			// se pasa a leer el body, como no se parsea esta informacion no se ejecutara denuevo esta maquina, por lo que guardamos
			// toda la informacion ya parseada en el buffer de salida del cliente, en conjunto con la que no se parseo
			copy_from_buffer_to_buffer(parser->data.parsed_request, *read_buffer);
			close_buffer(*read_buffer);
			*read_buffer = parser->data.parsed_request;
		}
	}

	return 0;
}
