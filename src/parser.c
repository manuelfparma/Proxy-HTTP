#include <buffer.h>
#include <connection.h>
#include <logger.h>
#include <parser.h>
#include <stdlib.h>
#include <string.h>
#define ANY -1
#define EMPTY -2
#define N(x) (sizeof(x) / sizeof((x)[0]))
#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')

static void copy_to_request_buffer(buffer *target, char *source, ssize_t bytes);
static void parse_start_line(char current_char);
static void parse_header_line(char current_char);
static int check_method_is_connect();

// Transiciones entre nodos
static void tr_copy_byte_to_buffer(char current_char);
static void tr_solve_request_target(char current_char);
static void tr_line_ended(char current_char);
static void tr_incomplete_header(char current_char);
static void tr_set_http_path_type(char current_char);
static void tr_set_host_type(char current_char);
static void tr_http_version(char current_char);
static void tr_reset_copy_index(char current_char);
static void tr_parse_error(char current_char);
static void tr_adv(char current_char);
static void tr_request_ended(char current_char);
static void tr_headers_ended(char current_char);
static void tr_check_method(char current_char);

http_request *current_request;

// TODO: PUERTO, HTTP/2, HEADERS, case-sensitive, espacios de mas

static const http_parser_state_transition ST_METHOD[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH, .transition = tr_check_method},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_METHOD, .transition = tr_copy_byte_to_buffer}};

static const http_parser_state_transition ST_PATH[3] = {
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_set_http_path_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SCHEMA, .transition = tr_set_http_path_type},
};

static const http_parser_state_transition ST_PATH_SCHEMA[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SLASHES, .transition = tr_reset_copy_index},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_SCHEMA,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_PATH_SLASHES[2] = {
	{.when = '/', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SLASHES, .transition = tr_adv},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_DOMAIN,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_PATH_DOMAIN[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_DOMAIN, .transition = tr_set_host_type},
};

static const http_parser_state_transition ST_IP[5] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_set_host_type},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv4, .transition = tr_set_host_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
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
	 .transition = tr_solve_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv4, .transition = tr_copy_byte_to_buffer},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv6[6] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_copy_byte_to_buffer},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_solve_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv6, .transition = tr_copy_byte_to_buffer},
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
	 .transition = tr_solve_request_target},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_DOMAIN, .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_PORT[4] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_RELATIVE_PATH,
	 .transition = tr_solve_request_target},
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
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR, .transition = tr_reset_copy_index},
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
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR, .transition = tr_reset_copy_index},
	//{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HEADER_VALUE, .transition = tr_adv},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HEADER_VALUE,
	 .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_CR[2] = {
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_LF, .transition = tr_line_ended},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_LF[2] = {
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR_END, .transition = tr_adv},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HEADER_TYPE, .transition = tr_incomplete_header},
};

static const http_parser_state_transition ST_CR_END[2] = {
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_LF_END, .transition = tr_headers_ended},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_LF_END[1] = {
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_BODY, .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition ST_BODY[2] = {
	{.when = '\0', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_END, .transition = tr_request_ended},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_BODY, .transition = tr_copy_byte_to_buffer},
};

static const http_parser_state_transition *states[] = {
	ST_METHOD, ST_PATH, ST_RELATIVE_PATH, ST_PATH_SCHEMA, ST_PATH_SLASHES, ST_PATH_DOMAIN, ST_IP,
	ST_IPv4,   ST_IPv6, ST_DOMAIN,		  ST_PORT,		  ST_HTTP_VERSION, ST_HEADER_TYPE, ST_HEADER_VALUE,
	ST_CR,	   ST_LF,	ST_CR_END,		  ST_LF_END,	  ST_BODY};

static const size_t states_n[] = {
	N(ST_METHOD), N(ST_PATH), N(ST_RELATIVE_PATH), N(ST_PATH_SCHEMA), N(ST_PATH_SLASHES), N(ST_PATH_DOMAIN), N(ST_IP),
	N(ST_IPv4),	  N(ST_IPv6), N(ST_DOMAIN),		   N(ST_PORT),		  N(ST_HTTP_VERSION), N(ST_HEADER_TYPE), N(ST_HEADER_VALUE),
	N(ST_CR),	  N(ST_LF),	  N(ST_CR_END),		   N(ST_LF_END),	  N(ST_BODY),
};

static void copy_to_request_buffer(buffer *target, char *source, ssize_t bytes) {
	ssize_t bytes_available = (ssize_t)(target->limit - target->write);
	if (bytes > bytes_available) {
		strncpy((char *)target->write, (const char *)source, bytes_available);
		buffer_write_adv(current_request->parsed_request, bytes_available);
	} else {
		strcpy((char *)target->write, (const char *)source);
		buffer_write_adv(current_request->parsed_request, bytes);
	}
}

static void copy_char_to_request_buffer(buffer *target, char c) {
	if (buffer_can_write(target)) buffer_write(target, (uint8_t)c);
}

static void tr_check_method(char current_char){
	tr_reset_copy_index(current_char);

	if (strcmp("CONNECT", current_request->start_line.method) == 0) {
		current_request->parser_state = PS_PATH_DOMAIN;
	}
}

static void tr_headers_ended(char current_char) {
	logger(DEBUG, "tr_headers_ended");
	char *cr_lf = "\r\n";
	copy_to_request_buffer(current_request->parsed_request, cr_lf, strlen(cr_lf));
	current_request->package_status = PARSE_BODY_INCOMPLETE;
}

static void tr_request_ended(char current_char) {
	logger(DEBUG, "tr_request_ended");
	current_request->parser_state = PARSE_END;
}

static void tr_incomplete_header(char current_char) {
	current_request->package_status = PARSE_HEADER_LINE_INCOMPLETE;
	tr_copy_byte_to_buffer(current_char);
}

static void tr_copy_byte_to_buffer(char current_char) {
	size_t *idx = &current_request->copy_index;
	size_t limit;
	char *copy_buffer;
	switch (current_request->parser_state) {
		case PS_METHOD:
			limit = MAX_METHOD_LENGTH;
			copy_buffer = current_request->start_line.method;
			break;
		case PS_IP:
		case PS_IPv4:
		case PS_IPv6:
			limit = MAX_IP_LENGTH;
			copy_buffer = current_request->start_line.destination.request_target.ip_addr;
			break;
		case PS_PATH_SCHEMA:
			limit = MAX_SCHEMA_LENGTH;
			copy_buffer = current_request->start_line.schema;
			break;
		case PS_PATH_DOMAIN:
		case PS_DOMAIN:
			limit = MAX_HOST_NAME_LENGTH;
			copy_buffer = current_request->start_line.destination.request_target.host_name;
			break;
		case PS_PORT:
			limit = MAX_PORT_LENGTH;
			copy_buffer = current_request->start_line.destination.port;
			break;
		case PS_RELATIVE_PATH:
			limit = MAX_RELATIVE_PATH_LENGTH;
			copy_buffer = current_request->start_line.destination.relative_path;
			break;
		case PS_HEADER_TYPE:
			limit = MAX_HEADER_TYPE_LENGTH;
			copy_buffer = current_request->header.header_type;
			break;
		case PS_HEADER_VALUE:
			limit = MAX_HEADER_VALUE_LENGTH;
			copy_buffer = current_request->header.header_value;
			break;
		case PS_BODY:
			copy_char_to_request_buffer(current_request->parsed_request, current_char);
			return;
		default:
			limit = -1; // da error
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
		tr_parse_error(current_char); // TODO: MEJORAR
	}
}

static void tr_solve_request_target(char current_char) {
	current_request->request_target_status = SOLVED;
	tr_reset_copy_index(current_char);
}

static int find_idx(char *array, char c) {
	int idx;
	for (idx = 0; array[idx] != '\0' && array[idx] != c; idx++) {};
	return array[idx] == c ? idx : -1;
}

static void parse_header_line(char current_char) {
	char *delimiter = ": ";
	logger(DEBUG, "Finished parsing header [%s: %s]", current_request->header.header_type, current_request->header.header_value);
	if (current_request->start_line.destination.path_type == RELATIVE && current_request->request_target_status == UNSOLVED &&
		strcmp("Host", current_request->header.header_type) == 0) {
		int idx_port = find_idx(current_request->header.header_value, ':');
		if (idx_port == -1) {
			strcpy(current_request->start_line.destination.port, "80");
			logger(ERROR, "Not found ':' delimiter in header type Host");
		} else
			strcpy(current_request->start_line.destination.port, current_request->header.header_value + (idx_port + 1));

		if (IS_DIGIT(current_request->header.header_value[0])) {
			// TODO: setear ipv4 o ipv6????
			if (idx_port >= 1) {
				strncpy(current_request->start_line.destination.request_target.ip_addr, current_request->header.header_value,
						(size_t)idx_port);
				current_request->start_line.destination.request_target.ip_addr[idx_port] = '\0';
			} else
				strcpy(current_request->start_line.destination.request_target.ip_addr, current_request->header.header_value);
		} else {
			current_request->start_line.destination.host_type = DOMAIN;
			if (idx_port >= 1) {
				strncpy(current_request->start_line.destination.request_target.host_name, current_request->header.header_value,
						(size_t)idx_port);
				current_request->start_line.destination.request_target.host_name[idx_port] = '\0';
			} else
				strcpy(current_request->start_line.destination.request_target.host_name, current_request->header.header_value);
		}

		copy_to_request_buffer(current_request->parsed_request, current_request->header.header_type,
							   strlen(current_request->header.header_type));
		copy_to_request_buffer(current_request->parsed_request, delimiter, strlen(delimiter));
		copy_to_request_buffer(current_request->parsed_request, current_request->header.header_value,
							   strlen(current_request->header.header_value));
		current_request->request_target_status = SOLVED;
	} else if (strcmp("Host", current_request->header.header_type) != 0) {
		// rellenar parse_state con header solo si no es Host(ya se copio por que soy absoluto o por que ya lo encontre)
		copy_to_request_buffer(current_request->parsed_request, current_request->header.header_type,
							   strlen(current_request->header.header_type));
		copy_to_request_buffer(current_request->parsed_request, delimiter, strlen(delimiter));
		copy_to_request_buffer(current_request->parsed_request, current_request->header.header_value,
							   strlen(current_request->header.header_value));
	}
	char *cr_lf = "\r\n";
	copy_to_request_buffer(current_request->parsed_request, cr_lf, strlen(cr_lf));
}

static void tr_line_ended(char current_char) {
	switch (current_request->package_status) {
		case PARSE_START_LINE_INCOMPLETE:
			// rellenar parse_state con start line
			parse_start_line(current_char);
			current_request->package_status = PARSE_START_LINE_COMPLETE;
			break;
		case PARSE_HEADER_LINE_INCOMPLETE:
			parse_header_line(current_char);
			current_request->package_status = PARSE_HEADER_LINE_COMPLETE;
			break;
		default:
			logger(ERROR, "State error"); // TODO: mejorar
	}
}

static void copy_to_request_buffer_request_target() {
	switch (current_request->start_line.destination.host_type) {
		case IPV4:
		case IPV6:
			copy_to_request_buffer(current_request->parsed_request,
								   current_request->start_line.destination.request_target.ip_addr,
								   strlen(current_request->start_line.destination.request_target.ip_addr));
			break;
		case DOMAIN:
			copy_to_request_buffer(current_request->parsed_request,
								   current_request->start_line.destination.request_target.host_name,
								   strlen(current_request->start_line.destination.request_target.host_name));
			break;
		default:
			// TODO: error
			break;
	}
}

static void copy_port_to_request_buffer() {
	copy_char_to_request_buffer(current_request->parsed_request, ':');
	if (strlen(current_request->start_line.destination.port) == 0) {
		// verificar es null terminated desde el arranque
		char *port;
		if (strcmp("http", current_request->start_line.schema) == 0) {
			port = "80";
			strcpy(current_request->start_line.destination.port, port);
			copy_to_request_buffer(current_request->parsed_request, port, strlen(port));
		} else if (strcmp("https", current_request->start_line.schema) == 0) {
			port = "433";
			strcpy(current_request->start_line.destination.port, port);
			copy_to_request_buffer(current_request->parsed_request, port, strlen(port));
		}
	} else {
		copy_to_request_buffer(current_request->parsed_request, current_request->start_line.destination.port,
							   strlen(current_request->start_line.destination.port));
	}
}

static int check_method_is_connect() {
	logger(INFO, "Identifying CONNECT method");

	if (strcmp("CONNECT", current_request->start_line.method) == 0) {
		logger(INFO, "Identified CONNECT method");
		current_request->parser_state = PS_BODY;
		current_request->package_status = PARSE_BODY_INCOMPLETE;
		return 1;
	}
	return 0;
}

static void parse_start_line(char current_char) {
	char *double_slash = "//";
	logger(DEBUG, "Parsing start_line");
	copy_to_request_buffer(current_request->parsed_request, current_request->start_line.method,
						   strlen(current_request->start_line.method));
	copy_char_to_request_buffer(current_request->parsed_request, ' ');

	switch (current_request->start_line.destination.path_type) {
		case ABSOLUTE:
			if (check_method_is_connect() != 1) {
				copy_to_request_buffer(current_request->parsed_request, current_request->start_line.schema,
									   strlen(current_request->start_line.schema));
				copy_char_to_request_buffer(current_request->parsed_request, ':');

				// Si es http o https va con '//', source: https://datatracker.ietf.org/doc/html/rfc7230#section-2.7.1
				if (strcmp("http", current_request->start_line.schema) == 0 ||
					strcmp("https", current_request->start_line.schema) == 0)
					// TODO:implementar case-unsensitive guardando el schemao en minuscula
					copy_to_request_buffer(current_request->parsed_request, double_slash, strlen(double_slash));
			}
			copy_to_request_buffer_request_target();

			copy_port_to_request_buffer();
			copy_char_to_request_buffer(current_request->parsed_request, '/');

			break;
		case RELATIVE:
			break;
		case NO_RESOURCE:
			// TODO
		default:
			// TODO: error
			break;
	}
	copy_to_request_buffer(current_request->parsed_request, current_request->start_line.destination.relative_path,
						   strlen(current_request->start_line.destination.relative_path));

	// Hardcodeamos la version para, en el caso ideal, recibir un paquete null terminated del servidor
	char *http = " HTTP/1.0";
	copy_to_request_buffer(current_request->parsed_request, http, strlen(http));
	char *cr_lf = "\r\n";
	copy_to_request_buffer(current_request->parsed_request, cr_lf, strlen(cr_lf));

	if (current_request->start_line.destination.path_type == ABSOLUTE) {
		char *header_host = "Host: ";
		copy_to_request_buffer(current_request->parsed_request, header_host, strlen(header_host));
		copy_to_request_buffer_request_target();
		copy_port_to_request_buffer();
		copy_to_request_buffer(current_request->parsed_request, cr_lf, strlen(cr_lf));
	}
}

static void tr_set_http_path_type(char current_char) {
	switch (current_char) {
		case '/':
			current_request->start_line.destination.path_type = RELATIVE;
			break;
		default:
			current_request->start_line.destination.path_type = ABSOLUTE;
	}
	tr_copy_byte_to_buffer(current_char);
}

static void tr_set_host_type(char current_char) {
	switch (current_char) {
		case '.':
			current_request->start_line.destination.host_type = IPV4;
			break;
		case ':':
			current_request->start_line.destination.host_type = IPV6;
			break;
		default:
			current_request->start_line.destination.host_type = DOMAIN;
	}
	tr_copy_byte_to_buffer(current_char);
}

static void tr_http_version(char current_char) {
	if ('9' >= current_char && current_char >= '0') {
		// TODO chequear inicializacion en NULL
		if (current_request->start_line.version.major == EMPTY_VERSION) {
			current_request->start_line.version.major = current_char;
		} else if (current_request->start_line.version.minor == EMPTY_VERSION) {
			current_request->start_line.version.minor = current_char;
		} else {
			// version no soportada
		}
	}
}

static void tr_reset_copy_index(char current_char) {
	current_request->copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_parse_error(char current_char) {
	// TODO: implementar
	current_request->package_status = PARSE_ERROR;
}

static void tr_adv(char current_char) {}

int parse_request(http_request *request, buffer *read_buffer) {
	current_request = request;
	char current_char;
	http_parser_state current_state;

	while (buffer_can_read(read_buffer)) {
		current_char = buffer_read(read_buffer);
		current_state = current_request->parser_state;
		logger(DEBUG, "current_char: %c, current_state: %u", current_char, current_state);
		for (size_t i = 0; i < states_n[current_state]; i++) {
			if (states[current_state][i].when != EMPTY) {
				if (current_char == states[current_state][i].when || states[current_state][i].when == (char)ANY) {
					current_request->parser_state = states[current_state][i].destination;
					states[current_state][i].transition(current_char);
					break;
				}
			} else if (states[current_state][i].upper_bound != EMPTY && states[current_state][i].lower_bound != EMPTY) {
				if (states[current_state][i].upper_bound >= current_char &&
					current_char >= states[current_state][i].lower_bound) {
					current_request->parser_state = states[current_state][i].destination;
					states[current_state][i].transition(current_char);
					break;
				}
			} else {
				logger(ERROR, "No hay transicion disponible para %c", current_char);
				break;
			}
		}
	}

	return 0;
}
