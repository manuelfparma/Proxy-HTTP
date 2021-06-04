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

static void copy_to_request_buffer(buffer *target, char *source);
static void tr_solve_request_target(char current_char);
static void tr_line_ended(char current_char);
static void parse_start_line(char current_char);
static void tr_incomplete_header(char current_char);
static void tr_copy_byte_header_type(char current_char);
static void tr_copy_byte_header_value(char current_char);
static void tr_set_http_path_type(char current_char);
static void tr_copy_byte_port(char current_char);
static void tr_set_host_type(char current_char);
static void tr_http_version(char current_char);
static void tr_copy_byte_protocol(char current_char);
static void tr_copy_byte_relative_path(char current_char);
static void tr_copy_byte_ip(char current_char);
static void tr_reset_copy_index(char current_char);
static void tr_copy_byte_host_name(char current_char);
static void tr_copy_byte_method(char current_char);
static void tr_parse_error(char current_char);
static void tr_adv(char current_char);
static void tr_request_ended(char current_char);

http_request *current_request;

// TODO: PUERTO, HTTP/2, HEADERS, case-sensitive, espacios de mas

static const http_parser_state_transition ST_METHOD[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_METHOD, .transition = tr_copy_byte_method}};

static const http_parser_state_transition ST_PATH[3] = {
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_RELATIVE,
	 .transition = tr_set_http_path_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_ip},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_PROTOCOL,
	 .transition = tr_set_http_path_type},
};

static const http_parser_state_transition ST_PATH_PROTOCOL[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SLASHES, .transition = tr_reset_copy_index},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_PROTOCOL,
	 .transition = tr_copy_byte_protocol},
};

static const http_parser_state_transition ST_PATH_SLASHES[2] = {
	{.when = '/', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_SLASHES, .transition = tr_adv},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_DOMAIN,
	 .transition = tr_copy_byte_host_name},
};

static const http_parser_state_transition ST_PATH_DOMAIN[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_URI, .transition = tr_set_host_type},
};

static const http_parser_state_transition ST_IP[5] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_set_host_type},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv4, .transition = tr_set_host_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv4[6] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv4, .transition = tr_copy_byte_ip},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_RELATIVE,
	 .transition = tr_solve_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv4, .transition = tr_copy_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv6[6] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_copy_byte_ip},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_RELATIVE,
	 .transition = tr_solve_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv6, .transition = tr_copy_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_URI[4] = {
	{.when = ' ',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HTTP_VERSION,
	 .transition = tr_solve_request_target},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PORT, .transition = tr_reset_copy_index},
	{.when = '/',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_RELATIVE,
	 .transition = tr_solve_request_target},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_URI, .transition = tr_copy_byte_host_name},
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
	 .destination = PS_PATH_RELATIVE,
	 .transition = tr_solve_request_target},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_PORT, .transition = tr_copy_byte_port},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_PATH_RELATIVE[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_PATH_RELATIVE,
	 .transition = tr_copy_byte_relative_path},
};

static const http_parser_state_transition ST_HTTP_VERSION[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
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
	 .transition = tr_copy_byte_header_type},
};

static const http_parser_state_transition ST_HEADER_VALUE[3] = {
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR, .transition = tr_reset_copy_index},
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HEADER_VALUE, .transition = tr_adv},
	{.when = ANY,
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_HEADER_VALUE,
	 .transition = tr_copy_byte_header_value},
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
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_LF_END, .transition = tr_request_ended},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_ERROR, .transition = tr_parse_error},
};

static const http_parser_state_transition *states[] = {
	ST_METHOD, ST_PATH, ST_PATH_RELATIVE, ST_PATH_PROTOCOL, ST_PATH_SLASHES, ST_PATH_DOMAIN, ST_IP, ST_IPv4,  ST_IPv6,
	ST_URI,	   ST_PORT, ST_HTTP_VERSION,  ST_HEADER_TYPE,	ST_HEADER_VALUE, ST_CR,			 ST_LF, ST_CR_END};

static const size_t states_n[] = {
	N(ST_METHOD), N(ST_PATH), N(ST_PATH_RELATIVE), N(ST_PATH_PROTOCOL), N(ST_PATH_SLASHES), N(ST_PATH_DOMAIN), N(ST_IP),
	N(ST_IPv4),	  N(ST_IPv6), N(ST_URI),		   N(ST_PORT),			N(ST_HTTP_VERSION), N(ST_HEADER_TYPE), N(ST_HEADER_VALUE),
	N(ST_CR),	  N(ST_LF),	  N(ST_CR_END),
};

// source debe ser NULL TERMINATED
static void copy_to_request_buffer(buffer *target, char *source) {
	ssize_t bytes = strlen((const char *)source);
	ssize_t bytes_available = (ssize_t)(target->limit - target->write);
	if (bytes > bytes_available) {
		strncpy((char *)target, (const char *)source, bytes_available);
		buffer_write_adv(current_request->parsed_request, bytes_available);
	} else {
		strcpy((char *)target, (const char *)source);
		buffer_write_adv(current_request->parsed_request, bytes);
	}
}

static void tr_request_ended(char current_char) { copy_to_request_buffer(current_request->parsed_request, "\r\n"); }

static void tr_incomplete_header(char current_char) {
	current_request->package_status = PARSE_HEADER_LINE_INCOMPLETE;
	tr_copy_byte_header_type(current_char);
}

static void tr_copy_byte_header_value(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->header.header_value[*idx] = current_char;
	current_request->header.header_value[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_copy_byte_header_type(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->header.header_type[*idx] = current_char;
	current_request->header.header_type[*idx + 1] = '\0';
	(*idx)++;
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

static void tr_line_ended(char current_char) {
	switch (current_request->package_status) {
		case PARSE_START_LINE_INCOMPLETE:
			// rellenar parse_state con start line
			parse_start_line(current_char);
			current_request->package_status = PARSE_START_LINE_COMPLETE;
			break;
		case PARSE_HEADER_LINE_INCOMPLETE:
			logger(DEBUG, "Finished parsing header [%s: %s]", current_request->header.header_type,
				   current_request->header.header_value);
			if (current_request->start_line.destination.path_type == RELATIVE &&
				current_request->request_target_status == UNSOLVED && strcmp("Host", current_request->header.header_type) == 0) {
				int idx_port = find_idx(current_request->header.header_value, ':');
				if (idx_port == -1) {
					strcpy(current_request->start_line.destination.port, "80");
					logger(ERROR, "Not found ':' delimiter in header type Host");
				} else
					strcpy(current_request->start_line.destination.port, current_request->header.header_value + (idx_port + 1));

				if (IS_DIGIT(current_request->header.header_value[0])) {
					// TODO: setear ipv4 o ipv6????
					if (idx_port >= 1) {
						strncpy(current_request->start_line.destination.request_target.ip_addr,
								current_request->header.header_value, (size_t)idx_port);
						current_request->start_line.destination.request_target.ip_addr[idx_port] = '\0';
					} else
						strcpy(current_request->start_line.destination.request_target.ip_addr,
							   current_request->header.header_value);
				} else {
					current_request->start_line.destination.host_type = DOMAIN;
					if (idx_port >= 1) {
						strncpy(current_request->start_line.destination.request_target.host_name,
								current_request->header.header_value, (size_t)idx_port);
						current_request->start_line.destination.request_target.host_name[idx_port] = '\0';
					} else
						strcpy(current_request->start_line.destination.request_target.host_name,
							   current_request->header.header_value);
				}

				copy_to_request_buffer(current_request->parsed_request, current_request->header.header_type);
				copy_to_request_buffer(current_request->parsed_request, ": ");
				copy_to_request_buffer(current_request->parsed_request, current_request->header.header_value);
				current_request->request_target_status = SOLVED;
			} else if (strcmp("Host", current_request->header.header_type) != 0) {
				// rellenar parse_state con header solo si no es Host(ya se copio por que soy absoluto o por que ya lo encontre)
				copy_to_request_buffer(current_request->parsed_request, current_request->header.header_type);
				copy_to_request_buffer(current_request->parsed_request, ": ");
				copy_to_request_buffer(current_request->parsed_request, current_request->header.header_value);
				current_request->package_status = PARSE_HEADER_LINE_COMPLETE;
			}
			break;
		default:
			logger(ERROR, "?????");
	}
	copy_to_request_buffer(current_request->parsed_request, "\r\n");
}

static void copy_to_request_buffer_request_target() {
	switch (current_request->start_line.destination.host_type) {
		case IPV4:
		case IPV6:
			copy_to_request_buffer(current_request->parsed_request,
								   current_request->start_line.destination.request_target.ip_addr);
			break;
		case DOMAIN:
			copy_to_request_buffer(current_request->parsed_request,
								   current_request->start_line.destination.request_target.host_name);
			break;
		default:
			// TODO: error
			break;
	}
}

static void parse_start_line(char current_char) {

	logger(DEBUG, "FILLING PARSE REQUEST");
	copy_to_request_buffer(current_request->parsed_request, current_request->start_line.method);
	copy_to_request_buffer(current_request->parsed_request, " ");

	switch (current_request->start_line.destination.path_type) {
		case ABSOLUTE:
			copy_to_request_buffer(current_request->parsed_request, current_request->start_line.protocol);
			copy_to_request_buffer(current_request->parsed_request, ":");

			// Si es http o https va con '//', source: https://datatracker.ietf.org/doc/html/rfc7230#section-2.7.1
			if (strcmp("http", current_request->start_line.protocol) == 0 ||
				strcmp("https", current_request->start_line.protocol) == 0)
				// TODO:implementar case-unsensitive guardando el protocolo en minuscula
				copy_to_request_buffer(current_request->parsed_request, "//");

			copy_to_request_buffer_request_target();

			copy_to_request_buffer(current_request->parsed_request, ":");
			if (strlen(current_request->start_line.destination.port) == 0) {
				// verificar es null terminated desde el arranque
				if (strcmp("http", current_request->start_line.protocol) == 0) {
					strcpy(current_request->start_line.destination.port, "80");
					copy_to_request_buffer(current_request->parsed_request, "80");
				} else if (strcmp("https", current_request->start_line.protocol) == 0) {
					strcpy(current_request->start_line.destination.port, "433");
					copy_to_request_buffer(current_request->parsed_request, "433");
				}
			} else {
				copy_to_request_buffer(current_request->parsed_request, current_request->start_line.destination.port);
			}
			break;
		case RELATIVE:
			break;
		case NO_RESOURCE:
			// TODO
		default:
			// TODO: error
			break;
	}

	copy_to_request_buffer(current_request->parsed_request, "/");
	copy_to_request_buffer(current_request->parsed_request, current_request->start_line.destination.relative_path);
	copy_to_request_buffer(current_request->parsed_request, " HTTP/");
	copy_to_request_buffer(current_request->parsed_request, &current_request->start_line.version.major);
	copy_to_request_buffer(current_request->parsed_request, ".");
	copy_to_request_buffer(current_request->parsed_request,
						   &current_request->start_line.version.minor); // TODO: Deberia ir siempre 0 para que sea mejor?
	copy_to_request_buffer(current_request->parsed_request, "\r\n");

	if (current_request->start_line.destination.path_type == ABSOLUTE) {
		copy_to_request_buffer(current_request->parsed_request, "Host: ");
		copy_to_request_buffer_request_target();
		copy_to_request_buffer(current_request->parsed_request, "\r\n");
	}
}

static void tr_copy_byte_port(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.destination.port[*idx] = current_char;
	current_request->start_line.destination.port[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_set_http_path_type(char current_char) {
	switch (current_char) {
		case '/':
			current_request->start_line.destination.path_type = RELATIVE;
			tr_copy_byte_relative_path(current_char);
			break;
		default:
			current_request->start_line.destination.path_type = ABSOLUTE;
			tr_copy_byte_protocol(current_char);
	}
}

static void tr_set_host_type(char current_char) {
	switch (current_char) {
		case '.':
			current_request->start_line.destination.host_type = IPV4;
			tr_copy_byte_ip(current_char);
			break;
		case ':':
			current_request->start_line.destination.host_type = IPV6;
			tr_copy_byte_ip(current_char);
			break;
		default:
			current_request->start_line.destination.host_type = DOMAIN;
			tr_copy_byte_host_name(current_char);
	}
}

static void tr_http_version(char current_char) {
	if ('9' >= current_char && current_char >= '0') {
		// TODO chequear inicializacion en NULL
		if (current_request->start_line.version.major == EMPTY) {
			current_request->start_line.version.major = current_char;
		} else if (current_request->start_line.version.minor == EMPTY) {
			current_request->start_line.version.minor = current_char;
		} else {
			// version no soportada
		}
	}
}

static void tr_copy_byte_protocol(char current_char) {
	size_t *idx = &current_request->copy_index;
	if (*idx < MAX_PROTOCOL_LENGTH) {
		current_request->start_line.protocol[*idx] = current_char;
		current_request->start_line.protocol[*idx + 1] = '\0';
		(*idx)++;
	}
}

static void tr_copy_byte_relative_path(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.destination.relative_path[*idx] = current_char;
	current_request->start_line.destination.relative_path[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_copy_byte_ip(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.destination.request_target.ip_addr[*idx] = current_char;
	current_request->start_line.destination.request_target.ip_addr[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_copy_byte_host_name(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.destination.request_target.host_name[*idx] = current_char;
	current_request->start_line.destination.request_target.host_name[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_reset_copy_index(char current_char) {
	current_request->copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_copy_byte_method(char current_char) {
	size_t *idx = &current_request->copy_index;
	if (*idx < MAX_METHOD_LENGTH) {
		current_request->start_line.method[*idx] = current_char;
		current_request->start_line.method[*idx + 1] = '\0';
		(*idx)++;
	} else
		return; // TODO: Error -1 ?????
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
