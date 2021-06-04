#include <buffer.h>
#include <connection.h>
#include <logger.h>
#include <parser.h>
#include <stdlib.h>
#include <string.h>
#define ANY -1
#define EMPTY -2
#define N(x) (sizeof(x) / sizeof((x)[0]))

static void copy_to_request_buffer(buffer *target, char *source);
static void tr_end(char current_char);
static void tr_set_http_path_type(char current_char);
static void tr_set_host_type(char current_char);
static void tr_http_version(char current_char);
static void tr_byte_protocol(char current_char);
static void tr_byte_relative_path(char current_char);
static void tr_byte_ip(char current_char);
static void tr_reset_copy_index(char current_char);
static void tr_byte_host_name(char current_char);
static void tr_byte_method(char current_char);
static void tr_parse_error(char current_char);

http_request *current_request;

// TODO: PUERTO, HTTP/2, HEADERS

static const http_parser_state_transition ST_METHOD[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_METHOD, .transition = tr_byte_method}};

static const http_parser_state_transition ST_PATH[3] = {
	{.when = '/', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_RELATIVE, .transition = tr_set_http_path_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_PROTOCOL, .transition = tr_set_http_path_type},
};

static const http_parser_state_transition ST_PATH_PROTOCOL[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_DOMAIN, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_PROTOCOL, .transition = tr_byte_protocol},
};

static const http_parser_state_transition ST_PATH_DOMAIN[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_URI, .transition = tr_set_host_type},
};

static const http_parser_state_transition ST_IP[5] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_set_host_type},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv4, .transition = tr_set_host_type},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv4[5] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv4, .transition = tr_byte_ip},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv4, .transition = tr_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_IPv6[5] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ':', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_IPv6, .transition = tr_byte_ip},
	{.when = '.', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IPv6, .transition = tr_byte_ip},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_URI[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_URI, .transition = tr_byte_host_name},
};

static const http_parser_state_transition ST_PATH_RELATIVE[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH_RELATIVE, .transition = tr_byte_relative_path},
};

static const http_parser_state_transition ST_HTTP_VERSION[3] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_parse_error},
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_http_version},
};

static const http_parser_state_transition ST_CR[2] = {
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_LF, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_LF[2] = {
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_CR_END, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_parse_error},
	// ir a header
};

static const http_parser_state_transition ST_CR_END[2] = {
	{.when = '\n', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_LF_END, .transition = tr_reset_copy_index},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_parse_error},
};

static const http_parser_state_transition ST_LF_END[2] = {
	{.when = '\r', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_FIN, .transition = tr_end},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_HTTP_VERSION, .transition = tr_parse_error},
	// ir a header
};

static const http_parser_state_transition *states[] = {ST_METHOD, ST_PATH, ST_PATH_PROTOCOL, ST_PATH_DOMAIN,   ST_IP,
													   ST_IPv4,	  ST_IPv6, ST_URI,			 ST_PATH_RELATIVE, ST_HTTP_VERSION,
													   ST_CR,	  ST_LF,   ST_CR_END,		 ST_LF_END};

static const size_t states_n[] = {
	N(ST_METHOD), N(ST_PATH),		   N(ST_PATH_PROTOCOL), N(ST_PATH_DOMAIN), N(ST_IP), N(ST_IPv4),   N(ST_IPv6),
	N(ST_URI),	  N(ST_PATH_RELATIVE), N(ST_HTTP_VERSION),	N(ST_CR),		   N(ST_LF), N(ST_CR_END), N(ST_LF_END),
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

static void tr_end(char current_char) {
	copy_to_request_buffer(current_request->parsed_request, current_request->start_line.method);
	copy_to_request_buffer(current_request->parsed_request, " ");

	switch (current_request->start_line.target.path_type) {
		case ABSOLUTE:
			switch (current_request->start_line.target.host_type) {
				case IPV4:
				case IPV6:
					copy_to_request_buffer(current_request->parsed_request,
										   current_request->start_line.target.request_target.ip_addr);
					break;
				case DOMAIN:
					copy_to_request_buffer(current_request->parsed_request,
										   current_request->start_line.target.request_target.host_name);
					break;
				default:
					// TODO: error
					break;
			}
		case RELATIVE:
			copy_to_request_buffer(current_request->parsed_request,
								   current_request->start_line.target.request_target.relative_path);
			break;
		case NO_RESOURCE:
			// TODO
		default:
			// TODO: error
			break;
	}

	copy_to_request_buffer(current_request->parsed_request, " ");
	copy_to_request_buffer(current_request->parsed_request, "HTTP/");
	copy_to_request_buffer(current_request->parsed_request, &current_request->start_line.version.major);
	copy_to_request_buffer(current_request->parsed_request, ".");
	copy_to_request_buffer(current_request->parsed_request, &current_request->start_line.version.minor);
	copy_to_request_buffer(current_request->parsed_request, "\r\n\r\n");
}

static void tr_set_http_path_type(char current_char) {
	switch (current_char) {
		case '/':
			current_request->start_line.target.path_type = RELATIVE;
			tr_byte_relative_path(current_char);
			break;
		default:
			current_request->start_line.target.path_type = ABSOLUTE;
			tr_byte_protocol(current_char);
	}
}

static void tr_set_host_type(char current_char) {
	switch (current_char) {
		case '.':
			current_request->start_line.target.host_type = IPV4;
			tr_byte_ip(current_char);
			break;
		case ':':
			current_request->start_line.target.host_type = IPV6;
			tr_byte_ip(current_char);
			break;
		default:
			current_request->start_line.target.host_type = DOMAIN;
			tr_byte_host_name(current_char);
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

static void tr_byte_protocol(char current_char) {
	size_t *idx = &current_request->copy_index;
	if (*idx < MAX_PROTOCOL_LENGTH) {
		current_request->protocol[*idx] = current_char;
		current_request->protocol[*idx + 1] = '\0';
		(*idx)++;
	}
}

static void tr_byte_relative_path(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.target.request_target.relative_path[*idx] = current_char;
	current_request->start_line.target.request_target.relative_path[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_byte_ip(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.target.request_target.ip_addr[*idx] = current_char;
	current_request->start_line.target.request_target.ip_addr[*idx + 1] = '\0';
	(*idx)++;
}

static void tr_byte_host_name(char current_char) {
	size_t *idx = &current_request->copy_index;
	current_request->start_line.target.request_target.host_name[*idx] = current_char;
	current_request->start_line.target.request_target.host_name[*idx + 1] = '\0';
	(*idx)++;
	logger(DEBUG, "HOSTNAME: %s with idx: %zu", current_request->start_line.target.request_target.host_name, *idx);
}

static void tr_reset_copy_index(char current_char) {
	current_request->copy_index = 0;
	logger(DEBUG, "CALLING RESET");
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_byte_method(char current_char) {
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
}

int parse_request(http_request *request, buffer *read_buffer) {
	current_request = request;
	char current_char;
	http_parser_state current_state;

	while (buffer_can_read(read_buffer)) {
		current_char = buffer_read(read_buffer);
		current_state = current_request->parser_state;
		logger(DEBUG, "current_char: %c", current_char);
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
		logger(DEBUG, "HOSTNAME: %s with idx: %zu", current_request->start_line.target.request_target.host_name, current_request->copy_index);

	}

	return 0;
}
