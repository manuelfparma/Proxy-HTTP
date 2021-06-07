#include <buffer.h>
#include <connection.h>
#include <http_parser.h>
#include <logger.h>
#include <stdlib.h>
#include <string.h>
#define ANY -1
#define EMPTY -2
#define N(x) (sizeof(x) / sizeof((x)[0]))
#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')
#define DISTANCE 'a' - 'A'

static void copy_to_request_buffer(buffer *target, char *source, ssize_t bytes);
static void parse_start_line(char current_char);
static void parse_header_line(char current_char);
static void copy_port();
static int strcmp_lower_case(char *str1, char *str2);

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
static void tr_check_asterisk_form(char current_char);

http_parser *current_parser;

//----------- ESTRUCTURAS QUE REPRESENTAN LOS NODOS DEL GRAFO -----------//

static const http_parser_state_transition ST_METHOD[2] = {
	{.when = ' ', .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_PATH, .transition = tr_check_method},
	{.when = ANY, .lower_bound = EMPTY, .upper_bound = EMPTY, .destination = PS_METHOD, .transition = tr_copy_byte_to_buffer}};

static const http_parser_state_transition ST_PATH[4] = {
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
	{.when = EMPTY, .lower_bound = '0', .upper_bound = '9', .destination = PS_IP, .transition = tr_copy_byte_to_buffer},
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
	{.when = ':',
	 .lower_bound = EMPTY,
	 .upper_bound = EMPTY,
	 .destination = PS_IPv6,
	 .transition = tr_copy_byte_to_buffer}, // TODO: FIX PUERTO
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

//----------- ESTRUCTURAS PARA SABER LAS TRANSICIONES DE CADA NODO -----------//

static const http_parser_state_transition *states[] = {
	ST_METHOD, ST_PATH,	  ST_ASTERISK_FORM, ST_RELATIVE_PATH, ST_PATH_SCHEMA,  ST_PATH_SLASHES, ST_PATH_DOMAIN,	 ST_IP,
	ST_IPv4,   ST_IPv6,	  ST_DOMAIN,		ST_PORT,		  ST_HTTP_VERSION, ST_HEADER_TYPE,	ST_HEADER_VALUE, ST_CR,
	ST_LF,	   ST_CR_END, ST_LF_END,		ST_BODY};

static const size_t states_n[] = {
	N(ST_METHOD),		N(ST_PATH),			N(ST_ASTERISK_FORM), N(ST_RELATIVE_PATH),
	N(ST_PATH_SCHEMA),	N(ST_PATH_SLASHES), N(ST_PATH_DOMAIN),	 N(ST_IP),
	N(ST_IPv4),			N(ST_IPv6),			N(ST_DOMAIN),		 N(ST_PORT),
	N(ST_HTTP_VERSION), N(ST_HEADER_TYPE),	N(ST_HEADER_VALUE),	 N(ST_CR),
	N(ST_LF),			N(ST_CR_END),		N(ST_LF_END),		 N(ST_BODY),
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

// deben ser NULL TERMINATED
static int strcmp_lower_case(char *str1, char *str2) {
	int i = 0, diff;
	for (; str1[i] != '\0' && str2[i] != '\0'; i++) {
		diff = (('A' <= str1[i] && str1[i] <= 'Z') ? str1[i] + DISTANCE : str1[i]) -
			   (('A' <= str2[i] && str2[i] <= 'Z') ? str2[i] + DISTANCE : str2[i]);
		// hago la resta de sus mayusculas para ser case-insensitive
		if (diff != 0) return diff;
	}
	if (str1[i] == '\0' && str2[i] == '\0') {
		return 0;
	} else if (str1[i] == '\0') {
		return -1;
	} else {
		return 1;
	}
}

static int find_idx(char *array, char c) {
	int idx;
	for (idx = 0; array[idx] != '\0' && array[idx] != c; idx++) {};
	return array[idx] == c ? idx : -1;
}
static void copy_to_request_buffer_request_target() {
	switch (current_parser->request.target.host_type) {
		case IPV4:
		case IPV6:
			copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.request_target.ip_addr,
								   strlen(current_parser->request.target.request_target.ip_addr));
			break;
		case DOMAIN:
			copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.request_target.host_name,
								   strlen(current_parser->request.target.request_target.host_name));
			break;
		default:
			// TODO: error
			break;
	}
}

static void copy_port() {
	if (strlen(current_parser->request.target.port) == 0) {
		logger(DEBUG, "No port");
		char *port;
		if (strcmp_lower_case("http", current_parser->request.schema) == 0) {
			port = "80";
			strcpy(current_parser->request.target.port, port);
		} else if (strcmp_lower_case("https", current_parser->request.schema) == 0) {
			port = "433";
			strcpy(current_parser->request.target.port, port);
		}
	}
}

static void parse_start_line(char current_char) {
	logger(DEBUG, "Parsing start_line");

	copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.method,
						   strlen(current_parser->request.method));
	copy_char_to_request_buffer(current_parser->data.parsed_request, ' ');

	if (current_parser->request.target.path_type != ASTERISK_FORM)
		copy_char_to_request_buffer(current_parser->data.parsed_request, '/');

	copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.relative_path,
						   strlen(current_parser->request.target.relative_path));

	// Hardcodeamos la version para, en el caso ideal, recibir el delimitador null terminated indicando que el servidor termino de
	// enviar sus recursosvoid tr_check_asterisk_form(char current_char) {
	if (strcmp("OPTIONS", current_parser->request.method) == 0) tr_set_http_path_type(current_char);
	else
		tr_parse_error(current_char);
	char *http = " HTTP/1.0";
	copy_to_request_buffer(current_parser->data.parsed_request, http, strlen(http));
	char *cr_lf = "\r\n";
	copy_to_request_buffer(current_parser->data.parsed_request, cr_lf, strlen(cr_lf));

	if (current_parser->request.target.path_type == ABSOLUTE) {
		char *header_host = "Host: ";
		copy_to_request_buffer(current_parser->data.parsed_request, header_host, strlen(header_host));
		copy_to_request_buffer_request_target();
		copy_char_to_request_buffer(current_parser->data.parsed_request, ':');
		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.target.port,
							   strlen(current_parser->request.target.port));
		copy_to_request_buffer(current_parser->data.parsed_request, cr_lf, strlen(cr_lf));
	}
}

static void parse_header_line(char current_char) {
	char *delimiter = ": ";
	char *cr_lf = "\r\n";
	// logger(DEBUG, "Finished parsing header [%s: %s]", current_parser->request.header.type,
	// current_parser->request.header.value);
	int strcmp_host = strcmp_lower_case("Host", current_parser->request.header.type);
	if (current_parser->request.target.path_type != ABSOLUTE && current_parser->data.target_status == NOT_FOUND &&
		strcmp_host == 0) {
		// Busco el indice del delimitador entre el path y el puerto, en caso de no existir retorna -1
		int idx_port = find_idx(current_parser->request.header.value, ':');
		if (idx_port == -1) {
			strcpy(current_parser->request.target.port, "80"); // ojo podria ser 443?
			logger(ERROR, "Not found ':' delimiter in header type Host");
		} else
			// almaceno en la estructura el puerto
			strcpy(current_parser->request.target.port, current_parser->request.header.value + (idx_port + 1));

		if (IS_DIGIT(current_parser->request.header.value[0])) {
			// TODO: setear ipv4 o ipv6????
			if (idx_port >= 1) {
				// tiene puerto no default
				strncpy(current_parser->request.target.request_target.ip_addr, current_parser->request.header.value,
						(size_t)idx_port);
				current_parser->request.target.request_target.ip_addr[idx_port] = '\0';
			} else
				strcpy(current_parser->request.target.request_target.ip_addr, current_parser->request.header.value);
		} else {
			current_parser->request.target.host_type = DOMAIN;
			if (idx_port >= 1) {
				strncpy(current_parser->request.target.request_target.host_name, current_parser->request.header.value,
						(size_t)idx_port);
				current_parser->request.target.request_target.host_name[idx_port] = '\0';
			} else
				strcpy(current_parser->request.target.request_target.host_name, current_parser->request.header.value);
		}

		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.header.type,
							   strlen(current_parser->request.header.type));
		copy_to_request_buffer(current_parser->data.parsed_request, delimiter, strlen(delimiter));
		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.header.value,
							   strlen(current_parser->request.header.value));
		current_parser->data.target_status = FOUND;
		copy_to_request_buffer(current_parser->data.parsed_request, cr_lf, strlen(cr_lf));
	} else if (strcmp_host != 0) {
		// rellenar parse_state con header solo si no es Host(ya se copio por que soy absoluto o por que ya lo encontre)
		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.header.type,
							   strlen(current_parser->request.header.type));
		copy_to_request_buffer(current_parser->data.parsed_request, delimiter, strlen(delimiter));
		copy_to_request_buffer(current_parser->data.parsed_request, current_parser->request.header.value,
							   strlen(current_parser->request.header.value));
		copy_to_request_buffer(current_parser->data.parsed_request, cr_lf, strlen(cr_lf));
	}
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
		logger(INFO, "Identified CONNECT method");
		current_parser->data.parser_state = PS_PATH_DOMAIN;
		current_parser->request.target.path_type = ABSOLUTE;
		current_parser->data.request_status = PARSE_CONNECT_METHOD;
	}
}

static void tr_headers_ended(char current_char) {
	char *cr_lf = "\r\n";
	copy_to_request_buffer(current_parser->data.parsed_request, cr_lf, strlen(cr_lf));
	current_parser->data.request_status = PARSE_BODY_INCOMPLETE;
}

static void tr_request_ended(char current_char) {
	logger(DEBUG, "tr_request_ended");
	current_parser->data.parser_state = PARSE_END;
}

static void tr_incomplete_header(char current_char) {
	current_parser->data.request_status = PARSE_HEADER_LINE_INCOMPLETE;
	tr_copy_byte_to_buffer(current_char);
}

static void tr_copy_byte_to_buffer(char current_char) {
	size_t *idx = &current_parser->data.copy_index;
	size_t limit;
	char *copy_buffer;
	switch (current_parser->data.parser_state) {
		case PS_METHOD:
			limit = MAX_METHOD_LENGTH;
			copy_buffer = current_parser->request.method;
			break;
		case PS_IP:
		case PS_IPv4:
		case PS_IPv6:
			limit = MAX_IP_LENGTH;
			copy_buffer = current_parser->request.target.request_target.ip_addr;
			break;
		case PS_PATH_SCHEMA:
			limit = MAX_SCHEMA_LENGTH;
			copy_buffer = current_parser->request.schema;
			break;
		case PS_PATH_DOMAIN:
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
		case PS_BODY:
			copy_char_to_request_buffer(current_parser->data.parsed_request, current_char);
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
	copy_port();
	tr_reset_copy_index(current_char);
	current_parser->data.target_status = FOUND;
}

static void tr_line_ended(char current_char) {
	switch (current_parser->data.request_status) {
		case PARSE_START_LINE_INCOMPLETE:
			// rellenar parse_state con start line
			parse_start_line(current_char);
			current_parser->data.request_status = PARSE_START_LINE_COMPLETE;
			break;
		case PARSE_HEADER_LINE_INCOMPLETE:
			parse_header_line(current_char);
			current_parser->data.request_status = PARSE_HEADER_LINE_COMPLETE;
			break;
		default:
			logger(ERROR, "State error"); // TODO: mejorar
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
	}
	tr_copy_byte_to_buffer(current_char);
}

static void tr_set_host_type(char current_char) {
	switch (current_char) {
		case '.':
			current_parser->request.target.host_type = IPV4;
			break;
		case ':':
			current_parser->request.target.host_type = IPV6;
			break;
		default:
			current_parser->request.target.host_type = DOMAIN;
	}
	tr_copy_byte_to_buffer(current_char);
}

static void tr_http_version(char current_char) {
	if ('9' >= current_char && current_char >= '0') {
		// TODO chequear inicializacion en NULL
		if (current_parser->request.version.major == EMPTY_VERSION) {
			current_parser->request.version.major = current_char;
		} else if (current_parser->request.version.minor == EMPTY_VERSION) {
			current_parser->request.version.minor = current_char;
		} else {
			// version no soportada
		}
	}
}

static void tr_reset_copy_index(char current_char) {
	current_parser->data.copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_parse_error(char current_char) { current_parser->data.request_status = PARSE_ERROR; }

static void tr_adv(char current_char) {}

//----------- FUNCION QUE REALIZA LA EJECUCION DE LA MAQUINA -----------//

int parse_request(http_parser *parser, buffer *read_buffer) {
	current_parser = parser;
	char current_char;
	http_parser_state current_state;

	while (buffer_can_read(read_buffer) && current_parser->data.parser_state != PS_ERROR) {
		current_char = buffer_read(read_buffer);
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
				logger(ERROR, "No hay transicion disponible para %c", current_char);
				break;
			}
		}
		if (current_parser->data.target_status == FOUND) {
			// se encontro el destino a conectar, corto la maquina para que se empieze a realizar la conexion
			current_parser->data.target_status = SOLVED;
			return 0;
		}
	}

	return 0;
}
