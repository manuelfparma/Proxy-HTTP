#include <buffer.h>
#include <pop3_connect_parser.h>
#include <stdio.h>
#include <string.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

pop3_connect_parser *current_parser;
buffer *current_read_buffer;

// Transiciones entre nodos
static void tr_check_prefix(char current_char);
static void tr_copy_byte_to_buffer(char current_char);
static void tr_line_ended(char current_char);
static void tr_parse_error(char current_char);
static void tr_reset_copy_index(char current_char);

//----------- ESTRUCTURAS QUE REPRESENTAN LOS NODOS DEL GRAFO -----------//

static const pop3_connect_parser_state_transition ST_PREFIX[2] = {
	{.when = ' ', .destination = POP3_PS_VALUE, .transition = tr_check_prefix},
	{.when = POP3_ANY, .destination = POP3_PS_PREFIX, .transition = tr_copy_byte_to_buffer},
};

static const pop3_connect_parser_state_transition ST_VALUE[2] = {
	{.when = '\n', .destination = POP3_PS_PREFIX, .transition = tr_line_ended},
	{.when = POP3_ANY, .destination = POP3_PS_VALUE, .transition = tr_copy_byte_to_buffer},
};

//----------- ESTRUCTURAS PARA SABER LAS TRANSICIONES DE CADA NODO -----------//

static const pop3_connect_parser_state_transition *states[] = {ST_PREFIX, ST_VALUE};

static const size_t states_n[] = {
	N(ST_PREFIX),
	N(ST_VALUE),
};

//----------- FUNCIONES AUXILIARES PARA LAS TRANSICIONES -----------//

static void tr_line_ended(char current_char) {
	if (current_parser->prefix_type == POP3_USER || current_parser->prefix_type == POP3_PASS) {
        // saltar?
    }
	tr_reset_copy_index(current_char);
}

static void tr_check_prefix(char current_char) {
	int strcmp_prefix = strcmp("USER", current_parser->line.prefix);
	if (strcmp_prefix == 0) {
		current_parser->prefix_type = POP3_USER;
	} else {
		strcmp_prefix = strcmp("PASS", current_parser->line.prefix);
		if (strcmp_prefix == 0) {
			current_parser->prefix_type = POP3_PASS;
		} else
			current_parser->prefix_type = POP3_UNKNOWN;
	}
	tr_reset_copy_index(current_char);
}

static void tr_copy_byte_to_buffer(char current_char) {
	size_t *idx = &current_parser->copy_index;
	size_t limit;
	char *copy_buffer;
	switch (current_parser->state) {
		case POP3_PS_PREFIX:
			limit = MAX_PREFIX_LENGTH;
			copy_buffer = current_parser->line.prefix;
			break;
		case POP3_PS_VALUE:
			limit = MAX_VALUE_LENGTH;
			switch (current_parser->prefix_type) {
				case POP3_USER:
					copy_buffer = current_parser->credentials.username;
					break;
				case POP3_PASS:
					copy_buffer = current_parser->credentials.password;
					break;
				default:
					copy_buffer = current_parser->line.value;
			}
		default:
			// TODO manejo de error
            limit = -1;
			break;
	}

	if (*idx < limit) {
		copy_buffer[*idx] = current_char;
		copy_buffer[*idx + 1] = '\0';
		(*idx)++;
	} else {
		tr_parse_error(current_char); // TODO: MEJORAR
	}
}

static void tr_reset_copy_index(char current_char) {
	current_parser->copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_parse_error(char current_char) {}

//----------- FUNCION QUE REALIZA LA EJECUCION DE LA MAQUINA -----------//

int parse_pop3_connect(pop3_connect_parser *parser, char *read_buffer) {
	current_parser = parser;
	char current_char;
	pop3_connect_parser_state current_state;
	int idx = 0;

	while (read_buffer[idx] != '\0') {
		current_char = read_buffer[idx++];
		current_state = current_parser->state;
		for (size_t i = 0; i < states_n[current_state]; i++) {
			if (current_char == states[current_state][i].when || states[current_state][i].when == (char)POP3_ANY) {
				current_parser->state = states[current_state][i].destination;
				states[current_state][i].transition(current_char);
				break;
			}
		}
	}
	return idx;
}
