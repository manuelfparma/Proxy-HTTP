#include <buffer.h>
#include <logger.h>
#include <pop3commandparser.h>
#include <stdio.h>
#include <netutils.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

pop3_command_parser *current_pop3_command_parser;
buffer *current_pop3_command_read_buffer;
buffer *current_pop3_command_write_buffer;
size_t line_count;

// Transiciones entre nodos
static void tr_check_prefix(char current_char);
static void tr_copy_byte_to_buffer(char current_char);
static void tr_line_ended(char current_char);
static void tr_parse_error(char current_char);
static void tr_reset_copy_index(char current_char);

//----------- ESTRUCTURAS QUE REPRESENTAN LOS NODOS DEL GRAFO -----------//

static const pop3_command_parser_state_transition ST_PREFIX[2] = {
	{.when = ' ', .destination = POP3_C_PS_VALUE, .transition = tr_check_prefix},
	{.when = POP3_C_ANY, .destination = POP3_C_PS_PREFIX, .transition = tr_copy_byte_to_buffer},
};

static const pop3_command_parser_state_transition ST_VALUE[3] = {
	{.when = '\r', .destination = POP3_C_PS_CR, .transition = tr_reset_copy_index},
	{.when = '\n', .destination = POP3_C_PS_PREFIX, .transition = tr_line_ended},
	{.when = POP3_C_ANY, .destination = POP3_C_PS_VALUE, .transition = tr_copy_byte_to_buffer},
};

static const pop3_command_parser_state_transition ST_CR[2] = {
	{.when = '\n', .destination = POP3_C_PS_PREFIX, .transition = tr_line_ended},
	{.when = POP3_C_ANY, .destination = POP3_C_PS_VALUE, .transition = tr_copy_byte_to_buffer},
};

//----------- ESTRUCTURAS PARA SABER LAS TRANSICIONES DE CADA NODO -----------//

static const pop3_command_parser_state_transition *states[] = {ST_PREFIX, ST_VALUE, ST_CR};

static const size_t states_n[] = {
	N(ST_PREFIX),
	N(ST_VALUE),
	N(ST_CR),
};

//----------- FUNCIONES AUXILIARES PARA LAS TRANSICIONES -----------//

static void tr_line_ended(char current_char) {
	if (current_pop3_command_parser->prefix_type == POP3_C_PASS) {
		logger(DEBUG, "FOUND CREDENTIALS");
		current_pop3_command_parser->credentials_state = POP3_C_FOUND;
	}
	line_count++;
	tr_reset_copy_index(current_char);
}

static void tr_check_prefix(char current_char) {
	// TODO: case-insensitive segun RFC
	int strcmp_prefix = strcmp_case_insensitive("USER", current_pop3_command_parser->line.prefix);
	if (strcmp_prefix == 0) {
		current_pop3_command_parser->prefix_type = POP3_C_USER;
	} else {
		strcmp_prefix = strcmp_case_insensitive("PASS", current_pop3_command_parser->line.prefix);
		if (strcmp_prefix == 0 && current_pop3_command_parser->credentials.username[0] != '\0') {
			// solo copio password si ya copie un user
			current_pop3_command_parser->prefix_type = POP3_C_PASS;
		} else
			current_pop3_command_parser->prefix_type = POP3_C_UNKNOWN;
	}
	tr_reset_copy_index(current_char);
}

static void tr_copy_byte_to_buffer(char current_char) {
	size_t *idx = &current_pop3_command_parser->copy_index;
	size_t limit;
	char *copy_buffer;
	switch (current_pop3_command_parser->parser_state) {
		case POP3_C_PS_PREFIX:
			limit = MAX_PREFIX_LENGTH;
			copy_buffer = current_pop3_command_parser->line.prefix;
			break;
		case POP3_C_PS_VALUE:
			limit = MAX_VALUE_LENGTH;
			switch (current_pop3_command_parser->prefix_type) {
				case POP3_C_USER:
					copy_buffer = current_pop3_command_parser->credentials.username;
					break;
				case POP3_C_PASS:
					copy_buffer = current_pop3_command_parser->credentials.password;
					break;
				default:
					copy_buffer = current_pop3_command_parser->line.value;
			}
			break;
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
		tr_parse_error(current_char);
	}
}

static void tr_reset_copy_index(char current_char) {
	current_pop3_command_parser->copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

static void tr_parse_error(char current_char) {
	current_pop3_command_parser->parser_state = POP3_C_PS_ERROR;
	tr_reset_copy_index(current_char);
}

//----------- FUNCION QUE REALIZA LA EJECUCION DE LA MAQUINA -----------//

int parse_pop3_command(pop3_command_parser *pop3_parser, buffer *read_buffer) {
	current_pop3_command_parser = pop3_parser;
	current_pop3_command_read_buffer = read_buffer;
	char current_char;
	pop3_command_parser_state current_state;
	line_count = 0;
	if (current_pop3_command_parser->parser_state == POP3_C_PS_ERROR) current_pop3_command_parser->parser_state = POP3_C_PS_PREFIX;
	while (buffer_can_read(current_pop3_command_read_buffer)) {
		current_char = buffer_read(read_buffer);
		buffer_write(current_pop3_command_parser->command_buffer, current_char); // todo lo que leo lo escribo en la salida
		current_state = current_pop3_command_parser->parser_state;
		for (size_t i = 0; current_pop3_command_parser->parser_state != POP3_C_PS_ERROR && i < states_n[current_state]; i++) {
			if (current_char == states[current_state][i].when || states[current_state][i].when == (char)POP3_C_ANY) {
				current_pop3_command_parser->parser_state = states[current_state][i].destination;
				states[current_state][i].transition(current_char);
				break;
			}
		}
		// condicion de salida pues encontre un par USER - PASS
		if (current_pop3_command_parser->parser_state == POP3_C_PS_PREFIX && current_pop3_command_parser->prefix_type == POP3_C_PASS) break;
	}
	return line_count;
}
