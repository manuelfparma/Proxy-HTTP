#include <pop3response_parser.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

pop3_response_parser *current_parser;

// Transiciones entre nodos
static void tr_set_status(char current_char);
static void tr_copy_byte_to_buffer(char current_char);
static void tr_line_ended(char current_char);
static void tr_reset_copy_index(char current_char);

//----------- ESTRUCTURAS QUE REPRESENTAN LOS NODOS DEL GRAFO -----------//

static const pop3_response_parser_state_transition ST_STATUS[3] = {
	{.when = '+', .destination = POP3_R_PS_POSITIVE, .transition = tr_set_status},
	{.when = '-', .destination = POP3_R_PS_NEGATIVE, .transition = tr_set_status},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_ERROR, .transition = tr_copy_byte_to_buffer},
};

static const pop3_response_parser_state_transition ST_POSITIVE[3] = {
	{.when = '\r', .destination = POP3_R_PS_POSITIVE_CR, .transition = tr_copy_byte_to_buffer},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_POSITIVE, .transition = tr_copy_byte_to_buffer},
};

static const pop3_response_parser_state_transition ST_NEGATIVE[3] = {
	{.when = '\r', .destination = POP3_R_PS_NEGATIVE_CR, .transition = tr_copy_byte_to_buffer},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_NEGATIVE, .transition = tr_copy_byte_to_buffer},
};

static const pop3_response_parser_state_transition ST_POSITIVE_CR[3] = {
	{.when = '\n', .destination = POP3_R_PS_END, .transition = tr_line_ended},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_POSITIVE, .transition = tr_copy_byte_to_buffer},
};

static const pop3_response_parser_state_transition ST_NEGATIVE_CR[3] = {
	{.when = '\n', .destination = POP3_R_PS_STATUS, .transition = tr_line_ended},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_NEGATIVE, .transition = tr_copy_byte_to_buffer},
};

//----------- ESTRUCTURAS PARA SABER LAS TRANSICIONES DE CADA NODO -----------//

static const pop3_response_parser_state_transition *states[] = {
	ST_STATUS, ST_POSITIVE, ST_NEGATIVE, ST_POSITIVE_CR, ST_NEGATIVE_CR,
};

static const size_t states_n[] = {
	N(ST_STATUS), N(ST_POSITIVE), N(ST_NEGATIVE), N(ST_POSITIVE_CR), N(ST_NEGATIVE_CR),
};

//----------- FUNCIONES AUXILIARES PARA LAS TRANSICIONES -----------//

static void tr_set_status(char current_char) {
	switch (current_char) {
		case '+':
            current_parser->data.status = POP3_R_POSITIVE_STATUS;
			break;
		case '-':
            current_parser->data.status = POP3_R_NEGATIVE_STATUS;
			break;
		default:
			break;
	}
}

static void tr_line_ended(char current_char) { 
    //se encontro una respuesta, espero a que el proxy la lea?
    tr_reset_copy_index(current_char); 
}

static void tr_copy_byte_to_buffer(char current_char) {
	size_t *idx = &current_parser->copy_index;
	size_t limit = MAX_RESPONSE_LENGTH;

/*  A DONDE SE COPIA??
	if (*idx < limit) {
		copy_buffer[*idx] = current_char;
		copy_buffer[*idx + 1] = '\0';
		(*idx)++;
	} else {
		tr_parse_error(current_char);
	}
*/
}

static void tr_reset_copy_index(char current_char) {
	current_parser->copy_index = 0;
	// no copio el caracter, solo reinicio el indice de copiado
}

// static void tr_parse_error(char current_char) {
// 	current_parser->parser_state = POP3_R_PS_ERROR;
// 	// TODO: MEJORAR
// }

//----------- FUNCION QUE REALIZA LA EJECUCION DE LA MAQUINA -----------//

int parse_pop3_response(pop3_response_parser *parser, char *read_buffer) {
	current_parser = parser;
	char current_char;
	pop3_response_parser_state current_state;
	int idx = 0;

	while (read_buffer[idx] != '\0') {
		current_char = read_buffer[idx++];
		current_state = current_parser->parser_state;
		for (size_t i = 0; i < states_n[current_state]; i++) {
			if (current_char == states[current_state][i].when || states[current_state][i].when == (char)POP3_R_ANY) {
				current_parser->parser_state = states[current_state][i].destination;
				states[current_state][i].transition(current_char);
				break;
			}
		}
	}
	return idx;
}
