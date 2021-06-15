#include <logger.h>
#include <pop3responseparser.h>

#define N(x) (sizeof(x) / sizeof((x)[0]))

pop3_response_parser *current_pop3_response_parser;
buffer *current_pop3_response_read_buffer, *current_pop3_response_write_buffer;
size_t lines_read;

//----------- PROTOTIPOS DE LAS FUNCIONES DE TRANSICION -----------//

// Funcion que setea si el estado fue positivo o negativo en los datos del parser
static void tr_set_status(char current_char);

// Funcion que solo consume el caracter
static void tr_adv(char current_char);

// Funcion que indica la finalizacion de una linea, incrementara el contador de lineas leidas
static void tr_line_ended(char current_char);

// Funcion que maneja los errores
static void tr_parse_error(char current_char);

//----------- ESTRUCTURAS QUE REPRESENTAN LOS NODOS DEL GRAFO -----------//

static const pop3_response_parser_state_transition ST_STATUS[3] = {
	{.when = '+', .destination = POP3_R_PS_POSITIVE, .transition = tr_set_status},
	{.when = '-', .destination = POP3_R_PS_NEGATIVE, .transition = tr_set_status},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_ERROR, .transition = tr_parse_error},
};

static const pop3_response_parser_state_transition ST_POSITIVE[2] = {
	{.when = '\r', .destination = POP3_R_PS_POSITIVE_CR, .transition = tr_adv},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_POSITIVE, .transition = tr_adv},
};

static const pop3_response_parser_state_transition ST_NEGATIVE[2] = {
	{.when = '\r', .destination = POP3_R_PS_NEGATIVE_CR, .transition = tr_adv},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_NEGATIVE, .transition = tr_adv},
};

static const pop3_response_parser_state_transition ST_POSITIVE_CR[2] = {
	{.when = '\n', .destination = POP3_R_PS_STATUS, .transition = tr_line_ended},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_POSITIVE, .transition = tr_adv},
};

static const pop3_response_parser_state_transition ST_NEGATIVE_CR[2] = {
	{.when = '\n', .destination = POP3_R_PS_STATUS, .transition = tr_line_ended},
	{.when = POP3_R_ANY, .destination = POP3_R_PS_NEGATIVE, .transition = tr_adv},
};

//----------- ESTRUCTURAS PARA SABER LAS TRANSICIONES DE CADA NODO -----------//

static const pop3_response_parser_state_transition *states[] = {
	ST_STATUS, ST_POSITIVE, ST_NEGATIVE, ST_POSITIVE_CR, ST_NEGATIVE_CR,
};

static const size_t states_n[] = {
	N(ST_STATUS), N(ST_POSITIVE), N(ST_NEGATIVE), N(ST_POSITIVE_CR), N(ST_NEGATIVE_CR),
};

//----------- FUNCIONES DE TRANSICION ENTRE LOS ESTADOS -----------//

static void tr_set_status(char current_char) {
	switch (current_char) {
		case '+':
			current_pop3_response_parser->data.status = POP3_R_POSITIVE_STATUS;
			break;
		case '-':
			current_pop3_response_parser->data.status = POP3_R_NEGATIVE_STATUS;
			break;
		default:
			break;
	}
}

static void tr_line_ended(char current_char) { lines_read++; }

static void tr_adv(char current_char) {}

static void tr_parse_error(char current_char) { current_pop3_response_parser->parser_state = POP3_R_PS_ERROR; }

//----------- FUNCION QUE REALIZA LA EJECUCION DE LA MAQUINA DE ESTADOS -----------//

int parse_pop3_response(pop3_response_parser *parser, buffer *read_buffer) {
	current_pop3_response_parser = parser;
	current_pop3_response_read_buffer = read_buffer;
	char current_char;
	pop3_response_parser_state current_state;
	lines_read = 0;

	while (buffer_can_read(read_buffer) && current_pop3_response_parser->parser_state != POP3_R_PS_ERROR) {
		current_char = buffer_read(read_buffer);
		buffer_write(current_pop3_response_parser->response_buffer, current_char);
		current_state = current_pop3_response_parser->parser_state;
		for (size_t i = 0; i < states_n[current_state]; i++) {
			if (current_char == states[current_state][i].when || states[current_state][i].when == (char)POP3_R_ANY) {
				current_pop3_response_parser->parser_state = states[current_state][i].destination;
				states[current_state][i].transition(current_char);
				break;
			}
		}
	}
	return lines_read;
}
