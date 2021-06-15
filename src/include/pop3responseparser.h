#ifndef __POP3_RESPONSE_PARSER_H__
#define __POP3_RESPONSE_PARSER_H__

#include <buffer.h>
#include <netinet/in.h>

typedef enum {
	POP3_R_ANY = -1,
} pop3_response_constants;

// Estados de la maquina
typedef enum {
	POP3_R_PS_STATUS,
	POP3_R_PS_POSITIVE,
	POP3_R_PS_NEGATIVE,
	POP3_R_PS_POSITIVE_CR,
	POP3_R_PS_NEGATIVE_CR,
	POP3_R_PS_END,
	POP3_R_PS_ERROR, // cuando se recibe \cr\lf\cr\lf
} pop3_response_parser_state;

// Estructura que maneja la maquina para saber, desde su estado actual, cual sera el siguiente de acuerdo al caracter leido y cual
// es la funcion a ejecutar
typedef struct {
	char when;
	pop3_response_parser_state destination;
	void (*transition)(char);
} pop3_response_parser_state_transition;

typedef enum {
	MAX_RESPONSE_LENGTH = 512, // incluye \r\n del final
} pop3_response_constraints;

typedef enum {
	POP3_R_POSITIVE_STATUS,
	POP3_R_NEGATIVE_STATUS,
} pop3_response_status;

typedef struct {
	pop3_response_status status;
} pop3_response_data;

// Estructura que se utiliza para guardar estados y poder retomar la ejecucion correctamente
typedef struct {
	buffer *response_buffer;
	pop3_response_parser_state parser_state;
	pop3_response_data data;
} pop3_response_parser;

int parse_pop3_response(pop3_response_parser *parser, buffer *read_buffer);

#endif
