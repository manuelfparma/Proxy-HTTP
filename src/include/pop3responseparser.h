#ifndef __POP3_RESPONSE_PARSER_H__
#define __POP3_RESPONSE_PARSER_H__

#include <netinet/in.h>
#include <buffer.h>

typedef enum {
	POP3_R_ANY = -1,
} pop3_response_constants;

typedef enum {
	POP3_R_PS_STATUS,
	POP3_R_PS_POSITIVE,
	POP3_R_PS_NEGATIVE,
	POP3_R_PS_POSITIVE_CR,
	POP3_R_PS_NEGATIVE_CR,
	POP3_R_PS_END,
	POP3_R_PS_ERROR, // cuando se recibe \cr\lf\cr\lf
} pop3_response_parser_state;

typedef struct {
	char when;
	pop3_response_parser_state destination;
	void (*transition)(char);
} pop3_response_parser_state_transition;

typedef enum {
	MAX_RESPONSE_LENGTH = 512,  // incluye \r\n del final
} pop3_response_constraints;

typedef enum {
	POP3_R_POSITIVE_STATUS,
	POP3_R_NEGATIVE_STATUS,
} pop3_response_status;

typedef struct {
	pop3_response_status status;
} pop3_response_data;

typedef struct {
	buffer *response_buffer;
	pop3_response_parser_state parser_state;
	pop3_response_data data;
} pop3_response_parser;

int parse_pop3_response(pop3_response_parser *parser, buffer *read_buffer);

#endif
