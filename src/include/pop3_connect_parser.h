#ifndef __POP3_CONNECT_PARSER_H__
#define __POP3_CONNECT_PARSER_H__

#include <buffer.h>

typedef enum {
	POP3_ANY = -1,
} pop3_connect_constants;

typedef enum {
	POP3_PS_PREFIX,
	POP3_PS_VALUE,
	POP3_PS_CR,
	POP3_PS_LF,
	POP3_PS_END,
	POP3_PS_ERROR, // cuando se recibe \cr\lf\cr\lf
} pop3_connect_parser_state;

typedef struct {
	char when;
	pop3_connect_parser_state destination;
	void (*transition)(char);
} pop3_connect_parser_state_transition;


typedef enum {
	MAX_USERNAME_LENGTH = 0xFF, // 255
	MAX_PASSWORD_LENGTH = 0xFF,
	MAX_PREFIX_LENGTH = 0xFF, // 255
	MAX_VALUE_LENGTH = 0xFF,
	USER_PREFIX_SP_LENGTH = 5, // largo del campo "User "
} pop3_connect_constraints;

typedef enum { POP3_UNKNOWN, POP3_USER, POP3_PASS,} pop3_connect_prefix_type;

typedef struct {
	char username[MAX_USERNAME_LENGTH + 1];
	char password[MAX_PASSWORD_LENGTH + 1];
} pop3_connect_credentials;

typedef struct {
	char prefix[MAX_PREFIX_LENGTH + 1];
	char value[MAX_VALUE_LENGTH + 1];
} pop3_connect_line;

typedef struct {
	pop3_connect_parser_state state;
	pop3_connect_prefix_type prefix_type;
	pop3_connect_line line;
	pop3_connect_credentials credentials;
	size_t copy_index;				// indice auxiliar para saber la posicion en la cual se debe copiar en el buffer objetivo
	char *pop3_read_buffer;
} pop3_connect_parser;

int parse_pop3_connect(pop3_connect_parser *pop3_parser, char *read_buffer);

#endif
