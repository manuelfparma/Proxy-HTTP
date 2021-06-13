#ifndef __POP3_CONNECT_PARSER_H__
#define __POP3_CONNECT_PARSER_H__

#include <buffer.h>

typedef enum {
	POP3_C_ANY = -1,
} pop3_command_constants;

typedef enum {
	POP3_C_PS_PREFIX,
	POP3_C_PS_VALUE,
	POP3_C_PS_CR,
	POP3_C_PS_LF,
	POP3_C_PS_END,
	POP3_C_PS_ERROR,
} pop3_command_parser_state;

typedef struct {
	char when;
	pop3_command_parser_state destination;
	void (*transition)(char);
} pop3_command_parser_state_transition;

typedef enum {
	MAX_PREFIX_LENGTH = 4,
	MAX_VALUE_LENGTH = 40,
	USER_PREFIX_SP_LENGTH = 5, // largo del campo "USER "
} pop3_command_constraints;

typedef enum { POP3_C_UNKNOWN, POP3_C_USER, POP3_C_PASS,} pop3_command_prefix_type;

typedef enum { POP3_C_NOT_FOUND, POP3_C_FOUND} pop3_command_credentials_state;

typedef struct {
	char username[MAX_VALUE_LENGTH + 1];
	char password[MAX_VALUE_LENGTH + 1];
} pop3_command_credentials;

typedef struct {
	char prefix[MAX_PREFIX_LENGTH + 1];
	char value[MAX_VALUE_LENGTH + 1];
} pop3_command_line;

typedef struct {
	buffer *command_buffer;
	pop3_command_parser_state parser_state;
	pop3_command_prefix_type prefix_type;
	pop3_command_line line;
	pop3_command_credentials credentials;
	pop3_command_credentials_state credentials_state;
	size_t copy_index;				// indice auxiliar para saber la posicion en la cual se debe copiar en el buffer objetivo
} pop3_command_parser;

int parse_pop3_command(pop3_command_parser *pop3_parser, buffer *read_buffer);

#endif
