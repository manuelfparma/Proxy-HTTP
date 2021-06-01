#ifndef _PARSER_H_
#define _PARSER_H_

#include <connection.h>

typedef const enum {
	METHOD,			// GET, POST, OPTION
	REQUEST_TARGET, // puede ser http://XXXX (absoluteURI) o /index.html (relative)
	HTTP_VERSION,	// por ej: ' HTTP/1.1 \r\n'
	HEADER_TYPE,	// por ej: 'Host: ' -> CASE INSENSITIVE
	HEADER_VALUE	// por ej: 'google.com\r\n'
} PARSE_STATE;

//typedef struct state_definition {
//
//	void (*consume)(const STATE, char* str);			// funcion para pasar al proximo nodo
//} state_definition;
//
//typedef struct state_machine {
//
//	const PARSE_STATE initial_state;			   // estado inicial de la maquina
//	const state_definition *states;		   // todos los estados posibles
//	const state_definition *current_state; // estado actual
//
//} state_machine;

int parse_request(ConnectionNode *node);

#endif // _PARSER_H_
