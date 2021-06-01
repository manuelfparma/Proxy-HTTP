#ifndef _PARSER_H_
#define _PARSER_H_

#include <connection.h>

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

int parse_request(ConnectionNode *node, char *host_name);

#endif // _PARSER_H_
