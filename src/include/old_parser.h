#ifndef _OLD_PARSER_H_
#define _OLD_PARSER_H_

#include <connection.h>

#define URI_MAX_LENGTH 2048
#define PORT_MAX_LENGTH 5   //maximo puerto es 2¹⁶ = 65535

typedef enum { PARSE_ERROR = -3, PARSE_INCOMPLETE, PARSE_OK } PARSER_RETURN_CODE;
// deben ser numeros negativos porque las funciones de parseo retornan caracteres leidos en casos exitosos

int parse_request(ConnectionNode *node, char *host_name, char *port);

#endif // _PARSER_H_
