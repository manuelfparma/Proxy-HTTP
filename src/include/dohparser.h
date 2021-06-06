#ifndef DOH_PARSER_H

#define DOH_PARSER_H

#include <connection.h>

// TODO: Comentar funciones
int read_doh_response(ConnectionNode *node);

int parse_doh_status_code(ConnectionNode *node);

int parse_doh_content_length_header(ConnectionNode *node);

int parse_doh_content_length_value(ConnectionNode *node);

int find_http_body(ConnectionNode *node);

int parse_dns_message(ConnectionNode *node);

#endif
