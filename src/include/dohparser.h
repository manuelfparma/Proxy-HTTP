#ifndef DOH_PARSER_H

#define DOH_PARSER_H

#include <connection.h>

// TODO: Comentar funciones
int read_doh_response(connection_node *node);

int parse_doh_status_code(connection_node *node);

int parse_doh_content_length_header(connection_node *node);

int parse_doh_content_length_value(connection_node *node);

int find_http_body(connection_node *node);

int parse_dns_message(connection_node *node);

#endif
