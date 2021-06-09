#ifndef DOH_CLIENT_H
#define DOH_CLIENT_H

#include <connection.h>
#include <stddef.h>
#include <stdint.h>

// TODO: Comentar funciones
int connect_to_doh_server(connection_node *node, fd_set *write_fd_set, char *doh_addr, char *doh_port);

bool is_connected_to_doh(connection_node *node);

int handle_doh_request(connection_node *node, fd_set *write_fd_set);

int handle_doh_response(connection_node *node, fd_set *read_fd_set);

//	Luego de recibir una response doh, veo si tengo que enviar de otros tipos
bool check_requests_sent(connection_node *node);

#endif
