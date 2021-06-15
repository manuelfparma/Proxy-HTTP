#ifndef DOH_CLIENT_H
#define DOH_CLIENT_H

#include <connection.h>
#include <stddef.h>
#include <stdint.h>

//	Abre una conexion al servidor DoH
int connect_to_doh_server(connection_node *node, fd_set *write_fd_set);

//	Checkea si existe una conexión al servidor DoH
bool is_connected_to_doh(connection_node *node);

//	Se encarga de armar y enviar consultas DoH
int handle_doh_request(connection_node *node, fd_set *write_fd_set);

//	Se encarga de recibir y parsear respuestas DoH
int handle_doh_response(connection_node *node, fd_set *read_fd_set);

//	Luego de recibir una response doh, veo si tengo que enviar de otros tipos
bool check_requests_sent(connection_node *node);

#endif
