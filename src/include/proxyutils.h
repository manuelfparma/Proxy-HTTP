#ifndef __PROXY_UTILS_H__
#define __PROXY_UTILS_H__

#include <connection.h>
#include <proxy.h>
#include <stddef.h>
#include <stdio.h>

typedef enum {
	ACCESS,
	PASSWORD,
} register_type;

typedef enum { WRITE, READ } operation;

typedef enum { CHARS_BEFORE_STATUS_CODE = 9 , STATUS_CODE_LENGTH = 3} proxy_utils_constraints;

int setup_proxy_passive_sockets(int proxy_sockets[SOCK_COUNT]);

// Funcion que genera el socket para el nuevo cliente
int accept_connection(int passive_sock, char *buffer_address, char *buffer_port);

// Funcion que realiza la escritura o lectura
ssize_t handle_operation(int fd, buffer *buffer, operation operation, peer peer);

int setup_connection(connection_node *node, fd_set *writeFdSet);

// Funcion que atiende la escritura y lectura del nodo del cliente, en caso de ser necesario
int handle_client_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

// Funcion que atiende la escritura y lectura del nodo del servidor, en caso de ser necesario
int handle_server_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

int try_next_addr(connection_node *node, fd_set write_fd_set[FD_SET_ARRAY_SIZE]) ;

#endif
