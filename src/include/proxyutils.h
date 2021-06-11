#ifndef __PROXY_UTILS_H__
#define __PROXY_UTILS_H__

#include <connection.h>
#include <proxy.h>
#include <stddef.h>

// Constantes para acceder a los FdSets, BASE para el persistente, TMP para el que varia con select
typedef enum {
	BASE = 0,
	TMP = 1,
	FD_SET_ARRAY_SIZE = 2,
	MAX_PENDING = 10,
	MAX_CLIENTS = 510,
	BUFFER_SIZE = 65000,
	MAX_ADDR_BUFFER = 128,
	MAX_OUTPUT_REGISTER_LENGTH = 256,
} proxy_utils_constants;

typedef enum {
	ACCESS,
	PASSWORD,
} register_type;

int setup_passive_socket(const char *service);

int accept_connection(int passive_sock, char *buffer_address, char *buffer_port);
typedef enum { WRITE, READ } operation;

int handle_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE], fd_set writeFdSet[FD_SET_ARRAY_SIZE],
					  peer peer);

ssize_t handle_operation(int fd, buffer *buffer, operation operation, peer peer, FILE *log_file);

int setup_connection(connection_node *node, fd_set *writeFdSet);

int handle_client_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

int handle_server_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

#endif
