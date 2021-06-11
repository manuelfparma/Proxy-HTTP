#ifndef __PROXY_UTILS_H__
#define __PROXY_UTILS_H__

#define MAX_PENDING 10
#define MAX_CLIENTS 510
#define BUFFER_SIZE 65000
#define MAX_ADDR_BUFFER 128
// Constantes para acceder a los FdSets, BASE para el persistente, TMP para el que varia con select
#define BASE 0
#define TMP 1
#define FD_SET_ARRAY_SIZE 2

#include <connection.h>
#include <proxy.h>
#include <stddef.h>

int setup_passive_socket(const char *service);

int accept_connection(int passive_sock, char *client_info);

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
