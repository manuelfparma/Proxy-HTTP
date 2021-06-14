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

int setup_passive_socket();

int accept_connection(int passive_sock, char *buffer_address, char *buffer_port);

ssize_t handle_operation(int fd, buffer *buffer, operation operation, peer peer, FILE *log_file);

int setup_connection(connection_node *node, fd_set *writeFdSet);

int handle_client_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

int handle_server_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

#endif
