#ifndef DOH_CLIENT_H
#define DOH_CLIENT_H

#include <connection.h>
#include <stdint.h>
#include <stddef.h>

int connect_to_doh_server(ConnectionNode *node, fd_set *write_fd_set, char *doh_addr, char *doh_port);

int handle_doh_connection(ConnectionNode *node, fd_set *writeFdSet, fd_set *readFdSet);

//int solve_name(ConnectionNode *node, char *doh_addr, char *doh_port, char *doh_hostname);

#endif
