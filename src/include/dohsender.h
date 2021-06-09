#ifndef DOH_SENDER_H

#define DOH_SENDER_H

#include <dohdata.h>
#include <buffer.h>
#include <connection.h>
#include <dohutils.h>
#include <unistd.h>

void prepare_doh_request(connection_node *node);

int send_doh_request(connection_node *node, fd_set *write_fd_set);

#endif
