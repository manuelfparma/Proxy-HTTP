#ifndef PCAMPSERVER_H
#define PCAMPSERVER_H

#define SERVER_PCAMP_VERSION 1
#define QUERY_ANSWER_BUFFER_LENGTH 32

// TODO: Comentar funciones

int setup_pcamp_sockets(int management_sockets[SOCK_COUNT]);

void handle_pcamp_request(int fd);

#endif
