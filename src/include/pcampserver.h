#ifndef PCAMPSERVER_H
#define PCAMPSERVER_H

#define SERVER_PCAMP_VERSION 1
#define QUERY_ANSWER_BUFFER_LENGTH 32

//	Abre dos sockets para escuchar consultas UDP que utiliza PCAMP
//	Los sockets se guardan en management_sockets[]: uno para IPv4 y otro para IPv6
int setup_pcamp_sockets(int management_sockets[SOCK_COUNT]);

//	Cuando un socket/fd seteado en management_sockets[] se activa, esta función resuelve la consulta
void handle_pcamp_request(int fd);

#endif
