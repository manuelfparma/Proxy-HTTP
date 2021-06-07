#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <dohdata.h>
#include <buffer.h>
#include <netdb.h>
#include <http_parser.h>
#include <pthread.h>
#include <sys/select.h>
#include <http_parser.h>
#include <stdio.h>

// Manejo de estados para getaddrinfo, la cual se corre en otro hilo
// TODO: Cambiar nombre a CONNECTION_STATE, porque usamos CONNECTING y CONNECTED y eso esta por fuera de addrinfo
typedef enum { DISCONNECTED, CONNECTING_TO_DOH, FETCHING_DNS, CONNECTING, CONNECTED } CONNECTION_STATE;

typedef struct {
	buffer *clientToServerBuffer;		// buffer donde cliente escribe y servidor lee
	buffer *serverToClientBuffer;		// buffer donde servidor escribe y cliente lee
	int clientSock;						// socket activo con cliente
	int serverSock;						// socket activo con servidor
	CONNECTION_STATE connection_state;		// estado de la busqueda DNS
	http_parser * parser;				// estructura donde se guarda el estado del parseo
	FILE * log_file;
	doh_data *doh;
} ConnectionData;

typedef struct ConnectionNode {
	ConnectionData data;
	struct ConnectionNode *next;
} ConnectionNode;

typedef struct {
	unsigned int clients;
	int maxFd;
	ConnectionNode *first;
} ConnectionHeader;

ConnectionNode *setupConnectionResources(int clientSock, int serverSock);

void addToConnections(ConnectionNode *node);

void close_connection(ConnectionNode *node, ConnectionNode *previous, fd_set *write_fd_set, fd_set *read_fd_set);

#endif
