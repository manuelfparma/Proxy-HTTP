#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "buffer.h"
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>
#include <parser.h>

// Manejo de estados para getaddrinfo, la cual se corre en otro hilo
typedef enum { EMPTY, FETCHING, READY, CONNECTING, CONNECTED , DNS_ERROR} ADDR_INFO_STATE;

typedef struct {
	buffer *clientToServerBuffer;		// buffer donde cliente escribe y servidor lee
	buffer *serverToClientBuffer;		// buffer donde servidor escribe y cliente lee
	int clientSock;						// socket activo con cliente
	int serverSock;						// socket activo con servidor
	ADDR_INFO_STATE addrInfoState;		// estado de la busqueda DNS
	pthread_t addrInfoThread;			// informacion del thread donde corre la resolución DNS
	struct addrinfo *addr_info_header;	// para guardar el inicio de la lista del resultado de la consulta DNS
	struct addrinfo *addr_info_current; // para guardar el ultimo nodo con el que se intento conectar
	http_request * request;				// estructura donde se guarda el estado del parseo
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
