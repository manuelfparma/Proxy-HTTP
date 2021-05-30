#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "../../buffer.h"
#include <pthread.h>
#include <sys/select.h>

// Manejo de estados para getaddrinfo, la cual se corre en otro hilo
typedef enum { NEEDS_ADDR_INFO, ADDR_INFO_READY, ADDR_INFO_SET } ADDR_INFO_STATE;

typedef struct {
	buffer *clientToServerBuffer;  // buffer donde cliente escribe y servidor lee
	buffer *serverToClientBuffer;  // buffer donde servidor escribe y cliente lee
	int clientSock;				   // socket activo con cliente
	int serverSock;				   // socket activo con servidor
	ADDR_INFO_STATE addrInfoState; // estado de la busqueda DNS
	pthread_t addrInfoThread;	   // informacion del thread donde corre la resolución DNS
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

void closeConnection(ConnectionNode *node, ConnectionNode *previous, fd_set *writeFdSet, fd_set *readFdSet);

#endif
