#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "../../buffer.h"
#include <sys/select.h>

typedef struct {
	buffer *clientToServerBuffer;	// buffer donde cliente escribe y servidor lee
	buffer *serverToClientBuffer; // buffer donde servidor escribe y cliente lee
	int clientSock;				// socket activo con cliente
	int serverSock;				// socket activo con servidor
} ConnectionData;

typedef struct ConnectionNode {
	ConnectionData data;
	struct ConnectionNode *next;
} ConnectionNode;

typedef struct {
	unsigned int clients;
	ConnectionNode *first;
} ConnectionHeader;

void setupConnectionResources(int clientSock, int serverSock);

void closeConnection(ConnectionNode *node, ConnectionNode *previous, fd_set *writeFdSet, fd_set *readFdSet);

#endif
