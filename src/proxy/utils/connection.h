#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <sys/select.h>

typedef struct {
	char *clientToServerBuffer;	// buffer donde cliente escribe y servidor lee
	char *serverToClientBuffer; // buffer donde servidor escribe y cliente lee
	int clientSock;				// socket activo con cliente
	int serverSock;				// socket activo con servidor
	int serverToClientPos;		// ultima posicion leida en buffer de cliente a servidor
	int clientToServerPos;		// ultima posicion leida en buffer de serivdor a cliente
	int bytesForClient;			// caracteres para enviar al cliente
	int bytesForServer;			// caracteres para enviar al servidor
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
