#include "connection.h"
#include "../../logger.h"
#include "proxyutils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "connection.h"

extern ConnectionHeader connections;

ConnectionNode *setupConnectionResources(int clientSock, int serverSock) {
	// asignacion de recursos para la conexion
	ConnectionNode *new = malloc(sizeof(ConnectionNode));
	new->next = NULL;
	new->data.clientSock = clientSock;
	new->data.serverSock = serverSock;

	new->data.clientToServerBuffer = malloc(sizeof(buffer));
	new->data.clientToServerBuffer->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	new->data.serverToClientBuffer = malloc(sizeof(buffer));
	new->data.serverToClientBuffer->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	new->data.addrInfoState = NEEDS_ADDR_INFO;	// hasta que el hilo de getaddrinfo resuelva la consulta DNS

	if (new->data.clientToServerBuffer == NULL || new->data.clientToServerBuffer->data == NULL ||
		new->data.serverToClientBuffer == NULL || new->data.serverToClientBuffer->data == NULL) {
		logger(ERROR, "malloc(): %s", strerror(errno));
		return NULL;
	}

	buffer_init(new->data.clientToServerBuffer, BUFFER_SIZE, new->data.clientToServerBuffer->data);
	buffer_init(new->data.serverToClientBuffer, BUFFER_SIZE, new->data.serverToClientBuffer->data);

	return new;
}

void addToConnections(ConnectionNode *node) {
	//	busqueda para la insercion
	ConnectionNode *last = connections.first;
	if(last != NULL) {
		while(last->next != NULL) {
			last = last->next;
		}
		last->next = node;
	} else {
		connections.first = node;
	}

	connections.clients++;
};

void closeConnection(ConnectionNode *node, ConnectionNode *previous, fd_set *writeFdSet, fd_set *readFdSet) {
	int clientFd = node->data.clientSock, serverFd = node->data.serverSock;
	printf("[INFO] : Cliente en socket %d desconectado\n", clientFd);
	printf("[INFO] : Server en socket %d desconectado\n", serverFd);
	free(node->data.serverToClientBuffer->data);
	free(node->data.clientToServerBuffer->data);
	free(node->data.clientToServerBuffer);
	free(node->data.serverToClientBuffer);

	if(previous == NULL) {
		// Caso primer nodo
		connections.first = node->next;
	} else {
		previous->next = node->next;
	}

	free(node);

	FD_CLR(clientFd, &readFdSet[BASE]);
	FD_CLR(clientFd, &writeFdSet[BASE]);
	FD_CLR(serverFd, &readFdSet[BASE]);
	FD_CLR(serverFd, &writeFdSet[BASE]);
	close(clientFd);
	close(serverFd);

	connections.clients--;
}
