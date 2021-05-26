#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "connection.h"
#include "proxyutils.h"

void setupConnectionResources(int clientSock, int serverSock, ConnectionHeader *connections) {
	// asignacion de recursos para la conexion
	ConnectionNode *new = malloc(sizeof(ConnectionNode));
	new->data.clientSock = clientSock;
	new->data.serverSock = serverSock;
	new->data.clientToServerBuffer = malloc(BUFFER_SIZE * sizeof(char));
	new->data.serverToClientBuffer = malloc(BUFFER_SIZE * sizeof(char));
	new->data.bytesForServer = 0;
	new->data.bytesForClient = 0;
	new->data.serverToClientPos = 0;
	new->data.clientToServerPos = 0;
	new->next = NULL;

	//	busqueda para la insercion
	ConnectionNode *last = connections->first;
	if(last != NULL) {
		while(last->next != NULL) {
			last = last->next;
		}
		last->next = new;
	} else {
		connections->first = new;
	}

	connections->clients++;
}

void closeConnection(ConnectionNode *node, ConnectionNode *previous, fd_set *writeFdSet, fd_set *readFdSet, ConnectionHeader *connections) {
	int clientFd = node->data.clientSock,
		serverFd = node->data.serverSock;
	printf("[INFO] : Cliente en socket %d desconectado\n", clientFd);
	printf("[INFO] : Server en socket %d desconectado\n", serverFd);
	free(node->data.clientToServerBuffer);
	free(node->data.serverToClientBuffer);

	if(previous == NULL) {
		// Caso primer nodo
		connections->first = node->next;
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

	connections->clients--;
}
