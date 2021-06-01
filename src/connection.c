#include <connection.h>
#include <errno.h>
#include <logger.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern ConnectionHeader connections;

ConnectionNode *setupConnectionResources(int clientSock, int serverSock) {
	// asignacion de recursos para la conexion
	ConnectionNode *new = malloc(sizeof(ConnectionNode));

	if (new->data.clientToServerBuffer == NULL) goto ERROR;

	new->next = NULL;
	new->data.clientSock = clientSock;
	new->data.serverSock = serverSock;

	new->data.clientToServerBuffer = malloc(sizeof(buffer));
	if (new->data.clientToServerBuffer == NULL) goto FREE_NEW;

	new->data.clientToServerBuffer->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.clientToServerBuffer->data == NULL) goto FREE_BUFFER_1;

	new->data.serverToClientBuffer = malloc(sizeof(buffer));
	if (new->data.serverToClientBuffer == NULL) goto FREE_BUFFER_1_DATA;

	new->data.serverToClientBuffer->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.serverToClientBuffer->data == NULL) goto FREE_BUFFER_2;

	// TODO: discutir si se necesita acceder a futuro
	// new->data.addr_info_header = malloc(sizeof(struct addrinfo));
	// if (new->data.addr_info_header == NULL) goto FREE_BUFFER_2_DATA;

	new->data.addrInfoState = EMPTY; // hasta que el hilo de getaddrinfo resuelva la consulta DNS
	new->data.parse_state = METHOD;

	buffer_init(new->data.clientToServerBuffer, BUFFER_SIZE, new->data.clientToServerBuffer->data);
	buffer_init(new->data.serverToClientBuffer, BUFFER_SIZE, new->data.serverToClientBuffer->data);

	return new;

//FREE_BUFFER_2_DATA:
//	free(new->data.serverToClientBuffer->data);
FREE_BUFFER_2:
	free(new->data.serverToClientBuffer);
FREE_BUFFER_1_DATA:
	free(new->data.clientToServerBuffer->data);
FREE_BUFFER_1:
	free(new->data.clientToServerBuffer);
FREE_NEW:
	free(new);
ERROR:
	logger(ERROR, "malloc(): %s", strerror(errno));
	return NULL;
}

void addToConnections(ConnectionNode *node) {
	//	busqueda para la insercion
	ConnectionNode *last = connections.first;
	if (last != NULL) {
		while (last->next != NULL) {
			last = last->next;
		}
		last->next = node;
	} else {
		connections.first = node;
	}

	connections.clients++;
}

void closeConnection(ConnectionNode *node, ConnectionNode *previous, fd_set *writeFdSet, fd_set *readFdSet) {
	int clientFd = node->data.clientSock, serverFd = node->data.serverSock;
	loggerPeer(CLIENT, "Socket with fd: %d disconnected", clientFd);
	loggerPeer(SERVER, "Socket with fd: %d disconnected", serverFd);
	free(node->data.serverToClientBuffer->data);
	free(node->data.clientToServerBuffer->data);
	free(node->data.clientToServerBuffer);
	free(node->data.serverToClientBuffer);

	if (previous == NULL) {
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
