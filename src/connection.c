#include <connection.h>
#include <errno.h>
#include <logger.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <parser.h>

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

	new->data.request = malloc(sizeof(http_request));
	if (new->data.request == NULL) goto FREE_BUFFER_2_DATA;

	new->data.request->parsed_request = malloc(sizeof(buffer));
	if (new->data.request->parsed_request == NULL) goto FREE_REQUEST;

	new->data.request->parsed_request->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.request->parsed_request->data == NULL) goto FREE_REQUEST_BUFFER;

	new->data.request->parser_state = PS_METHOD;
	new->data.request->package_status = PARSE_START_LINE_INCOMPLETE;
	new->data.request->request_target_status = UNSOLVED;
	new->data.request->copy_index = 0;
	new->data.request->start_line.method[0] = '\0';
	new->data.request->start_line.protocol[0] = '\0';
	new->data.request->start_line.destination.port[0] = '\0';
	new->data.request->start_line.destination.relative_path[0] = '\0';
	new->data.request->start_line.version.major = EMPTY_VERSION;
	new->data.request->start_line.version.minor = EMPTY_VERSION;
	new->data.request->header.header_type[0] = '\0';
	new->data.request->header.header_value[0] = '\0';

	buffer_init(new->data.clientToServerBuffer, BUFFER_SIZE, new->data.clientToServerBuffer->data);
	buffer_init(new->data.serverToClientBuffer, BUFFER_SIZE, new->data.serverToClientBuffer->data);
	buffer_init(new->data.request->parsed_request, BUFFER_SIZE, new->data.request->parsed_request->data);

	return new;

FREE_REQUEST_BUFFER:
	free(new->data.request->parsed_request);
FREE_REQUEST:
	free(new->data.request);
FREE_BUFFER_2_DATA:
	free(new->data.serverToClientBuffer->data);
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

void close_connection(ConnectionNode *node, ConnectionNode *previous, fd_set *write_fd_set, fd_set *read_fd_set) {
	int clientFd = node->data.clientSock, serverFd = node->data.serverSock;
	loggerPeer(CLIENT, "Socket with fd: %d disconnected", clientFd);
	loggerPeer(SERVER, "Socket with fd: %d disconnected", serverFd);
	free(node->data.serverToClientBuffer->data);
	free(node->data.clientToServerBuffer->data);
	free(node->data.clientToServerBuffer);
	free(node->data.serverToClientBuffer);
	free(node->data.request->parsed_request->data);
	free(node->data.request->parsed_request);
	free(node->data.request);

	if (previous == NULL) {
		// Caso primer nodo
		connections.first = node->next;
	} else {
		previous->next = node->next;
	}

	free(node);

	FD_CLR(clientFd, &read_fd_set[BASE]);
	FD_CLR(clientFd, &write_fd_set[BASE]);
	FD_CLR(serverFd, &read_fd_set[BASE]);
	FD_CLR(serverFd, &write_fd_set[BASE]);
	close(clientFd);
	close(serverFd);

	connections.clients--;
}
