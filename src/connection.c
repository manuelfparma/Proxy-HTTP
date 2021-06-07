#include <connection.h>
#include <errno.h>
#include <logger.h>
#include <http_parser.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern ConnectionHeader connections;

static size_t connection_number = 1;

static size_t power(size_t base, size_t exp) {
	size_t ret = 1;
	for (size_t i = 0; i < exp; i++) {
		ret *= base;
	}
	return ret;
}

static void number_to_str(size_t n, char *buffer) {
	size_t copy_n = n, length = 0;
	for( ; copy_n > 0; copy_n /= 10, length++){};
	copy_n = n;
	for(size_t i = 0; copy_n > 0; i++, copy_n /= 10){
		buffer[i] = '0' + ((n / power(10, length - i - 1)) % 10);
	}
}

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

	new->data.connection_state = DISCONNECTED; // hasta que el hilo de getaddrinfo resuelva la consulta DNS

	new->data.parser = malloc(sizeof(http_parser));
	if (new->data.parser == NULL) goto FREE_BUFFER_2_DATA;

	new->data.parser->data.parsed_request = malloc(sizeof(buffer));
	if (new->data.parser->data.parsed_request == NULL) goto FREE_REQUEST;

	new->data.parser->data.parsed_request->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.parser->data.parsed_request->data == NULL) goto FREE_REQUEST_BUFFER;

	new->data.parser->data.parser_state = PS_METHOD;
	new->data.parser->data.request_status = PARSE_START_LINE_INCOMPLETE;
	new->data.parser->data.target_status = NOT_FOUND;
	new->data.parser->data.copy_index = 0;
	new->data.parser->request.method[0] = '\0';
	new->data.parser->request.schema[0] = '\0';
	new->data.parser->request.target.port[0] = '\0';
	new->data.parser->request.target.relative_path[0] = '\0';
	new->data.parser->request.version.major = EMPTY_VERSION;
	new->data.parser->request.version.minor = EMPTY_VERSION;
	new->data.parser->request.header.type[0] = '\0';
	new->data.parser->request.header.value[0] = '\0';

	buffer_init(new->data.clientToServerBuffer, BUFFER_SIZE, new->data.clientToServerBuffer->data);
	buffer_init(new->data.serverToClientBuffer, BUFFER_SIZE, new->data.serverToClientBuffer->data);
	buffer_init(new->data.parser->data.parsed_request, BUFFER_SIZE, new->data.parser->data.parsed_request->data);

	char file_name[1024] = {0};
	const char *name = "./logs/log_connection_";
	strcpy(file_name, name);
	char number[1024] = {0};
	number_to_str(connection_number++, number);
	strcpy(file_name + strlen(name), number);
	logger(DEBUG, "File with name %s created", file_name);
	new->data.log_file = fopen(file_name, "w+");
	if (new->data.log_file == NULL) {
		logger(ERROR, "fopen: %s", strerror(errno));
		goto FREE_REQUEST_BUFFER;
	}

	return new;

FREE_REQUEST_BUFFER:
	free(new->data.parser->data.parsed_request);
FREE_REQUEST:
	free(new->data.parser);
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
	free(node->data.parser->data.parsed_request->data);
	free(node->data.parser->data.parsed_request);
	free(node->data.parser);
	fclose(node->data.log_file);

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
	if (serverFd > 0) close(serverFd);

	connections.clients--;
}
