#include <connection.h>
#include <dohclient.h>
#include <dohutils.h>
#include <errno.h>
#include <fcntl.h>
#include <http_parser.h>
#include <logger.h>
#include <proxy.h>
#include <proxyutils.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

// Funcion que se encarga de liberar los recursos de una conexion entre un cliente y servidor
static void handle_connection_error(ConnectionNode *node, ConnectionNode *previous, fd_set *write_fd_set, fd_set *read_fd_set);
// Funcion para buscar el id maximo entre los sets de escritura y lectura que utiliza el pselect. Utilizada por handle_connection_error
static void find_max_id();

ConnectionHeader connections = {0};

int main(int argc, char **argv) {
	if (argc != 2) { logger(FATAL, "Usage: %s <Proxy Port>\n", argv[0]); }

	char *proxyPort = argv[1];

	int passiveSock = setupPassiveSocket(proxyPort);
	if (passiveSock < 0) logger(ERROR, "setupPassiveSocket() failed");

	fd_set writeFdSet[FD_SET_ARRAY_SIZE];
	fd_set readFdSet[FD_SET_ARRAY_SIZE];

	for (int i = 0; i < FD_SET_ARRAY_SIZE; i++) {
		FD_ZERO(&writeFdSet[i]);
		FD_ZERO(&readFdSet[i]);
	}

	FD_SET(passiveSock, &readFdSet[BASE]);

	int readyFds;
	sigset_t sigMask;
	sigemptyset(&sigMask);
	// configuracion de signal para interrumpir select desde otro thread

	connections.maxFd = passiveSock + 1;

	while (1) {
		// resetear fd_set
		readFdSet[TMP] = readFdSet[BASE];
		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(connections.maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, &sigMask);

		if (FD_ISSET(passiveSock, &readFdSet[TMP]) && connections.clients <= MAX_CLIENTS) {
			// establezco conexión con cliente en socket activo
			int clientSock = acceptConnection(passiveSock);
			if (clientSock > -1) {
				// la consulta DNS para la conexión con el servidor se realiza asincronicamente,
				// esto imposibilita la creación de un socket activo con el servidor hasta que dicha consulta
				// este resulta. Por lo tanto dicho FD arranca en -1 inicialmente.
				// aloco recursos para el respectivo cliente
				ConnectionNode *newConnection = setupConnectionResources(clientSock, -1);
				if (newConnection != NULL) {
					// acepto lecturas del socket
					FD_SET(clientSock, &readFdSet[BASE]);
					addToConnections(newConnection);
					if (clientSock >= connections.maxFd) connections.maxFd = clientSock + 1;
				} else {
					close(clientSock);
					logger(ERROR, "setupConnectionResources() failed with NULL value");
				}
			}
			readyFds--;
		}

		int handle;
		// itero por todas las conexiones cliente-servidor
		for (ConnectionNode *node = connections.first, *previous = NULL; node != NULL && readyFds > 0;
			 previous = node, node = node->next) {
			if (node->data.connection_state == CONNECTING_TO_DOH) {
				handle = handle_doh_request(node, writeFdSet, readFdSet);
				if (handle > -1) readyFds -= handle;
				// TODO: Manejo de error
			} else if (node->data.connection_state == FETCHING_DNS) {
				handle = handle_doh_response(node, readFdSet);
				if (handle >= 0) {
					readyFds -= handle;
					if (handle == 1) {
						FD_CLR(node->data.doh->sock, &readFdSet[BASE]);
						close(node->data.doh->sock);
						if (setup_connection(node, writeFdSet) == -1) {
							logger(ERROR, "setup_connection(): failed to connect");
							// FIXME: ?????
							return -1;
						}
					}
				} else {
					// TODO: Liberar recursos y cliente
					FD_CLR(node->data.doh->sock, &readFdSet[BASE]);
					close(node->data.doh->sock);
					free_doh_resources(node);
					close_connection(node, previous, writeFdSet, readFdSet);
				}
			} else {
				handle = handle_client_connection(node, previous, readFdSet, writeFdSet);
				if (handle > -1) readyFds -= handle;
				else if (handle == CLOSE_CONNECTION_CODE) {
					// Caso conexion cerrada, veo si no quedo nada para el cliente
					if (!buffer_can_read(node->data.serverToClientBuffer)) {
						handle_connection_error(node, previous, writeFdSet, readFdSet);
						break;
					}
				} else {
					handle_connection_error(node, previous, writeFdSet, readFdSet);
					break;
				}
				handle = handle_server_connection(node, previous, readFdSet, writeFdSet);
				if (handle > -1) readyFds -= handle;
				else if (handle == CLOSE_CONNECTION_CODE) {
					// Caso conexion cerrada, veo si no quedo nada para el cliente
					if (!buffer_can_read(node->data.serverToClientBuffer)) {
						handle_connection_error(node, previous, writeFdSet, readFdSet);
						break;
					}
				} else {
					handle_connection_error(node, previous, writeFdSet, readFdSet);
					break;
				}
			}
		}
	}
}

static void handle_connection_error(ConnectionNode *node, ConnectionNode *previous, fd_set *write_fd_set, fd_set *read_fd_set) {
	int aux_server_sock = node->data.serverSock >= connections.maxFd;
	int aux_client_sock = node->data.clientSock >= connections.maxFd;
	// guardo copias de los sockets a borrar, para compararlos con el maximo actual(luego de ser borrados) y decidir
	// si se debe buscar otro maximo
	close_connection(node, previous, write_fd_set, read_fd_set);
	if (aux_server_sock >= connections.maxFd || aux_client_sock >= connections.maxFd) find_max_id();
}

static void find_max_id() {
	for (ConnectionNode *node = connections.first; node != NULL; node = node->next) {
		if (node->data.clientSock >= connections.maxFd) connections.maxFd = node->data.clientSock;
		if (node->data.serverSock >= connections.maxFd) connections.maxFd = node->data.serverSock;
	}
}
