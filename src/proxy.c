#include <connection.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <parser.h>
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

static void wake_handler(const int signal);

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
 	struct sigaction act = {
 		.sa_handler = wake_handler,
 	};

 	if (sigaction(SIGIO, &act, 0)) logger(FATAL, "sigaction(): %s", strerror(errno));

 	connections.maxFd = passiveSock + 1;

 	while (1) {
 		// resetear fd_set
 		readFdSet[TMP] = readFdSet[BASE];
 		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(connections.maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, &sigMask);
		if (readyFds <= -1) {
			// el select fue interrumpido por un thread que resolvio la consulta DNS
			if (errno == EINTR) {
				// chequeamos cual nodo resolvio la consulta DNS TODO: ineficiente????
				int found = 0;
				for (ConnectionNode *node = connections.first, *prev = NULL; node != NULL && !found;  prev = node, node = node->next) {
					if (node->data.addrInfoState == READY) {
						found = 1;
						// FIXME: verificar si la quedo el dns
						int ans = pthread_join(node->data.addrInfoThread, NULL);
						if (ans != 0) {
							logger(ERROR, "pthread_join(): %s", strerror(errno));
						} else {
							if (setup_connection(node, writeFdSet) == -1) {
								logger(INFO, "setup_connection()");
								// FIXME: ?????
								return -1;
							}
							logger(DEBUG, "Trying setup_connection()");
						}
					}else if(node->data.addrInfoState == DNS_ERROR){
						logger(DEBUG, "getaddrinfo failed");
						close_connection(node, prev, writeFdSet, readFdSet);
					}
				}
			} else {
				logger(ERROR, "pselect(): %s", strerror(errno));
			}
			continue;
		}

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
			handle = handle_client_connection(node, previous, readFdSet, writeFdSet);
			if (handle > -1) readyFds -= handle;
			else
				break; // Caso conexion cerrada
			handle = handle_server_connection(node, previous, readFdSet, writeFdSet);
			if (handle > -1) readyFds -= handle;
			else
				break; // Caso conexion cerrada
		}
	}
}

static void wake_handler(const int signal) {
 	// nada que hacer. está solo para interrumpir el select
 }
