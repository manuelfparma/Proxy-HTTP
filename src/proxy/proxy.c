#include "proxy.h"
#include "../logger.h"
#include "utils/connection.h"
#include "utils/proxyutils.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

ConnectionHeader connections = {0};

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <Proxy Port> <Server Host> <Server Port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	char *proxyPort = argv[1];
	char *serverHost = argv[2];
	char *serverPort = argv[3];

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
	// sigaddset(&sigMask, SIGINT);

	connections.maxFd = passiveSock + 1;

	while (1) {
		readFdSet[TMP] = readFdSet[BASE];
		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(connections.maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, &sigMask);
		if (readyFds == -1) {
			// FIX ERROR HANDLING
			perror("[ERROR] : Error en pselect() - main() - server.c");
			continue;
		}

		if (FD_ISSET(passiveSock, &readFdSet[TMP]) && connections.clients <= MAX_CLIENTS) {
			// abro conexiones con cliente y servidor
			int clientSock = acceptConnection(passiveSock);
			if(clientSock > -1){
				// aloco recursos para estructura de conexion cliente-servidor
				// el socket del servidor se crea asincronicamente, por lo cual arranca en -1 inicialmente
				pthread_t thread;
				int serverSock = -1;
				ConnectionNode *newConnection = setupConnectionResources(clientSock, serverSock);
				ThreadArgs *args = malloc(sizeof(ThreadArgs));
				char *hostCopy = malloc(strlen(serverHost) * sizeof(char) + 1);
				char *serviceCopy = malloc(strlen(serverPort) * sizeof(char) + 1);
				strcpy(hostCopy, serverHost);
				strcpy(serviceCopy, serverPort);
				args->host = hostCopy;
				args->service = serviceCopy;
				args->connection = newConnection;

				int ret = pthread_create(&thread, NULL, setupClientSocket, (void *)args);

				if (ret != 0) {
					logger(ERROR, "pthread_create(): %s", strerror(errno));
					close(clientSock);
					free(newConnection);
				} else {
					FD_SET(clientSock, &readFdSet[BASE]);

					addToConnections(newConnection);
					if (clientSock >= connections.maxFd) connections.maxFd = clientSock + 1;
				}
			}
			readyFds--;
		}

		// itero por todas las conexiones cliente-servidor
		for (ConnectionNode *node = connections.first, *previous = NULL; node != NULL && readyFds > 0;
			 previous = node, node = node->next) {
			int handle;
			// manejo las conexiones mediante sockets de cliente y servidor
			for (PEER peer = CLIENT; peer <= SERVER; peer++) {
				handle = handleConnection(node, previous, readFdSet, writeFdSet, peer);

				if (handle > -1) readyFds -= handle;
				else if (handle == -1)
					break; // Caso conexion cerrada
				else if (handle == -2)
					continue; // Caso argumento invalido
			}
			if (handle == -1) break;
		}
	}
}
