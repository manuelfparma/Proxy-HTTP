#include "proxy.h"
#include "../logger.h"
#include "utils/connection.h"
#include "utils/proxyutils.h"
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
	if (passiveSock < 0) logger(ERROR, "setupPassiveSocket() failed", STDERR_FILENO);

	fd_set writeFdSet[FD_SET_ARRAY_SIZE];
	fd_set readFdSet[FD_SET_ARRAY_SIZE];

	for (int i = 0; i < FD_SET_ARRAY_SIZE; i++) {
		FD_ZERO(&writeFdSet[i]);
		FD_ZERO(&readFdSet[i]);
	}

	FD_SET(passiveSock, &readFdSet[BASE]);

	int maxFd = passiveSock + 1;
	int readyFds;

	sigset_t sigMask;
	sigemptyset(&sigMask);
	// sigaddset(&sigMask, SIGINT);

	while (1) {
		readFdSet[TMP] = readFdSet[BASE];
		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, &sigMask);
		if (readyFds == -1) {
			// FIX ERROR HANDLING
			perror("[ERROR] : Error en pselect() - main() - server.c");
			continue;
		}

		if (FD_ISSET(passiveSock, &readFdSet[TMP]) && connections.clients <= MAX_CLIENTS) {
			// abro conexiones con cliente y servidor
			int clientSock = acceptConnection(passiveSock);
			int serverSock = setupClientSocket(serverHost, serverPort);
			FD_SET(clientSock, &readFdSet[BASE]);
			FD_SET(serverSock, &readFdSet[BASE]);
			readyFds--;

			// aloco recursos para estructura de conexion cliente-servidor
			setupConnectionResources(clientSock, serverSock);

			// actualizacion de FD maximo para select
			if (serverSock >= maxFd) maxFd = serverSock + 1;
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
