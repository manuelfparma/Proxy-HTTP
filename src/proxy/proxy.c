#include "proxy.h"
#include "../logger.h"
#include "utils/connection.h"
#include "utils/proxyutils.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static enum OPERATION { WRITE = 0, READ };
static enum PEER { CLIENT = 0, SERVER };
static void copyToCircularBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes);
static void copyToLinearBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes);
void handleConnection(ConnectionNode *node, ConnectionNode *prev, fd_set readFdSet[FD_SET_ARRAY_SIZE],
					  fd_set writeFdSet[FD_SET_ARRAY_SIZE], enum PEER peer);
size_t handleOperation(ConnectionNode *node, ConnectionNode *prev, int fd, char buffer[BUFFER_SIZE], int pos, size_t bytes,
					   enum OPERATION operation);

	ConnectionHeader connections = {0};

int main2(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <Proxy Port> <Server Host> <Server Port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	char *proxyPort = argv[1];
	char *serverHost = argv[2];
	char *serverPort = argv[3];

	int passiveSock = setupPassiveSocket(proxyPort);
	if (passiveSock < 0)
		logger(ERROR, "setupPassiveSocket() failed", STDERR_FILENO);

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
	sigaddset(&sigMask, SIGINT);

	while (1) {

		readFdSet[TMP] = readFdSet[BASE];
		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, NULL);
		if (readyFds == -1) {
			// FIX ERROR HANDLING
			perror("[ERROR] : Error en pselect() - main() - server.c");
			continue;
		}

		if (FD_ISSET(passiveSock, &readFdSet[TMP]) && connections.clients <= MAX_CLIENTS) {
			// abrir conexiones con cliente y servidor
			int clientSock = acceptConnection(passiveSock);
			int serverSock = setupClientSocket(serverHost, serverPort);
			FD_SET(clientSock, &readFdSet[BASE]);
			FD_SET(serverSock, &readFdSet[BASE]);
			readyFds--;

			setupConnectionResources(clientSock, serverSock, &connections);

			// actualizacion de FD maximo para select
			if (serverSock >= maxFd)
				maxFd = serverSock + 1;
		}

		// TODO: Pasar cada operacion de lectura y escritura a funciones auxiliares
		for (ConnectionNode *node = connections.first, *previous = NULL; node != NULL; previous = node, node = node->next) {

			// Leer de cliente
			int clientFd = node->data.clientSock;
			if (FD_ISSET(clientFd, &readFdSet[TMP])) {
				int bytesForServer = node->data.bytesForServer;
				// si el buffer esta lleno, no puedo recibir el mensaje
				if (bytesForServer < BUFFER_SIZE) {
					// leemos en un buffer lineal auxiliar y lo copiamos al buffer circular global
					char auxBuff[BUFFER_SIZE] = {0};
					int bytesRecv = recv(clientFd, auxBuff, BUFFER_SIZE - bytesForServer, 0);

					if (bytesRecv <= 0) {
						if (bytesRecv == -1)
							perror("[ERROR] : Error en recv() - main() - server.c");

						closeConnection(node, previous, writeFdSet, readFdSet, &connections);
						break;
					} else {
						printf("[INFO] : SERVER RECEIVED %s\n", auxBuff);

						copyToCircularBuffer(node->data.clientToServerBuffer, auxBuff, node->data.clientToServerPos, bytesRecv);
						node->data.bytesForServer += bytesRecv;

						// comenzamos a ver si el server acepta escritura desde select
						FD_SET(node->data.serverSock, &writeFdSet[BASE]);
					}
				}
				readyFds--;
			}

			// Escribir al cliente
			if (FD_ISSET(clientFd, &writeFdSet[TMP])) {
				int bytesForClient = node->data.bytesForClient;
				// si no hay nada para escribir, no escribo
				if (bytesForClient > 0) {
					// enviamos el mensaje mediante un buffer lineal auxiliar
					char auxBuff[BUFFER_SIZE] = {0};
					copyToLinearBuffer(auxBuff, node->data.serverToClientBuffer, node->data.serverToClientPos, bytesForClient);

					int bytesSent = send(clientFd, auxBuff, bytesForClient, 0);

					if (bytesSent <= 0) {
						if (bytesSent == -1)
							perror("[ERROR] : Error en send() - main() - server.c");

						closeConnection(node, previous, writeFdSet, readFdSet, &connections);
						break;
					} else {
						node->data.bytesForClient -= bytesSent;
						if (node->data.bytesForClient == 0)
							FD_CLR(clientFd, &writeFdSet[BASE]);
					}
				}
				readyFds--;
			}

			// Leer de server
			int serverFd = node->data.serverSock;
			if (FD_ISSET(serverFd, &readFdSet[TMP])) {
				int bytesForClient = node->data.bytesForClient;
				// si el buffer esta lleno, no puedo recibir el mensaje
				if (bytesForClient < BUFFER_SIZE) {
					// leemos en un buffer lineal auxiliar y lo copiamos al buffer circular global
					char auxBuff[BUFFER_SIZE] = {0};
					int bytesRecv = recv(serverFd, auxBuff, BUFFER_SIZE - bytesForClient, 0);

					if (bytesRecv <= 0) {
						if (bytesRecv == -1)
							perror("[ERROR] : Error en recv() - main() - server.c");
						closeConnection(node, previous, writeFdSet, readFdSet, &connections);
						break;
					} else {
						printf("[INFO] : SERVER RECEIVED %s\n", auxBuff);

						copyToCircularBuffer(node->data.serverToClientBuffer, auxBuff, node->data.serverToClientPos, bytesRecv);
						node->data.bytesForClient += bytesRecv;

						// comenzamos a ver si el server acepta escritura desde select
						FD_SET(node->data.clientSock, &writeFdSet[BASE]);
					}
				}
				readyFds--;
			}

			// Escribir al server
			if (FD_ISSET(serverFd, &writeFdSet[TMP])) {
				int bytesForServer = node->data.bytesForServer;
				// si no hay nada para escribir, no escribo
				if (bytesForServer > 0) {
					// enviamos el mensaje mediante un buffer lineal auxiliar
					char auxBuff[BUFFER_SIZE] = {0};
					copyToLinearBuffer(auxBuff, node->data.clientToServerBuffer, node->data.clientToServerPos, bytesForServer);

					int bytesSent = send(serverFd, auxBuff, bytesForServer, 0);

					if (bytesSent <= 0) {
						if (bytesSent == -1)
							perror("[ERROR] : Error en send() - main() - server.c");
						closeConnection(node, previous, writeFdSet, readFdSet, &connections);
						break;
					} else {
						node->data.bytesForServer -= bytesSent;
						if (node->data.bytesForServer == 0)
							FD_CLR(serverFd, &writeFdSet[BASE]);
					}
				}
				readyFds--;
			}
		}
	}
	// FREE y close de todo?
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <Proxy Port> <Server Host> <Server Port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	char *proxyPort = argv[1];
	char *serverHost = argv[2];
	char *serverPort = argv[3];

	int passiveSock = setupPassiveSocket(proxyPort);
	if (passiveSock < 0)
		logger(ERROR, "setupPassiveSocket() failed", STDERR_FILENO);

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
	sigaddset(&sigMask, SIGINT);

	while (1) {

		readFdSet[TMP] = readFdSet[BASE];
		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, NULL);
		if (readyFds == -1) {
			// FIX ERROR HANDLING
			perror("[ERROR] : Error en pselect() - main() - server.c");
			continue;
		}

		if (FD_ISSET(passiveSock, &readFdSet[TMP]) && connections.clients <= MAX_CLIENTS) {
			// abrir conexiones con cliente y servidor
			int clientSock = acceptConnection(passiveSock);
			int serverSock = setupClientSocket(serverHost, serverPort);
			FD_SET(clientSock, &readFdSet[BASE]);
			FD_SET(serverSock, &readFdSet[BASE]);
			readyFds--;

			setupConnectionResources(clientSock, serverSock, &connections);

			// actualizacion de FD maximo para select
			if (serverSock >= maxFd)
				maxFd = serverSock + 1;
		}

		// TODO: Pasar cada operacion de lectura y escritura a funciones auxiliares
		for (ConnectionNode *node = connections.first, *previous = NULL; node != NULL; previous = node, node = node->next) {
			handleConnection(node, previous, readFdSet, writeFdSet, CLIENT);
			handleConnection(node, previous, readFdSet, writeFdSet, SERVER);
		}
	}
	// FREE y close de todo?
}

int handleClient(int clntSocket) {
	char buffer[BUFFER_SIZE]; // Buffer for echo string
	// Receive message from client
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFFER_SIZE - 1, 0);
	if (numBytesRcvd < 0) {
		logger(ERROR, "recv() failed", STDERR_FILENO);
		return -1; // TODO definir codigos de error
	}
	buffer[numBytesRcvd] = '\0';

	// Send received string and receive again until end of stream
	while (numBytesRcvd > 0) { // 0 indicates end of stream
		printf("SERVER: received message: %s\n", buffer);
		// Echo message back to client
		ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
		if (numBytesSent < 0) {
			logger(ERROR, "send() failed", STDERR_FILENO);
			return -1; // TODO definir codigos de error
		} else if (numBytesSent != numBytesRcvd) {
			logger(ERROR, "send() sent unexpected number of bytes", STDERR_FILENO);
			return -1; // TODO definir codigos de error
		}

		// See if there is more data to receive
		numBytesRcvd = recv(clntSocket, buffer, BUFFER_SIZE - 1, 0);
		if (numBytesRcvd < 0) {
			logger(ERROR, "recv() failed", STDERR_FILENO);
			return -1; // TODO definir codigos de error
		}
		buffer[numBytesRcvd] = '\0';
	}

	close(clntSocket);
	return 0;
}

static void copyToCircularBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes) {
	for (int j = 0; j < bytes; j++) {
		target[(startIndex + j) % BUFFER_SIZE] = source[j];
	}
}

static void copyToLinearBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes) {
	for (int j = 0; j < bytes; j++) {
		target[j] = source[(startIndex + j) % BUFFER_SIZE];
	}
}

void handleConnection(ConnectionNode *node, ConnectionNode *prev, fd_set readFdSet[FD_SET_ARRAY_SIZE],
					  fd_set writeFdSet[FD_SET_ARRAY_SIZE], enum PEER peer) {
	int operation[2], *bytes[2];
	enum PEER toPeer;
	int fd[2], pos[2];
	char *buffer[2] = {0};

	fd[CLIENT] = node->data.clientSock;
	fd[SERVER] = node->data.serverSock;
	bytes[CLIENT] = &node->data.bytesForServer;
	bytes[SERVER] = &node->data.bytesForClient;
	buffer[CLIENT] = node->data.clientToServerBuffer;
	buffer[SERVER] = node->data.serverToClientBuffer;
	pos[CLIENT] = node->data.clientToServerPos;
	pos[SERVER] = node->data.serverToClientPos;

	switch (peer) {
	case CLIENT:
		toPeer = SERVER;
		break;
	case SERVER:
		toPeer = CLIENT;
		break;
	default:
		// TODO: ERROR
		break;
	}

	if (readFdSet != NULL && FD_ISSET(fd[peer], &readFdSet[TMP])) {
		if (*bytes[peer] < BUFFER_SIZE) {
			operation[READ] = handleOperation(node, prev, fd[peer], buffer[peer], pos[peer], BUFFER_SIZE - (*bytes[peer]), READ);
			if (operation[READ] == -1) {
				// CLOSE CONNECTION
				closeConnection(node, prev, writeFdSet, readFdSet, &connections);
			}
			*bytes[peer] += operation[READ];
			FD_SET(fd[toPeer], &writeFdSet[BASE]);
		}
	}

	if (writeFdSet != NULL && FD_ISSET(fd[peer], &writeFdSet[TMP])) {
		if (*bytes[toPeer] > 0) {
			operation[WRITE] = handleOperation(node, prev, fd[peer], buffer[toPeer], pos[toPeer], *bytes[toPeer], WRITE);
			if (operation[WRITE] == -1) {
				// CLOSE CONNECTION
				closeConnection(node, prev, writeFdSet, readFdSet, &connections);
			}
			*bytes[toPeer] -= operation[WRITE];
			if (*bytes[toPeer] == 0)
				FD_CLR(fd[peer], &writeFdSet[BASE]);
		}
	}
}

size_t handleOperation(ConnectionNode *node, ConnectionNode *prev, int fd, char buffer[BUFFER_SIZE], int pos, size_t bytes,
					   enum OPERATION operation) {
	char auxBuff[BUFFER_SIZE] = {0};
	size_t operationBytes;
	switch (operation) {
	case WRITE:
		copyToLinearBuffer(auxBuff, buffer, pos, bytes);
		operationBytes = send(fd, buffer, bytes, 0);
		if (operationBytes <= 0) {
			if (operationBytes == -1)
				perror("[ERROR] : Error en send() - main() - server.c");

			// TODO: check 0 error?
			return -1;
		}
		break;
	case READ:
		operationBytes = recv(fd, auxBuff, bytes, 0);
		if (operationBytes <= 0) {
			if (operationBytes == -1)
				perror("[ERROR] : Error en recv() - main() - server.c");
			printf("[INFO] : Socket with fd %d closed connection prematurely\n", fd);
			return -1;
		}
		printf("[INFO] : SERVER RECEIVED %s\n", auxBuff);
		copyToCircularBuffer(buffer, auxBuff, pos, operationBytes);
		break;
	default:
		printf("[ERROR] : Unknown operation on Socket with fd %d\n", fd);
		return -1;
		break;
	}
	return operationBytes;
}