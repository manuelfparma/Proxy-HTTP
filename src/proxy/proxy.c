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

static enum OPERATION { WRITE, READ };
static enum PEER { CLIENT, SERVER };
static void copyToCircularBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes);
static void copyToLinearBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes);
void handleConnection(ConnectionNode *node, ConnectionNode *prev, fd_set readFdSet[FD_SET_ARRAY_SIZE],
					  fd_set writeFdSet[FD_SET_ARRAY_SIZE], enum PEER peer);
size_t handleOperation(ConnectionNode *node, ConnectionNode *prev, int fd, char buffer[BUFFER_SIZE], int pos, size_t bytes,
					   enum OPERATION operation);

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
			//activo la escritura hacia el otro punto
			FD_SET(fd[toPeer], &writeFdSet[BASE]);
		}else{
			//desactivo la lectura desde este punto
			FD_CLR(fd[peer], &readFdSet[BASE]);
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
			pos[toPeer] = (operation[WRITE] + pos[toPeer]) % BUFFER_SIZE;
			//activo la lectura del servidor por si se habia desactivado por buffer lleno
			FD_SET(node->data.serverSock, &readFdSet[BASE]);
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
			operationBytes = send(fd, auxBuff, bytes, 0);
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
			//debug
			char msg[BUFFER_SIZE+1];
			strncpy(msg, auxBuff, operationBytes);
			msg[operationBytes] = '\0';
			printf("[INFO] : RECEIVED %s FROM fd %d\n", msg, fd);
			
			copyToCircularBuffer(buffer, auxBuff, pos, operationBytes);
			break;
		default:
			printf("[ERROR] : Unknown operation on Socket with fd %d\n", fd);
			return -1;
			break;
	}
	return operationBytes;
}