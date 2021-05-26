#include "clientutils.h"
#include "logger.h"
#include "serverutils.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <proxy.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void copyToBuffer(char auxBuff[BUFFER_SIZE], int fd, int bytesRecv);
static void closeConnection(int idx, fd_set *writeFdSet, fd_set *readFdSet);

Connection *connections[MAX_CLIENTS];

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
	int clients = 0;

	sigset_t sigMask;
	sigemptyset(&sigMask);
	sigaddset(&sigMask, SIGINT);

	while (1) {

		readFdSet[TMP] = readFdSet[BASE];
		writeFdSet[TMP] = writeFdSet[BASE];

		readyFds = pselect(maxFd, &readFdSet[TMP], &writeFdSet[TMP], NULL, NULL, &sigMask);
		if (readyFds == -1) {
			// FIX ERROR HANDLING
			perror("[ERROR] : Error en pselect() - main() - server.c");
			continue;
		}

		if (FD_ISSET(passiveSock, &readFdSet[TMP])) {
			// abrir conexion
			int activeSockClient = acceptConnection(passiveSock);
            int activeProxySockClient = setupClientSocket(serverHost, serverPort);
			FD_SET(activeSockClient, &readFdSet[BASE]);
			readyFds--;

			// asignacion de recursos para la conexion
			connections[clients] = malloc(sizeof(Connection));
			connections[clients]->clientFd = activeSockClient;
			connections[clients]->inputBuffer = malloc(BUFFER_SIZE * sizeof(char));
			connections[clients]->outputBuffer = malloc(BUFFER_SIZE * sizeof(char));
			connections[clients]->bytesToRead = 0;
			connections[clients]->bytesToWrite = 0;
			connections[clients]->writePos = 0;
			connections[clients]->readPos = 0;
			clients++;

			// actualizacion de FD maximo para select
			if (activeSockClient >= maxFd)
				maxFd = activeSockClient + 1;
		}

		for (int i = 0; readyFds > 0 && i < MAX_CLIENTS; i++) {
			// ver donde hay algo para leer y/o escribir
			if (connections[i] == NULL)
				continue;

			int fd = connections[i]->clientFd;
			if (FD_ISSET(fd, &readFdSet[TMP])) {
				// leer
				int bytesToRead = connections[i]->bytesToRead;
				// si el buffer esta lleno, no puedo recibir el mensaje
				if (bytesToRead < BUFFER_SIZE) {
					// leemos en un buffer lineal auxiliar y lo copiamos al buffer circular global
					char auxBuff[BUFFER_SIZE] = {0};
					int bytesRecv = recv(fd, auxBuff, BUFFER_SIZE - bytesToRead, 0);
					printf("[INFO] : SERVER RECEIVED %s\n", auxBuff);
					if (bytesRecv <= 0) {
						if (bytesRecv == -1)
							perror("[ERROR] : Error en recv() - main() - server.c");
						closeConnection(i, writeFdSet, readFdSet);
						break;
					} else {
						copyToBuffer(auxBuff, i, bytesRecv);
						connections[i]->bytesToRead += bytesRecv;
						FD_SET(fd, &writeFdSet[BASE]);
					}
				}
				readyFds--;
			}

			if (FD_ISSET(fd, &writeFdSet[TMP])) {
				// escribir
				int bytesSent = send(fd, "Echo from pepe", 15, 0);
				printf("[INFO] : SERVER SENT Echo from pepe\n");
				if (bytesSent <= 0) {
					if (bytesSent == -1)
						perror("[ERROR] : Error en send() - main() - server.c");
					closeConnection(i, writeFdSet, readFdSet);
					break;
				} else {
					// connections[i]->bytesToWrite -= bytesSent;
					// if(connections[i]->bytesToWrite == 0)
					FD_CLR(fd, &writeFdSet[BASE]);

					readyFds--;
				}
			}
		}
	}
	// FREE y close de todo?
}

static void copyToBuffer(char auxBuff[BUFFER_SIZE], int fd, int bytesRecv) {
	int i = connections[fd]->readPos + connections[fd]->bytesToRead;
	for (int j = 0; j < bytesRecv; i++, j++) {
		connections[fd]->inputBuffer[i % BUFFER_SIZE] = auxBuff[j];
	}
}

static void closeConnection(int idx, fd_set *writeFdSet, fd_set *readFdSet) {
	int fd = connections[idx]->clientFd;
	printf("[INFO] : Cliente en socket %d desconectado\n", fd);
	free(connections[idx]->inputBuffer);
	free(connections[idx]->outputBuffer);
	free(connections[idx]);
	connections[idx] = NULL;
	FD_CLR(fd, &readFdSet[BASE]);
	FD_CLR(fd, &writeFdSet[BASE]);
	close(fd);
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
