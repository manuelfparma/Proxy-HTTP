#include "proxyutils.h"
#include "../../logger.h"
#include "connection.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupPassiveSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;					// Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;				// Any address family
	addrCriteria.ai_flags = AI_PASSIVE;				// Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;			// Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;			// Only TCP protocol

	struct addrinfo *servAddr; // List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) { logger(FATAL, "getaddrinfo() failed", STDERR_FILENO); }

	int passiveSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio
	// Iteramos por todas las Ips y hacemos el bind por alguna de ellas.
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && passiveSock == -1; addr = addr->ai_next) {
		// Create a TCP socket
		passiveSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (passiveSock < 0) {
			logger(INFO, "socket() failed, trying next address", STDOUT_FILENO);
			continue; // Socket creation failed; try next address
		}
		// Bind to All the address and set socket to listen
		if ((bind(passiveSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(passiveSock, MAX_PENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(passiveSock, (struct sockaddr *)&localAddr, &addrSize) >= 0) {
				logger(INFO, "Binding...", STDERR_FILENO);
			}
		} else {
			logger(INFO, "bind() or listen() failed, trying next address", STDOUT_FILENO);
			close(passiveSock); // Close and try again
			passiveSock = -1;
		}
	}

	// Non blocking socket
	fcntl(passiveSock, F_SETFL, O_NONBLOCK);

	freeaddrinfo(servAddr);

	return passiveSock;
}

int acceptConnection(int passiveSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect
	int clntSock = accept(passiveSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		logger(FATAL, "accept() failed", STDERR_FILENO);
		return -1;
	}

	// Non blocking
	fcntl(clntSock, F_SETFL, O_NONBLOCK);

	// clntSock is connected to a client!
	logger(INFO, "Handling client", STDOUT_FILENO);

	return clntSock;
}

int setupClientSocket(const char *host, const char *service) {
	// Tell the system what kind(s) of address info we want
	struct addrinfo addrCriteria;					// Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;				// v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;			// Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;			// Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) { logger(ERROR, "getaddrinfo() failed", STDERR_FILENO); }

	int sock = -1;
	for (struct addrinfo *addr = servAddr; addr != NULL && sock == -1; addr = addr->ai_next) {
		// Create a reliable, stream socket using TCP
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock >= 0) {
			// Establish the connection to the echo server
			if (connect(sock, addr->ai_addr, addr->ai_addrlen) != 0) {
				logger(INFO, "connect() failed, trying next address", STDOUT_FILENO);
				close(sock); // Socket connection failed; try next address
				sock = -1;
			}
		} else
			logger(INFO, "socket() failed, trying next address", STDOUT_FILENO);
	}

	freeaddrinfo(servAddr);
	return sock;
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

int handleConnection(ConnectionNode *node, ConnectionNode *prev, fd_set readFdSet[FD_SET_ARRAY_SIZE],
					 fd_set writeFdSet[FD_SET_ARRAY_SIZE], PEER peer) {
	int operation[2], *bytes[2], returnValue = 0;
	PEER toPeer;
	int fd[2], *pos[2];
	char *buffer[2] = {0};

	fd[CLIENT] = node->data.clientSock;
	fd[SERVER] = node->data.serverSock;
	bytes[CLIENT] = &node->data.bytesForServer;
	bytes[SERVER] = &node->data.bytesForClient;
	buffer[CLIENT] = node->data.clientToServerBuffer;
	buffer[SERVER] = node->data.serverToClientBuffer;
	pos[CLIENT] = &node->data.clientToServerPos;
	pos[SERVER] = &node->data.serverToClientPos;

	switch (peer) {
		case CLIENT:
			toPeer = SERVER;
			break;
		case SERVER:
			toPeer = CLIENT;
			break;
		default:
			return -2;
	}

	if (readFdSet != NULL && FD_ISSET(fd[peer], &readFdSet[TMP])) {
		if (*bytes[peer] < BUFFER_SIZE) {
			operation[READ] = handleOperation(node, prev, fd[peer], buffer[peer], *pos[peer], BUFFER_SIZE - (*bytes[peer]), READ);
			if (operation[READ] == -1) {
				// CLOSE CONNECTION
				closeConnection(node, prev, writeFdSet, readFdSet);
				return -1;
			} else {
				*bytes[peer] += operation[READ];
				// activo la escritura hacia el otro punto
				FD_SET(fd[toPeer], &writeFdSet[BASE]);
			}
		} else {
			// desactivo la lectura desde este punto
			FD_CLR(fd[peer], &readFdSet[BASE]);
		}
		returnValue++;
	}

	if (writeFdSet != NULL && FD_ISSET(fd[peer], &writeFdSet[TMP])) {
		if (*bytes[toPeer] > 0) {
			operation[WRITE] = handleOperation(node, prev, fd[peer], buffer[toPeer], *pos[toPeer], *bytes[toPeer], WRITE);
			if (operation[WRITE] == -1) {
				// CLOSE CONNECTION
				closeConnection(node, prev, writeFdSet, readFdSet);
				return -1;
			} else {
				*bytes[toPeer] -= operation[WRITE];
				*pos[toPeer] = (operation[WRITE] + *pos[toPeer]) % BUFFER_SIZE;
				// activo la lectura del servidor por si se habia desactivado por buffer lleno
				FD_SET(node->data.serverSock, &readFdSet[BASE]);
				if (*bytes[toPeer] == 0) FD_CLR(fd[peer], &writeFdSet[BASE]);
			}
		}
		returnValue++;
	}

	return returnValue;
}

size_t handleOperation(ConnectionNode *node, ConnectionNode *prev, int fd, char buffer[BUFFER_SIZE], int pos, size_t bytes,
					   OPERATION operation) {
	char auxBuff[BUFFER_SIZE] = {0};
	size_t operationBytes;
	switch (operation) {
		case WRITE:
			copyToLinearBuffer(auxBuff, buffer, pos, bytes);
			operationBytes = send(fd, auxBuff, bytes, 0);
			if (operationBytes <= 0) {
				if (operationBytes == -1) perror("[ERROR] : Error en send() - main() - server.c");

				// TODO: check 0 error?
				return -1;
			}
			break;
		case READ:
			operationBytes = recv(fd, auxBuff, bytes, 0);
			if (operationBytes <= 0) {
				if (operationBytes == -1) perror("[ERROR] : Error en recv() - main() - server.c");
				printf("[INFO] : Socket with fd %d closed connection prematurely\n", fd);
				return -1;
			}
			// debug
			char msg[BUFFER_SIZE + 1];
			strncpy(msg, auxBuff, operationBytes);
			msg[operationBytes] = '\0';
			printf("[INFO] : RECEIVED %s FROM fd %d\n", msg, fd);

			copyToCircularBuffer(buffer, auxBuff, pos + bytes, operationBytes);
			break;
		default:
			printf("[ERROR] : Unknown operation on Socket with fd %d\n", fd);
			return -1;
			break;
	}
	return operationBytes;
}
