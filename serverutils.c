#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include "logger.h"
#include <fcntl.h>
#include "serverutils.h"
#include <stdio.h>

static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupServerSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // Any address family
	addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	struct addrinfo *servAddr; 			// List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		logger(FATAL, "getaddrinfo() failed", STDERR_FILENO);
	}

	int servSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio 
	// Iteramos por todas las Ips y hacemos el bind por alguna de ellas.
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && servSock == -1; addr = addr->ai_next) {
		// Create a TCP socket
		servSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (servSock < 0){
            logger(INFO, "socket() failed, trying next address", STDOUT_FILENO);
			continue;       // Socket creation failed; try next address
        }
		// Bind to All the address and set socket to listen
		if ((bind(servSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(servSock, MAXPENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(servSock, (struct sockaddr *) &localAddr, &addrSize) >= 0) {
				logger(INFO, "Binding...", STDERR_FILENO);
			}
		} else {
            logger(INFO, "bind() or listen() failed, trying next address", STDOUT_FILENO);
			close(servSock);  // Close and try again
			servSock = -1;
		}
	}

    //fcntl(servSock, F_SETFL, O_NONBLOCK);

	freeaddrinfo(servAddr);

	return servSock;
}

int acceptConnection(int servSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);

	// Wait for a client to connect
	int clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		logger(FATAL, "accept() failed", STDERR_FILENO);
		return -1;
	}

	// clntSock is connected to a client!
	logger(INFO, "Handling client", STDOUT_FILENO);

	return clntSock;
}

int handleClient(int clntSocket) {
	char buffer[BUFFER_SIZE]; // Buffer for echo string
	// Receive message from client
	ssize_t numBytesRcvd = recv(clntSocket, buffer, BUFFER_SIZE - 1, 0);
	if (numBytesRcvd < 0) {
		logger(ERROR, "recv() failed", STDERR_FILENO);
		return -1;   // TODO definir codigos de error
	}
    buffer[numBytesRcvd] = '\0';

	// Send received string and receive again until end of stream
	while (numBytesRcvd > 0) { // 0 indicates end of stream
		printf("SERVER: received message: %s\n", buffer);
		// Echo message back to client
		ssize_t numBytesSent = send(clntSocket, buffer, numBytesRcvd, 0);
		if (numBytesSent < 0) {
			logger(ERROR, "send() failed", STDERR_FILENO);
			return -1;   // TODO definir codigos de error
		}
		else if (numBytesSent != numBytesRcvd) {
			logger(ERROR, "send() sent unexpected number of bytes", STDERR_FILENO);
			return -1;   // TODO definir codigos de error
		}

		// See if there is more data to receive
		numBytesRcvd = recv(clntSocket, buffer, BUFFER_SIZE - 1, 0);
		if (numBytesRcvd < 0) {
			logger(ERROR, "recv() failed", STDERR_FILENO);
			return -1;   // TODO definir codigos de error
		}
        buffer[numBytesRcvd] = '\0';
	}

	close(clntSocket);
	return 0;
}
