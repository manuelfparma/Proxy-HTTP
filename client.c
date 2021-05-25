#include "client.h"
#include "clientutils.h"
#include "logger.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <Host> <Server port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *host = argv[1];
	char *port = argv[2];
	// char *proxyHost = argv[3];
	// char *proxyPort = argv[4];

	char buffer[BUFFER_SIZE];
	char *echoString = "Echo from pepe";
	size_t echoStringLen = strlen(echoString);

	// int proxySock = setupClientSocket(proxyHost, proxyPort);
	int sock = setupClientSocket(host, port);
	if (sock < 0) {
		logger(FATAL, "setupClientSocket() failed", STDERR_FILENO);
	}

	// char proxyHeader[BUFFER_SIZE];
	// sprintf(proxyHeader, "Host:%s ;Port:%s", host, port);
	// size_t headerLength = strlen(proxyHeader);

	ssize_t bytesSent, bytesRecv;
	char *responseBuffer[BUFFER_SIZE];

	// Send the string to the server
	// Receive the same string back from the server
	while (1) {
		bytesSent = send(sock, echoString, echoStringLen, 0);
		printf("CLIENT: sent: %s\n", echoString);
		if (bytesSent < 0)
			logger(FATAL, "send() failed", STDERR_FILENO);
		else if (bytesSent != echoStringLen) {
			close(sock);
			logger(ERROR, "send() sent unexpected number of bytes", STDERR_FILENO);
		}
		bytesRecv = recv(sock, responseBuffer, BUFFER_SIZE - 1, 0);
		if (bytesRecv < 0) {
			close(sock);
			logger(ERROR, "recv() failed", STDERR_FILENO);
		} else if (bytesRecv == 0) {
			close(sock);
			logger(ERROR, "recv() connection closed prematurely", STDERR_FILENO);
		}
		responseBuffer[bytesRecv] = '\0';
		if (strcmp(echoString, responseBuffer) != 0) {
			close(sock);
			logger(ERROR, "response message different than expected", STDERR_FILENO);
		}
		printf("CLIENT: received: %s\n", responseBuffer);
		sleep(3);
	}

	close(sock);
	return 0;
}
