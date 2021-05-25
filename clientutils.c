#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "logger.h"

int setupClientSocket(const char *host, const char *service) {
	// Tell the system what kind(s) of address info we want
	struct addrinfo addrCriteria;                   // Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;         // Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;         // Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int rtnVal = getaddrinfo(host, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) {
		logger(ERROR, "getaddrinfo() failed", STDERR_FILENO);
	}

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