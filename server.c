#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "logger.h"
#include "serverutils.h"

int main(int argc, char ** argv) {
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <Server port>\n", argv[0]);
		exit(EXIT_FAILURE);
    }

    char *service = argv[1];

    int sock = setupServerSocket(service), clientSock;
    if(sock < 0)
        logger(ERROR, "setupServerSocket() failed", STDERR_FILENO);
    
    while(1) {
        if((clientSock = acceptConnection(sock)) < 0)
            logger(ERROR, "acceptConnection() failed", STDERR_FILENO);
        handleClient(clientSock);
    }

}