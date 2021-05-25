#ifndef _SERVER_UTILS_H_
#define _SERVER_UTILS_H_

#define MAXPENDING 5 // Maximum outstanding connection requests
#define BUFFER_SIZE 256
#define MAX_ADDR_BUFFER 128

int setupServerSocket(const char *service);
int acceptConnection(int servSock);
int handleClient(int clntSocket);

#endif
