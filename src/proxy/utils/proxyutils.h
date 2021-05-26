//  DEPRECATED
#ifndef _PROXY_UTILS_H_
#define _PROXY_UTILS_H_

#define MAX_PENDING 10
#define MAX_CLIENTS 510
#define BUFFER_SIZE 1024
#define MAX_ADDR_BUFFER 128
// Constantes para acceder a los FdSets, BASE para el persistente, TMP para el que varia con select
#define BASE 0
#define TMP 1
#define FD_SET_ARRAY_SIZE 2

#include "connection.h"
#include <stddef.h>

int setupPassiveSocket(const char *service);

int setupClientSocket(const char *host, const char *service);

int acceptConnection(int passiveSock);

typedef enum { WRITE, READ } OPERATION;
typedef enum { CLIENT, SERVER } PEER;

static void copyToCircularBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes);

static void copyToLinearBuffer(char target[BUFFER_SIZE], char source[BUFFER_SIZE], int startIndex, int bytes);

int handleConnection(ConnectionNode *node, ConnectionNode *prev, fd_set readFdSet[FD_SET_ARRAY_SIZE],
					  fd_set writeFdSet[FD_SET_ARRAY_SIZE], PEER peer);

size_t handleOperation(ConnectionNode *node, ConnectionNode *prev, int fd, char buffer[BUFFER_SIZE], int pos, size_t bytes,
					   OPERATION operation);


#endif