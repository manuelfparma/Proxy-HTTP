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

int setupPassiveSocket(const char *service);

int setupClientSocket(const char *host, const char *service);

int acceptConnection(int passiveSock);

#endif