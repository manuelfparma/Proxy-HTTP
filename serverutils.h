#ifndef _SERVER_UTILS_H_
#define _SERVER_UTILS_H_

#define MAXPENDING 5 // Maximum outstanding connection requests
#define MAX_CLIENTS 1023
#define BUFFER_SIZE 1024
#define MAX_ADDR_BUFFER 128
// Constantes para acceder a los FdSets, BASE para el persistente, TMP para el que varia con select
#define BASE 0
#define TMP 1
#define FD_SET_ARRAY_SIZE 2

typedef struct {
	char *inputBuffer;
	char *outputBuffer;
	int sockFd;
	int writePos;	  // a partir de donde escribir
	int readPos;	  // a partir de donde leer
	int bytesToWrite; // caracteres a escribir
	int bytesToRead;  // caracteres a leer
} Connection;

int setupServerSocket(const char *service);

int acceptConnection(int servSock);

#endif
