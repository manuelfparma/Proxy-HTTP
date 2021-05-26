#ifndef _SERVER_UTILS_H_
#define _SERVER_UTILS_H_

#define MAXPENDING 5 // Maximum outstanding connection requests
#define MAX_CLIENTS 510
#define BUFFER_SIZE 1024
#define MAX_ADDR_BUFFER 128
// Constantes para acceder a los FdSets, BASE para el persistente, TMP para el que varia con select
#define BASE 0
#define TMP 1
#define FD_SET_ARRAY_SIZE 2

typedef struct {
	unsigned int clients;
	ConnectionNode *first;
} ConnectionHeader;

typedef struct {
	ConnectionData data;
	ConnectionNode *next;
} ConnectionNode;

typedef struct {
	char *inputBuffer;
	char *outputBuffer;
	int clientFd;		// del lado del cliente (socket activo abierto por conexion al proxy)
	int serverFd;		// del lado del proxy (socket activo abierto por conexion al server)
	int writePos;		// a partir de donde escribir
	int readPos;		// a partir de donde leer
	int bytesToWrite;	// caracteres a escribir
	int bytesToRead;	// caracteres a leer
} ConnectionData;

int setupPassiveSocket(const char *service);

int acceptConnection(int passiveSock);

#endif
