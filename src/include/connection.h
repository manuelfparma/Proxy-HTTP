#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "buffer.h"
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>

// Manejo de estados para getaddrinfo, la cual se corre en otro hilo
typedef enum { EMPTY, FETCHING, READY, CONNECTING, CONNECTED } ADDR_INFO_STATE;

typedef enum {
	METHOD,				// GET, POST, OPTION
	REQUEST_TARGET, 	// puede ser http://XXXX (absoluteURI) o /index.html (relative)
	HTTP_VERSION,		// por ej: ' HTTP/1.1 \r\n'
	HEADER_TYPE,		// por ej: 'Host: ' -> CASE INSENSITIVE
	HEADER_VALUE,		// por ej: 'google.com\r\n'
	HEADER_HOST_VALUE,	// el valor del header host
	NO_MORE_HEADERS		// estado final
} PARSE_STATE;

typedef struct {
	PARSE_STATE parse_state;			// estado actual de la maquina de estados
	unsigned long current_index;		// indice donde estoy leyendo actualmente
} parser_data;

typedef struct {
	buffer *clientToServerBuffer;		// buffer donde cliente escribe y servidor lee
	buffer *serverToClientBuffer;		// buffer donde servidor escribe y cliente lee
	int clientSock;						// socket activo con cliente
	int serverSock;						// socket activo con servidor
	parser_data *parser;			// estado del parseo de la request/response
	ADDR_INFO_STATE addrInfoState;		// estado de la busqueda DNS
	pthread_t addrInfoThread;			// informacion del thread donde corre la resolución DNS
	struct addrinfo *addr_info_header;	// para guardar el inicio de la lista del resultado de la consulta DNS
	struct addrinfo *addr_info_current; // para guardar el ultimo nodo con el que se intento conectar
} ConnectionData;

typedef struct ConnectionNode {
	ConnectionData data;
	struct ConnectionNode *next;
} ConnectionNode;

typedef struct {
	unsigned int clients;
	int maxFd;
	ConnectionNode *first;
} ConnectionHeader;

ConnectionNode *setupConnectionResources(int clientSock, int serverSock);

void addToConnections(ConnectionNode *node);

void closeConnection(ConnectionNode *node, ConnectionNode *previous, fd_set *writeFdSet, fd_set *readFdSet);

#endif
