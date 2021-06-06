#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <dohdata.h>
#include <buffer.h>
#include <netdb.h>
#include <parser.h>
#include <pthread.h>
#include <sys/select.h>

// Manejo de estados para getaddrinfo, la cual se corre en otro hilo
// TODO: Cambiar nombre a CONNECTION_STATE, porque usamos CONNECTING y CONNECTED y eso esta por fuera de addrinfo
typedef enum { EMPTY, CONNECTING_TO_DOH, FETCHING, READY, CONNECTING, CONNECTED, DNS_ERROR } ADDR_INFO_STATE;

typedef struct {
	buffer *clientToServerBuffer;			 // buffer donde cliente escribe y servidor lee
	buffer *serverToClientBuffer;			 // buffer donde servidor escribe y cliente lee
	int clientSock;							 // socket activo con cliente
	int serverSock;							 // socket activo con servidor
	http_request *request;					 // estructura donde se guarda el estado del parseo
	ADDR_INFO_STATE addrInfoState;			 // estado de la busqueda DNS //TODO: ESTADO DE LA CONEXION, NO DE LA BUSQUEDA DNS
	doh_data *doh;
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

void close_connection(ConnectionNode *node, ConnectionNode *previous, fd_set *write_fd_set, fd_set *read_fd_set);

#endif
