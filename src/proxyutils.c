#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <buffer.h>
#include <connection.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netdb.h>
#include <proxyutils.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern ConnectionHeader connections;

// static char addrBuffer[MAX_ADDR_BUFFER];
/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setupPassiveSocket(const char *service) {
	// Construct the server address structure
	struct addrinfo addrCriteria;					// Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;				// Any address family
	addrCriteria.ai_flags = AI_PASSIVE;				// Accept on any address/port
	addrCriteria.ai_socktype = SOCK_STREAM;			// Only stream sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;			// Only TCP protocol

	struct addrinfo *servAddr; // List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &addrCriteria, &servAddr);
	if (rtnVal != 0) logger(FATAL, "getaddrinfo(): %s", strerror(errno));

	int passiveSock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio
	// Iteramos por todas las Ips y hacemos el bind por alguna de ellas.
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = servAddr; addr != NULL && passiveSock == -1; addr = addr->ai_next) {
		// Create a TCP socket
		passiveSock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (passiveSock < 0) {
			logger(INFO, "socket() failed, trying next address");
			continue; // Socket creation failed; try next address
		}

		if (setsockopt(passiveSock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
			logger(INFO, "setsockopt(): %s", strerror(errno));
			continue;
		}
		// Non blocking socket
		if (fcntl(passiveSock, F_SETFL, O_NONBLOCK) == -1) {
			logger(INFO, "fcntl(): %s", strerror(errno));
			continue;
		}
		// Bind to All the address and set socket to listen
		if ((bind(passiveSock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(passiveSock, MAX_PENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage localAddr;
			socklen_t addrSize = sizeof(localAddr);
			if (getsockname(passiveSock, (struct sockaddr *)&localAddr, &addrSize) >= 0) {
				logger(INFO, "Binding and listening...");
			}
		} else {
			logger(INFO, "bind() or listen() failed, trying next address");
			close(passiveSock); // Close and try again
			passiveSock = -1;
		}
	}

	freeaddrinfo(servAddr);
	return passiveSock;
}

int acceptConnection(int passiveSock) {
	struct sockaddr_storage clntAddr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clntAddrLen = sizeof(clntAddr);
	// Wait for a client to connect
	int clntSock = accept(passiveSock, (struct sockaddr *)&clntAddr, &clntAddrLen);
	if (clntSock < 0) {
		logger(ERROR, "accept(): %s", strerror(errno));
		return -1;
	}
	// Non blocking
	fcntl(clntSock, F_SETFL, O_NONBLOCK);
	// clntSock is connected to a client!
	logger(INFO, "Handling client with socket fd: %d", clntSock);
	return clntSock;
}

// function that setups active socket to connect to server peer
void *resolve_addr(void *args) {
	ThreadArgs *threadArgs = (ThreadArgs *)args;
	char *host = threadArgs->host;
	char *service = threadArgs->service;
	pthread_t *main_thread_id = threadArgs->main_thread_id;
	ConnectionNode *node = threadArgs->connection;

	// asigno al nodo el ID del thread
	node->data.addrInfoThread = pthread_self();

	// Tell the system what kind(s) of address info we want
	struct addrinfo addrCriteria;					// Criteria for address match
	memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
	addrCriteria.ai_family = AF_UNSPEC;				// v4 or v6 is OK
	addrCriteria.ai_socktype = SOCK_STREAM;			// Only streaming sockets
	addrCriteria.ai_protocol = IPPROTO_TCP;			// Only TCP protocol

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int addrInfoResult = getaddrinfo(host, service, &addrCriteria, &servAddr);
	if (addrInfoResult != 0) {
		logger(ERROR, "getaddrinfo(): %s", strerror(errno));
		free(host);
		free(service);
		free(threadArgs);
		freeaddrinfo(servAddr);
		return NULL;
	}

	node->data.addr_info_current = node->data.addr_info_header = servAddr;

	pthread_t aux_main_pthread_id = *main_thread_id;
	free(host);
	free(service);
	free(main_thread_id);
	free(threadArgs);

	// seteamos el cliente como listo
	node->data.addrInfoState = READY;

	// despertamos pselect con una señal
	logger(INFO, "Thread ended");
	pthread_kill(aux_main_pthread_id, SIGIO);

	return NULL;
}

// funcion modular para manejar una operación sobre una conexión, tomando un lado (peer) en particular
int handleConnection(ConnectionNode *node, ConnectionNode *prev, fd_set readFdSet[FD_SET_ARRAY_SIZE],
					 fd_set writeFdSet[FD_SET_ARRAY_SIZE], PEER peer) {
	size_t resultBytes[2];
	int returnValue = 0, fd[2];
	PEER toPeer;
	buffer *aux_buffer[2];

	fd[CLIENT] = node->data.clientSock;
	fd[SERVER] = node->data.serverSock;

	aux_buffer[CLIENT] = node->data.clientToServerBuffer;
	aux_buffer[SERVER] = node->data.serverToClientBuffer;

	switch (peer) {
		case CLIENT:
			toPeer = SERVER;
			break;
		case SERVER:
			toPeer = CLIENT;
			break;
		default:
			return -2;
	}
	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (readFdSet != NULL && FD_ISSET(fd[peer], &readFdSet[TMP])) {

		if (buffer_can_write(aux_buffer[peer])) {
			resultBytes[READ] = handleOperation(fd[peer], aux_buffer[peer], READ);
			if (resultBytes[READ] <= 0) {
				closeConnection(node, prev, writeFdSet, readFdSet);
				logger(INFO, "handleOperation() READ with no bytes in fd: %d", fd[peer]);
				return -1;
			} else { // Si pudo leer algo, ahora debe ver si puede escribir al otro peer (siempre y cuando este seteado)
				if (node->data.addrInfoState == EMPTY) {
					logger(INFO, "fetching addr");
					node->data.addrInfoState = FETCHING;
					// hacemos la consulta dns
					// creo los recursos para la resolucion DNS mediante thread nuevo
					ThreadArgs *args = malloc(sizeof(ThreadArgs));
					if (args == NULL) {
						logger(ERROR, "malloc(): %s", strerror(errno));
						return -1; // TODO: ???????
					}

					// TODO: PARSEAR REQUEST DEL CLIENTE. HARDCODEADO POR AHORA
					args->host = malloc(1024 * sizeof(char));
					args->service = malloc(5 * sizeof(char));
					args->main_thread_id = malloc(10 * sizeof(char));
					args->connection = malloc(sizeof(ConnectionNode));
					// seteo los argumentos necesarios para conectarse al server
					strcpy(args->host, "localhost");
					strcpy(args->service, "9090");
					*args->main_thread_id = pthread_self();
					args->connection = node;

					pthread_t thread;
					int ret = pthread_create(&thread, NULL, resolve_addr, (void *)args);
					if (ret != 0) {
						logger(ERROR, "pthread_create(): %s", strerror(errno));
						return -1; // TODO: ?????
					}
				}
				if (fd[toPeer] != -1) { FD_SET(fd[toPeer], &writeFdSet[BASE]); }
			}
		} else {
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd[peer], &readFdSet[BASE]);
		}
		returnValue++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (writeFdSet != NULL && FD_ISSET(fd[peer], &writeFdSet[TMP])) {
		if (buffer_can_read(aux_buffer[toPeer])) {
			resultBytes[WRITE] = handleOperation(fd[peer], aux_buffer[toPeer], WRITE);
			if (resultBytes[WRITE] <= 0) {
				closeConnection(node, prev, writeFdSet, readFdSet);
				logger(INFO, "handleOperation() WRITE with no bytes in fd: %d", fd[toPeer]);
				return -1;
			} else {
				// ahora que el buffer de entrada tiene espacio, intento leer del otro par
				FD_SET(fd[toPeer], &readFdSet[BASE]);

				// si el buffer de salida se vacio, no nos interesa intentar escribir
				if (!buffer_can_read(aux_buffer[toPeer])) FD_CLR(fd[peer], &writeFdSet[BASE]);
			}
		}
		returnValue++;
	}

	return returnValue;
}

// Leer o escribir a un socket
size_t handleOperation(int fd, buffer *buffer, OPERATION operation) {
	ssize_t resultBytes;
	size_t bytesToSend;
	switch (operation) {
		case WRITE: // escribir a un socket
			bytesToSend = buffer->write - buffer->read;
			resultBytes = send(fd, buffer->read, bytesToSend, 0);
			if (resultBytes <= 0) {
				if (resultBytes == -1) logger(ERROR, "send(): %s", strerror(errno));
			} else {
				// TODO pasar a arreglo auxiliar (con strncpy)
				logger(INFO, "Sended info on fd: %d", fd);
				// loggerPeer(SERVER, "Sended %s to fd %d", buffer->read, fd);
				buffer_read_adv(buffer, resultBytes);
			}
			break;
		case READ: // leer de un socket
			resultBytes = recv(fd, buffer->write, buffer->limit - buffer->write, 0);
			if (resultBytes <= 0) {
				if (resultBytes == -1) logger(ERROR, "recv(): %s", strerror(errno));
				logger(INFO, "Socket with fd %d: %s", fd, strerror(errno));
			} else {
				// TODO pasar a arreglo auxiliar (con strncpy)
				logger(INFO, "Received info on fd: %d", fd);
				// loggerPeer(SERVER, "Received %s from fd %d", buffer->write, fd)
				buffer_write_adv(buffer, resultBytes);
			}
			break;
		default:
			logger(ERROR, "Unknown operation on socket with fd: %d", fd);
			resultBytes = -1;
	}

	return resultBytes;
}
