#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <buffer.h>
#include <connection.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netdb.h>
#include <parser.h>
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

// funcion que rsuelve consulta DNS  asincronicamente
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

	logger(DEBUG, "hostname:%s, port:%s", host, service);

	// Get address(es)
	struct addrinfo *servAddr; // Holder for returned list of server addrs
	int addrInfoResult = getaddrinfo(host, service, &addrCriteria, &servAddr);
	pthread_t aux_main_pthread_id = *main_thread_id;

	if (addrInfoResult != 0) {
		logger(ERROR, "getaddrinfo(): %s", strerror(errno));
		free(host);
		free(service);
		free(threadArgs);
		free(main_thread_id);
		// freeaddrinfo(servAddr);
		node->data.addrInfoState = DNS_ERROR;
		pthread_kill(aux_main_pthread_id, SIGIO);
		return NULL;
	}

	node->data.addr_info_current = node->data.addr_info_header = servAddr;

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

int handle_server_connection(ConnectionNode *node, ConnectionNode *prev, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {

	int fd_server = node->data.serverSock;
	int fd_client = node->data.clientSock;
	int return_value = 0;
	size_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_server, &read_fd_set[TMP])) {
		loggerPeer(SERVER, "Trying to read from fd %d", fd_server);

		if (buffer_can_write(node->data.serverToClientBuffer)) {
			result_bytes = handle_operation(fd_server, node->data.serverToClientBuffer, READ);
			if (result_bytes <= 0) {
				loggerPeer(SERVER, "Close connection for server_fd: %d and client_fd: %d, READ operation", fd_server, fd_client);
				return -1;
			} else {
				// Se escribio algo en el buffer, activo la escritura hacia el cliente
				if (fd_client != -1) { FD_SET(fd_client, &write_fd_set[BASE]); }
			}
		} else {
			loggerPeer(SERVER, "Server with fd: %d has buffer full", fd_server);
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd_server, &read_fd_set[BASE]);
		}
		return_value++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (write_fd_set != NULL && FD_ISSET(fd_server, &write_fd_set[TMP])) {
		loggerPeer(SERVER, "Trying to write to fd %d", fd_server);

		if (node->data.addrInfoState == CONNECTING) {
			socklen_t optlen = sizeof(int);
			// chequeamos el estado del socket
			int ans = getsockopt(fd_server, SOL_SOCKET, SO_ERROR, &(int){1}, &optlen);
			if (ans <= -1) {
				// en caso de error, chequear la señal, si la conexion fue rechazada, probar con la siguiente
				if (errno == ECONNREFUSED) {
					node->data.addr_info_current = node->data.addr_info_current->ai_next;
					if (setup_connection(node, write_fd_set) == -1) {
						logger(ERROR, "setup_connection(): %d", errno);
						// FIXME: ?????
						return -1;
					}
				} else {
					// error de getsockopt, saco el socket de prueba
					logger(ERROR, "getsockopt(): %s", strerror(errno));
					FD_CLR(fd_server, &write_fd_set[BASE]);
					return -1;
				}
			} else {
				loggerPeer(SERVER, "Connected to server for client with fd %d", node->data.clientSock);
				node->data.addrInfoState = CONNECTED;
				freeaddrinfo(node->data.addr_info_header);
				node->data.addr_info_current = node->data.addr_info_header = NULL;
				// en caso que el server mande un primer mensaje, quiero leerlo
				FD_SET(fd_server, &read_fd_set[BASE]);
			}
		}

		if (buffer_can_read(node->data.request->parsed_request)) {
			result_bytes = handle_operation(fd_server, node->data.request->parsed_request, WRITE);
			if (result_bytes <= 0) {
				loggerPeer(SERVER, "Close connection for server_fd: %d and client_fd: %d, WRITE operation", fd_server, fd_client);
				return -1;
			} else {
				// ahora que el buffer de entrada tiene espacio, intento leer del otro par
				FD_SET(fd_client, &read_fd_set[BASE]);

				// si el buffer de salida se vacio, no nos interesa intentar escribir
				if (!buffer_can_read(node->data.request->parsed_request)) FD_CLR(fd_server, &write_fd_set[BASE]);
			}
		} else {
			FD_CLR(fd_server, &write_fd_set[BASE]);
		}
		return_value++;
	}

	return return_value;
}

int handle_client_connection(ConnectionNode *node, ConnectionNode *prev, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	int fd_server = node->data.serverSock;
	int fd_client = node->data.clientSock;
	int return_value = 0;
	ssize_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_client, &read_fd_set[TMP])) {
		loggerPeer(CLIENT, "Trying to read from fd %d", fd_client);
		if (buffer_can_write(node->data.clientToServerBuffer)) {
			result_bytes = handle_operation(fd_client, node->data.clientToServerBuffer, READ);
			if (result_bytes < 0) {
				loggerPeer(CLIENT, "Close connection for server_fd: %d and client_fd: %d, READ operation", fd_server, fd_client);
				return -1;
			} else if (result_bytes == 0) {
				loggerPeer(CLIENT, "client_fd: %d request sent completed", fd_client);
				FD_CLR(fd_client, &read_fd_set[BASE]);
			} else { // Si pudo leer algo, ahora debe ver si puede escribir al otro peer (siempre y cuando este seteado)
				parse_request(node->data.request, node->data.clientToServerBuffer);

				if (node->data.addrInfoState == EMPTY) {
					if (node->data.request->request_target_status == UNSOLVED) {
						logger(DEBUG, "Request target not solved yet");
						return 1;
					}

					node->data.addrInfoState = FETCHING;
					// creo los recursos para la resolucion DNS mediante thread nuevo
					ThreadArgs *args = malloc(sizeof(ThreadArgs));
					if (args == NULL) {
						logger(ERROR, "malloc(): %s", strerror(errno));
						return -1; // TODO: ???????
					}

					args->host = malloc(1024 * sizeof(char));
					args->service = malloc(5 * sizeof(char));
					args->main_thread_id = malloc(10 * sizeof(char));
					args->connection = malloc(sizeof(ConnectionNode));

					// seteo los argumentos necesarios para conectarse al server
					switch (node->data.request->start_line.destination.host_type) {
						case IPV4:
						case IPV6:
							strcpy(args->host, node->data.request->start_line.destination.request_target.ip_addr);
							break;
						case DOMAIN:
							strcpy(args->host, node->data.request->start_line.destination.request_target.host_name);
							break;
						default:
							logger(ERROR, "Undefined domain type");
					}

					strcpy(args->service, node->data.request->start_line.destination.port);
					*args->main_thread_id = pthread_self();
					args->connection = node;
					pthread_t thread;

					int ret = pthread_create(&thread, NULL, resolve_addr, (void *)args);
					if (ret != 0) {
						logger(ERROR, "pthread_create(): %s", strerror(errno));
						return -1; // TODO: ?????
					}
				}
				// Si el parser cargo algo y el servidor esta seteado, activamos la escritura al origin server
				if (buffer_can_read(node->data.request->parsed_request) && fd_server != -1) {
					FD_SET(fd_server, &write_fd_set[BASE]);
				}
			}
		} else {
			loggerPeer(CLIENT, "Client with fd: %d has buffer full", fd_server);
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd_client, &read_fd_set[BASE]);
		}
		return_value++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (write_fd_set != NULL && FD_ISSET(fd_client, &write_fd_set[TMP])) {
		loggerPeer(CLIENT, "Trying to write to fd %d", fd_client);
		if (buffer_can_read(node->data.serverToClientBuffer)) {
			char aux_buffer[BUFFER_SIZE] = {0};
			strncpy(aux_buffer, (char *)node->data.serverToClientBuffer->read,
					(size_t)(node->data.serverToClientBuffer->write - node->data.serverToClientBuffer->read));
			fprintf(node->data.file, "-------------------------------------------------\n");
			fprintf(node->data.file, "%s\n", aux_buffer);

			result_bytes = handle_operation(fd_client, node->data.serverToClientBuffer, WRITE);
			if (result_bytes <= 0) {
				loggerPeer(CLIENT, "Close connection for server_fd: %d and client_fd: %d, WRITE operation", fd_server, fd_client);
				return -1;
			} else {
				// ahora que el buffer de entrada tiene espacio, intento leer del otro par
				FD_SET(fd_server, &read_fd_set[BASE]);

				// si el buffer de salida se vacio, no nos interesa intentar escribir
				if (!buffer_can_read(node->data.serverToClientBuffer)) FD_CLR(fd_client, &write_fd_set[BASE]);
			}
		}
		return_value++;
	}
	return return_value;
}

int setup_connection(ConnectionNode *node, fd_set *writeFdSet) {
	if (node->data.addr_info_current == NULL) {
		logger(INFO, "No more addresses for client with fd %d", node->data.clientSock);
		// FIXME: Liberar cliente
		return -1;
	}
	if (node->data.serverSock != -1) FD_CLR(node->data.serverSock, &writeFdSet[BASE]);
	node->data.serverSock = socket(node->data.addr_info_current->ai_family, node->data.addr_info_current->ai_socktype,
								   node->data.addr_info_current->ai_protocol);

	if (node->data.serverSock >= 0) {
		// configuracion para socket no bloqueante
		if (fcntl(node->data.serverSock, F_SETFL, O_NONBLOCK) == -1) {
			logger(INFO, "fcntl(): %s", strerror(errno));
			// FIXME: PEPE???
			return -1;
		}

		if (node->data.serverSock >= connections.maxFd) connections.maxFd = node->data.serverSock + 1;

		struct addrinfo aux_addr_info = *node->data.addr_info_current;
		// Intento de connect
		logger(INFO, "Trying to connect to server from client with fd: %d", node->data.clientSock);
		if (connect(node->data.serverSock, aux_addr_info.ai_addr, aux_addr_info.ai_addrlen) != 0 && errno != EINPROGRESS) {
			logger(ERROR, "connect(): %s", strerror((errno)));
			// FIXME: QUE PASA CON EL CLIENTE MALLOQUEADO?
			close(node->data.serverSock);
			close(node->data.clientSock);
			return -1;
		} else {
			// una vez conectado, liberamos la lista
			logger(INFO, "Connecting to server from client with fd: %d", node->data.clientSock);
			node->data.addrInfoState = CONNECTING;
			// TODO: lista de estadisticas
			// el cliente puede haber escrito algo y el proxy crear la conexion despues, por lo tanto
			// agrego como escritura el fd activo
			FD_SET(node->data.serverSock, &writeFdSet[BASE]);
		}
	} else {
		logger(INFO, "Socket() failed");
		// FIXME: OCTA ARREGLAME
		return -1;
	}
	return 0;
}

// Leer o escribir a un socket
ssize_t handle_operation(int fd, buffer *buffer, OPERATION operation) {
	ssize_t resultBytes;
	ssize_t bytesToSend;
	switch (operation) {
		case WRITE: // escribir a un socket
			bytesToSend = buffer->write - buffer->read;
			resultBytes = send(fd, buffer->read, bytesToSend, 0);
			if (resultBytes <= 0) {
				if (resultBytes == -1) logger(ERROR, "send(): %s", strerror(errno));
			} else {
				// TODO pasar a arreglo auxiliar (con strncpy)
				logger(INFO, "Sent info on fd: %d", fd);
				buffer_read_adv(buffer, resultBytes);
			}
			break;
		case READ: // leer de un socket
			resultBytes = recv(fd, buffer->write, buffer->limit - buffer->write, 0);
			if (resultBytes <= 0) {
				if (resultBytes == -1 && errno != EWOULDBLOCK) {
					logger(ERROR, "recv(): %s", strerror(errno));
					return -1;
				}
			} else {
				// TODO pasar a arreglo auxiliar (con strncpy)
				logger(INFO, "Received info on fd: %d", fd);
				buffer_write_adv(buffer, resultBytes);
			}
			break;
		default:
			logger(ERROR, "Unknown operation on socket with fd: %d", fd);
			resultBytes = -1;
	}

	return resultBytes;
}
