#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <buffer.h>
#include <connection.h>
#include <dohclient.h>
#include <dohutils.h>
#include <errno.h>
#include <fcntl.h>
#include <http_parser.h>
#include <logger.h>
#include <netdb.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern ConnectionHeader connections;

static void send_parse_error(int fd_client, ConnectionNode *node) {
	// TODO: CAMBIAR A SEND CUANDO SE BORREN LOS LOGS
	logger(INFO, "Connection established");
	char *response = "HTTP/1.1 400 Bad Request\r\n\r\n";
	buffer *buffer_response;
	buffer_response = malloc(sizeof(buffer));
	buffer_response->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	buffer_init(buffer_response, BUFFER_SIZE, buffer_response->data);
	strncpy((char *)buffer_response->write, response, strlen(response));
	buffer_write_adv(buffer_response, strlen(response));
	ssize_t result_bytes = handle_operation(fd_client, buffer_response, WRITE, CLIENT, node->data.file);
	if (result_bytes <= 0) logger(ERROR, "Invalid request from client with fd: %d", fd_client);

	free(buffer_response->data);
	free(buffer_response);

	buffer_reset(node->data.clientToServerBuffer); // por si quedaron cosas sin parsear del request
}

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
	logger(DEBUG, "Created active socket for client with fd: %d", clntSock);
	return clntSock;
}

int handle_server_connection(ConnectionNode *node, ConnectionNode *prev, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {

	int fd_server = node->data.serverSock;
	int fd_client = node->data.clientSock;
	int return_value = 0;
	ssize_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_server, &read_fd_set[TMP])) {
		loggerPeer(SERVER, "Trying to read from fd %d", fd_server);

		if (buffer_can_write(node->data.serverToClientBuffer)) {
			result_bytes = handle_operation(fd_server, node->data.serverToClientBuffer, READ, SERVER, node->data.file);
			if (result_bytes < 0) {
				// loggerPeer(SERVER, "Close connection for server_fd: %d and client_fd: %d, READ operation", fd_server,
				// fd_client); return -1; TODO: FIX!
			} else if (result_bytes == 0) {
				// server quiere cerrar la conexion
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

		// TODO: Modularizar esta seccion
		if (node->data.addrInfoState == CONNECTING) {
			socklen_t optlen = sizeof(int);

			// chequeamos el estado del socket
			if (getsockopt(fd_server, SOL_SOCKET, SO_ERROR, &(int){1}, &optlen) < 0) {

				// en caso de error, ver si la conexion fue rechazada, cerrar el socket y probar con la siguiente
				if (errno == ECONNREFUSED) {
					node->data.doh->addr_info_current = node->data.doh->addr_info_current->next;

					FD_CLR(node->data.serverSock, &write_fd_set[BASE]);
					close(node->data.serverSock);

					// TODO: Si esto falla, liberar todo, no sabemos como tratarlo
					if (setup_connection(node, write_fd_set) == -1) {
						logger(ERROR, "handle_server_connection :: setup_connection(): %s", strerror(errno));
						// FIXME: ?????
						free_doh_resources(node->data.doh);

						return -1;
					}
				} else {
					// error de getsockopt, saco el socket de prueba
					logger(ERROR, "handle_server_connection :: getsockopt(): %s", strerror(errno));
					FD_CLR(fd_server, &write_fd_set[BASE]);
					// TODO: Manejo de errores - liberar recursos?
					close(node->data.serverSock);
					return -1;
				}
			} else {
				loggerPeer(SERVER, "Connected to server with fd %d for client with fd %d", node->data.serverSock,
						   node->data.clientSock);
				node->data.addrInfoState = CONNECTED;
				free_doh_resources(node->data.doh);
				// en caso que el server mande un primer mensaje, quiero leerlo
				FD_SET(fd_server, &read_fd_set[BASE]);
				if (node->data.parser->data.request_status != PARSE_CONNECT_METHOD) {
					// ya que estoy conectado, me fijo si quedo algo para parsear
					parse_request(node->data.parser, node->data.clientToServerBuffer);
					if (node->data.parser->data.parser_state == PS_ERROR) {
						send_parse_error(fd_client, node);
						return -1; // fix codigo de error
					}

				} else {
					// enviamos al cliente que nos conectamos satisfactoriamente al servidor
					// TODO: CAMBIAR A SEND CUANDO SE BORREN LOS LOGS
					logger(INFO, "Connection established");
					char *response_connect_method = "HTTP/1.1 200 Connection Established\r\n\r\n";
					buffer *buffer_response;
					buffer_response = malloc(sizeof(buffer));
					buffer_response->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
					buffer_init(buffer_response, BUFFER_SIZE, buffer_response->data);
					strncpy((char *)buffer_response->write, response_connect_method, strlen(response_connect_method));
					buffer_write_adv(buffer_response, strlen(response_connect_method));
					result_bytes = handle_operation(fd_client, buffer_response, WRITE, CLIENT, node->data.file);
					if (result_bytes <= 0) logger(ERROR, "Couldnt send connection established to client with fd: %d", fd_client);

					free(buffer_response->data);
					free(buffer_response);

					buffer_reset(node->data.clientToServerBuffer); // por si quedaron cosas sin parsear del request
				}
			}
		}

		if (node->data.parser->data.request_status != PARSE_CONNECT_METHOD) {
			if (buffer_can_read(node->data.parser->data.parsed_request)) {

				result_bytes =
					handle_operation(fd_server, node->data.parser->data.parsed_request, WRITE, SERVER, node->data.file);
				if (result_bytes <= 0) {
					loggerPeer(SERVER, "Close connection for server_fd: %d and client_fd: %d, WRITE operation", fd_server,
							   fd_client);
					return -1;
				} else {
					// ahora que el buffer de entrada tiene espacio, intento leer del otro par
					FD_SET(fd_client, &read_fd_set[BASE]);
					// si el buffer de salida se vacio, no nos interesa intentar escribir
					if (!buffer_can_read(node->data.parser->data.parsed_request)) FD_CLR(fd_server, &write_fd_set[BASE]);
				}
			} else {
				FD_CLR(fd_server, &write_fd_set[BASE]);
			}
		} else {
			if (buffer_can_read(node->data.clientToServerBuffer)) {

				result_bytes = handle_operation(fd_server, node->data.clientToServerBuffer, WRITE, SERVER, node->data.file);
				if (result_bytes < 0) {
					// loggerPeer(SERVER, "Close connection for server_fd: %d and client_fd: %d, WRITE operation", fd_server,
					//    fd_client);
					// return -1; TODO: FIX!
				} else if (result_bytes == 0) {
					// por alguna razon no le llego nada, paso la iteracion y el pselect se levantara cuando este disponible para
					// recibirlo
				} else {
					// ahora que el buffer de entrada tiene espacio, intento leer del otro par
					FD_SET(fd_client, &read_fd_set[BASE]);
					// si el buffer de salida se vacio, no nos interesa intentar escribir
					if (!buffer_can_read(node->data.clientToServerBuffer)) FD_CLR(fd_server, &write_fd_set[BASE]);
				}
			} else {
				FD_CLR(fd_server, &write_fd_set[BASE]);
			}
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
			result_bytes = handle_operation(fd_client, node->data.clientToServerBuffer, READ, CLIENT, node->data.file);
			if (result_bytes < 0) {
				loggerPeer(CLIENT, "Close connection for server_fd: %d and client_fd: %d, READ operation", fd_server, fd_client);
				// return -1;
			} else if (result_bytes == 0) {
				loggerPeer(CLIENT, "client_fd: %d request sent completed", fd_client);
				FD_CLR(fd_client, &read_fd_set[BASE]);
			} else { // Si pudo leer algo, ahora debe ver si puede escribir al otro peer (siempre y cuando este seteado)
				if (node->data.parser->data.request_status != PARSE_CONNECT_METHOD) {
					parse_request(node->data.parser, node->data.clientToServerBuffer);
					if (node->data.parser->data.parser_state == PS_ERROR) {
						send_parse_error(fd_client, node);
						return -1;
					}
					if (node->data.addrInfoState == EMPTY) {
						if (node->data.parser->data.target_status == NOT_FOUND) {
							logger(DEBUG, "Request target not solved yet");
							return 1;
						}

						// seteo los argumentos necesarios para conectarse al server
						switch (node->data.parser->request.target.host_type) {
							case IPV4:
							case IPV6:
								// strcpy(args->host, node->data.request->start_line.destination.request_target.ip_addr);
								// TODO: aca no hace falta hacer DoH, ya tenemos la IP
								break;
							case DOMAIN:
								// TODO: Obtener doh addr, hostname y port de args
								if (connect_to_doh_server(node, &write_fd_set[BASE], "127.0.0.1", "8053") == -1) {
									logger(ERROR, "connect_to_doh_server(): error while connecting to DoH. %s", strerror(errno));
									return -1;
								}
								break;
							default:
								logger(ERROR, "Undefined domain type");
						}
					}
					// Si el parser cargo algo y el servidor esta seteado, activamos la escritura al origin server
					if (buffer_can_read(node->data.parser->data.parsed_request) && fd_server != -1) {
						FD_SET(fd_server, &write_fd_set[BASE]);
					}
				} else if (buffer_can_read(node->data.clientToServerBuffer) && fd_server != -1)
					FD_SET(fd_server, &write_fd_set[BASE]);
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
			// char aux_buffer[BUFFER_SIZE] = {0};
			// strncpy(aux_buffer, (char *)node->data.serverToClientBuffer->read,(size_t) (node->data.serverToClientBuffer->write
			// - node->data.serverToClientBuffer->read)); logger(DEBUG, "Response: %s", aux_buffer);
			result_bytes = handle_operation(fd_client, node->data.serverToClientBuffer, WRITE, CLIENT, node->data.file);
			if (result_bytes <= 0) {
				close_connection(node, prev, write_fd_set, read_fd_set);
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
	if (node->data.doh->addr_info_current == NULL) {
		logger(INFO, "No more addresses to connect to for client with fd %d", node->data.clientSock);
		// FIXME: Liberar cliente y estructuras de DoH desde afuera
		return -1;
	}

	// TODO: está bien hardcodear SOCK_STREAM y el protocolo?
	node->data.serverSock = socket(node->data.doh->addr_info_current->addr.sa_family, SOCK_STREAM, 0);

	if (node->data.serverSock < 0) {
		logger(ERROR, "setup_connection :: socket(): %s", strerror(errno));
		return -1;
	}
	// configuracion para socket no bloqueante
	if (fcntl(node->data.serverSock, F_SETFL, O_NONBLOCK) == -1) {
		logger(INFO, "fcntl(): %s", strerror(errno));
		// FIXME: PEPE???
		return -1;
	}

	if (node->data.serverSock >= connections.maxFd) connections.maxFd = node->data.serverSock + 1;

	struct addr_info_node aux_addr_info = *node->data.doh->addr_info_current;

	// Intento de connect
	logger(INFO, "Trying to connect to server from client with fd: %d", node->data.clientSock);
	if (connect(node->data.serverSock, &aux_addr_info.addr, sizeof(aux_addr_info.addr)) != 0 && errno != EINPROGRESS) {
		// error inesperado en connect
		logger(ERROR, "setup_connection :: connect(): %s", strerror((errno)));
		// FIXME: QUE PASA CON EL CLIENTE MALLOQUEADO?
		// TODO: Liberar recursos de DoH, close_connection
		// TODO: Tirar 500 por HTTP al cliente
		close(node->data.serverSock);
		close(node->data.clientSock);
		return -1;
	}

	logger(INFO, "Connecting to server from client with fd: %d", node->data.clientSock);
	node->data.addrInfoState = CONNECTING;
	// TODO: lista de estadisticas
	// el cliente puede haber escrito algo y el proxy crear la conexion despues, por lo tanto
	// agrego como escritura el fd activo
	FD_SET(node->data.serverSock, &writeFdSet[BASE]);

	return 0;
}

// Leer o escribir a un socket
ssize_t handle_operation(int fd, buffer *buffer, OPERATION operation, PEER peer, FILE *file) {
	ssize_t resultBytes;
	ssize_t bytesToSend;
	switch (operation) {
		case WRITE: // escribir a un socket
			bytesToSend = buffer->write - buffer->read;
			resultBytes = send(fd, buffer->read, bytesToSend, 0);
			if (resultBytes <= 0) {
				logger(ERROR, "send(): %s", strerror(errno));
			} else {
				// TODO pasar a arreglo auxiliar (con strncpy)
				logger(INFO, "Sent info on fd: %d", fd);
				uint8_t aux_buffer[BUFFER_SIZE] = {0};
				strncpy((char *)aux_buffer, (char *)buffer->read, (size_t)(buffer->write - buffer->read));
				fprintf(file, "-------------------	PROXY %s SERVER	-------------------\n", peer == SERVER ? "CLIENT" : "ORIGIN");
				fprintf(file, "%s\n", aux_buffer);
				fprintf(file, "---------------------------------------------------------\n");

				buffer_read_adv(buffer, resultBytes);
			}
			break;
		case READ: // leer de un socket
			resultBytes = recv(fd, buffer->write, buffer->limit - buffer->write, 0);
			if (resultBytes < 0) {
				if (resultBytes == -1 && (errno != EWOULDBLOCK || errno == EAGAIN)) {
					loggerPeer(peer, "recv(): %s", strerror(errno));
					return -1;
				}
			} else if (resultBytes == 0) {
				if (peer == SERVER) logger(INFO, "Server with fd: %d closing connection", fd);
			} else {
				logger(INFO, "Received info on fd: %d", fd);
				buffer_write_adv(buffer, resultBytes);
				uint8_t aux_buffer[BUFFER_SIZE] = {0};
				strncpy((char *)aux_buffer, (char *)buffer->read, (size_t)(buffer->write - buffer->read));
				fprintf(file, "-------------------	%s SERVER	-------------------\n", peer == SERVER ? "ORIGIN" : "CLIENT");
				fprintf(file, "%s\n", aux_buffer);
				fprintf(file, "---------------------------------------------------------\n");
			}
			break;
		default:
			logger(ERROR, "Unknown operation on socket with fd: %d", fd);
			resultBytes = -1;
	}

	return resultBytes;
}
