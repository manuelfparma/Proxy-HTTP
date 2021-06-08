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
#include <proxy.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern connection_header connections;

static void send_parse_error(int fd_client, connection_node *node) {
	// TODO: CAMBIAR A SEND CUANDO SE BORREN LOS LOGS
	logger(INFO, "Connection established");
	char *response = "HTTP/1.1 400 Bad Request\r\n\r\n";
	buffer *buffer_response;
	buffer_response = malloc(sizeof(buffer));
	buffer_response->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	buffer_init(buffer_response, BUFFER_SIZE, buffer_response->data);
	strncpy((char *)buffer_response->write, response, strlen(response));
	buffer_write_adv(buffer_response, strlen(response));
	ssize_t result_bytes = handle_operation(fd_client, buffer_response, WRITE, CLIENT, node->data.log_file);
	if (result_bytes <= 0)
		// TODO: enviar denuevo?
		logger(ERROR, "Invalid request from client with fd: %d", fd_client);

	free(buffer_response->data);
	free(buffer_response);

	buffer_reset(node->data.client_to_server_buffer); // por si quedaron cosas sin parsear del request
}

void send_server_error(int fd_client, connection_node *node) {
	// TODO: CAMBIAR A SEND CUANDO SE BORREN LOS LOGS
	logger(INFO, "Connection established");
	char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
	buffer *buffer_response;
	buffer_response = malloc(sizeof(buffer));
	buffer_response->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	buffer_init(buffer_response, BUFFER_SIZE, buffer_response->data);
	strncpy((char *)buffer_response->write, response, strlen(response));
	buffer_write_adv(buffer_response, strlen(response));
	ssize_t result_bytes = handle_operation(fd_client, buffer_response, WRITE, CLIENT, node->data.log_file);
	if (result_bytes <= 0)
		// TODO: enviar denuevo?
	logger(ERROR, "Invalid request from client with fd: %d", fd_client);

	free(buffer_response->data);
	free(buffer_response);

	buffer_reset(node->data.client_to_server_buffer); // por si quedaron cosas sin parsear del request
}

/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setup_passive_socket(const char *service) {
	// Construct the server address structure
	struct addrinfo add_criteria;					// Criteria for address match
	memset(&add_criteria, 0, sizeof(add_criteria)); // Zero out structure
	add_criteria.ai_family = AF_UNSPEC;				// Any address family
	add_criteria.ai_flags = AI_PASSIVE;				// Accept on any address/port
	add_criteria.ai_socktype = SOCK_STREAM;			// Only stream sockets
	add_criteria.ai_protocol = IPPROTO_TCP;			// Only TCP protocol

	struct addrinfo *serv_addr; // List of server addresses
	int rtnVal = getaddrinfo(NULL, service, &add_criteria, &serv_addr);
	if (rtnVal != 0) {
		// no se pudo instanciar el socket pasivo
		logger(FATAL, "getaddrinfo(): %s", strerror(errno));
	}

	int passive_sock = -1;
	// Intentamos ponernos a escuchar en alguno de los puertos asociados al servicio
	// Iteramos por todas las Ips y hacemos el bind por alguna de ellas.
	// Con esta implementación estaremos escuchando o bien en IPv4 o en IPv6, pero no en ambas
	for (struct addrinfo *addr = serv_addr; addr != NULL && passive_sock == -1; addr = addr->ai_next) {
		// Create a TCP socket
		passive_sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (passive_sock < 0) {
			logger(INFO, "socket() failed, trying next address");
			continue; // Socket creation failed; try next address
		}

		if (setsockopt(passive_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
			logger(INFO, "setsockopt(): %s", strerror(errno));
			continue;
		}
		// Non blocking socket
		if (fcntl(passive_sock, F_SETFL, O_NONBLOCK) == -1) {
			logger(INFO, "fcntl(): %s", strerror(errno));
			continue;
		}
		// Bind to All the address and set socket to listen
		if ((bind(passive_sock, addr->ai_addr, addr->ai_addrlen) == 0) && (listen(passive_sock, MAX_PENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage local_addr;
			socklen_t addr_size = sizeof(local_addr);
			if (getsockname(passive_sock, (struct sockaddr *)&local_addr, &addr_size) >= 0) {
				logger(INFO, "Binding and listening...");
			}
		} else {
			logger(INFO, "bind() or listen() failed, trying next address");
			close(passive_sock); // Close and try again
			passive_sock = -1;
		}
	}

	freeaddrinfo(serv_addr);
	return passive_sock;
}

int accept_connection(int passive_sock) {
	struct sockaddr_storage clnt_addr; // Client address
	// Set length of client address structure (in-out parameter)
	socklen_t clnt_addrLen = sizeof(clnt_addr);
	// Wait for a client to connect
	int clnt_sock = accept(passive_sock, (struct sockaddr *)&clnt_addr, &clnt_addrLen);
	if (clnt_sock < 0) {
		logger(ERROR, "accept(): %s", strerror(errno));
		return ACCEPT_CONNECTION_ERROR;
	}
	// Non blocking
	if (fcntl(clnt_sock, F_SETFL, O_NONBLOCK) < 0) {
		logger(ERROR, "fcntl(): %s", strerror(errno));
		close(clnt_sock);
		return ACCEPT_CONNECTION_ERROR;
	}
	// clnt_sock is connected to a client!
	logger(DEBUG, "Created active socket for client with fd: %d", clnt_sock);
	return clnt_sock;
}

int handle_server_connection(connection_node *node, connection_node *prev, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {

	int fd_server = node->data.server_sock;
	int fd_client = node->data.client_sock;
	int return_value = 0;
	ssize_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_server, &read_fd_set[TMP])) {
		// logger_peer(SERVER, "Trying to read from fd %d", fd_server);

		if (buffer_can_write(node->data.server_to_client_buffer)) {
			result_bytes = handle_operation(fd_server, node->data.server_to_client_buffer, READ, SERVER, node->data.log_file);
			if (result_bytes == RECV_ERROR_CODE) {
				// error en el servidor en el receive, lo dejo para que intente denuevo en la proxima iteracion
				logger_peer(SERVER, "recv(): error for server_fd: %d and client_fd: %d, READ operation", fd_server, fd_client);
			} else if (result_bytes == CLOSE_CONNECTION_CODE) {
				// server quiere cerrar la conexion, liberamos los recursos y cerramos la conexion pues no hay nada mas para
				// recibir
				logger_peer(SERVER, "Close connection for server_fd: %d and client_fd: %d, READ operation", fd_server, fd_client);
				return CLOSE_CONNECTION_CODE;
			} else {
				// Se escribio algo en el buffer, activo la escritura hacia el cliente
				if (fd_client != -1) { FD_SET(fd_client, &write_fd_set[BASE]); }
			}
		} else {
			logger_peer(SERVER, "Server with fd: %d has buffer full", fd_server);
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd_server, &read_fd_set[BASE]);
		}
		return_value++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (write_fd_set != NULL && FD_ISSET(fd_server, &write_fd_set[TMP])) {
		// logger_peer(SERVER, "Trying to write to fd %d", fd_server);

		// TODO: Modularizar esta seccion
		if (node->data.connection_state == CONNECTING) {
			socklen_t optlen = sizeof(int);

			// chequeamos el estado del socket
			if (getsockopt(fd_server, SOL_SOCKET, SO_ERROR, &(int){1}, &optlen) < 0) {

				// en caso de error, ver si la conexion fue rechazada, cerrar el socket y probar con la siguiente
				if (errno == ECONNREFUSED) {
					node->data.doh->addr_info_current = node->data.doh->addr_info_current->next;

					FD_CLR(node->data.server_sock, &write_fd_set[BASE]);
					close(node->data.server_sock);

					int ans = setup_connection(node, write_fd_set);
					if (ans == CLOSE_CONNECTION_CODE) {
						// nos quedamos sin addresses en la lista
						logger(ERROR, "handle_server_connection :: setup_connection(): %s", strerror(errno));
						free_doh_resources(node);
						return CLOSE_CONNECTION_CODE;
					} else if (ans == SETUP_CONNECTION_ERROR_CODE) {
						// intentara con la proxima direccion
						logger(INFO, "Connection to address failed from client with fd: %d", node->data.client_sock);
					}
				} else {
					// error de getsockopt respecto al server, liberamos todos los recursos
					logger(ERROR, "handle_server_connection :: getsockopt(): %s", strerror(errno));
					free_doh_resources(node);
					return CLOSE_CONNECTION_CODE;
				}
			} else {
				logger_peer(SERVER, "Connected to server with fd %d for client with fd %d", node->data.server_sock,
						   node->data.client_sock);
				node->data.connection_state = CONNECTED;
				free_doh_resources(node);
				// en caso que el server mande un primer mensaje, quiero leerlo
				FD_SET(fd_server, &read_fd_set[BASE]);
				if (node->data.parser->data.request_status != PARSE_CONNECT_METHOD) {
					// ya que estoy conectado, me fijo si quedo algo para parsear
					parse_request(node->data.parser, node->data.client_to_server_buffer);
					if (node->data.parser->data.parser_state == PS_ERROR) {
						send_parse_error(fd_client, node);
						return CLOSE_CONNECTION_CODE;
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
					result_bytes = handle_operation(fd_client, buffer_response, WRITE, CLIENT, node->data.log_file);
					if (result_bytes <= 0) logger(ERROR, "Couldnt send connection established to client with fd: %d", fd_client);

					free(buffer_response->data);
					free(buffer_response);

					buffer_reset(node->data.client_to_server_buffer); // por si quedaron cosas sin parsear del request
				}
			}
		}

		if (node->data.parser->data.request_status != PARSE_CONNECT_METHOD) {
			if (buffer_can_read(node->data.parser->data.parsed_request)) {
				result_bytes =
					handle_operation(fd_server, node->data.parser->data.parsed_request, WRITE, SERVER, node->data.log_file);
				if (result_bytes == SEND_ERROR_CODE) {
					// el SEND dio algun error inesperado, lo dejo para intentar denuevo en la proxima iteracion
					logger_peer(SERVER, "send(): error for server_fd: %d and client_fd: %d, WRITE operation", fd_server,
							   fd_client);
				}
				else if(result_bytes == CLOSE_CONNECTION_CODE) {
					return CLOSE_CONNECTION_CODE;
				}
				else {
					// ahora que el buffer de entrada tiene espacio, intento leer del otro par
					FD_SET(fd_client, &read_fd_set[BASE]);
					connections.total_proxy_to_origins_bytes += result_bytes;
					// si el buffer de salida se vacio, no nos interesa intentar escribir
					if (!buffer_can_read(node->data.parser->data.parsed_request)) FD_CLR(fd_server, &write_fd_set[BASE]);
				}
			} else {
				FD_CLR(fd_server, &write_fd_set[BASE]);
			}
		} else {
			if (buffer_can_read(node->data.client_to_server_buffer)) {

				result_bytes =
					handle_operation(fd_server, node->data.client_to_server_buffer, WRITE, SERVER, node->data.log_file);
				if (result_bytes == SEND_ERROR_CODE) {
					// el SEND dio algun error inesperado, lo dejo para intentar denuevo en la proxima iteracion
					logger_peer(SERVER, "send(): error for server_fd: %d and client_fd: %d, WRITE operation", fd_server,
							   fd_client);
				}
				else if (result_bytes < 0)
				{
					return result_bytes;
				}
				else {
					// ahora que el buffer de entrada tiene espacio, intento leer del otro par
					FD_SET(fd_client, &read_fd_set[BASE]);
					connections.total_proxy_to_origins_bytes += result_bytes;
					connections.total_connect_method_bytes += result_bytes;
					// si el buffer de salida se vacio, no nos interesa intentar escribir
					if (!buffer_can_read(node->data.client_to_server_buffer)) FD_CLR(fd_server, &write_fd_set[BASE]);
				}
			} else {
				FD_CLR(fd_server, &write_fd_set[BASE]);
			}
		}
		return_value++;
	}
	return return_value;
}

int handle_client_connection(connection_node *node, connection_node *prev, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	int fd_server = node->data.server_sock;
	int fd_client = node->data.client_sock;
	int return_value = 0;
	ssize_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_client, &read_fd_set[TMP])) {
		// logger_peer(CLIENT, "Trying to read from fd %d", fd_client);
		if (buffer_can_write(node->data.client_to_server_buffer)) {
			result_bytes = handle_operation(fd_client, node->data.client_to_server_buffer, READ, CLIENT, node->data.log_file);
			if (result_bytes == RECV_ERROR_CODE) {
				// dio error el receive, lo dejamos para intentar denuevo luego
				logger_peer(CLIENT, "recv(): error for server_fd: %d and client_fd: %d, READ operation", fd_server, fd_client);
			} else if (result_bytes == CLOSE_CONNECTION_CODE) {
				// el cliente me indica que no me va a enviar mas informacion, como quizas el servidor quiere seguir escribiendo
				// dejo al cliente solo como receptor
				logger_peer(CLIENT, "client_fd: %d request sent completed", fd_client);
				FD_CLR(fd_client, &read_fd_set[BASE]);
			} else { // Si pudo leer algo, ahora debe ver si puede escribir al otro peer (siempre y cuando este seteado)
				if (node->data.parser->data.request_status != PARSE_CONNECT_METHOD) {
					parse_request(node->data.parser, node->data.client_to_server_buffer);
					if (node->data.parser->data.parser_state == PS_ERROR) {
						send_parse_error(fd_client, node);
						return CLOSE_CONNECTION_CODE;
					}
					if (node->data.connection_state == DISCONNECTED) {
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
									return CLOSE_CONNECTION_CODE; // cierro todas las conexiones
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
				} else if (buffer_can_read(node->data.client_to_server_buffer) && fd_server != -1)
					FD_SET(fd_server, &write_fd_set[BASE]);
			}
		} else {
			logger_peer(CLIENT, "Client with fd: %d has buffer full", fd_server);
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd_client, &read_fd_set[BASE]);
		}
		return_value++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (write_fd_set != NULL && FD_ISSET(fd_client, &write_fd_set[TMP])) {
		// logger_peer(CLIENT, "Trying to write to fd %d", fd_client);
		if (buffer_can_read(node->data.server_to_client_buffer)) {
			result_bytes = handle_operation(fd_client, node->data.server_to_client_buffer, WRITE, CLIENT, node->data.log_file);
			if (result_bytes == SEND_ERROR_CODE) {
				// el SEND dio algun error inesperado, lo dejo para intentar denuevo en la proxima iteracion
				logger_peer(CLIENT, "send(): error for server_fd: %d and client_fd: %d, WRITE operation", fd_server, fd_client);
			}
			else if(result_bytes < 0) {
				return result_bytes;
			}
			else {
				// ahora que el buffer de entrada tiene espacio, intento leer del otro par
				FD_SET(fd_server, &read_fd_set[BASE]);
				connections.total_proxy_to_clients_bytes += result_bytes;
				// si el buffer de salida se vacio, no nos interesa intentar escribir
				if (!buffer_can_read(node->data.server_to_client_buffer)) FD_CLR(fd_client, &write_fd_set[BASE]);
			}
		}
		return_value++;
	}
	return return_value;
}

int setup_connection(connection_node *node, fd_set *writeFdSet) {
	if (node->data.doh->addr_info_current == NULL) {
		logger(INFO, "No more addresses to connect to for client with fd %d", node->data.client_sock);
		return CLOSE_CONNECTION_CODE;
	}

	// TODO: está bien hardcodear SOCK_STREAM y el protocolo?
	node->data.server_sock = socket(node->data.doh->addr_info_current->addr.sa_family, SOCK_STREAM, 0);

	if (node->data.server_sock < 0) {
		logger(ERROR, "setup_connection :: socket(): %s", strerror(errno));
		return SETUP_CONNECTION_ERROR_CODE;
	}

	// configuracion para socket no bloqueante
	if (fcntl(node->data.server_sock, F_SETFL, O_NONBLOCK) == -1) {
		logger(INFO, "fcntl(): %s", strerror(errno));
		return SETUP_CONNECTION_ERROR_CODE;
	}

	if (node->data.server_sock >= connections.max_fd) connections.max_fd = node->data.server_sock + 1;

	struct addr_info_node aux_addr_info = *node->data.doh->addr_info_current;

	// Intento de connect
	logger(INFO, "Trying to connect to server from client with fd: %d", node->data.client_sock);
	if (connect(node->data.server_sock, &aux_addr_info.addr, sizeof(aux_addr_info.storage)) != 0 && errno != EINPROGRESS) {
		// error inesperado en connect
		logger(ERROR, "setup_connection :: connect(): %s", strerror((errno)));
		// TODO: Tirar 500 por HTTP al cliente
		close(node->data.server_sock);
		close(node->data.client_sock);
		return CLOSE_CONNECTION_CODE;
	}

	logger(INFO, "Connecting to server from client with fd: %d", node->data.client_sock);
	node->data.connection_state = CONNECTING;
	// TODO: lista de estadisticas
	// el cliente puede haber escrito algo y el proxy crear la conexion despues, por lo tanto
	// agrego como escritura el fd activo
	FD_SET(node->data.server_sock, &writeFdSet[BASE]);

	return 0;
}

// Leer o escribir a un socket
ssize_t handle_operation(int fd, buffer *buffer, operation operation, peer peer, FILE *file) {
	ssize_t resultBytes = 0;
	ssize_t bytesToSend = 0;
	switch (operation) {
		case WRITE: // escribir a un socket
			bytesToSend = buffer->write - buffer->read;
			resultBytes = send(fd, buffer->read, bytesToSend, MSG_NOSIGNAL);
			if (resultBytes < 0) {
				if (errno != EWOULDBLOCK && errno != EAGAIN) {
					// si hubo error y no sale por ser no bloqueante, corto la conexion
					logger_peer(peer, "send: %s", strerror(errno));
					if(errno == EPIPE){
						return BROKEN_PIPE_CODE;
					}
					return SEND_ERROR_CODE;
				} else
					// no envie nada, me desperte innecesariamente
					return 0;
			} else {
				// logger(DEBUG, "Sent info on fd: %d", fd);
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
				if (errno != EWOULDBLOCK && errno != EAGAIN) {
					// si hubo error y no sale por ser no bloqueante, corto la conexion
					logger_peer(peer, "handle_operation :: recv(): %s", strerror(errno));
					return RECV_ERROR_CODE;
				}
				// no lei nada, me desperte innecesariamente
				return 0;
			} else if (resultBytes == 0) {
				// como es no bloqueante, un 0 indica cierre prematuro de conexion
				if (peer == SERVER) logger(INFO, "Server with fd: %d closing connection", fd);
				return CLOSE_CONNECTION_CODE;
			} else {
				// logger(DEBUG, "Received info on fd: %d", fd);
				buffer_write_adv(buffer, resultBytes);

				// logeo, TODO: sacar para la entrega
				uint8_t aux_buffer[BUFFER_SIZE] = {0};
				strncpy((char *)aux_buffer, (char *)buffer->read, (size_t)(buffer->write - buffer->read));
				fprintf(file, "-------------------	%s SERVER	-------------------\n", peer == SERVER ? "ORIGIN" : "CLIENT");
				fprintf(file, "%s\n", aux_buffer);
				fprintf(file, "---------------------------------------------------------\n");
			}
			break;
		default:
			logger(ERROR, "Unknown operation on socket with fd: %d", fd);
			resultBytes = CLOSE_CONNECTION_CODE;
	}

	return resultBytes;
}
