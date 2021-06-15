// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <arpa/inet.h>
#include <buffer.h>
#include <connection.h>
#include <ctype.h>
#include <dohclient.h>
#include <dohdata.h>
#include <dohutils.h>
#include <errno.h>
#include <fcntl.h>
#include <httpparser.h>
#include <logger.h>
#include <netdb.h>
#include <netutils.h>
#include <pop3responseparser.h>
#include <proxy.h>
#include <proxyargs.h>
#include <proxyutils.h>
#include <string.h>
#include <time.h>

extern connection_header connections;
extern proxy_arguments args;
extern proxy_settings settings;

// Funcion que parsea el request target guardado como string en nodo para almacenarlo en la estructura apropiada para realizar la
// conexion
static int set_node_request_target(connection_node *node, fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

// Funcion que verifica si se concreto la conexion, o si esta en progreso o si fallo maneja el error
static int try_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE], fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

// Funcion que resuelve la respuesta del llamado al parser de la response pop3
static void handle_pop3_response(connection_node *node, fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

// Funcion que pasa la direccion a string
static int copy_address_info(struct sockaddr *address, char *buffer_address, char *buffer_port);

// Funcion que imprime los registros
static void print_register(register_type register_wanted, connection_node *node, fd_set *write_fd_set);

// Funcion que copia el host objetivo en el string buffer
static int copy_host(char *buffer, http_target target);

// Funcion que envia a STDOUT el status code de la nueva conexion
static void print_status_code(connection_node *node, fd_set *write_fd_set);

// Funcion que incrementa los bytes del metodo connect en las estadisticas
static void increase_connect_method_bytes(connection_node *node, ssize_t result_bytes);

/*
 ** Se encarga de resolver el número de puerto para service (puede ser un string con el numero o el nombre del servicio)
 ** y crear el socket pasivo, para que escuche en cualquier IP, ya sea v4 o v6
 */
int setup_proxy_passive_sockets(int proxy_sockets[SOCK_COUNT]) {
	addr_info proxy_addr = {0};

	// Ciclo para crear sockets y escuchar tanto en IPv4 como en IPv6
	for (int i = 0; i < SOCK_COUNT; i++) {
		if (i == IPV4_SOCK) proxy_addr.in4 = args.proxy_addr4;
		else if (i == IPV6_SOCK)
			proxy_addr.in6 = args.proxy_addr6;

		if (proxy_addr.addr.sa_family == 0) {
			proxy_sockets[i] = -1;
			continue;
		}

		// Create a TCP socket
		proxy_sockets[i] = socket(proxy_addr.addr.sa_family, SOCK_STREAM, 0);
		if (proxy_sockets[i] < 0) {
			logger(INFO, "socket() for passive socket failed");
			return -1;
		}

		if (setsockopt(proxy_sockets[i], SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
			logger(INFO, "setsockopt(): %s", strerror(errno));
			return -1;
		}

		if (i == IPV6_SOCK && setsockopt(proxy_sockets[i], IPPROTO_IPV6, IPV6_V6ONLY, &(int){1}, sizeof(int)) < 0) {
			logger(INFO, "setsockopt(): %s", strerror(errno));
			return -1;
		}

		// Non blocking socket
		if (fcntl(proxy_sockets[i], F_SETFL, O_NONBLOCK) == -1) {
			logger(INFO, "fcntl(): %s", strerror(errno));
			return -1;
		}

		socklen_t len = (proxy_addr.addr.sa_family == AF_INET6) ? sizeof(proxy_addr.in6) : sizeof(proxy_addr.in4);
		// Bind to All the address and set socket to listen
		if ((bind(proxy_sockets[i], &proxy_addr.addr, len) == 0) && (listen(proxy_sockets[i], MAX_PENDING) == 0)) {
			// Print local address of socket
			struct sockaddr_storage local_addr;
			socklen_t addr_size = sizeof(local_addr);
			if (getsockname(proxy_sockets[i], (struct sockaddr *)&local_addr, &addr_size) >= 0) {
				logger(INFO, "Binding and listening...");
			}
		} else {
			logger(INFO, "bind() or listen() failed for passive socket");
			close(proxy_sockets[i]);
			return -1;
		}
	}

	return 0;
}

int accept_connection(int passive_sock, char *buffer_address, char *buffer_port) {
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

	// guardar registro del cliente
	if (copy_address_info((struct sockaddr *)&clnt_addr, buffer_address, buffer_port) < 0) {
		logger(ERROR, "copy_address_info() failed");
		close(clnt_sock);
		return ACCEPT_CONNECTION_ERROR;
	}

	return clnt_sock;
}

int handle_server_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {

	int fd_server = node->data.server_sock;
	int fd_client = node->data.client_sock;
	int fd_set_consume_count = 0;
	ssize_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_server, &read_fd_set[TMP])) {
		if (buffer_can_write(node->data.server_to_client_buffer)) {
			result_bytes = handle_operation(fd_server, node->data.server_to_client_buffer, READ, SERVER, node->data.log_file);
			if (result_bytes < 0) return result_bytes;
			node->data.timestamp = time(NULL);

			if (node->data.parser->data.request_status == PARSE_CONNECT_METHOD_POP3) handle_pop3_response(node, write_fd_set);

			// lo prendo pues hay nueva informacion
			FD_SET(fd_client, &write_fd_set[BASE]);
		} else {
			// logger_peer(SERVER, "Server with fd: %d has buffer full", fd_server);
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd_server, &read_fd_set[BASE]);
		}
		fd_set_consume_count++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (write_fd_set != NULL && FD_ISSET(fd_server, &write_fd_set[TMP])) {
		if (node->data.connection_state == CONNECTING) {
			// chequeamos si logro conectarse
			int handle = try_connection(node, read_fd_set, write_fd_set);
			if (handle < 0) return handle;
			return fd_set_consume_count++;
		}
		buffer *aux_buffer;
		switch (node->data.parser->data.request_status) {
			case PARSE_BODY_INCOMPLETE:
			case PARSE_CONNECT_METHOD:
				aux_buffer = node->data.client_to_server_buffer;
				break;
			case PARSE_CONNECT_METHOD_POP3:
				aux_buffer = node->data.parser->pop3->command.command_buffer;
				break;
			default:
				aux_buffer = node->data.parser->data.parsed_request;
				break;
		}
		if (!buffer_can_read(aux_buffer)) {
			FD_CLR(fd_server, &write_fd_set[BASE]);
		} else {
			result_bytes = handle_operation(fd_server, aux_buffer, WRITE, SERVER, node->data.log_file);
			if (result_bytes < 0) return result_bytes;
			node->data.timestamp = time(NULL);

			if (node->data.parser->request.authorization.value[0] != '\0') print_register(PASSWORD, node, write_fd_set);
			increase_connect_method_bytes(node, result_bytes);
			// ahora que el buffer de entrada tiene espacio, intento leer del otro par solo si es posible
			if (node->data.connection_state < CLIENT_READ_CLOSE && read_fd_set != NULL) FD_SET(fd_client, &read_fd_set[BASE]);

			connections.statistics.total_proxy_to_origins_bytes += result_bytes;
			// si el buffer de salida se vacio, no nos interesa intentar escribir
			if (!buffer_can_read(aux_buffer)) FD_CLR(fd_server, &write_fd_set[BASE]);
		}
		fd_set_consume_count++;
	}
	return fd_set_consume_count;
}

int handle_client_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE],
							 fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	int fd_server = node->data.server_sock;
	int fd_client = node->data.client_sock;
	int fd_set_consume_count = 0;
	ssize_t result_bytes;

	// Si hay algo para leer de un socket, lo volcamos en un buffer de entrada para mandarlo al otro peer
	// (siempre y cuando haya espacio en el buffer)
	if (read_fd_set != NULL && FD_ISSET(fd_client, &read_fd_set[TMP])) {
		if (!buffer_can_write(node->data.client_to_server_buffer)) {
			if (node->data.parser->data.target_status == NOT_FOUND) {
				// se lleno el buffer, nunca voy a poder recibir la informacion con el target
				return BAD_REQUEST_ERROR;
			}
			// logger_peer(CLIENT, "Client with fd: %d has buffer full", fd_server);
			// si el buffer esta lleno, dejo de leer del socket
			FD_CLR(fd_client, &read_fd_set[BASE]);
		} else {
			result_bytes = handle_operation(fd_client, node->data.client_to_server_buffer, READ, CLIENT, node->data.log_file);
			if (result_bytes < 0) return result_bytes;
			node->data.timestamp = time(NULL);

			buffer *aux_buffer;
			switch (node->data.parser->data.request_status) {
				case PARSE_CONNECT_METHOD_POP3:
					if (settings.password_dissector) {
						aux_buffer = node->data.parser->pop3->command.command_buffer;
						node->data.parser->pop3->line_count +=
							parse_pop3_command(&node->data.parser->pop3->command, node->data.client_to_server_buffer);
						break;
					}
					close_pop3_parser(node);
				case PARSE_BODY_INCOMPLETE:
				case PARSE_CONNECT_METHOD:
					aux_buffer = node->data.client_to_server_buffer;
					break;
				default:
					aux_buffer = node->data.parser->data.parsed_request;
					parse_request(node->data.parser, &node->data.client_to_server_buffer);
					if (node->data.parser->data.request_status == PARSE_ERROR) return BAD_REQUEST_ERROR;
					if (node->data.parser->data.parser_state == PS_END) { return CLIENT_CLOSE_READ_ERROR_CODE; }
					if (node->data.connection_state == DISCONNECTED && node->data.parser->data.target_status == SOLVED) {
						// seteo los argumentos necesarios para conectarse al server
						if (node->data.parser->request.target.host_type == DOMAIN) {
							if (connect_to_doh_server(node, &write_fd_set[BASE]) == -1) {
								logger(ERROR, "connect_to_doh_server(): error while connecting to DoH. %s", strerror(errno));
								return CLOSE_CONNECTION_ERROR_CODE; // cierro todas las conexiones
							}
						} else {
							int connect_ret = set_node_request_target(node, write_fd_set);
							if (connect_ret < 0) return connect_ret;
						}
						if (node->data.parser->data.request_status == PARSE_CONNECT_METHOD_POP3) setup_pop3_command_parser(node);

						break;
					}
			}
			// Si el parser cargo algo y el servidor esta seteado, activamos la escritura al origin server
			if (buffer_can_read(aux_buffer) && fd_server != -1) FD_SET(fd_server, &write_fd_set[BASE]);
		}
		fd_set_consume_count++;
	}

	// Si un socket se activa para escritura, leo de la otra punta y
	// mandamos lo que llego del otro peer en el buffer de salida interno
	if (write_fd_set != NULL && FD_ISSET(fd_client, &write_fd_set[TMP])) {
		buffer *aux_buffer;
		switch (node->data.parser->data.request_status) {
			case PARSE_CONNECT_METHOD_POP3:
				aux_buffer = node->data.parser->pop3->response.response_buffer;
				break;
			case PARSE_CONNECT_METHOD:
				aux_buffer = node->data.server_to_client_buffer;
				break;
			default:
				aux_buffer = node->data.server_to_client_buffer;
				print_status_code(node, write_fd_set);
				break;
		}
		if (buffer_can_read(aux_buffer)) {
			result_bytes = handle_operation(fd_client, aux_buffer, WRITE, CLIENT, node->data.log_file);
			if (result_bytes < 0) return result_bytes;
			node->data.timestamp = time(NULL);

			increase_connect_method_bytes(node, result_bytes);
			if (node->data.connection_state < CLIENT_READ_CLOSE && read_fd_set != NULL && fd_server != -1)
				FD_SET(fd_server, &read_fd_set[BASE]);
			connections.statistics.total_proxy_to_clients_bytes += result_bytes;
			// si el buffer de salida se vacio, no nos interesa intentar escribir
			if (!buffer_can_read(aux_buffer)) { FD_CLR(fd_client, &write_fd_set[BASE]); }
		}
		fd_set_consume_count++;
	}
	return fd_set_consume_count;
}

int setup_connection(connection_node *node, fd_set *write_fd_set) {
	if (node->data.addr_info_current == NULL) {
		logger(INFO, "No more addresses to connect to for client with fd %d", node->data.client_sock);
		return SETUP_CONNECTION_ERROR_CODE;
	}

	node->data.server_sock = socket(node->data.addr_info_current->addr.sa_family, SOCK_STREAM, 0);

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

	struct addr_info_node aux_addr_info = *node->data.addr_info_current;

	socklen_t length = 0;
	switch (aux_addr_info.addr.sa_family) {
		case AF_INET:
			length = sizeof(aux_addr_info.in4);
			break;
		case AF_INET6:
			length = sizeof(aux_addr_info.in6);
			break;
	}

	if (connect(node->data.server_sock, &aux_addr_info.addr, length) != 0 && errno != EINPROGRESS) {
		// error inesperado en connect
		logger(ERROR, "setup_connection :: connect(): %s", strerror((errno)));
		close(node->data.server_sock);
		close(node->data.client_sock);
		return SETUP_CONNECTION_ERROR_CODE;
	}

	logger(DEBUG, "Connecting to server from client with fd: %d", node->data.client_sock);
	node->data.connection_state = CONNECTING;
	// el cliente puede haber escrito algo y el proxy crear la conexion despues, por lo tanto
	// agrego como escritura el fd activo
	FD_SET(node->data.server_sock, &write_fd_set[BASE]);

	node->data.timestamp = time(NULL);

	return 0;
}

// Leer o escribir a un socket
ssize_t handle_operation(int fd, buffer *buffer, operation operation, peer peer, FILE *file) {
	ssize_t result_bytes = 0;
	ssize_t bytes_to_send = 0;
	switch (operation) {
		case WRITE: // escribir a un socket
			bytes_to_send = buffer->write - buffer->read;
			result_bytes = send(fd, buffer->read, bytes_to_send, 0);
			if (result_bytes < 0) {
				if (errno != EWOULDBLOCK && errno != EAGAIN) {
					// si hubo error y no sale por ser no bloqueante, corto la conexion
					logger_peer(peer, "fd = %d - send: %s", fd, strerror(errno));
					if (errno == EPIPE) { return BROKEN_PIPE_ERROR_CODE; }
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
				buffer_read_adv(buffer, result_bytes);
			}
			break;
		case READ: // leer de un socket
			result_bytes = recv(fd, buffer->write, buffer->limit - buffer->write, 0);
			if (result_bytes < 0) {
				if (errno != EWOULDBLOCK && errno != EAGAIN) {
					// si hubo error y no sale por ser no bloqueante, corto la conexion
					logger_peer(peer, "handle_operation :: recv(): %s", strerror(errno));
					return RECV_ERROR_CODE;
				}
				// no lei nada, me desperte innecesariamente
				return 0;
			} else if (result_bytes == 0) {
				// como es no bloqueante, un 0 indica cierre prematuro de conexion

				if (peer == SERVER) {
					logger(INFO, "Server with fd: %d closing connection", fd);
					return SERVER_CLOSE_READ_ERROR_CODE;
				}
				//				logger(DEBUG, "errno: %s [%d]", strerror(errno), errno);
				return CLIENT_CLOSE_READ_ERROR_CODE;

			} else {
				// logger(DEBUG, "Received info on fd: %d", fd);
				buffer_write_adv(buffer, result_bytes);

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
			result_bytes = CLOSE_CONNECTION_ERROR_CODE;
	}

	return result_bytes;
}

static int set_node_request_target(connection_node *node, fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	struct sockaddr_in addr_in4;
	struct sockaddr_in6 addr_in6;
	int aux_af_inet;
	void *aux_addr_in;
	switch (node->data.parser->request.target.host_type) {
		case IPV4:
			aux_af_inet = AF_INET;
			aux_addr_in = &addr_in4.sin_addr.s_addr;
			break;
		case IPV6:
			aux_af_inet = AF_INET6;
			aux_addr_in = &addr_in6.sin6_addr;
			break;
		default:
			logger(ERROR, "Undefined host type");
			return BAD_REQUEST_ERROR;
	}
	if (inet_pton(aux_af_inet, node->data.parser->request.target.request_target.ip_addr, aux_addr_in) != 1) {
		logger(ERROR, "handle_client_connection(): bad IP address");
		return BAD_REQUEST_ERROR;
	}
	if (add_ip_address(node, aux_af_inet, aux_addr_in) == -1) {
		logger(ERROR, "handle_client_connection(): bad port number");
		return BAD_REQUEST_ERROR;
	}
	return setup_connection(node, &write_fd_set[BASE]);
}

int try_connection(connection_node *node, fd_set read_fd_set[FD_SET_ARRAY_SIZE], fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	int error_code = 0;
	socklen_t error_code_size = sizeof(error_code);
	if (getsockopt(node->data.server_sock, SOL_SOCKET, SO_ERROR, &error_code, &error_code_size) < 0 || error_code > 0) {

		// en caso de error, ver si la conexion fue rechazada, cerrar el socket y probar con la siguiente
		if (error_code == ECONNREFUSED || error_code == ETIMEDOUT) {
			return try_next_addr(node, write_fd_set);
		} else {
			// error de getsockopt respecto al server, liberamos todos los recursos
			logger(ERROR, "handle_server_connection :: getsockopt(): %s", strerror(error_code));
			free_doh_resources(node);
			return SETUP_CONNECTION_ERROR_CODE;
		}
	} else {
		logger_peer(SERVER, "Connected to server with fd %d for client with fd %d", node->data.server_sock,
					node->data.client_sock);
		node->data.connection_state = CONNECTED;
		free_doh_resources(node);
		// en caso que el server mande un primer mensaje, quiero leerlo
		if (read_fd_set != NULL) FD_SET(node->data.server_sock, &read_fd_set[BASE]);
		switch (node->data.parser->data.request_status) {
			case PARSE_CONNECT_METHOD_POP3:
				setup_pop3_response_parser(node);
			case PARSE_CONNECT_METHOD:
				// enviamos al cliente que nos conectamos satisfactoriamente al servidor
				logger(INFO, "Connection established");
				send_message("HTTP/1.1 200 Connection Established\r\n\r\n", node, write_fd_set, STATUS_200);
				node->data.client_information.status_code = STATUS_200;
				print_register(ACCESS, node, write_fd_set);
				buffer_reset(node->data.client_to_server_buffer); // por si quedaron cosas sin parsear del request, las borro
				FD_CLR(node->data.server_sock, &write_fd_set[BASE]);
				close_buffer(node->data.parser->data.parsed_request);
				node->data.parser->data.parsed_request = NULL;
				break;
			default:
				// ya que estoy conectado, me fijo si quedo algo para parsear
				parse_request(node->data.parser, &node->data.client_to_server_buffer);
				if (node->data.parser->data.request_status == PARSE_ERROR) return BAD_REQUEST_ERROR;
				if (node->data.parser->data.parser_state == PS_END) { return CLIENT_CLOSE_READ_ERROR_CODE; }
				break;
		}
	}
	return 0;
}

int try_next_addr(connection_node *node, fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	node->data.addr_info_current = node->data.addr_info_current->next;
	// intentara con la proxima direccion
	logger(INFO, "Connection to address failed from client with fd: %d", node->data.client_sock);

	FD_CLR(node->data.server_sock, &write_fd_set[BASE]);
	close(node->data.server_sock);

	int ans = setup_connection(node, write_fd_set);

	if (ans == SETUP_CONNECTION_ERROR_CODE) {
		// nos quedamos sin addresses en la lista
		logger(ERROR, "try_next_addr(): no more address to connect to server");
		free_doh_resources(node);
		return ans;
	}

	return 0;
}

static void handle_pop3_response(connection_node *node, fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	node->data.parser->pop3->line_count -=
		parse_pop3_response(&node->data.parser->pop3->response, node->data.server_to_client_buffer);
	if (node->data.parser->pop3->line_count == 0 && node->data.parser->pop3->command.credentials_state == POP3_C_FOUND) {
		if (node->data.parser->pop3->response.data.status == POP3_R_POSITIVE_STATUS) {
			// una vez que encontre la password y es correcta, cambio el estado a connect, asi no sniffeo mas
			strcpy(node->data.parser->request.authorization.value, node->data.parser->pop3->command.credentials.username);
			size_t length = strlen(node->data.parser->pop3->command.credentials.username);
			strcpy(node->data.parser->request.authorization.value + length, "    ");
			length += strlen("    ");
			strcpy(node->data.parser->request.authorization.value + length,
				   node->data.parser->pop3->command.credentials.password);
			length += strlen(node->data.parser->pop3->command.credentials.password);
			node->data.parser->request.authorization.value[length] = '\0';
			print_register(PASSWORD, node, write_fd_set);
			// copio las respuestas al buffer original
			copy_from_buffer_to_buffer(node->data.server_to_client_buffer, node->data.parser->pop3->response.response_buffer);
			close_pop3_parser(node);
		} else {
			// dio acceso no autorizado, reseteo la busqueda de credentials
			node->data.parser->pop3->command.credentials_state = POP3_C_NOT_FOUND;
			node->data.parser->pop3->command.prefix_type = POP3_C_UNKNOWN;
		}
	}
}

static int copy_address_info(struct sockaddr *address, char *buffer_address, char *buffer_port) {

	void *ip_address;
	in_port_t port;

	switch (address->sa_family) {
		case AF_INET:
			ip_address = &(((struct sockaddr_in *)address)->sin_addr);
			port = ((struct sockaddr_in *)address)->sin_port;
			break;
		case AF_INET6:
			ip_address = &(((struct sockaddr_in6 *)address)->sin6_addr);
			port = ((struct sockaddr_in6 *)address)->sin6_port;
			break;
		default:
			logger(DEBUG, "Unkown address family");
			return -1;
	}

	if (inet_ntop(address->sa_family, ip_address, buffer_address, INET6_ADDRSTRLEN) == NULL) {
		logger(ERROR, "inet_ntop(): %s", strerror(errno));
		return -1;
	} else {
		if (port > 0) {
			sprintf(buffer_port, "%u", port);
		} else {
			logger(DEBUG, "Invalid port number");
			return -1;
		}
	}
	return 0;
}

static void print_register(register_type register_wanted, connection_node *node, fd_set *write_fd_set) {
	ssize_t actual_length = 0;
	time_t timer = time(NULL);
	struct tm local_time = *localtime(&timer);
	char output[MAX_OUTPUT_REGISTER_LENGTH + MAX_HEADER_VALUE_LENGTH] = {0};
	// only for PASSWORD register
	char aux_buffer_schema[MAX_SCHEMA_LENGTH] = {0};
	char *schema = node->data.parser->request.schema;
	sprintf(output, "%d-%02d-%02dT%02d:%02d:%02dZ", local_time.tm_year + 1900, local_time.tm_mon + 1, local_time.tm_mday,
			local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
	actual_length += strlen(output);
	switch (register_wanted) {
		case ACCESS:
			sprintf(output + actual_length, "    A    [%s]:%s    %s", node->data.client_information.ip,
					node->data.client_information.port, node->data.parser->request.method);
			actual_length += strlen(output + actual_length);
			if (copy_host(output + actual_length, node->data.parser->request.target) < 0) {
				logger(ERROR, "copy_host(): failed");
				return;
			}
			actual_length += strlen(output + actual_length);
			// podria copiar el puerto en copy_host pero se podria cambiar el formato a futuro
			sprintf(output + actual_length, ":%s    %hu\n", node->data.parser->request.target.port,
					node->data.client_information.status_code);

			break;
		case PASSWORD:
			for (int i = 0; schema[i] != '\0'; i++)
				aux_buffer_schema[i] = toupper(schema[i]);
			sprintf(output + actual_length, "    P    %s", aux_buffer_schema);
			actual_length += strlen(output + actual_length);
			if (copy_host(output + actual_length, node->data.parser->request.target) < 0) {
				logger(ERROR, "copy_host(): failed");
				return;
			}
			actual_length += strlen(output + actual_length);
			// podria copiar el puerto en copy_host pero se podria cambiar el formato a futuro
			sprintf(output + actual_length, ":%s    %s\n", node->data.parser->request.target.port,
					node->data.parser->request.authorization.value);
			node->data.parser->request.authorization.value[0] = '\0'; // para que no se vuelva a copiar
			break;
		default:
			break;
	}
	actual_length += strlen(output + actual_length);
	sprintf((char *)connections.stdout_buffer->write, "%s", output);
	buffer_write_adv(connections.stdout_buffer, actual_length);
	connections.stdout_buffer->write[0] = '\0';
	// pongo el stdout en el select para que lea cuando pueda
	FD_SET(STDOUT_FILENO, &write_fd_set[BASE]);
}

static int copy_host(char *buffer, http_target target) {
	switch (target.host_type) {
		case IPV4:
		case IPV6:
			sprintf(buffer, "    [%s]", target.request_target.ip_addr);
			break;
		case DOMAIN:
			sprintf(buffer, "    %s", target.request_target.host_name);
			break;
		default:
			return -1;
			break;
	}
	return 0;
}

static void print_status_code(connection_node *node, fd_set *write_fd_set) {
	if (node->data.client_information.status_code != ALREADY_LOGGED_STATUS) {
		if (node->data.client_information.status_code == NO_STATUS &&
			(node->data.server_to_client_buffer->write - node->data.server_to_client_buffer->read) >=
				(CHARS_BEFORE_STATUS_CODE + STATUS_CODE_LENGTH)) {
			uint8_t *status_response = node->data.server_to_client_buffer->read;
			status_response += CHARS_BEFORE_STATUS_CODE;
			unsigned short status_response_code = 0;
			sscanf((const char *)status_response, "%hu ", &status_response_code);
			node->data.client_information.status_code = (unsigned short)status_response_code;
		}
		print_register(ACCESS, node, write_fd_set);
		node->data.client_information.status_code = ALREADY_LOGGED_STATUS;
	}
}

static void increase_connect_method_bytes(connection_node *node, ssize_t result_bytes) {
	if (node->data.parser->data.request_status == PARSE_CONNECT_METHOD ||
		node->data.parser->data.request_status == PARSE_CONNECT_METHOD_POP3)
		connections.statistics.total_connect_method_bytes += result_bytes;
}
