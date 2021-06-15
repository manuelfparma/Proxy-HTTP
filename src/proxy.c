// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <connection.h>
#include <dohclient.h>
#include <dohutils.h>
#include <errno.h>
#include <inttypes.h>
#include <logger.h>
#include <pcampserver.h>
#include <proxy.h>
#include <proxyargs.h>
#include <proxyutils.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

extern proxy_arguments args;

// Funcion que se encarga de levantar argumentos, inicializar estructuras, sockets y FD sets.
// Devuelve 0 en caso exitoso, -1 en caso de error.
static int proxy_init(int argc, char **argv, int management_sockets[SOCK_COUNT], int proxy_sockets[SOCK_COUNT],
					  fd_set read_fd_set[FD_SET_ARRAY_SIZE], fd_set write_fd_set[FD_SET_ARRAY_SIZE]);

// Funcion que intenta aceptar un nuevo cliente del proxy y crear un socket activo con el mismo.
// Devuelve true en caso de que haya podido aceptarlo, false en caso contrario
static void try_accept_proxy_client(int passive_sock, fd_set *read_fd_set);

// Funcion que itera por lista de conexiones y trata a cada una de ellas
static void handle_connection_list(fd_set read_fd_set[2], fd_set write_fd_set[2]);

// Funcion que se encarga de liberar los recursos de una conexion entre un cliente y servidor
static int handle_connection_error(connection_error_code error_code, connection_node *node, fd_set *read_fd_set,
								   fd_set *write_fd_set, peer peer);
// Funcion que se encarga de manejar la conexion con el doh para resolver la current_request dns
static int handle_doh_exchange(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set);

// Funcion para buscar el id maximo entre los sets de escritura y lectura que utiliza el pselect. Utilizada por
// handle_connection_error
static void find_max_id();

connection_header connections = {0};
proxy_settings settings = {.max_clients = MAX_CLIENTS, .io_buffer_size = BUFFER_SIZE};

int main(const int argc, char **argv) {

	int management_sockets[SOCK_COUNT];
	int proxy_passive_sockets[SOCK_COUNT];
	fd_set read_fd_set[FD_SET_ARRAY_SIZE];
	fd_set write_fd_set[FD_SET_ARRAY_SIZE];

	if (proxy_init(argc, argv, management_sockets, proxy_passive_sockets, read_fd_set, write_fd_set) < 0) {
		logger(FATAL, "proxy_init(): error while initializing proxy resources");
	}

	struct timeval timeout = {PROXY_TIMEOUT, 0};

	printf("Proxy up and running\n");

	while (1) {
		// resetear fd_set
		read_fd_set[TMP] = read_fd_set[BASE];
		write_fd_set[TMP] = write_fd_set[BASE];

		timeout.tv_sec = PROXY_TIMEOUT;
		select(connections.max_fd, &read_fd_set[TMP], &write_fd_set[TMP], NULL, &timeout);

		if (FD_ISSET(STDOUT_FILENO, &write_fd_set[TMP]) && buffer_can_read(connections.stdout_buffer)) {
			ssize_t result_bytes = write(STDOUT_FILENO, connections.stdout_buffer->read,
										 connections.stdout_buffer->write - connections.stdout_buffer->read);
			if (result_bytes < 0) {
				if (errno != EWOULDBLOCK && errno != EAGAIN) {
					// error inesperado, no intento escribirle mas
					FD_CLR(STDOUT_FILENO, &write_fd_set[BASE]);
				}
			} else {
				buffer_read_adv(connections.stdout_buffer, result_bytes);
				if (!buffer_can_read(connections.stdout_buffer)) FD_CLR(STDOUT_FILENO, &write_fd_set[BASE]);
			}
		}

		for (int i = 0; i < SOCK_COUNT; i++)
			if (proxy_passive_sockets[i] != -1) try_accept_proxy_client(proxy_passive_sockets[i], read_fd_set);

		for (int i = 0; i < SOCK_COUNT; i++) {
			if (management_sockets[i] != -1 && FD_ISSET(management_sockets[i], &read_fd_set[TMP])) {
				handle_pcamp_request(management_sockets[i]);
			}
		}

		handle_connection_list(read_fd_set, write_fd_set);
	}
}

static int proxy_init(int argc, char **argv, int management_sockets[SOCK_COUNT], int proxy_sockets[SOCK_COUNT],
					  fd_set read_fd_set[FD_SET_ARRAY_SIZE], fd_set write_fd_set[FD_SET_ARRAY_SIZE]) {
	parse_proxy_args(argc, argv);
	settings.password_dissector = args.password_dissector;
	settings.doh_addr_info = args.doh_addr_info;
	strcpy(settings.doh_host, args.doh_host);

	// Liberamos STDIN y STDERR ya que no lo usamos
	close(STDIN_FILENO);
//	close(STDERR_FILENO);

	if (setup_proxy_passive_sockets(proxy_sockets) < 0) {
		goto INIT_ERROR;
	}

	if (setup_pcamp_sockets(management_sockets) < 0) {
		goto CLOSE_PROXY_SOCKETS;
	}

	connections.stdout_buffer = malloc(sizeof(buffer));
	if (connections.stdout_buffer == NULL) {
		goto CLOSE_MANAGEMENT_SOCKETS;
	}
	connections.stdout_buffer->data = malloc(settings.io_buffer_size * sizeof(uint8_t));
	if (connections.stdout_buffer->data == NULL) {
		goto FREE_STDOUT_BUFFER;
	}
	buffer_init(connections.stdout_buffer, settings.io_buffer_size, connections.stdout_buffer->data);

	for (int i = 0; i < FD_SET_ARRAY_SIZE; i++) {
		FD_ZERO(&write_fd_set[i]);
		FD_ZERO(&read_fd_set[i]);
	}

	// seteo de sockets pasivos (lectura)
	for (int i = 0; i < SOCK_COUNT; i++) {
		if (proxy_sockets[i] != -1) {
			FD_SET(proxy_sockets[i], &read_fd_set[BASE]);
			if (connections.max_fd <= proxy_sockets[i]) connections.max_fd = proxy_sockets[i] + 1;
		}

		if (management_sockets[i] != -1) {
			FD_SET(management_sockets[i], &read_fd_set[BASE]);
			if (connections.max_fd <= management_sockets[i]) connections.max_fd = management_sockets[i] + 1;
		}
	}

	// ignoramos SIGPIPE, dado que tal error lo manejamos nosotros
	signal(SIGPIPE, SIG_IGN);

	return 0;

FREE_STDOUT_BUFFER:
	free(connections.stdout_buffer);
CLOSE_MANAGEMENT_SOCKETS:
	for (int i = 0; i < SOCK_COUNT; i++)
		if (management_sockets[i] != -1) close(management_sockets[i]);
CLOSE_PROXY_SOCKETS:
	for (int i = 0; i < SOCK_COUNT; i++)
		if (proxy_sockets[i] != -1) close(proxy_sockets[i]);
INIT_ERROR:
	return -1;
}

static void try_accept_proxy_client(int passive_sock, fd_set *read_fd_set) {
	if (FD_ISSET(passive_sock, &read_fd_set[TMP]) && connections.current_clients < settings.max_clients) {
		char client_ip_str[MAX_IP_LENGTH + 1] = {0};
		char client_port_str[MAX_PORT_LENGTH + 1] = {0};

		int client_sock = accept_connection(passive_sock, client_ip_str, client_port_str);
		if (client_sock >= 0) {
			connection_node *new_connection = setup_connection_resources(client_sock, -1);
			if (new_connection == NULL) {
				close(client_sock);
				return;
			}

			strcpy(new_connection->data.client_information.ip, client_ip_str);
			strcpy(new_connection->data.client_information.port, client_port_str);

			FD_SET(client_sock, &read_fd_set[BASE]);
			add_to_connections(new_connection);
			if (client_sock >= connections.max_fd) connections.max_fd = client_sock + 1;
		}
	}
}

static void handle_connection_list(fd_set read_fd_set[2], fd_set write_fd_set[2]) {
	int handle;
	connection_node *next;
	// itero por todas las conexiones cliente-servidor
	for (connection_node *node = connections.first; node != NULL; node = next) {
		next = node->next;
		switch (node->data.connection_state) {
			case SENDING_DNS:
			case FETCHING_DNS:
				handle = handle_doh_exchange(node, read_fd_set, write_fd_set);
				if (handle < 0) handle_connection_error(handle, node, read_fd_set, write_fd_set, CLIENT);
				break;
			default:
				if (time(NULL) - node->data.timestamp >= PROXY_TIMEOUT &&
					node->data.parser->data.request_status != PARSE_CONNECT_METHOD_POP3) {
					if (node->data.connection_state == CONNECTING) {
						handle = try_next_addr(node, write_fd_set);
						if (handle == 0) break;
					}
					handle_connection_error(CLOSE_CONNECTION_ERROR_CODE, node, read_fd_set, write_fd_set, CLIENT);
					break;
				}

				handle = handle_client_connection(node, read_fd_set, write_fd_set);

				if (handle < 0 && handle_connection_error(handle, node, read_fd_set, write_fd_set, CLIENT) < 0)
					// para que no intente seguir atendiendo a un nodo borrado
					break; // para que no atienda al servidor

				if (node->data.server_sock >= 0) {
					handle = handle_server_connection(node, read_fd_set, write_fd_set);

					if (handle < 0 && handle_connection_error(handle, node, read_fd_set, write_fd_set, SERVER) < 0)
						// para que no intente seguir atendiendo a un nodo borrado
						break;
				}

				if (node->data.connection_state == SERVER_READ_CLOSE && !buffer_can_read(node->data.server_to_client_buffer)) {
					// Ya se cerro el servidor y no hay informacion pendiente para el cliente
					if (handle_connection_error(CLOSE_CONNECTION_ERROR_CODE, node, read_fd_set, write_fd_set, SERVER) < 0)
						// para que no intente seguir atendiendo a un nodo borrado
						break;
				}
		}
	}
}
// Cuando retorna un valor < 0, no se debe volver a atender al nodo en esta iteracion
static int handle_connection_error(connection_error_code error_code, connection_node *node, fd_set *read_fd_set,
								   fd_set *write_fd_set, peer peer) {
	switch (error_code) {
		case BAD_REQUEST_ERROR:
			send_message("HTTP/1.1 400 Bad Request\r\n\r\n", node, write_fd_set, STATUS_400);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case RECV_ERROR_CODE:
			// dio error el receive, lo dejamos para intentar denuevo luego
		case SEND_ERROR_CODE:
			// el SEND dio algun error inesperado, lo dejo para intentar denuevo en la proxima iteracion
			return 0;
		case DOH_ERROR_CODE:
			FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);
			FD_CLR(node->data.doh->sock, &write_fd_set[BASE]);
			close(node->data.doh->sock);
			free_doh_resources(node);
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node, write_fd_set, STATUS_500);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case DOH_TRY_ANOTHER_REQUEST:
			return -1;
		case SETUP_CONNECTION_ERROR_CODE:
			send_message("HTTP/1.1 502 Service Unavailable\r\n\r\n", node, write_fd_set, STATUS_502);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case CLOSE_CONNECTION_ERROR_CODE:
			// Cierra toda la conexion
			break;
		case BROKEN_PIPE_ERROR_CODE:
			if (node->data.connection_state == SERVER_READ_CLOSE) break;
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node, write_fd_set, STATUS_500);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case SERVER_CLOSE_READ_ERROR_CODE:
		case CLIENT_CLOSE_READ_ERROR_CODE:
			if (node->data.server_sock > 0) close_server_connection(node, read_fd_set, write_fd_set);
			node->data.connection_state = SERVER_READ_CLOSE;
			FD_SET(node->data.client_sock, &write_fd_set[BASE]);
			return -1;
		default:
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node, write_fd_set, STATUS_500);
			break;
	}
	int aux_server_sock = node->data.server_sock;
	int aux_client_sock = node->data.client_sock;
	// guardo copias de los sockets a borrar, para compararlos con el maximo actual(luego de ser borrados) y decidir
	// si se debe buscar otro maximo
	close_connection(node, read_fd_set, write_fd_set);
	if (aux_server_sock >= connections.max_fd || aux_client_sock >= connections.max_fd) find_max_id();
	return -1;
}

static int handle_doh_exchange(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set) {
	int handle;
	if (node->data.connection_state == SENDING_DNS) {
		handle = handle_doh_request(node, write_fd_set);

		switch (handle) {
			case DOH_SEND_ERROR:
				return DOH_ERROR_CODE;
			case DOH_SEND_COMPLETE:
				node->data.connection_state = FETCHING_DNS;
				FD_SET(node->data.doh->sock, &read_fd_set[BASE]);
			case DOH_SEND_INCOMPLETE:
				return 1;
			default:
				break;
		}

	} else {
		handle = handle_doh_response(node, read_fd_set);

		if (handle == -1) {
			FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);
			return DOH_ERROR_CODE;
		} else {
			if (handle == 1) {
				FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);

				if (check_requests_sent(node)) {
					int ans_connection = setup_connection(node, write_fd_set);
					if (ans_connection < 0) return ans_connection;
				} else {
					// Si devolvio 0, todavia tengo requests dns para hacer (los estados se setearon en
					// check_requests_sent)
					FD_SET(node->data.doh->sock, &write_fd_set[BASE]);
					return DOH_TRY_ANOTHER_REQUEST;
				}
			}
			return 1;
		}
	}
	return 0;
}

static void find_max_id() {
	for (connection_node *node = connections.first; node != NULL; node = node->next) {
		if (node->data.client_sock >= connections.max_fd) connections.max_fd = node->data.client_sock;
		if (node->data.server_sock >= connections.max_fd) connections.max_fd = node->data.server_sock;
	}
}

void send_message(char *message, connection_node *node, fd_set *write_fd_set, unsigned short status_code) {
	int bytes_available = node->data.server_to_client_buffer->limit - node->data.server_to_client_buffer->write;
	int bytes_to_copy = strlen(message);
	int bytes_copied = (bytes_available > bytes_to_copy) ? bytes_to_copy : bytes_available;
	if (node->data.parser->data.request_status == PARSE_CONNECT_METHOD_POP3) {
		strncpy((char *)node->data.parser->pop3->response.response_buffer->write, message, bytes_copied);
		buffer_write_adv(node->data.parser->pop3->response.response_buffer, bytes_copied);
	} else {
		strncpy((char *)node->data.server_to_client_buffer->write, message, bytes_copied);
		buffer_write_adv(node->data.server_to_client_buffer, bytes_copied);
	}
	FD_SET(node->data.client_sock, &write_fd_set[BASE]);
	node->data.client_information.status_code = status_code;
}
