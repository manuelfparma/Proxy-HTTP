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

extern proxy_arguments args;

// Funcion que se encarga de liberar los recursos de una conexion entre un cliente y servidor
static int handle_connection_error(connection_error_code error_code, connection_node *node, connection_node *previous,
								   fd_set *read_fd_set, fd_set *write_fd_set, peer peer);
// Funcion que se encarga de manejar la conexion con el doh para resolver la current_request dns
static int handle_doh_exchange(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set);

// Funcion para buscar el id maximo entre los sets de escritura y lectura que utiliza el pselect. Utilizada por
// handle_connection_error
static void find_max_id();

// Funcion para imprimir las estadisticas del server
void write_proxy_statistics();

connection_header connections = {0};
proxy_settings settings = {
	.max_clients = MAX_CLIENTS,
	.io_buffer_size = BUFFER_SIZE
};

int main(const int argc, char **argv) {

	parse_proxy_args(argc, argv);
	settings.password_dissector = args.password_dissector;
	settings.doh_addr_info = args.doh_addr_info;
	strcpy(settings.doh_host, args.doh_host);

	int passive_sock = setup_passive_socket();
	if (passive_sock < 0) logger(FATAL, "setup_passive_socket() failed: %s", strerror(errno));

	int management_sock = setup_pcamp_socket();
	if (management_sock < 0) logger(FATAL, "setup_pcamp_socket() failed: %s", strerror(errno));

	const char *name = "./logs/proxy_log";
	connections.proxy_log = fopen(name, "w+");
	if (connections.proxy_log == NULL) { logger(FATAL, "fopen: %s", strerror(errno)); }
	logger(DEBUG, "Proxy file log with name %s created", name);
	fprintf(connections.proxy_log, "Total connections\tCurrent connections\tTranferred bytes\tBytes to origins\tBytes to "
								   "current_clients\tBytes through connect\n");

	connections.stdout_buffer = malloc(sizeof(buffer));
	if (connections.stdout_buffer == NULL) {
		free(connections.proxy_log);
		logger(FATAL, "malloc(): %s", strerror(errno));
	}
	connections.stdout_buffer->data = malloc(settings.io_buffer_size * sizeof(uint8_t));
	if (connections.stdout_buffer->data == NULL) {
		free(connections.proxy_log);
		free(connections.stdout_buffer);
		logger(FATAL, "malloc(): %s", strerror(errno));
	}
	buffer_init(connections.stdout_buffer, settings.io_buffer_size, connections.stdout_buffer->data);

	fd_set write_fd_set[FD_SET_ARRAY_SIZE];
	fd_set read_fd_set[FD_SET_ARRAY_SIZE];

	for (int i = 0; i < FD_SET_ARRAY_SIZE; i++) {
		FD_ZERO(&write_fd_set[i]);
		FD_ZERO(&read_fd_set[i]);
	}

	// seteo de socket pasivo (lectura)
	FD_SET(passive_sock, &read_fd_set[BASE]);
	FD_SET(management_sock, &read_fd_set[BASE]);

	int ready_fds;
	// TODO: REVISAR SEÑALES
	sigset_t sig_mask;
	sigemptyset(&sig_mask);

	// ignoramos SIGPIPE, dado que tal error lo manejamos nosotros
	signal(SIGPIPE, SIG_IGN);

	connections.max_fd = management_sock + 1;

	while (1) {
		// resetear fd_set
		read_fd_set[TMP] = read_fd_set[BASE];
		write_fd_set[TMP] = write_fd_set[BASE];

		ready_fds = pselect(connections.max_fd, &read_fd_set[TMP], &write_fd_set[TMP], NULL, NULL, &sig_mask);

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
			ready_fds--;
		}

		if (FD_ISSET(passive_sock, &read_fd_set[TMP]) && connections.current_clients <= settings.max_clients) {
			// almaceno el espacio para la info del cliente (ip y puerto)
			char client_ip[MAX_IP_LENGTH + 1] = {0};
			char client_port[MAX_PORT_LENGTH + 1] = {0};
			// establezco conexión con cliente en socket activo
			int client_sock = accept_connection(passive_sock, client_ip, client_port);
			if (client_sock > -1) {
				// la consulta DNS para la conexión con el servidor se realiza asincronicamente,
				// esto imposibilita la creación de un socket activo con el servidor hasta que dicha consulta
				// este resulta. Por lo tanto dicho FD arranca en -1 inicialmente.
				// aloco recursos para el respectivo cliente
				connection_node *new_connection = setup_connection_resources(client_sock, -1);
				if (new_connection != NULL) {
					// cargo los datos del cliente
					strcpy(new_connection->data.client_information.ip, client_ip);
					strcpy(new_connection->data.client_information.port, client_port);

					// acepto lecturas del socket
					FD_SET(client_sock, &read_fd_set[BASE]);
					add_to_connections(new_connection);
					if (client_sock >= connections.max_fd) connections.max_fd = client_sock + 1;
				} else {
					close(client_sock);
					logger(ERROR, "setup_connection_resources() failed with NULL value");
				}
			}
			ready_fds--;
		}

		if (FD_ISSET(management_sock, &read_fd_set[TMP])) {
			handle_pcamp_request(management_sock);
			// TODO valores de retorno
			ready_fds--;
		}

		int handle;
		// itero por todas las conexiones cliente-servidor
		for (connection_node *node = connections.first, *previous = NULL; node != NULL && ready_fds > 0; node = node->next) {
			switch (node->data.connection_state) {
				case SENDING_DNS:
				case FETCHING_DNS:
					handle = handle_doh_exchange(node, read_fd_set, write_fd_set);
					if (handle >= 0) ready_fds -= handle;
					else
						handle_connection_error(handle, node, previous, read_fd_set, write_fd_set, CLIENT);
					break;
				default:
					handle = handle_client_connection(node, read_fd_set, write_fd_set);

					if (handle >= 0) ready_fds -= handle;
					else if (handle_connection_error(handle, node, previous, read_fd_set, write_fd_set, CLIENT) < 0)
						// para que no intente seguir atendiendo a un nodo borrado
						break; // para que no atienda al servidor

					handle = handle_server_connection(node, read_fd_set, write_fd_set);

					if (handle >= 0) ready_fds -= handle;
					else if (handle_connection_error(handle, node, previous, read_fd_set, write_fd_set, SERVER) < 0)
						// para que no intente seguir atendiendo a un nodo borrado
						break;

					if (node->data.connection_state == SERVER_READ_CLOSE &&
						!buffer_can_read(node->data.server_to_client_buffer)) {
						// Ya se cerro el servidor y no hay informacion pendiente para el cliente
						if (handle_connection_error(CLOSE_CONNECTION_ERROR_CODE, node, previous, read_fd_set, write_fd_set,
													SERVER) < 0)
							// para que no intente seguir atendiendo a un nodo borrado
							break;
					}
					// Si no se borro el nodo llego aca, y asigno previous
					previous = node;
			}
		}
	}
}

// Cuando retorna un valor < 0, no se debe volver a atender al nodo en esta iteracion
static int handle_connection_error(connection_error_code error_code, connection_node *node, connection_node *previous,
								   fd_set *read_fd_set, fd_set *write_fd_set, peer peer) {
	switch (error_code) {
		case BAD_REQUEST_ERROR:
			logger(DEBUG, "Invalid request for server_fd: %d and client_fd: %d", node->data.server_sock, node->data.client_sock);
			send_message("HTTP/1.1 400 Bad Request\r\n\r\n", node, write_fd_set);
			break;
			break;
		case RECV_ERROR_CODE:
			// dio error el receive, lo dejamos para intentar denuevo luego
			logger_peer(peer, "recv(): error for server_fd: %d and client_fd: %d, READ operation", node->data.server_sock,
						node->data.server_sock);
			return 0;
		case SEND_ERROR_CODE:
			// el SEND dio algun error inesperado, lo dejo para intentar denuevo en la proxima iteracion
			logger_peer(peer, "send(): error for server_fd: %d and client_fd: %d, WRITE operation", node->data.server_sock,
						node->data.server_sock);
			return 0;
		case DOH_ERROR_CODE:
			FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);
			FD_CLR(node->data.doh->sock, &write_fd_set[BASE]);
			close(node->data.doh->sock);
			free_doh_resources(node);
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node, write_fd_set);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case DOH_TRY_ANOTHER_REQUEST:
			return -1;
		case ACCEPT_CONNECTION_ERROR:
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case SETUP_CONNECTION_ERROR_CODE:
			send_message("HTTP/1.1 502 Service unavailable\r\n\r\n", node, write_fd_set);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case CLOSE_CONNECTION_ERROR_CODE:
			// Cierra toda la conexion
			break;
		case BROKEN_PIPE_ERROR_CODE:
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node, write_fd_set);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		case SERVER_CLOSE_READ_ERROR_CODE:
		case CLIENT_CLOSE_READ_ERROR_CODE:
			close_server_connection(node, read_fd_set, write_fd_set);
			node->data.connection_state = SERVER_READ_CLOSE;
			return 0;
		default:
			logger(ERROR, "UNKNOWN ERROR CODE");
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node, write_fd_set);
			break;
	}
	int aux_server_sock = node->data.server_sock;
	int aux_client_sock = node->data.client_sock;
	// guardo copias de los sockets a borrar, para compararlos con el maximo actual(luego de ser borrados) y decidir
	// si se debe buscar otro maximo
	close_connection(node, previous, read_fd_set, write_fd_set);
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

void write_proxy_statistics() {
	uint64_t proxy_to_origins = connections.statistics.total_proxy_to_origins_bytes;
	uint64_t proxy_to_clients = connections.statistics.total_proxy_to_clients_bytes;
	fprintf(connections.proxy_log,
			"%" PRIu64 "\t\t\t%" PRIu64 "\t\t\t%" PRIu64 "\t\t\t%" PRIu64 "\t\t\t%" PRIu64 "\t\t\t%" PRIu64 "\n",
			connections.statistics.total_connections, connections.current_clients, proxy_to_clients + proxy_to_origins,
			proxy_to_origins, proxy_to_clients, connections.statistics.total_connect_method_bytes);
}

void send_message(char *message, connection_node *node, fd_set *write_fd_set) {
	int bytes_available = node->data.server_to_client_buffer->limit - node->data.server_to_client_buffer->write;
	int bytes_to_copy = strlen(message);
	int bytes_copied = (bytes_available > bytes_to_copy) ? bytes_to_copy : bytes_available;
	logger(DEBUG, "bytes_copied: %d, string: %s", bytes_copied, message);
	strncpy((char *)node->data.server_to_client_buffer->write, message, bytes_copied);
	buffer_write_adv(node->data.server_to_client_buffer, bytes_copied);
	FD_SET(node->data.client_sock, &write_fd_set[BASE]);
}
