#include <args.h>
#include <connection.h>
#include <dohclient.h>
#include <dohutils.h>
#include <errno.h>
#include <logger.h>
#include <proxy.h>
#include <proxyutils.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

// Funcion que se encarga de liberar los recursos de una conexion entre un cliente y servidor
static void handle_connection_error(connection_error_code error_code, connection_node *node, connection_node *previous,
									fd_set *write_fd_set, fd_set *read_fd_set, peer peer);
// Funcion para buscar el id maximo entre los sets de escritura y lectura que utiliza el pselect. Utilizada por
// handle_connection_error
static void find_max_id();
// Funcion para imprimir las estadisticas del server
void write_proxy_statistics();

connection_header connections = {0};

int main(const int argc, char **argv) {

	arguments args;
	// TODO: utilizarlos
	parse_args(argc, argv, &args);

	char *proxy_port = args.proxy_port;

	int passive_sock = setup_passive_socket(proxy_port);
	if (passive_sock < 0) logger(FATAL, "setup_passive_socket() failed");

	const char *name = "./logs/proxy_log";
	connections.proxy_log = fopen(name, "w+");
	if (connections.proxy_log == NULL) { logger(FATAL, "fopen: %s", strerror(errno)); }
	logger(DEBUG, "Proxy file log with name %s created", name);

	fprintf(
		connections.proxy_log,
		"Total connections\tCurrent connections\tTranferred bytes\tBytes to origins\tBytes to clients\tBytes through connect\n");

	fd_set write_fd_set[FD_SET_ARRAY_SIZE];
	fd_set read_fd_set[FD_SET_ARRAY_SIZE];

	for (int i = 0; i < FD_SET_ARRAY_SIZE; i++) {
		FD_ZERO(&write_fd_set[i]);
		FD_ZERO(&read_fd_set[i]);
	}

	FD_SET(passive_sock, &read_fd_set[BASE]);

	int ready_fds;
	// TODO: REVISAR SEÑALES
	sigset_t sig_mask;
	sigemptyset(&sig_mask);

	// ignoramos SIGPIPE, dado que tal error lo manejamos nosotros
	signal(SIGPIPE, SIG_IGN);

	connections.max_fd = passive_sock + 1;

	while (1) {
		// resetear fd_set
		read_fd_set[TMP] = read_fd_set[BASE];
		write_fd_set[TMP] = write_fd_set[BASE];

		ready_fds = pselect(connections.max_fd, &read_fd_set[TMP], &write_fd_set[TMP], NULL, NULL, &sig_mask);

		if (FD_ISSET(passive_sock, &read_fd_set[TMP]) && connections.clients <= MAX_CLIENTS) {
			// establezco conexión con cliente en socket activo
			int client_sock = accept_connection(passive_sock);
			if (client_sock > -1) {
				// la consulta DNS para la conexión con el servidor se realiza asincronicamente,
				// esto imposibilita la creación de un socket activo con el servidor hasta que dicha consulta
				// este resulta. Por lo tanto dicho FD arranca en -1 inicialmente.
				// aloco recursos para el respectivo cliente
				connection_node *new_connection = setup_connection_resources(client_sock, -1);
				if (new_connection != NULL) {
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

		int handle;
		// itero por todas las conexiones cliente-servidor
		// TODO: Emprolijar
		for (connection_node *node = connections.first, *previous = NULL; node != NULL && ready_fds > 0;
			 previous = node, node = node->next) {
			if (node->data.connection_state == SENDING_DNS) {
				handle = handle_doh_request(node, write_fd_set);

				switch (handle) {
					case DOH_SEND_ERROR:
						close(node->data.doh->sock);
						free_doh_resources(node);
						close_connection(node, previous, write_fd_set, read_fd_set);
						break;
					case DOH_SEND_COMPLETE:
						node->data.connection_state = FETCHING_DNS;
						FD_SET(node->data.doh->sock, &read_fd_set[BASE]);
					case DOH_SEND_INCOMPLETE:
						ready_fds -= 1;
						break;
					default:
						break;
				}

			} else if (node->data.connection_state == FETCHING_DNS) {
				handle = handle_doh_response(node, read_fd_set);

				if (handle == -1) {
					FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);
					close(node->data.doh->sock);
					free_doh_resources(node);
					close_connection(node, previous, write_fd_set, read_fd_set);

				} else {
					ready_fds -= 1;

					if (handle == 1) {
						FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);

						if (check_requests_sent(node)) {
							int ans_connection = setup_connection(node, write_fd_set);
							if (ans_connection < 0)
								handle_connection_error(ans_connection, node, previous, read_fd_set, write_fd_set, CLIENT);
							// TODO: esta intentando con la proxima direccion? o se deberian liberar todos los recursos?
						} else {
							// Si devolvio 0, todavia tengo requests dns para hacer (los estados se setearon en
							// check_requests_sent)
							FD_SET(node->data.doh->sock, &write_fd_set[BASE]);
							continue;
						}
					}
				}

			} else {
				handle = handle_client_connection(node, previous, read_fd_set, write_fd_set);

				if (handle > -1) ready_fds -= handle;
				else {
					handle_connection_error(handle, node, previous, read_fd_set, write_fd_set, CLIENT);
					break; // para que no atienda al servidor
				}

				handle = handle_server_connection(node, previous, read_fd_set, write_fd_set);

				if (handle > -1) ready_fds -= handle;
				else
					handle_connection_error(handle, node, previous, read_fd_set, write_fd_set, SERVER);

				if(node->data.connection_state == SERVER_READ_CLOSE && !buffer_can_read(node->data.server_to_client_buffer)){
					logger(DEBUG, "CLOSING CLIENT WITH FD: %d FROM PSELECT", node->data.client_sock);
					handle_connection_error(CLOSE_CONNECTION_ERROR_CODE, node, previous, write_fd_set, read_fd_set, SERVER);
				}
			}
		}
		// write_proxy_statistics();
	}
}

static void handle_connection_error(connection_error_code error_code, connection_node *node, connection_node *previous,
									fd_set *write_fd_set, fd_set *read_fd_set, peer peer) {
	switch (error_code) {
		case SERVER_CLOSE_READ_ERROR_CODE:
			logger(DEBUG, "SERVER_CLOSE_READ for client fd: %d", node->data.client_sock);

			node->data.connection_state = SERVER_READ_CLOSE;
			FD_CLR(node->data.server_sock, &read_fd_set[BASE]);
			FD_CLR(node->data.server_sock, &write_fd_set[BASE]);
			FD_CLR(node->data.client_sock, &read_fd_set[BASE]);
			// TODO: FREE DEL SERVIDOR ACA
			return;
		case CLIENT_CLOSE_READ_ERROR_CODE:
			logger(DEBUG, "CLIENT_CLOSE_READ for client fd: %d", node->data.client_sock);

			// dejo de leer del cliente
			FD_CLR(node->data.client_sock, &read_fd_set[BASE]);
			node->data.connection_state = CLIENT_READ_CLOSE;
			return;
		case RECV_ERROR_CODE:
			// dio error el receive, lo dejamos para intentar denuevo luego
			logger_peer(peer, "recv(): error for server_fd: %d and client_fd: %d, READ operation", node->data.server_sock,
						node->data.server_sock);
			return;
		case SEND_ERROR_CODE:
			// el SEND dio algun error inesperado, lo dejo para intentar denuevo en la proxima iteracion
			logger_peer(peer, "send(): error for server_fd: %d and client_fd: %d, WRITE operation", node->data.server_sock,
						node->data.server_sock);
			return;
		case ACCEPT_CONNECTION_ERROR:
			// FIXME: Error message
			send_message("HTTP/1.1 501 Couldnt connect to origin server\r\n\r\n", node->data.client_sock, node);
			break;
		case SETUP_CONNECTION_ERROR_CODE:
			logger(ERROR, "Setup connection failed for client_fd: %d", node->data.server_sock);
			break;
		case CLOSE_CONNECTION_ERROR_CODE:
			logger(INFO, "Closing connection for server_fd: %d and client_fd: %d", node->data.server_sock,
				   node->data.server_sock);
			break;
		case BROKEN_PIPE_ERROR_CODE:
			send_message("HTTP/1.1 500 Internal Server Error\r\n\r\n", node->data.client_sock, node);
			break;
		case INVALID_REQUEST_ERROR_CODE:
			send_message("HTTP/1.1 400 Bad Request\r\n\r\n", node->data.client_sock, node);
			break;
		default:
			logger(INFO, "UNKNOWN ERROR CODE");
			break;
	}

	int aux_server_sock = node->data.server_sock;
	int aux_client_sock = node->data.client_sock;
	// guardo copias de los sockets a borrar, para compararlos con el maximo actual(luego de ser borrados) y decidir
	// si se debe buscar otro maximo
	close_connection(node, previous, write_fd_set, read_fd_set);
	if (aux_server_sock >= connections.max_fd || aux_client_sock >= connections.max_fd) find_max_id();
}

static void find_max_id() {
	for (connection_node *node = connections.first; node != NULL; node = node->next) {
		if (node->data.client_sock >= connections.max_fd) connections.max_fd = node->data.client_sock;
		if (node->data.server_sock >= connections.max_fd) connections.max_fd = node->data.server_sock;
	}
}

void write_proxy_statistics() {
	ssize_t proxy_to_origins = connections.total_proxy_to_origins_bytes;
	ssize_t proxy_to_clients = connections.total_proxy_to_clients_bytes;
	fprintf(connections.proxy_log, "%zd\t\t\t%d\t\t\t%zd\t\t\t%zd\t\t\t%zd\t\t\t%zd\n", connections.total_connections,
			connections.clients, proxy_to_clients + proxy_to_origins, proxy_to_origins, proxy_to_clients,
			connections.total_connect_method_bytes);
}

void send_message(char *message, int fd_client, connection_node *node) {
	// TODO: CAMBIAR A SEND CUANDO SE BORREN LOS LOGS, SE USA BUFFERS SOLO PARA QUE LOGEE EL MENSAJE
	buffer *buffer_response;
	buffer_response = malloc(sizeof(buffer));
	buffer_response->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	buffer_init(buffer_response, BUFFER_SIZE, buffer_response->data);
	strncpy((char *)buffer_response->write, message, strlen(message));
	buffer_write_adv(buffer_response, strlen(message));
	ssize_t result_bytes = handle_operation(fd_client, buffer_response, WRITE, CLIENT, node->data.log_file);
	if (result_bytes <= 0)
		// TODO: enviar denuevo?
		logger(ERROR, "Invalid request from client with fd: %d", fd_client);

	free(buffer_response->data);
	free(buffer_response);

	buffer_reset(node->data.client_to_server_buffer); // por si quedaron cosas sin parsear del request
}
