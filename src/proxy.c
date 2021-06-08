#include <connection.h>
#include <dohclient.h>
#include <dohutils.h>
#include <errno.h>
#include <fcntl.h>
#include <http_parser.h>
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
static void handle_connection_error(connection_node *node, connection_node *previous, fd_set *write_fd_set, fd_set *read_fd_set);
// Funcion para buscar el id maximo entre los sets de escritura y lectura que utiliza el pselect. Utilizada por
// handle_connection_error
static void find_max_id();
// Funcion para imprimir las estadisticas del server
void write_proxy_statistics();

connection_header connections = {0};

int main(int argc, char **argv) {
	if (argc != 2) { logger(FATAL, "Usage: %s <Proxy Port>\n", argv[0]); }

	char *proxy_port = argv[1];

	int passive_sock = setup_passive_socket(proxy_port);
	if (passive_sock < 0) logger(FATAL, "setup_passive_socket() failed");

	const char *name = "./logs/proxy_log";
	connections.proxy_log = fopen(name, "w+");
	if (connections.proxy_log == NULL) { logger(FATAL, "fopen: %s", strerror(errno)); }
	logger(DEBUG, "Proxy file log with name %s created", name);

	fprintf(connections.proxy_log, "Total connections\tCurrent connections\tTranferred bytes\tBytes to origins\tBytes to clients\tBytes through connect\n");

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
		for (connection_node *node = connections.first, *previous = NULL; node != NULL && ready_fds > 0;
			 previous = node, node = node->next) {
			if (node->data.connection_state == CONNECTING_TO_DOH) {
				handle = handle_doh_request(node, write_fd_set, read_fd_set);
				if (handle > -1) ready_fds -= handle;
				// TODO: Manejo de error
			} else if (node->data.connection_state == FETCHING_DNS) {
				handle = handle_doh_response(node, read_fd_set);
				if (handle >= 0) {
					ready_fds -= handle;
					if (handle == 1) {
						FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);
						close(node->data.doh->sock);
						if (setup_connection(node, write_fd_set) == -1) {
							logger(ERROR, "setup_connection(): failed to connect");
							// FIXME: ?????
							return -1;
						}
					}
				} else {
					// TODO: Liberar recursos y cliente
					FD_CLR(node->data.doh->sock, &read_fd_set[BASE]);
					close(node->data.doh->sock);
					free_doh_resources(node);
					close_connection(node, previous, write_fd_set, read_fd_set);
				}
			} else {
				handle = handle_client_connection(node, previous, read_fd_set, write_fd_set);
				if (handle > -1) ready_fds -= handle;
				else if (handle == CLOSE_CONNECTION_CODE) {
					// Caso conexion cerrada, veo si no quedo nada para el cliente
					//if (!buffer_can_read(node->data.server_to_client_buffer)) {
						handle_connection_error(node, previous, write_fd_set, read_fd_set);
						break;
					//}
				} else {
					handle_connection_error(node, previous, write_fd_set, read_fd_set);
					break;
				}
				handle = handle_server_connection(node, previous, read_fd_set, write_fd_set);
				if (handle > -1) ready_fds -= handle;
				else if (handle == CLOSE_CONNECTION_CODE) {
					// Caso conexion cerrada, veo si no quedo nada para el cliente
					//if (!buffer_can_read(node->data.server_to_client_buffer)) {
						handle_connection_error(node, previous, write_fd_set, read_fd_set);
						break;
					//}
				} else {
					handle_connection_error(node, previous, write_fd_set, read_fd_set);
					break;
				}
			}
		}
		// write_proxy_statistics();
	}
}

static void handle_connection_error(connection_node *node, connection_node *previous, fd_set *write_fd_set, fd_set *read_fd_set) {
	int aux_server_sock = node->data.server_sock >= connections.max_fd;
	int aux_client_sock = node->data.client_sock >= connections.max_fd;
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
	fprintf(connections.proxy_log, "%zd\t\t\t%d\t\t\t%zd\t\t\t%zd\t\t\t%zd\t\t\t%zd\n", connections.total_connections, connections.clients, proxy_to_clients + proxy_to_origins, proxy_to_origins, proxy_to_clients, connections.total_connect_method_bytes);
}
