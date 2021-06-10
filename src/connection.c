#include <connection.h>
#include <errno.h>
#include <http_parser.h>
#include <logger.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <proxy.h>

extern connection_header connections;

static size_t connection_number = 1;

static size_t power(size_t base, size_t exp) {
	size_t ret = 1;
	for (size_t i = 0; i < exp; i++) {
		ret *= base;
	}
	return ret;
}

static void number_to_str(size_t n, char *buffer) {
	size_t copy_n = n, length = 0;
	for (; copy_n > 0; copy_n /= 10, length++) {};
	copy_n = n;
	for (size_t i = 0; copy_n > 0; i++, copy_n /= 10) {
		buffer[i] = '0' + ((n / power(10, length - i - 1)) % 10);
	}
}

static void set_node_default_values(connection_node *node) {
	node->data.parser->data.parser_state = PS_METHOD;
	node->data.parser->data.request_status = PARSE_START_LINE_INCOMPLETE;
	node->data.parser->data.target_status = NOT_FOUND;
	node->data.parser->data.copy_index = 0;
	node->data.parser->request.method[0] = '\0';
	node->data.parser->request.schema[0] = '\0';
	node->data.parser->request.target.port[0] = '\0';
	node->data.parser->request.target.relative_path[0] = '\0';
	node->data.parser->request.version.major = EMPTY_VERSION;
	node->data.parser->request.version.minor = EMPTY_VERSION;
	node->data.parser->request.header.type[0] = '\0';
	node->data.parser->request.header.value[0] = '\0';

	buffer_init(node->data.client_to_server_buffer, BUFFER_SIZE, node->data.client_to_server_buffer->data);
	buffer_init(node->data.server_to_client_buffer, BUFFER_SIZE, node->data.server_to_client_buffer->data);
	buffer_init(node->data.parser->data.parsed_request, BUFFER_SIZE, node->data.parser->data.parsed_request->data);

	node->data.addr_info_first = node->data.addr_info_current = NULL;
}

connection_node *setup_connection_resources(int client_sock, int server_sock) {
	// asignacion de recursos para la conexion
	connection_node *new = malloc(sizeof(connection_node));

	if (new->data.client_to_server_buffer == NULL) goto ERROR;

	new->next = NULL;
	new->data.client_sock = client_sock;
	new->data.server_sock = server_sock;

	new->data.client_to_server_buffer = malloc(sizeof(buffer));
	if (new->data.client_to_server_buffer == NULL) goto FREE_NEW;

	new->data.client_to_server_buffer->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.client_to_server_buffer->data == NULL) goto FREE_BUFFER_1;

	new->data.server_to_client_buffer = malloc(sizeof(buffer));
	if (new->data.server_to_client_buffer == NULL) goto FREE_BUFFER_1_DATA;

	new->data.server_to_client_buffer->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.server_to_client_buffer->data == NULL) goto FREE_BUFFER_2;

	new->data.connection_state = DISCONNECTED;

	new->data.parser = malloc(sizeof(http_parser));
	if (new->data.parser == NULL) goto FREE_BUFFER_2_DATA;

	new->data.parser->data.parsed_request = malloc(sizeof(buffer));
	if (new->data.parser->data.parsed_request == NULL) goto FREE_REQUEST;

	new->data.parser->data.parsed_request->data = malloc(BUFFER_SIZE * sizeof(uint8_t));
	if (new->data.parser->data.parsed_request->data == NULL) goto FREE_REQUEST_BUFFER;

	set_node_default_values(new);

	char file_name[1024] = {0};
	const char *name = "./logs/log_connection_";
	strcpy(file_name, name);
	char number[1024] = {0};
	number_to_str(connection_number++, number);
	strcpy(file_name + strlen(name), number);
	new->data.log_file = fopen(file_name, "w+");
	if (new->data.log_file == NULL) {
		logger(ERROR, "fopen: %s", strerror(errno));
		goto FREE_REQUEST_BUFFER;
	}

	return new;

FREE_REQUEST_BUFFER:
	free(new->data.parser->data.parsed_request);
FREE_REQUEST:
	free(new->data.parser);
FREE_BUFFER_2_DATA:
	free(new->data.server_to_client_buffer->data);
FREE_BUFFER_2:
	free(new->data.server_to_client_buffer);
FREE_BUFFER_1_DATA:
	free(new->data.client_to_server_buffer->data);
FREE_BUFFER_1:
	free(new->data.client_to_server_buffer);
FREE_NEW:
	free(new);
ERROR:
	logger(ERROR, "malloc(): %s", strerror(errno));
	return NULL;
}

void add_to_connections(connection_node *node) {
	//	busqueda para la insercion
	connection_node *last = connections.first;
	if (last != NULL) {
		while (last->next != NULL) {
			last = last->next;
		}
		last->next = node;
	} else {
		connections.first = node;
	}
	connections.total_connections++;
	connections.clients++;
}

void close_connection(connection_node *node, connection_node *previous, fd_set *read_fd_set, fd_set *write_fd_set) {
	int client_fd = node->data.client_sock, server_fd = node->data.server_sock;
	logger_peer(CLIENT, "Socket with fd: %d disconnected", client_fd);
	logger_peer(SERVER, "Socket with fd: %d disconnected", server_fd);
	free(node->data.server_to_client_buffer->data);
	free(node->data.client_to_server_buffer->data);
	free(node->data.client_to_server_buffer);
	free(node->data.server_to_client_buffer);
	free(node->data.parser->data.parsed_request->data);
	free(node->data.parser->data.parsed_request);
	free(node->data.parser);
	fclose(node->data.log_file);

	if (previous == NULL) {
		// Caso primer nodo
		connections.first = node->next;
	} else {
		previous->next = node->next;
	}

	free(node);

	FD_CLR(client_fd, &read_fd_set[BASE]);
	FD_CLR(client_fd, &write_fd_set[BASE]);
	FD_CLR(server_fd, &read_fd_set[BASE]);
	FD_CLR(server_fd, &write_fd_set[BASE]);
	close(client_fd);
	if (server_fd > 0) close(server_fd);
	write_proxy_statistics();
	connections.clients--;
}
