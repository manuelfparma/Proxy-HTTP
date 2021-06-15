#include <connection.h>
#include <errno.h>
#include <httpparser.h>
#include <logger.h>
#include <proxy.h>
#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

extern connection_header connections;
extern proxy_settings settings;

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
	node->data.client_information.status_code = NO_STATUS;
	node->data.client_information.ip[0] = '\0';
	node->data.client_information.port[0] = '\0';

	// parser info
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
	node->data.parser->request.authorization.value[0] = '\0';
	node->data.parser->pop3 = NULL;

	buffer_init(node->data.client_to_server_buffer, settings.io_buffer_size, node->data.client_to_server_buffer->data);
	buffer_init(node->data.server_to_client_buffer, settings.io_buffer_size, node->data.server_to_client_buffer->data);
	buffer_init(node->data.parser->data.parsed_request, settings.io_buffer_size, node->data.parser->data.parsed_request->data);

	node->data.addr_info_first = node->data.addr_info_current = NULL;
	node->data.timestamp = time(NULL);
}

connection_node *setup_connection_resources(int client_sock, int server_sock) {
	// asignacion de recursos para la conexion
	connection_node *new = malloc(sizeof(connection_node));

	if (new == NULL) goto ERROR;

	new->next = NULL;
	new->data.client_sock = client_sock;
	new->data.server_sock = server_sock;

	new->data.client_information.ip = malloc(MAX_IP_LENGTH + 1);
	if (new->data.client_information.ip == NULL) goto FREE_NEW;

	new->data.client_information.port = malloc(MAX_PORT_LENGTH + 1);
	if (new->data.client_information.port == NULL) goto FREE_CLIENT_IP;

	new->data.client_to_server_buffer = malloc(sizeof(buffer));
	if (new->data.client_to_server_buffer == NULL) goto FREE_CLIENT_PORT;

	new->data.client_to_server_buffer->data = malloc(settings.io_buffer_size * sizeof(uint8_t));
	if (new->data.client_to_server_buffer->data == NULL) goto FREE_BUFFER_1;

	new->data.server_to_client_buffer = malloc(sizeof(buffer));
	if (new->data.server_to_client_buffer == NULL) goto FREE_BUFFER_1_DATA;

	new->data.server_to_client_buffer->data = malloc(settings.io_buffer_size * sizeof(uint8_t));
	if (new->data.server_to_client_buffer->data == NULL) goto FREE_BUFFER_2;

	new->data.connection_state = DISCONNECTED;

	new->data.parser = malloc(sizeof(http_parser));
	if (new->data.parser == NULL) goto FREE_BUFFER_2_DATA;

	new->data.parser->data.parsed_request = malloc(sizeof(buffer));
	if (new->data.parser->data.parsed_request == NULL) goto FREE_REQUEST;

	new->data.parser->data.parsed_request->data = malloc(settings.io_buffer_size * sizeof(uint8_t));
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
FREE_CLIENT_PORT:
	free(new->data.client_information.port);
FREE_CLIENT_IP:
	free(new->data.client_information.ip);
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
	connections.statistics.total_connections++;
	connections.current_clients++;
}

void close_server_connection(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set) {
	int client_fd = node->data.client_sock, server_fd = node->data.server_sock;
	logger_peer(SERVER, "Socket with fd: %d disconnected", server_fd);
	close_buffer(node->data.client_to_server_buffer);

	switch (node->data.parser->data.request_status) {
		case PARSE_BODY_INCOMPLETE:
		case PARSE_CONNECT_METHOD:
			break;
		case PARSE_CONNECT_METHOD_POP3:
			close_pop3_command_parser(node);
			break;
		default:
			close_buffer(node->data.parser->data.parsed_request);
	}

	free(node->data.parser);
	FD_CLR(client_fd, &read_fd_set[BASE]);
	FD_CLR(server_fd, &read_fd_set[BASE]);
	FD_CLR(server_fd, &write_fd_set[BASE]);
	close(server_fd);
	node->data.server_sock = -2;
}

void close_pop3_response_parser(connection_node *node) {
	close_buffer(node->data.parser->pop3->response.response_buffer);
	node->data.parser->pop3->response.response_buffer = NULL;
}

void close_pop3_command_parser(connection_node *node) {
	if (node->data.parser->pop3->command.command_buffer != NULL) {
		close_buffer(node->data.parser->pop3->command.command_buffer);
		node->data.parser->pop3->command.command_buffer = NULL;
	}
}

void close_pop3_parser(connection_node *node) {
	if (node->data.parser->pop3 == NULL) {
		// si la conexion no se completa, no se malloquean los recursos del parser
		return;
	}

	close_pop3_command_parser(node);
	close_pop3_response_parser(node);
	free(node->data.parser->pop3);
}

void close_connection(connection_node *node, connection_node *previous, fd_set *read_fd_set, fd_set *write_fd_set) {
	int client_fd = node->data.client_sock, server_fd = node->data.server_sock;
	logger_peer(CLIENT, "Socket with fd: %d disconnected", client_fd);
	if (server_fd >= 0) {
		close_server_connection(node, read_fd_set, write_fd_set);
	} else if (server_fd == -1){
		free(node->data.parser);
		close_buffer(node->data.client_to_server_buffer);
	}
	free(node->data.server_to_client_buffer->data);
	free(node->data.server_to_client_buffer);
	free(node->data.client_information.ip);
	free(node->data.client_information.port);
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
	close(client_fd);

	if (connections.current_clients != 0) {
		connections.current_clients--;
	} else {
		logger(FATAL, "close_connection called when current_clients = 0");
	}

	write_proxy_statistics();
}

int setup_pop3_response_parser(connection_node *node) {
	node->data.parser->pop3->response.response_buffer = malloc(sizeof(buffer));
	if (node->data.parser->pop3->response.response_buffer == NULL) {
		node->data.parser->data.request_status = PARSE_CONNECT_METHOD;
		close_pop3_parser(node);
		return -1;
	}

	node->data.parser->pop3->response.response_buffer->data = malloc(settings.io_buffer_size * sizeof(uint8_t));
	if (node->data.parser->pop3->response.response_buffer->data == NULL) {
		node->data.parser->data.request_status = PARSE_CONNECT_METHOD;
		close_pop3_parser(node);
		return -1;
	}

	buffer_init(node->data.parser->pop3->response.response_buffer, settings.io_buffer_size,
				node->data.parser->pop3->response.response_buffer->data);

	return 0;
}

int setup_pop3_command_parser(connection_node *node) {
	node->data.parser->pop3 = malloc(sizeof(http_pop3_parser));
	if (node->data.parser->pop3 == NULL) { return -1; }

	node->data.parser->pop3->command.command_buffer = malloc(sizeof(buffer));

	if (node->data.parser->pop3->command.command_buffer == NULL) {
		node->data.parser->data.request_status = PARSE_CONNECT_METHOD;
		free(node->data.parser->pop3);
		return -1;
	}

	node->data.parser->pop3->command.command_buffer->data = malloc(settings.io_buffer_size * sizeof(uint8_t));

	if (node->data.parser->pop3->command.command_buffer->data == NULL) {
		node->data.parser->data.request_status = PARSE_CONNECT_METHOD;
		free(node->data.parser->pop3->command.command_buffer);
		free(node->data.parser->pop3);
		return -1;
	}

	buffer_init(node->data.parser->pop3->command.command_buffer, settings.io_buffer_size,
				node->data.parser->pop3->command.command_buffer->data);

	node->data.parser->pop3->response.parser_state = POP3_R_PS_STATUS;
	node->data.parser->pop3->command.parser_state = POP3_C_PS_PREFIX;
	node->data.parser->pop3->command.copy_index = 0;
	node->data.parser->pop3->command.credentials.username[0] = '\0';
	node->data.parser->pop3->command.credentials.password[0] = '\0';
	node->data.parser->pop3->command.credentials_state = POP3_C_NOT_FOUND;
	node->data.parser->pop3->command.line.prefix[0] = '\0';
	node->data.parser->pop3->command.line.value[0] = '\0';
	node->data.parser->pop3->line_count = 1;
	// El servidor responde primero con un accepted connection, por lo que ya hay una linea para leer
	buffer_reset(node->data.client_to_server_buffer);
	logger(DEBUG, "POP3 PARSER MALLOQUEADO");
	return 0;
}

void close_buffer(buffer *buff) {
	free(buff->data);
	free(buff);
}
