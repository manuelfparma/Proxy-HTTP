#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <buffer.h>
#include <dohdata.h>
#include <http_parser.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/select.h>

// Manejo de estados para getaddrinfo, la cual se corre en otro hilo
typedef enum {
	DISCONNECTED,
	SENDING_DNS,
	FETCHING_DNS,
	CONNECTING,
	CONNECTED,
	// A partir de este valor, se asume que el cliente dejo de escribir
	CLIENT_READ_CLOSE,
	SERVER_READ_CLOSE,
} connection_state;

typedef struct addr_info_node {
	union {
		struct sockaddr_storage storage;
		struct sockaddr addr;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
	struct addr_info_node *next;
} addr_info_node;

typedef struct {
	char *ip;
	char *port;
	unsigned short status_code;
} information;

typedef struct {
	buffer *client_to_server_buffer;   	// buffer donde cliente escribe y servidor lee
	buffer *server_to_client_buffer;   	// buffer donde servidor escribe y cliente lee
	int client_sock;				   	// socket activo con cliente
	int server_sock;				   	// socket activo con servidor
	connection_state connection_state; 	// estado de la busqueda DNS
	http_parser *parser;			   	// estructura donde se guarda el estado del parseo
	FILE *log_file;
	addr_info_node *addr_info_first;   	// primer resultado de la consulta doh
	addr_info_node *addr_info_current; 	// ip para conectarse utilizada actualmente
	information client_information;			// ip y puerto del cliente, ya formateados
	doh_data *doh;
} connection_data;

typedef struct connection_node {
	connection_data data;
	struct connection_node *next;
} connection_node;

typedef struct {
	unsigned int clients;
	int max_fd;
	ssize_t total_connections;
	ssize_t total_proxy_to_origins_bytes;
	ssize_t total_proxy_to_clients_bytes;
	ssize_t total_connect_method_bytes;
	connection_node *first;
	FILE *proxy_log;
} connection_header;

connection_node *setup_connection_resources(int client_sock, int server_sock);

void add_to_connections(connection_node *node);

void close_server_connection(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set);

void close_connection(connection_node *node, connection_node *previous, fd_set *read_fd_set, fd_set *write_fd_set);

#endif
