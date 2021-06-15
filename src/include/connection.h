#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include <buffer.h>
#include <dohdata.h>
#include <httpparser.h>
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
	buffer *client_to_server_buffer;   // buffer donde cliente escribe y servidor lee
	buffer *server_to_client_buffer;   // buffer donde servidor escribe y cliente lee
	int client_sock;				   // socket activo con cliente
	int server_sock;				   // socket activo con servidor
	connection_state connection_state; // estado de la busqueda DNS
	http_parser *parser;			   // estructura donde se guarda el estado del parseo
	addr_info_node *addr_info_first;   // primer resultado de la consulta doh
	addr_info_node *addr_info_current; // ip para conectarse utilizada actualmente
	information client_information;	   // ip y puerto del cliente, ya formateados
	doh_data *doh;
	time_t timestamp;				   // timestamp de creacion de la conexion
} connection_data;

typedef struct connection_node {
	connection_data data;
	struct connection_node *next;
	struct connection_node *previous;
} connection_node;

typedef struct {
	uint64_t total_connections;
	uint64_t total_proxy_to_origins_bytes;
	uint64_t total_proxy_to_clients_bytes;
	uint64_t total_connect_method_bytes;
} proxy_statistics;

typedef struct {
	int max_fd;
	uint64_t current_clients;
	proxy_statistics statistics;
	connection_node *first;
	connection_node *last;
	buffer *stdout_buffer;
} connection_header;

// Funcion que crea un nuevo nodo para una conexion
connection_node *setup_connection_resources(int client_sock, int server_sock);

// Funcion que agrega un nodo a la lista de nodos
void add_to_connections(connection_node *node);

// Funcion que libera los campos adjudicados al servidor y lo saca de los fd que atiende select
void close_server_connection(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set);

// Funcion que libera el nodo y saca al cliente y al servidor de los fd que atiende el select
void close_connection(connection_node *node, fd_set *read_fd_set, fd_set *write_fd_set);

// Funcion que crea el pop3 command parser
int setup_pop3_command_parser(connection_node *node);

// Funcion que crea el pop3 response parser
int setup_pop3_response_parser(connection_node *node);

// Funcion que libera el parser pop3 y modifica el estado del request a CONNECT
void close_pop3_parser(connection_node *node);

// Funcion que libera el parser pop3 command
void close_pop3_command_parser(connection_node *node);

// Funcion que libera el buffer pasado por parametro
void close_buffer(buffer *buff);

#endif
