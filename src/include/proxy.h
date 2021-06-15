#ifndef _PROXY_H_
#define _PROXY_H_

#include "netutils.h"
#include <connection.h>

// TODO: Comentar funciones, enums y estructuras

#define SOCK_COUNT 2
#define IPV4_SOCK 0
#define IPV6_SOCK 1

#define PROXY_TIMEOUT 10

typedef enum { CLIENT, SERVER } peer;

// Constantes para acceder a los FdSets, BASE para el persistente, TMP para el que varia con select
typedef enum {
	BASE = 0,
	TMP = 1,
	FD_SET_ARRAY_SIZE = 2,
	MAX_PENDING = 10,
	MAX_CLIENTS = 510,
	BUFFER_SIZE = 65000, // TODO cambiar a variable para poder editarlo
	MAX_ADDR_BUFFER = 128,
	MAX_OUTPUT_REGISTER_LENGTH = 256,
} proxy_utils_constants;

typedef enum {
	NO_STATUS = 0,
	ALREADY_LOGGED_STATUS = 1,
	STATUS_200 = 200,
	STATUS_400 = 400,
	STATUS_500 = 500,
	STATUS_502 = 502,
} http_status_codes;

void send_message(char *message, connection_node *node, fd_set *write_fd_set, unsigned short status_code);

typedef enum {
	// estos codigos usan valores negativos para distinguirlos de los que si devuelven las funciones involucradas
	BAD_REQUEST_ERROR = -20,
	RECV_ERROR_CODE,			 // fallo el receive por algo no relacionado al que socket sea no bloqueante
	SEND_ERROR_CODE,			 // fallo el send por algo no relacionado al que socket sea no bloqueante
	DOH_ERROR_CODE,				 // fallo el DNS OVER HTTP
	DOH_TRY_ANOTHER_REQUEST,	 // fallo la request hacia el DOH
	ACCEPT_CONNECTION_ERROR,	 // fallo la creacion del socket para el cliente
	SETUP_CONNECTION_ERROR_CODE, // fallo la conexion contra el servidor objetivo
	CLOSE_CONNECTION_ERROR_CODE,
	BROKEN_PIPE_ERROR_CODE,
	CLIENT_CLOSE_READ_ERROR_CODE, // el cliente mando EOF
	SERVER_CLOSE_READ_ERROR_CODE  // el servidor mando EOF
} connection_error_code;

typedef struct {
	uint16_t io_buffer_size;
	uint16_t max_clients;
	uint8_t password_dissector; // 0 es apagado (no tiene en cuenta contraseñas), 1 es encendido
	char doh_host[MAX_DNS_HOST_LENGTH];
	addr_info doh_addr_info;
} proxy_settings;

void write_proxy_statistics();

#endif
