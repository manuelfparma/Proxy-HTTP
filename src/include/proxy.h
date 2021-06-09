#ifndef _PROXY_H_
#define _PROXY_H_

#include <connection.h>

typedef enum { CLIENT, SERVER } peer;

void write_proxy_statistics();

void send_message(char *message, int fd_client, connection_node *node);

typedef enum {
	TRY_CLOSE_CONNECTION_ERROR_CODE =
		-20,		 // estos codigos usan valores negativos para distinguirlos de los que si devuelven las funciones involucradas
	BAD_REQUEST_ERROR,
	RECV_ERROR_CODE, // fallo el receive por algo no relacionado al que socket sea no bloqueante
	SEND_ERROR_CODE, // fallo el send por algo no relacionado al que socket sea no bloqueante
	ACCEPT_CONNECTION_ERROR,
	SETUP_CONNECTION_ERROR_CODE,
	CLOSE_CONNECTION_ERROR_CODE,
	BROKEN_PIPE_ERROR_CODE,
	INVALID_REQUEST_ERROR_CODE,
} connection_error_code;

typedef struct {
	char *doh_ip;
	char *doh_host;
	char *doh_port;
	char *doh_path;
	char *proxy_port;
	char *management_port;
	char *proxy_ip;
	char *management_ip;
} arguments;

#endif
