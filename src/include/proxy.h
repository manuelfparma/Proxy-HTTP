#ifndef _PROXY_H_
#define _PROXY_H_
void write_proxy_statistics();

typedef enum {
	CLOSE_CONNECTION_CODE =
		-10,		 // estos codigos usan valores negativos para distinguirlos de los que si devuelven las funciones involucradas
	RECV_ERROR_CODE, // fallo el receive por algo no relacionado al que socket sea no bloqueante
	SEND_ERROR_CODE, // fallo el send por algo no relacionado al que socket sea no bloqueante
	ACCEPT_CONNECTION_ERROR,
	SETUP_CONNECTION_ERROR_CODE,
	BROKEN_PIPE_CODE,
} connection_status_code;

#endif
