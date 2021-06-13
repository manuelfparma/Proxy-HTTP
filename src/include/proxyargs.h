#ifndef ARGS_H
#define ARGS_H

#include <netutils.h>

typedef enum {
    DOH_IP,
    DOH_PORT,
    DOH_HOST,
    DOH_PATH,
	DOH_QUERY
} long_opts_values;

typedef struct {
	char *doh_ip;
	char *doh_host;
	char *doh_port;
	char *doh_path;
	char *doh_query;
	char *proxy_port;
	char *management_port;
	char *proxy_ip;
	char *management_ip;
	addr_info doh_addr_info;
	addr_info proxy_addr_info;
	addr_info management_addr_info;
	uint8_t password_dissector; 	// 0 es apagado (no tiene en cuenta contraseñas), 1 es encendido
} proxy_arguments;

void parse_proxy_args(int argc, char **argv);

#endif
