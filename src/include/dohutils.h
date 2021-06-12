#ifndef _DNS_UTILS_H_
#define _DNS_UTILS_H_

#include <buffer.h>
#include <connection.h>
#include <dohparser.h>
#include <stddef.h>
#include <stdint.h>

//  Funcion para alocar recursos de la conexion con el servidor DoH en el heap, requerido para
//  persistir informacion utilizada al parsear la response DoH
int setup_doh_resources(connection_node *node, int doh_fd);

int add_ip_address(connection_node *node, int addr_family, void *addr);

void free_doh_resources(connection_node *node);

#endif
