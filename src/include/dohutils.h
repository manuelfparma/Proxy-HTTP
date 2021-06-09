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

//	Funcion para copiar de informacion almacenada en 16 bits Big-Endian a un buffer dest n veces
void read_big_endian_16(uint16_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar de informacion almacenada en 32 bits Big-Endian a un buffer dest n veces
void read_big_endian_32(uint32_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar a partir de src de 16 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_16(uint8_t *dest, uint16_t *src, size_t n);

//	Funcion para copiar a partir de src de 32 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_32(uint8_t *dest, uint32_t *src, size_t n);

#endif
