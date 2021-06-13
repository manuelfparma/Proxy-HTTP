#ifndef NETUTILS_H
#define NETUTILS_H

#include <buffer.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_PORT 65535
#define SIZE_8 1
#define SIZE_16 2
#define SIZE_32 4
#define SIZE_64 8

// TODO: Meter esto en addr_info_node en connection.h
typedef union {
	struct sockaddr_storage storage;
	struct sockaddr addr;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
} addr_info;

// Funcion que recibe un puerto y una direccion IP en human readable format y los almacena en formato
// de red en la estructura addr_info. En caso de no ser una direccion valida devuelve false. En caso contrario true
bool parse_ip_address(const char *addr_str, uint16_t port, addr_info *addr);

//	Funcion que recibe un string null-terminated representando un numero de puerto y lo vuelca en port
//	Si no se logró convertir, devuelve false
bool parse_port(const char *port_str, uint16_t *port);

//	Funcion para copiar de un buffer src en Big-Endian una variable dest de tamaño 16 bits n veces
void read_big_endian_16(uint16_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar de un buffer src en Big-Endian una variable dest de tamaño 32 bits n veces
void read_big_endian_32(uint32_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar de un buffer src en Big-Endian una variable dest de tamaño 32 bits n veces
void read_big_endian_64(uint64_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar a partir de src de 16 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_16(uint8_t *dest, uint16_t *src, size_t n);

//	Funcion para copiar a partir de src de 32 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_32(uint8_t *dest, uint32_t *src, size_t n);

//	Funcion para copiar a partir de src de 64 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_64(uint8_t *dest, uint64_t *src, size_t n);

#endif
