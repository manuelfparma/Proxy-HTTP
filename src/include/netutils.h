#ifndef NETUTILS_H
#define NETUTILS_H

#include <buffer.h>
#include <connection.h>
#include <dohparser.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_PORT 65535

// TODO: Meter esto en addr_info_node en connection.h
typedef union {
	struct sockaddr_storage storage;
	struct sockaddr addr;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
} addr_info;

//	Funcion para copiar de un buffer src en Big-Endian una variable dest de tamaño 16 bits n veces
void read_big_endian_16(uint16_t *dest, uint8_t *src, size_t n);
//	Funcion para copiar de un buffer src en Big-Endian una variable dest de tamaño 32 bits n veces
void read_big_endian_32(uint32_t *dest, uint8_t *src, size_t n);
//	Funcion para copiar a partir de src de 16 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_16(uint8_t *dest, uint16_t *src, size_t n);
//	Funcion para copiar a partir de src de 32 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_32(uint8_t *dest, uint32_t *src, size_t n);

#endif
