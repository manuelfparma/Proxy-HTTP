#ifndef __NETUTILS_H__
#define __NETUTILS_H__

#include <buffer.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_PORT 65535
#define SIZE_8 1
#define SIZE_16 2
#define SIZE_32 4
#define SIZE_64 8

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

// Funcion para comparar strings(null terminated) que no tiene en cuenta el case de las letras del alfabeto
// Valor de retorno: str1 == str2 -> 0, str1 > str2 -> 1, str1 < str2 -> -1
int strcmp_case_insensitive(char *str1, char *str2);

//	Funciones para convertir 64 bits entre formato memoria para el host y big-endian para network
uint64_t hton64(uint64_t host_64);
uint64_t ntoh64(uint64_t network_64);

// Funcion que copia el maximo de bytes posibles del buffer source al buffer destino
void copy_from_buffer_to_buffer(buffer *dest, buffer *src);

#endif
