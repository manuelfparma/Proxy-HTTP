#ifndef _DNS_UTILS_H_
#define _DNS_UTILS_H_

#include <buffer.h>
#include <connection.h>
#include <dohparser.h>
#include <stddef.h>
#include <stdint.h>

#define SIZE_8 1
#define SIZE_16 2
#define SIZE_32 4

#define MAX_DOH_PACKET_SIZE 4096
#define DNS_MESSAGE_LENGTH 512

#define IN_CLASS 1
#define IPV4_TYPE 1
#define IPV6_TYPE 28

/*
 Header DNS:
								   1  1  1  1  1  1
	 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      ID                       |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    QDCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ANCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    NSCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                    ARCOUNT                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct {
	uint16_t id;
	unsigned int qr : 1;
	unsigned int opcode : 4;
	unsigned int aa : 1;
	unsigned int tc : 1;
	unsigned int rd : 1;
	unsigned int ra : 1;
	unsigned int z : 3;
	unsigned int rcode : 4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header;

/*
 * Question DNS:
 *                                  1  1  1  1  1  1
	  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                     QNAME                     /
	/                                               /
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QTYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     QCLASS                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
typedef struct {
	char *name;		// Este es de longitud variable
	uint16_t type;	// Valor 1 para A
	uint16_t class; // Valor 1 para IN (internet)
} dns_question;

typedef struct {
	char *method;
	char *path;
	char *http_version;
	char *host;
	char *accept;
	char *content_type;
	size_t content_length;
	char *body;
} http_dns_request;

//  Funcion para alocar recursos de la conexion con el servidor DoH en el heap, requerido para
//  persistir informacion utilizada al parsear la response DoH
int setup_doh_resources(ConnectionNode *node, int doh_fd);

int add_ip_address(ConnectionNode *node, int addr_family, void *addr);

void free_doh_resources(ConnectionNode *node);

//	Funcion para copiar de informacion almacenada en 16 bits Big-Endian a un buffer dest n veces
void read_big_endian_16(uint16_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar de informacion almacenada en 32 bits Big-Endian a un buffer dest n veces
void read_big_endian_32(uint32_t *dest, uint8_t *src, size_t n);

//	Funcion para copiar a partir de src de 16 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_16(uint8_t *dest, uint16_t *src, size_t n);

//	Funcion para copiar a partir de src de 32 bits a un buffer dest en formato Big-Endian n veces
void write_big_endian_32(uint8_t *dest, uint32_t *src, size_t n);

#endif
