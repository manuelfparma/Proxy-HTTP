#ifndef DOH_CLIENT_H
#define DOH_CLIENT_H

#include <stdint.h>
#include <stddef.h>

#define HTTP_PACKET_LENGTH 4096
#define DNS_MESSAGE_LENGTH 512

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
	char *name;	// Este es de longitud variable
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

int solve_name(char *name, char *doh_host, char *doh_port);

#endif
