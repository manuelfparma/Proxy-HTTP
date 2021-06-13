#ifndef DOHDATA_H
#define DOHDATA_H

#include <buffer.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_DOH_PACKET_SIZE 4096
#define DNS_MESSAGE_LENGTH 512

#define IN_CLASS 1

#define TYPE_COUNT 2		// Cantidad de types a enviar
#define IPV4_TYPE 1
#define IPV6_TYPE 28

// Manejo de codigos de return para saber el estado despues de correr
// una funcion de parseo de DoH. Son valores negativos ya que algunas de las funciones
// que lo utilizan retornan valores no negativos para expresar cantidades
typedef enum { DOH_PARSE_INCOMPLETE = -3, DOH_PARSE_COMPLETE, DOH_PARSE_ERROR } doh_parser_status_code;

// Similar a doh_parser_status_code pero para funciones que envian al servidor DoH
typedef enum { DOH_WRITE_NOT_SET = -4, DOH_SEND_INCOMPLETE, DOH_SEND_COMPLETE, DOH_SEND_ERROR } doh_send_status_code;

// Manejo de estados de parseo de response de DoH para saber desde donde
// retomar el parseo en caso de haber respuestas parciales
typedef enum {
	DOH_INIT,
	PREPARING_DOH_PACKET,
	SENDING_DOH_PACKET,
	FINDING_HTTP_STATUS_CODE,
	FINDING_CONTENT_LENGTH,
	PARSING_CONTENT_LENGTH,
	FINDING_HTTP_BODY,
	PARSING_DNS_MESSAGE,
	DNS_READY
} doh_state;

typedef struct {
	int sock;						   // socket activo con servidor DoH
	doh_state state;				   // estado del parseo del response DoH
	buffer *doh_buffer;
	long response_content_length;
	uint16_t question_types[TYPE_COUNT];	// types de dns question a enviar
	unsigned int request_number;			// cantidad de requests dns ya manejados (enviados y recibidos)
} doh_data;

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
	const char *name;		// Este es de longitud variable
	uint16_t type;			// Valor 1 para A
	uint16_t class;			// Valor 1 para IN (internet)
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

#endif
