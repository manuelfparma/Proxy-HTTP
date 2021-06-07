#ifndef DOHDATA_H
#define DOHDATA_H

#include <buffer.h>
#include <netinet/in.h>
#include <stdint.h>

// Manejo de codigos de return para saber el estado despues de correr
// una funcion de parseo de DoH. Son valores negativos ya que algunas de las funciones
// que lo utilizan retornan valores no negativos para expresar cantidades
typedef enum { DOH_PARSE_INCOMPLETE = -3, DOH_PARSE_COMPLETE, DOH_PARSE_ERROR } doh_parser_status_code;

// Manejo de estados de parseo de response de DoH para saber desde donde
// retomar el parseo en caso de haber respuestas parciales
typedef enum {
	DOH_PARSER_INIT,
	FINDING_HTTP_STATUS_CODE,
	FINDING_CONTENT_LENGTH,
	PARSING_CONTENT_LENGTH,
	FINDING_HTTP_BODY,
	PARSING_DNS_MESSAGE,
	DNS_READY
} doh_parser_state;

typedef struct addr_info_node {
	union {
		struct sockaddr_storage storage;
		struct sockaddr addr;
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	};
	struct addr_info_node *next;
} addr_info_node;

typedef struct {
	int sock;						   // socket activo con servidor DoH
	addr_info_node *addr_info_first;   // primer resultado de la consulta doh
	addr_info_node *addr_info_current; // ip para conectarse utilizada actualmente
	doh_parser_state state;			   // estado del parseo del response DoH
	buffer *doh_response_buffer;
	long response_content_length;
} doh_data;

#endif
