#ifndef PCAMPUTILS_H
#define PCAMPUTILS_H

#include <stdint.h>

#define PCAMP_VERSION 1

typedef enum { QUERY, CONFIG } pcamp_method;
typedef enum { REQUEST, RESPONSE } pcamp_op;

typedef struct {
	uint8_t version;
	uint8_t flags; // contiene en el bit mas significativo la operacion (request (0)/response (1)) y en el siguiente el metodo
				   // (query(0)/config(1))
	uint16_t id;
} pcamp_header;

typedef struct {
	
} pcamp_query_request;

#endif
