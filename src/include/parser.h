#ifndef __PARSER_H__
#define __PARSER_H__

#include <buffer.h>
#include <netinet/in.h>
#include <stdint.h>

typedef enum {
	NOT_FOUND, FOUND, SOLVED,
} http_request_target_status;

typedef enum {
	PARSE_ERROR,
	PARSE_START_LINE_INCOMPLETE,
	PARSE_START_LINE_COMPLETE,
	PARSE_HEADER_LINE_INCOMPLETE,
	PARSE_HEADER_LINE_COMPLETE,
	PARSE_BODY_INCOMPLETE,
	PARSE_END,
	PARSE_CONNECT_METHOD,
} parser_status_code;
// deben ser numeros negativos porque las funciones de parseo retornan caracteres leidos en casos exitosos

typedef enum {
	MAX_HOST_NAME_LENGTH = 0xFF, // 255
	MAX_HEADER_TYPE_LENGTH = 64,
	MAX_HEADER_VALUE_LENGTH = 1024,
	MAX_BODY_LENGTH = 1023,
	MAX_METHOD_LENGTH = 24,
	MAX_SCHEMA_LENGTH = 24,
	MAX_IP_LENGTH = 24,
	MAX_RELATIVE_PATH_LENGTH = 64,
	MAX_PORT_LENGTH = 5,
} http_request_constraints;

typedef enum {
	EMPTY_VERSION = -1,

} constants;

typedef enum {
	PS_METHOD,
	PS_PATH,
	PS_ASTERISK_FORM,
	PS_RELATIVE_PATH,
	PS_PATH_SCHEMA,
	PS_PATH_SLASHES,
	PS_PATH_DOMAIN,
	PS_IP,
	PS_IPv4,
	PS_IPv6,
	PS_DOMAIN,
	PS_PORT,
	PS_HTTP_VERSION,
	PS_HEADER_TYPE,
	PS_HEADER_VALUE,
	PS_CR,
	PS_LF,
	PS_CR_END,
	PS_LF_END, 
	PS_BODY,
	PS_END,
	PS_ERROR // cuando se recibe \cr\lf\cr\lf
} http_parser_state;

typedef struct {
	char when;
	char upper_bound; // con limite incluido
	char lower_bound; // con limite incluido
	http_parser_state destination;
	void (*transition)(char);
} http_parser_state_transition;

typedef struct {
	char major; // parte izquierda de la version http1.0 -> 1
	char minor; // parte derecha de la version http1.0 -> 0
} http_version;

typedef enum { ABSOLUTE, RELATIVE, ASTERISK_FORM } http_path_type;

typedef enum { IPV4, IPV6, DOMAIN } http_host_type;

typedef union {
	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;
	// uint8_t domain[MAX_FQDN_LENGTH + 1];   // null terminated
} http_host;

typedef union {
	char host_name[MAX_HOST_NAME_LENGTH + 1];
	char ip_addr[MAX_IP_LENGTH + 1];
} http_request_target;

typedef struct {
	http_path_type path_type;
	http_request_target request_target;
	http_host_type host_type;
	http_host host;
	char port[MAX_PORT_LENGTH + 1];
	char relative_path[MAX_RELATIVE_PATH_LENGTH + 1];	//ojo no se guarda con primer /
} http_target;

typedef struct {
	char method[MAX_METHOD_LENGTH + 1];
	char schema[MAX_SCHEMA_LENGTH + 1]; // schemao del request
	http_target destination;
	http_version version;
} http_start_line;

typedef struct {
	char header_type[MAX_HEADER_TYPE_LENGTH + 1];
	char header_value[MAX_HEADER_VALUE_LENGTH + 1];
} http_header;

typedef struct {
	http_start_line start_line;		   // start_line(por si no se completo)
	http_header header;				   // header actual(por si no se completo)
	buffer *parsed_request;			   // listo para enviar
	http_parser_state parser_state;	   // estado actual
	size_t copy_index;				   // indice auxiliar para saber la posicion en la cual se debe copiar en el buffer objetivo
	parser_status_code package_status; // codigo que indica el estado de los recursos leidos
	http_request_target_status request_target_status;
} http_request;

int parse_request(http_request *request, buffer *read_buffer);

#endif
