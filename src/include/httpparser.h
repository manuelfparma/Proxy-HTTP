#ifndef __HTTP_REQUEST_PARSER_H__
#define __HTTP_REQUEST_PARSER_H__

#include <buffer.h>
#include <pop3commandparser.h>
#include <pop3responseparser.h>
#include <stdint.h>

typedef enum {
	NOT_FOUND,
	FOUND,
	SOLVED,
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
	PARSE_CONNECT_METHOD_POP3,
} http_request_status_code;

// TODO: Mover a netutils.h
typedef enum {
	MAX_HOST_NAME_LENGTH = 255,
	MAX_HEADER_TYPE_LENGTH = 64,
	MAX_HEADER_VALUE_LENGTH = 1024,
	MAX_BODY_LENGTH = 1023,
	MAX_METHOD_LENGTH = 24,
	MAX_SCHEMA_LENGTH = 24,
	MAX_IP_LENGTH = 45,
	MAX_RELATIVE_PATH_LENGTH = 1024,
	MAX_PORT_LENGTH = 5,
	BASIC_CREDENTIAL_LENGTH = 6, // soporta "Basic " para credenciales de autorizacion
	SPHTTP_1_0_LENGTH = 9,		 // longitud del string " HTTP/1.0" que se utiliza en todas las request enviadas desde el proxy
	CR_LF_LENGTH = 2,			 // longitud del string "\r\n"
	HEADER_TYPE_HOST_LENGTH = 6, // longitud del string "Host: "
} http_request_constraints;

typedef enum {
	ANY = -1,
	EMPTY = -2,
	EMPTY_VERSION = -3,
} http_constants;

typedef enum {
	PS_METHOD,
	PS_PATH,
	PS_ASTERISK_FORM,
	PS_RELATIVE_PATH,
	PS_PATH_SCHEMA,
	PS_PATH_SLASHES,
	PS_IPv4,
	PS_IPv6,
	PS_IPv6_END,
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

typedef enum { ABSOLUTE, RELATIVE, ABSOLUTE_WITH_RELATIVE, ASTERISK_FORM } http_path_type;

typedef enum { IPV4, IPV6, DOMAIN } http_host_type;

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

typedef union {
	char host_name[MAX_HOST_NAME_LENGTH + 1];
	char ip_addr[MAX_IP_LENGTH + 1];
} http_request_target;

typedef struct {
	http_path_type path_type;
	http_request_target request_target;
	http_host_type host_type;
	char port[MAX_PORT_LENGTH + 1];
	char relative_path[MAX_RELATIVE_PATH_LENGTH + 1]; // ojo no se guarda con primer /
} http_target;

typedef struct {
	char type[MAX_HEADER_TYPE_LENGTH + 1];
	char value[MAX_HEADER_VALUE_LENGTH + 1];
} http_header;

typedef struct {
	char value[MAX_HEADER_VALUE_LENGTH + 1];
} http_authorization;

typedef struct {
	char method[MAX_METHOD_LENGTH + 1];
	char schema[MAX_SCHEMA_LENGTH + 1]; // schema del request
	http_target target;
	http_version version;
	http_header header; // header actual(por si no se completo)
	http_authorization authorization;
} http_request_data;

typedef struct {
	http_parser_state parser_state; // estado actual
	size_t copy_index;				// indice auxiliar para saber la posicion en la cual se debe copiar en el buffer objetivo
	http_request_status_code request_status;  // codigo que indica el estado de los recursos leidos
	http_request_target_status target_status; // estado del hostname en el parseo
	buffer *parsed_request;		   // request parseada lista para enviar
} http_request_parser_data;

typedef struct {
	pop3_command_parser command;
	pop3_response_parser response;
	size_t line_count;
} http_pop3_parser;

typedef struct {
	http_request_data request;	   // datos de la request parseada
	http_request_parser_data data; // datos de la maquina
	http_pop3_parser *pop3;		   // datos de la maquina en caso que haya un connect al protocolo POP
} http_parser;

int parse_request(http_parser *parser, buffer *read_buffer);

#endif
