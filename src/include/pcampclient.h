#ifndef _PCAMPCLIENT_H
#define _PCAMPCLIENT_H

#include <pcamputils.h>

#define CLIENT_PCAMP_VERSION 1
#define PCAMP_BUFFER_SIZE 512
#define PCAMP_CLIENT_MAX_RECV_ATTEMPS 3
#define PCAMP_CLIENT_TIMEOUT 3

typedef struct {
	uint8_t method;
	union {
		uint8_t status_code;
		pcamp_query_response query;
		pcamp_config_response config;
	};
} pcamp_response_info;

char *method_strings[PCAMP_METHOD_COUNT] = {
	"Query (get tracked access data from HTTP proxy server)",
	"Configuration (modify HTTP proxy server settings at runtime",
};

char *query_type_strings[PCAMP_QUERY_TYPE_COUNT] = {"Number of historic connections established",
													"Number of connections currently established",
													"Total count of bytes transferred between clients and servers",
													"Total count of bytes sent from clients to servers",
													"Total count of bytes sent from servers to clients",
													"Total count of bytes transferred using the CONNECT HTTP method"};

char *config_type_strings[PCAMP_CONFIG_TYPE_COUNT] = {"Proxy I/O buffer size (min. 1, max. 65535)",
													  "Maximum number of simultaneous clients allowed (min. 0, max. 510)",
													  "Toggle on/off credentials logger (0 - off / 1 - on)",
													  "DoH server address",
													  "DoH server port (0 - 65535)",
													  "DoH hostname (max. 255 characters)"};

char *status_code_strings[PCAMP_STATUS_CODE_COUNT] = {"Request solved successfully",
													  "Incorrect passphrase",
													  "The server does not support this version of PCAMP",
													  "The server does not support the query type requested",
													  "The server does not support the configuration requested for modification",
													  "The configuration value requested for modification is invalid",
													  "Bad request",
													  "Internal server error"};


#endif
