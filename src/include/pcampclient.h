#ifndef _PCAMPCLIENT_H
#define _PCAMPCLIENT_H

#include <pcamputils.h>

#define PCAMP_BUFFER_SIZE 512

char *method_strings[METHOD_COUNT] = {
	"Query (get tracked access data from HTTP proxy server)",
	"Configuration (modify HTTP proxy server settings at runtime",
};

char *query_type_strings[QUERY_TYPE_COUNT] = {"Number of historic connections established",
											  "Number of connections currently established",
											  "Total count of bytes transferred between clients and servers",
											  "Total count of bytes sent from clients to servers",
											  "Total count of bytes sent from servers to clients",
											  "Total count of bytes transferred using the CONNECT HTTP method"};

char *config_type_strings[CONFIG_TYPE_COUNT] = {"Proxy I/O buffer size (min. 1, max. 65535)",
												"Maximum number of simultaneous clients allowed (min. 0, max. 510)",
												"Toggle on/off credentials logger (0 - off / 1 - on)",
												"DoH server address",
												"DoH server port (0 - 65535)",
												"DoH hostname (max. 255 characters)"};

#endif
