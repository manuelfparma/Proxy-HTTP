#ifndef _PCAMPCLIENT_H
#define _PCAMPCLIENT_H

#include <pcamputils.h>

// TODO: Meter en addr_info_node
typedef union {
	struct sockaddr_storage storage;
	struct sockaddr addr;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
} addr_info;

char *query_type_strings[QUERY_TYPE_COUNT] = {"Number of historic connections established",
										 "Number of connections currently established",
										 "Total count of bytes transferred between clients and servers",
										 "Total count of bytes sent from clients to servers",
										 "Total count of bytes sent from servers to clients",
										 "Total count of bytes transferred using the CONNECT HTTP method"};

char *method_strings[METHOD_COUNT] = {
	"Query (get tracked access data from HTTP proxy server)",
	"Configuration (modify HTTP proxy server settings at runtime",
};

#endif
