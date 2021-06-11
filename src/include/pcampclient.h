#ifndef _PCAMPCLIENT_H
#define _PCAMPCLIENT_H

// TODO: Meter en addr_info_node
typedef union {
	struct sockaddr_storage storage;
	struct sockaddr addr;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
} addr_info;

#endif
