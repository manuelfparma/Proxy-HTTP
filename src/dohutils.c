#include <netutils.h>
#include <dohdata.h>
#include <dohutils.h>
#include <errno.h>
#include <logger.h>
#include <string.h>

int setup_doh_resources(connection_node *node, int doh_fd) {
	node->data.doh = malloc(sizeof(doh_data));
	if (node->data.doh == NULL) goto EXIT;

	node->data.doh->doh_buffer = malloc(sizeof(buffer));
	if (node->data.doh->doh_buffer == NULL) goto FREE_DOH_DATA;

	node->data.doh->doh_buffer->data = malloc(MAX_DOH_PACKET_SIZE * SIZE_8);
	if (node->data.doh->doh_buffer->data == NULL) goto FREE_BUFFER;

	buffer_init(node->data.doh->doh_buffer, MAX_DOH_PACKET_SIZE, node->data.doh->doh_buffer->data);

	node->data.doh->sock = doh_fd;
	node->data.doh->state = DOH_INIT;

	node->data.doh->question_types[0] = IPV4_TYPE;
	node->data.doh->question_types[1] = IPV6_TYPE;
	node->data.doh->request_number = 0;

	return 0;

FREE_BUFFER:
	free(node->data.doh->doh_buffer);
FREE_DOH_DATA:
	free(node->data.doh);
EXIT:
	logger(ERROR, "malloc(): %s", strerror(errno));
	return -1;
}

// TODO: Mandar a otro .c mas generico
int add_ip_address(connection_node *node, int addr_family, void *addr) {

	addr_info_node *new = malloc(sizeof(addr_info_node));
	if (new == NULL) goto EXIT;

	uint16_t parsed_port;
	if(!parse_port(node->data.parser->request.target.port, &parsed_port)) {
		logger(ERROR, "connect_to_doh_server(): invalid port. Use a number between 0 and 65535");
		goto FREE_NODE;
	}

	switch (addr_family) {
		case AF_INET:
			new->in4.sin_family = AF_INET;
			new->in4.sin_addr = *((struct in_addr *)addr);
			new->in4.sin_port = htons(parsed_port);
			break;
		case AF_INET6:
			new->in6.sin6_family = AF_INET6;
			new->in6.sin6_addr = *((struct in6_addr *)addr);
			new->in6.sin6_port = htons(parsed_port);
			break;
		default:
			free(new);
			return -1;
	}

	new->next = NULL;

	if (node->data.addr_info_first == NULL) {
		node->data.addr_info_first = new;
		node->data.addr_info_current = node->data.addr_info_first;
	} else {
		addr_info_node *search = node->data.addr_info_first;
		while (search->next != NULL)
			search = search->next;
		search->next = new;
	}

	return 0;

FREE_NODE:
	free(new);
EXIT:
	return -1;
}

void free_doh_resources(connection_node *node) {
	addr_info_node *addr_node = node->data.addr_info_first;
	addr_info_node *prev = addr_node;

	while (addr_node != NULL) {
		prev = addr_node;
		addr_node = prev->next;
		free(prev);
	}
	if (node->data.parser->request.target.host_type == DOMAIN) {
		free(node->data.doh->doh_buffer->data);
		free(node->data.doh->doh_buffer);
		free(node->data.doh);
		node->data.doh = NULL;
	}
}
