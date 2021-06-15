// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <arpa/inet.h>
#include <dohclient.h>
#include <dohdata.h>
#include <dohparser.h>
#include <dohsender.h>
#include <dohutils.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netutils.h>
#include <proxyargs.h>
#include <proxyutils.h>
#include <string.h>

extern connection_header connections;
extern proxy_settings settings;
extern proxy_arguments args;

// path y host se definen en args
http_dns_request doh_request_template = {.method = "POST",
										 .http_version = "1.1",
										 .accept = "application/dns-message",
										 .content_type = "application/dns-message",
										 .content_length = 0,
										 .body = NULL};

dns_header dns_header_template = {.id = 0,
								  .qr = 0,
								  .opcode = 0,
								  .aa = 0,
								  .tc = 0,
								  .rd = 1,
								  .ra = 0,
								  .z = 0,
								  .rcode = 0,
								  .qdcount = 1,
								  .ancount = 0,
								  .nscount = 0,
								  .arcount = 0};

int connect_to_doh_server(connection_node *node, fd_set *write_fd_set) {
	//	Levanto estos valores de los argumentos o settings del programa (o los defaults)
	doh_request_template.path = args.doh_path;
	doh_request_template.host = settings.doh_host;

	addr_info doh_addr = settings.doh_addr_info;

	int doh_sock = socket(doh_addr.addr.sa_family, SOCK_STREAM, 0);

	if (doh_sock < 0) {
		return -1;
	}

	if (fcntl(doh_sock, F_SETFL, O_NONBLOCK) == -1) {
		goto ERROR;
	}

	socklen_t len = (doh_addr.addr.sa_family == AF_INET6) ? sizeof(doh_addr.in6) : sizeof(doh_addr.in4);
	if (connect(doh_sock, &doh_addr.addr, len) == -1 && errno != EINPROGRESS) {
		goto ERROR;
	}

	if (setup_doh_resources(node, doh_sock) == -1) {
		goto ERROR;
	}

	node->data.connection_state = SENDING_DNS;

	if (doh_sock >= connections.max_fd) { connections.max_fd = doh_sock + 1; }

	FD_SET(doh_sock, write_fd_set);

	return doh_sock;

ERROR:
	close(doh_sock);
	return -1;
}

int handle_doh_request(connection_node *node, fd_set *write_fd_set) {
	int doh_sock = node->data.doh->sock;

	if (FD_ISSET(doh_sock, &write_fd_set[TMP])) {
		FD_CLR(doh_sock, &write_fd_set[BASE]);

		int result;
		switch (node->data.doh->state) {
			case DOH_INIT:
				if (is_connected_to_doh(node)) {
					node->data.doh->state = PREPARING_DOH_PACKET;
				} else {
					return DOH_SEND_ERROR;
				}
			case PREPARING_DOH_PACKET:
				prepare_doh_request(node);
				node->data.doh->state = SENDING_DOH_PACKET;
			case SENDING_DOH_PACKET:
				result = send_doh_request(node, write_fd_set);
				if (result == DOH_PARSE_COMPLETE) {
					node->data.doh->state = FINDING_HTTP_STATUS_CODE;
				}
				return result;
			default:
				// No deberia pasar nunca
				return DOH_SEND_ERROR;
		}
	}

	return DOH_WRITE_NOT_SET;
}

bool is_connected_to_doh(connection_node *node) {
	int doh_sock = node->data.doh->sock;

	int error_code = 0;
	socklen_t error_code_size = sizeof(error_code);
	if (getsockopt(doh_sock, SOL_SOCKET, SO_ERROR, &error_code, &error_code_size) < 0 || error_code == ECONNREFUSED) {
		return false;
	}

	return true;
}

int handle_doh_response(connection_node *node, fd_set *read_fd_set) {
	int doh_sock = node->data.doh->sock;
	doh_parser_status_code result = DOH_PARSE_ERROR;

	if (FD_ISSET(doh_sock, &read_fd_set[TMP])) {

		int read = read_doh_response(node);

		if (read < 0) {
			return -1;
		} else if (read == 0) {
			// Caso: no hay response DoH, suponemos que no va a venir
			return 1;
		}

		buffer *response = node->data.doh->doh_buffer;
		while (response->write - response->read) {
			switch (node->data.doh->state) {
				case FINDING_HTTP_STATUS_CODE:
					result = parse_doh_status_code(node);
					if (result == DOH_PARSE_COMPLETE) node->data.doh->state = FINDING_CONTENT_LENGTH;
					break;
				case FINDING_CONTENT_LENGTH:
					result = parse_doh_content_length_header(node);
					if (result == DOH_PARSE_COMPLETE) node->data.doh->state = PARSING_CONTENT_LENGTH;
					break;
				case PARSING_CONTENT_LENGTH:
					result = parse_doh_content_length_value(node);
					if (result == DOH_PARSE_COMPLETE) node->data.doh->state = FINDING_HTTP_BODY;
					break;
				case FINDING_HTTP_BODY:
					result = find_http_body(node);
					if (result == DOH_PARSE_COMPLETE) node->data.doh->state = PARSING_DNS_MESSAGE;
					break;
				case PARSING_DNS_MESSAGE:
					result = parse_dns_message(node);
					if (result == DOH_PARSE_COMPLETE) node->data.doh->state = DNS_READY;
					break;
				case DNS_READY:
					break;
				default:
					// No deberia pasar nunca
					return -1;
			}

			//	Necesito esperar al resto de la DoH response
			if (result == DOH_PARSE_INCOMPLETE) break;
			else if (result == DOH_PARSE_ERROR) {
				return -1;
			}

			if (node->data.doh->state == DNS_READY)
				return 1;
		}
	}

	return 0;
}

bool check_requests_sent(connection_node *node) {
	node->data.doh->request_number++;

	// Veo si ya manejé todas las requests doh
	if (node->data.doh->request_number >= TYPE_COUNT) {
		close(node->data.doh->sock);
		return true;
	}

	// Todavia me faltan enviar requests
	node->data.connection_state = SENDING_DNS;
	node->data.doh->state = PREPARING_DOH_PACKET;

	return false;
}
