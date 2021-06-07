#include <arpa/inet.h>
#include <dohclient.h>
#include <dohparser.h>
#include <dohsender.h>
#include <dohutils.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netinet/in.h>
#include <proxyutils.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define HOST_NAME "foo.leak.com.ar" // TODO este valor viene por parametro al iniciar el server

extern ConnectionHeader connections;

http_dns_request doh_request_template = {.method = "POST",
										 .path = "/dns-query",
										 .http_version = "1.1",
										 .host = "localhost",
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
								  .qdcount = 2,
								  .ancount = 0,
								  .nscount = 0,
								  .arcount = 0};

int connect_to_doh_server(ConnectionNode *node, fd_set *write_fd_set, char *doh_addr, char *doh_port) {
	logger(INFO, "creating socket with DoH server for client with socket fd %d", node->data.clientSock);

	int doh_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (doh_sock < 0) {
		logger(ERROR, "connect_to_doh_server :: socket(): %s", strerror(errno));
		return -1;
	}

	if (fcntl(doh_sock, F_SETFL, O_NONBLOCK) == -1) {
		logger(ERROR, "connect_to_doh_server :: fcntl(): %s", strerror(errno));
		return -1;
	}

	// TODO: USAR PARSED PORT
	long parsed_port = strtol(doh_port, NULL, 10);
	if ((parsed_port == 0 && errno == EINVAL) || parsed_port < 0 || parsed_port > 65535) {
		close(doh_sock);
		logger(ERROR, "connect_to_doh_server(): invalid port. Use a number between 0 and 65535");
		return -1;
	}

	struct sockaddr_in doh_addr_in;
	doh_addr_in.sin_family = AF_INET;
	doh_addr_in.sin_port = htons(parsed_port);

	// TODO: esta llamada es para IPv4, para IPv6 se usa AF_INET6 y otra estructura
	inet_pton(AF_INET, doh_addr, &doh_addr_in.sin_addr.s_addr);
	if (doh_addr_in.sin_addr.s_addr == (in_addr_t)-1) {
		close(doh_sock);
		logger(ERROR, "connect_to_doh_server(): %s", strerror(errno));
		return -1;
	}

	if (connect(doh_sock, (struct sockaddr *)&doh_addr_in, sizeof(doh_addr_in)) == -1 && errno != EINPROGRESS) {
		close(doh_sock);
		logger(ERROR, "connect(): %s", strerror(errno));
		return -1;
	}

	if (setup_doh_resources(node, doh_sock) == -1) {
		close(doh_sock);
		logger(ERROR, "setup_doh_resources(): couldn't set up DoH connection resources");
		return -1;
	}

	node->data.addrInfoState = CONNECTING_TO_DOH;

	logger(INFO, "connecting to DoH server for client with socket fd %d (DoH fd: %d)", node->data.clientSock, doh_sock);

	if (doh_sock >= connections.maxFd) { connections.maxFd = doh_sock + 1; }

	FD_SET(doh_sock, write_fd_set);

	return doh_sock;
}

int handle_doh_request(ConnectionNode *node, fd_set *writeFdSet, fd_set *readFdSet) {
	int doh_sock = node->data.doh->sock;

	if (FD_ISSET(doh_sock, &writeFdSet[TMP])) {
		FD_CLR(doh_sock, &writeFdSet[BASE]);

		socklen_t optlen = sizeof(int);
		if (getsockopt(doh_sock, SOL_SOCKET, SO_ERROR, &(int){1}, &optlen) < 0) {
			logger(ERROR, "handle_doh_request :: getsockopt(): %s", strerror(errno));
			return -1;
		}

		node->data.addrInfoState = FETCHING;
		logger(INFO, "connected to DoH, client fd: %d", node->data.clientSock);

		if (write_doh_request(doh_sock, node->data.parser->request.target.request_target.host_name, HOST_NAME) < 0) {
			logger(ERROR, "handle_doh_request :: write_doh_request(): failed to write DoH HTTP request");
			return -1;
		}

		FD_SET(doh_sock, &readFdSet[BASE]);
		if (doh_sock >= connections.maxFd) connections.maxFd = doh_sock + 1;

		node->data.doh->state = DOH_PARSER_INIT;

		return 1;
	}

	return 0;
}

int handle_doh_response(ConnectionNode *node, fd_set *readFdSet) {
	int doh_sock = node->data.doh->sock;
	doh_parser_status_code result;

	//FIXME: DA SEGMENTATION FAULT A VECES
	if (FD_ISSET(doh_sock, &readFdSet[TMP])) {

		if (read_doh_response(node) < 0) {
			logger(ERROR, "handle_doh_response(): unable to read DoH response");
			return -1;
		}
		buffer *response = node->data.doh->doh_response_buffer;
		while (response->write - response->read) {
			switch (node->data.doh->state) {
					// TODO: el init se va?
				case DOH_PARSER_INIT:
					node->data.doh->state = FINDING_HTTP_STATUS_CODE;
					break;
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
					// TODO: Atajar parsing complete
				case DNS_READY:
					break;
			}

			//	Necesito esperar al resto de la DoH response
			if (result == DOH_PARSE_INCOMPLETE) break;
			else if (result == DOH_PARSE_ERROR) {
				return -1; // TODO manejo de error
			}

			if (node->data.doh->state == DNS_READY) {
				node->data.addrInfoState = READY; // TODO otro estado?
				return 1;
			}
		}
	}

	return 0;
}
