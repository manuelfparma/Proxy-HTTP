#include <arpa/inet.h>
#include <dnsutils.h>
#include <dohclient.h>
#include <dohparser.h>
#include <dohsender.h>
#include <errno.h>
#include <fcntl.h>
#include <logger.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <proxyutils.h>
#include <dohsender.h>

#define HOST_NAME "foo.leak.com.ar"		//TODO este valor viene por parametro al iniciar el server

static const char *DOH_SERVER = "127.0.0.1";
// TODO: PASAR A CHAR*
static const uint16_t DOH_PORT = 8053;

extern ConnectionHeader connections;

http_dns_request test_request = {.method = "POST",
								 .path = "/dns-query",
								 .http_version = "1.1",
								 .host = "localhost",
								 .accept = "application/dns-message",
								 .content_type = "application/dns-message",
								 .content_length = 0,
								 .body = NULL};

dns_header test_dns_header = {.id = 1, // autoincrementar?
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

// TODO: Guarda que el type puede variar segun si pide IPv4 o IPv6 (A/AAAA record)
dns_question test_dns_question = {.name = "www.netflix.com", .class = 1, .type = 1};

//int solve_name(ConnectionNode *node, char *doh_addr, char *doh_port, char *doh_hostname) {
//	// TODO: Malloc de structs de HTTP request, DNS, etc.
//
//	// TODO: Mandarlo al select antes de llegar al connect
//	// conectarse al server
//	int doh_sock = connect_to_doh_server(node, doh_addr, doh_port);
//	if (doh_sock < 0) {
//		logger(ERROR, "connect_to_doh_server(): %s", strerror(errno));
//		return -1;
//	}
//
//	logger(INFO, "connected to DoH server");
//
//	return doh_sock;
//
////	char *name = node->data.request->start_line.destination.request_target.host_name;
////	write_http_request(doh_sock, name);
////	return read_http_response(doh_sock);
//}

// int main() { return solve_name("netflix.com", "127.0.0.1", "8053"); }

int connect_to_doh_server(ConnectionNode *node, fd_set *write_fd_set, char *doh_addr, char *doh_port) {
	logger(INFO, "creating socket with DoH server for client with socket fd %d", node->data.clientSock);

	int doh_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (doh_sock < 0) {
		logger(ERROR, "doh_sock(): %s", strerror(errno));
		return -1;
	}

	fcntl(doh_sock, F_SETFL, O_NONBLOCK);

	struct sockaddr_in doh_addr_in;
	doh_addr_in.sin_family = AF_INET;
	doh_addr_in.sin_port = htons(DOH_PORT);

	// TODO: esta llamada es para IPv4, para IPv6 se usa AF_INET6 y otra estructura
	inet_pton(AF_INET, doh_addr, &doh_addr_in.sin_addr.s_addr);
	if (doh_addr_in.sin_addr.s_addr == (in_addr_t)-1) {
		close(doh_sock);
		logger(ERROR, "connect_to_doh_server(): %s", strerror(errno));
		return -1;
	}

	long parsed_port = strtol(doh_port, NULL, 10);
	if ((parsed_port == 0 && errno == EINVAL) || parsed_port < 0 || parsed_port > 65535) {
		close(doh_sock);
		logger(ERROR, "connect_to_doh_server(): invalid port. Use a number between 0 and 65535");
		return -1;
	}

	node->data.doh_sock = doh_sock;

	if (connect(doh_sock, (struct sockaddr *)&doh_addr_in, sizeof(doh_addr_in)) == -1 && errno != EINPROGRESS) {
		close(doh_sock);
		logger(ERROR, "connect(): %s", strerror(errno));
		return -1;
	}

	node->data.addrInfoState = CONNECTING_TO_DOH;

	logger(INFO, "connecting to DoH server for client with socket fd %d (DoH fd: %d)", node->data.clientSock, doh_sock);

	if (doh_sock >= connections.maxFd) {
		connections.maxFd = doh_sock + 1;
	}

	FD_SET(doh_sock, write_fd_set);

	return doh_sock;
}

int handle_doh_connection(ConnectionNode *node, fd_set *writeFdSet, fd_set *readFdSet) {
	int doh_sock = node->data.doh_sock;
	
	if(FD_ISSET(doh_sock, &writeFdSet[TMP])) {
		FD_CLR(doh_sock, &writeFdSet[BASE]);

		socklen_t optlen = sizeof(int);
		if (getsockopt(doh_sock, SOL_SOCKET, SO_ERROR, &(int){1}, &optlen) < 0) {
			logger(ERROR, "handle_doh_connection :: getsockopt(): %s", strerror(errno));
			return -1;
		}

		node->data.addrInfoState = FETCHING;
		logger(INFO, "connected to DoH, client fd: %d", node->data.clientSock);

		if (write_http_request(doh_sock, node->data.domainName, HOST_NAME) < 0) {
			logger(ERROR, "handle_doh_connection :: write_http_request(): failed to write DoH HTTP request");
			return -1;
		}

		FD_SET(doh_sock, &readFdSet[BASE]);
		if(doh_sock >= connections.maxFd)
			connections.maxFd = doh_sock + 1;

		return 1;	
	}

	return 0;
}
