#include <arpa/inet.h>
#include <dnsutils.h>
#include <dohclient.h>
#include <errno.h>
#include <logger.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <dohsender.h>
#include <dohparser.h>

static const char *DOH_SERVER = "127.0.0.1";
// TODO: PASAR A CHAR*
static const uint16_t DOH_PORT = 8053;

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

static int connect_to_server(char *doh_host, char *doh_port);

int solve_name(char *name, char *doh_host, char *doh_port) {
	// TODO: Malloc de structs de HTTP request, DNS, etc.

	// TODO: Mandarlo al select antes de llegar al connect
	// conectarse al server
	logger(INFO, "connecting to DoH server");
	int dns_sock = connect_to_server(doh_host, doh_port);
	if (dns_sock < 0) {
		logger(ERROR, "connect_to_server(): %s", strerror(errno));
		return -1;
	}

	logger(INFO, "connected to DoH server");

	write_http_request(dns_sock, name);
	return read_http_response(dns_sock);
}

int main() { return solve_name("netflix.com", "127.0.0.1", "8053"); }

// TODO: cablear host y puerto dinamico
static int connect_to_server(char *doh_host, char *doh_port) {
	struct sockaddr_in dns_addr;

	int dns_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (dns_sock < 0) {
		logger(ERROR, "dns_sock(): %s", strerror(errno));
		return -1;
	}

	dns_addr.sin_family = AF_INET;
	dns_addr.sin_port = htons(DOH_PORT);
	// TODO: cambiar a inet_aton
	dns_addr.sin_addr.s_addr = inet_addr(DOH_SERVER);

	if (dns_addr.sin_addr.s_addr == (in_addr_t)-1) {
		logger(ERROR, "inet_addr(): %s", strerror(errno));
		return -1;
	}

	if (connect(dns_sock, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) == -1) {
		logger(ERROR, "connect(): %s", strerror(errno));
		return -1;
	}

	return dns_sock;
}
