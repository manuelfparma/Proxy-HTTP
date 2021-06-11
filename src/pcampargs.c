#include <arpa/inet.h>
#include <logger.h>
#include <netinet/in.h>
#include <pcampargs.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static void version();
static void usage(const char *program_name);
static addr_info check_info(const char *proxy_ip, const char *proxy_port);

addr_info parse_pcamp_args(const int argc, char **argv) {

	char *proxy_ip = PROXY_IP;
	char *proxy_port = PROXY_PORT;

	// variables para getopt_long()
	int c;
	char *flags = "hvp:l:";

	while(1) {
		c = getopt(argc, argv, flags);
		if (c == -1) { break; }

		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				version();
				break;
			case 'p':
				proxy_port = optarg;
				break;
			case 'l':
				proxy_ip = optarg;
				break;
			default:
				break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Argument%snot accepted\n\t\t", optind == (argc - 1) ? " " : "s ");
		while (optind < argc) {
			fprintf(stderr, " %s,", argv[optind++]);
			if (optind == argc) fprintf(stderr, "%c", '\b');
		}
		exit(EXIT_FAILURE);
	}

	return check_info(proxy_ip, proxy_port);
}

static void version() {
	fprintf(stderr, "Client PCAMP (Proxy Configuration And Monitoring Protocol) version 0.1\n"
					"ITBA\n"
					"Protocolos de Comunicacion 2021/1 - Grupo 7\n"
					"Licencia: ...\n");
	exit(EXIT_SUCCESS);
}

static void usage(const char *program_name) {
	fprintf(stderr,
			"OPTIONS\n"
			"\t-h\n\t\tImprime el manual y finaliza.\n\n"
			"\t-v\n\t\tImprime la versión del programa %s y finaliza.\n\n"
			"\t-p puerto-proxy\n\t\tPuerto TCP donde el proxy HTTP escucha conexiones. Por defecto toma el valor 8080.\n\n"
			"\t-l dirección-proxy\n\t\tEstablece la dirección donde el proxy HTTP brinda servicio. Por defecto escucha en todas "
			"las interfaces.\n\n",
			program_name);
	exit(EXIT_SUCCESS);
}

static addr_info check_info(const char *proxy_ip, const char *proxy_port) {
	// Informacion de retorno
	addr_info args_addr;
	// Variables auxiliares:
	struct sockaddr_in addr_in4;
	struct sockaddr_in6 addr_in6;

	long parsed_port = strtol(proxy_port, NULL, 10);

	if ((parsed_port == 0 && errno == EINVAL) || parsed_port < 0 || parsed_port > 65535) {
		logger(FATAL, "Invalid port number. Must be an integer between 0 and 65535. Exiting...\n");
	}

	addr_in4.sin_port = addr_in6.sin6_port = htons(parsed_port);

	if (inet_pton(AF_INET, proxy_ip, &addr_in4.sin_addr.s_addr) == 1) {
		// es ipv4
		addr_in4.sin_family = AF_INET;
		args_addr.in4 = addr_in4;
	} else if (inet_pton(AF_INET6, proxy_ip, &addr_in6.sin6_addr) == 1) {
		// es ipv6
		addr_in6.sin6_family = AF_INET6;
		args_addr.in6 = addr_in6;
	} else {
		logger(FATAL, "Invalid IP address. Exiting...\n");
	}

	return args_addr;
}
