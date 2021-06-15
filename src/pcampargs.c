// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <logger.h>
#include <pcampargs.h>
#include <getopt.h>


static void version();
static void usage(const char *program_name);
static addr_info check_info(const char *proxy_ip, const char *proxy_port);

addr_info parse_pcamp_args(const int argc, char **argv) {

	char *proxy_ip = PROXY_IP;
	char *proxy_port = PROXY_PORT;

	// variables para getopt_long()
	int c;
	char *flags = "hvp:l:";

	while (1) {
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
	fprintf(stderr, "PCAMP Client version 1.0\n"
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
			"\t-p puerto-proxy\n\t\tPuerto UDP donde el servidor PCAMP escucha. Por defecto toma el valor 9090.\n\n"
			"\t-l dirección-proxy\n\t\tEstablece la dirección donde el servidor PCAMP escucha. Por defecto toma el valor 127.0.0.1.\n\n",
			program_name);
	exit(EXIT_SUCCESS);
}

static addr_info check_info(const char *proxy_ip, const char *proxy_port) {
	addr_info args_addr;
	uint16_t port;

	if (!parse_port(proxy_port, &port))
		logger(FATAL, "Invalid port number. Must be an integer between 0 and 65535. Exiting...\n");

	if (!parse_ip_address(proxy_ip, port, &args_addr)) logger(FATAL, "Invalid IP address. Exiting...\n");

	return args_addr;
}
