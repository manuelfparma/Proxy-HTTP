#include <args.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <logger.h>
#include <proxy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */

#define NUM_BASE 10

static void version();
static void usage(const char *program_name);
static void check_port(const char *service);

void parse_args(const int argc, char **argv, arguments *args) {

	// cargo todo en cero y seteo valores defaults
	memset(args, 0, sizeof(*args));
	args->doh_ip = "127.0.0.1";
	args->doh_host = "localhost";
	args->doh_port = "8053";
	args->doh_path = "/getnsrecord";
	args->doh_query = "?dns=";
	args->proxy_port = "8080";
	args->management_port = "9090";
	args->proxy_ip = "0.0.0.0";
	args->management_ip = "127.0.0.1";
	args->password_dissector = 1;

	// variables para getopt_long()
	int c, long_opts_idx;
	char *flags = "hvNp:o:l:L:";

	char has_invalid_arguments = 0;

	// flags con formato long (precedidos por --)
	static const struct option long_opts[] = {{.name = "doh-ip", .has_arg = required_argument, .flag = NULL, .val = DOH_IP},
											  {.name = "doh-host", .has_arg = required_argument, .flag = NULL, .val = DOH_HOST},
											  {.name = "doh-port", .has_arg = required_argument, .flag = NULL, .val = DOH_PORT},
											  {.name = "doh-path", .has_arg = required_argument, .flag = NULL, .val = DOH_PATH},
											  {.name = "doh-query", .has_arg = required_argument, .flag = NULL, .val = DOH_QUERY},
											  {.name = 0, .has_arg = 0, .flag = 0, .val = 0}};

	while (1) {
		c = getopt_long(argc, argv, flags, long_opts, &long_opts_idx);
		if (c == -1) { break; }

		switch (c) {
			case 'h':
				usage(argv[0]);
				break;
			case 'v':
				version();
				break;
			case 'N':
				args->password_dissector = 0;
				break;
			case 'p':
				check_port(optarg);
				args->proxy_port = optarg;
				break;
			case 'o':
				check_port(optarg);
				args->management_port = optarg;
				break;
			case 'l':
				args->proxy_ip = optarg;
				break;
			case 'L':
				args->management_ip = optarg;
				break;
			case DOH_IP:
				args->doh_ip = optarg;
				break;
			case DOH_HOST:
				check_port(optarg);
				args->doh_host = optarg;
				break;
			case DOH_PORT:
				check_port(optarg);
				args->doh_port = optarg;
				break;
			case DOH_PATH:
				args->doh_path = optarg;
				break;
			case DOH_QUERY:
				args->doh_query = optarg;
				break;
			default:
				fprintf(stderr, "Invalid argument %s\n", argv[optind - 1]);
				has_invalid_arguments = 1;
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

	if(has_invalid_arguments) exit(EXIT_FAILURE);
}

static void version() {
	fprintf(stderr, "proxy HTTP version 0.0\n"
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
			"\t-N\n\t\tDeshabilita los passwords disectors.\n\n"
			"\t-p puerto-local\n\t\tPuerto TCP donde el proxy HTTP escucha conexiones. Por defecto toma el valor 8080.\n\n"
			"\t-o puerto-de-management\n\t\tPuerto donde el servicio de management escucha conexiones. Por defecto toma el valor "
			"9090.\n\n"
			"\t-l dirección-http\n\t\tEstablece la dirección donde el proxy HTTP brinda servicio. Por defecto escucha en todas "
			"las interfaces.\n\n"
			"\t-L dirección-de-management\n\t\tEstablece la dirección donde se brinda el servicio de management. Por defecto "
			"escucha en loopback.\n\n"
			"\t--doh-ip dirección\n\t\tEstablece la direccion del servidor DoH. Por defecto toma el valor 127.0.0.1 .\n\n"
			"\t--doh-port puerto\n\t\tPuerto donde se encuentra el servidor DoH. Por defecto toma el valor 8053.\n\n"
			"\t--doh-host hostname\n\t\tEstablece el valor del header Host de la petición DoH. Por defecto localhost.\n\n"
			"\t--doh-path path\n\t\tEstablece el path de la petición DoH. Por defecto toma el valor /getnsrecord.\n\n",
			program_name);
	exit(EXIT_SUCCESS);
}

static void check_port(const char *service) {
	char *end = 0;
	const long service_number = strtol(service, &end, NUM_BASE);

	if (end == service || *end != '\0' || ((service_number == LONG_MAX || service_number == LONG_MIN) && errno == ERANGE) ||
		service_number < 0 || service_number > USHRT_MAX) {
		logger(ERROR, "Port should be between 0 - 65535: %s", service);
	}
}