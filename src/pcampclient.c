#include <arpa/inet.h>
#include <errno.h>
#include <logger.h>
#include <sha
#include <netinet/in.h>
#include <pcampclient.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcampargs.h>

//TODO: 0-	 printear menu de ayuda
//DONE: 1- 	 recibo la IP del proxy por STDIN
//DONE: 2- 	 armar socket
//TODO: 3- 	 pedis por STDIN si quiere configurar o consultar registros de acceso (multiple choice)
//TODO: 4- 	 pedis por STDIN que cosa quiere consultar / configurar
//TODO: 5- 	 pedis parametro de config
//TODO: 6- 	 armas paquete en binario y lo envias
//TODO: 7- 	 loader (print de '.' cada segundo)
//TODO: 8.1-  si no recibis respuesta en 3 seg -> retransmitis
//TODO: 8.2 - a los 10 seg timeout
//TODO: 9 -	 recibis la respuesta, la parseas, y la mostras
//TODO: 10 -  repetir 3

#define INPUT_BUFFER 1024

static addr_info current_addr = {0};

int main(const int argc, char **argv) {
	current_addr = parse_pcamp_args(argc, argv);

	printf("\033[1:36m ======= Proxy Configuration and Monitoring Protocol - Version 1.0 =======\n\n\033[0m ");

	bool isInputValid = false;
	char input[INPUT_BUFFER + 1];
	while (!isInputValid) {
		printf("Select a method:\n0 - Query (get tracked access data from HTTP proxy server)\n1 - Configuration (modify HTTP proxy server settings at runtime\n\033[1:32m→ \033[0m");

		ssize_t read_bytes = read(STDIN_FILENO, input, INPUT_BUFFER);
		input[read_bytes] = 0;

		if (read_bytes != 1 || (input[0] != '0' && input[0] != '1')) {
			printf("Invalid option\n");
		} else
			isInputValid = true;
	}





	int server_sock = socket(current_addr.addr.sa_family, SOCK_DGRAM, 0);

	if (server_sock < 0)
		logger(FATAL, "%s", strerror(errno));











}