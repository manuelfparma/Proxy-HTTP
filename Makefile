CC=gcc
FLAGS=-fsanitize=address -g
#--std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough

server: server.c
	${CC} server.c serverutils.c logger.c -o server ${FLAGS}

client: client.c
	${CC} client.c clientutils.c logger.c -o client ${FLAGS}

#proxy: proxy.c
#	${CC} proxy.c clientutils.c serverutils.c -o proxy

all: server client

clean: 
	rm -r server client

.PHONY: clean all