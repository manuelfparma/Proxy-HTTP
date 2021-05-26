CC=gcc
FLAGS=-g
FSANITIZE=-fsanitize=address
#--std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough

server: server.c
	${CC} server.c serverutils.c logger.c -o server ${FLAGS}

clientfs: client.c
	${CC} client.c clientutils.c logger.c -o client ${FLAGS} ${FSANITIZE}

serverfs: server.c
	${CC} server.c serverutils.c logger.c -o server ${FLAGS} ${FSANITIZE}

client: client.c
	${CC} client.c clientutils.c logger.c -o client ${FLAGS}

#proxy: proxy.c
#	${CC} proxy.c clientutils.c serverutils.c -o proxy

all: server client 

allfs: serverfs clientfs

clean: 
	rm -r server client

.PHONY: clean all