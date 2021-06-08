CFLAGS= -g -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L -Wno-gnu-zero-variadic-macro-arguments
FSANITIZE= -fsanitize=address

SOURCES_PROXY= src/proxy.c 
SOURCES_PARSER= src/http_parser.c
SOURCES_PROXY_UTILS= src/proxyutils.c
SOURCES_LOGGER= src/logger.c
SOURCES_CONNECTION= src/connection.c
SOURCES_BUFFER = src/buffer.c
SOURCES_DOH_CLIENT = src/dohclient.c
SOURCES_DOH_UTILS = src/dohutils.c
SOURCES_DOH_SENDER = src/dohsender.c
SOURCES_DOH_PARSER = src/dohparser.c
OBJECTS = src/proxy.o src/http_parser.o src/proxyutils.o src/logger.o src/connection.o src/buffer.o src/dohclient.o src/dohparser.o src/dohsender.o src/dohutils.o

all: proxy

proxy: $(OBJECTS)
	$(CC) $(FSANITIZE) -o httpd $^

%.o: %.c
	$(CC) $(CFLAGS) -I./src/include -c $< -o $@

# proxy: $(SOURCES_PROXY) $(SOURCES_PARSER) $(SOURCES_PROXY_UTILS) $(SOURCES_LOGGER) $(SOURCES_CONNECTION) $(SOURCES_BUFFER)
# 	$(CC) $(CFLAGS) $(FSANITIZE) -I./src -I./src/include -o httpd $^

clean:
	rm -rf httpd src/*.o logs/log_connection_* logs/proxy_log

.PHONY: all proxy clean
