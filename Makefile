PHONY: all proxy clean

CFLAGS= -g -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L
FSANITIZE= -fsanitize=address

SOURCES_PROXY= src/proxy.c 
SOURCES_PARSER= src/parser.c
SOURCES_PROXY_UTILS= src/proxyutils.c
SOURCES_LOGGER= src/logger.c
SOURCES_CONNECTION= src/connection.c
SOURCES_BUFFER = src/buffer.c
OBJECTS = src/proxy.o src/parser.o src/proxyutils.o src/logger.o src/connection.o src/buffer.o

all: proxy

# proxy: $(OBJECTS)
# 	$(LD) -o httpd $^

proxy: $(SOURCES_PROXY) $(SOURCES_PARSER) $(SOURCES_PROXY_UTILS) $(SOURCES_LOGGER) $(SOURCES_CONNECTION) $(SOURCES_BUFFER)
	$(CC) $(CFLAGS) $(FSANITIZE) -pthread -I./src -I./src/include -o httpd $^

# %.o: %.c
# 	$(CC) $(CFLAGS) $(FSANITIZE) -pthread -I./src -I./src/include -c $< -o $@

clean:
	rm -rf httpd src/*.o
