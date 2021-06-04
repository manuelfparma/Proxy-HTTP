PHONY: all proxy clean

CFLAGS= -g -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L -Wno-gnu-zero-variadic-macro-arguments
FSANITIZE= -fsanitize=address

# SOURCES_PROXY= src/proxy.c 
# SOURCES_PARSER= src/parser.c
# SOURCES_PROXY_UTILS= src/proxyutils.c
SOURCES_LOGGER= src/logger.c
# SOURCES_CONNECTION= src/connection.c
# SOURCES_BUFFER = src/buffer.c
SOURCES_DOH_CLIENT = src/dohclient.c
OBJECTS = src/logger.o src/dohclient.o

all: proxy

# proxy: $(OBJECTS)
# 	$(LD) -o httpd $^

proxy: $(SOURCES_LOGGER) ${SOURCES_DOH_CLIENT}
	$(CC) $(CFLAGS) $(FSANITIZE) -pthread -I./src -I./src/include -o httpd $^

# %.o: %.c
# 	$(CC) $(CFLAGS) $(FSANITIZE) -pthread -I./src -I./src/include -c $< -o $@

clean:
	rm -rf httpd src/*.o
