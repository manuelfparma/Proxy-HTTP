PHONY: all proxy clean

CFLAGS= -Isrc/include/ -g -std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L
FSANITIZE=-fsanitize=address

SOURCE=$(wildcard src/*.c)
PROXY_SOURCE=$(wildcard src/proxy/*.c)
PROXY_UTILS_SOURCE=$(wildcard src/proxy/utils/*.c)

all: proxy

proxy: ${PROXY_SOURCE} ${PROXY_UTILS_SOURCE} ${SOURCE}
	${CC} -pthread ${PROXY_SOURCE} ${PROXY_UTILS_SOURCE} ${SOURCE} ${CFLAGS}  -o httpd ${FSANITIZE}

clean:
	rm -rf httpd
