CC=gcc
FLAGS=-g 
#--std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough
FSANITIZE=-fsanitize=address


SOURCE=$(wildcard src/*.c)
PROXY_SOURCE=$(wildcard src/proxy/*.c)
PROXY_UTILS_SOURCE=$(wildcard src/proxy/utils/*.c)

all: proxy 

proxy: ${PROXY_SOURCE} ${PROXY_UTILS_SOURCE} ${SOURCE}
	${CC} ${PROXY_SOURCE} ${PROXY_UTILS_SOURCE} ${SOURCE} -o httpd ${FLAGS} ${FSANITIZE}

clean: 
	rm -rf httpd

.PHONY: all proxy clean
