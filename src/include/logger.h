#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <proxyutils.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum { DEBUG = 0, INFO, ERROR, FATAL } level;

char *get_level_description(level level);

char *get_peer_description(peer peer);

#define logger(level, ...)                                                                                                       \
	{                                                                                                                            \
		char *description = get_level_description(level);                                                                          \
		fprintf(stderr, "%s : ", description);                                                                                   \
		fprintf(stderr, ##__VA_ARGS__);                                                                                          \
		if (level != INFO) fprintf(stderr, " at %s(%s:%d)", __func__, __FILE__, __LINE__);                                       \
		fprintf(stderr, "\n");                                                                                                   \
		if (level == FATAL) exit(EXIT_FAILURE);                                                                                  \
	}

#define logger_peer(peer, ...)                                                                                                    \
	{                                                                                                                            \
		fprintf(stderr, "%s : ", get_peer_description(peer));                                                                      \
		fprintf(stderr, ##__VA_ARGS__);                                                                                          \
		fprintf(stderr, "\n");                                                                                                   \
	}

#endif
