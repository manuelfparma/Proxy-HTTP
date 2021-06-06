#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdio.h>
#include <stdlib.h>
#include <proxyutils.h>

typedef enum { DEBUG = 0, INFO, ERROR, FATAL } LEVEL;

char *getLevelDescription(LEVEL level);

char *getPeerDescription(PEER peer);

#define logger(level, ...)                                                                                                       \
	{                                                                                                                            \
		char *description = getLevelDescription(level);                                                                          \
		fprintf(stderr, "%s : ", description);                                                                                   \
		fprintf(stderr, ##__VA_ARGS__);                                                                                          \
		if (level != INFO) fprintf(stderr, " at %s(%s:%d)", __func__, __FILE__, __LINE__);                                       \
		fprintf(stderr, "\n");                                                                                                   \
		if (level == FATAL) exit(EXIT_FAILURE);                                                                                  \
	}

#define loggerPeer(peer, ...)                                                                                                    \
	{                                                                                                                            \
		fprintf(stderr, "%s : ", getPeerDescription(peer));                                                                      \
		fprintf(stderr, ##__VA_ARGS__);                                                                                          \
		fprintf(stderr, "\n");                                                                                                   \
	}

#endif
