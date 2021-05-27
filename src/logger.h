#ifndef __LOGGER_H__
#define __LOGGER_H__

typedef enum {DEBUG = 0, INFO, ERROR, FATAL} LEVEL;

char * getLevelDescription(LEVEL level);

#define logger(level, fmt, ...)    	{ 																\
	char * description = getLevelDescription(level);     											\
	fprintf(stderr, "%s : ", description);               											\
	fprintf(stderr, (fmt), ##__VA_ARGS__);  														\
    if(level != INFO)                                             									\
			fprintf(stderr, " at %s(%s:%d)", __FUNCTION__,  __FILE__, __LINE__); 					\
    fprintf(stderr, "\n");                                 											\
    if(level == FATAL) exit(EXIT_FAILURE);											                \
	}

#define loggerPeer(peer, ftm, ...)		{ 	\
    fprintf(stderr, "%s : ", getPeerDescription(peer)); 	\
    fprintf(stderr, (fmt), ##__VA_ARGS__);                  \
	}

#endif