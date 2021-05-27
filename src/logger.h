#ifndef __LOGGER_H__
#define __LOGGER_H__

typedef enum {DEBUG = 0, INFO, ERROR, FATAL} LEVEL;

char * getLevelDescription(LEVEL level);

#define logger(level, fmt, ...)    	{	        																				\
    fprintf(stderr, "%s : In file %s in %s() at line %d. ", getLevelDescription(level), __FILE__ , __FUNCTION__, __LINE__); 	\
    fprintf(stderr, (fmt), ##__VA_ARGS__);  																					\
    fprintf(stderr, "\n");                                 																		\
    if(level == FATAL) exit(EXIT_FAILURE);											                                			\
	}

#define loggerPeer(peer, ftm, ...)		{ 	\
    fprintf(stderr, "%s : ", getPeerDescription(peer)); 	\
    fprintf(stderr, (fmt), ##__VA_ARGS__);                  \
	}

#endif