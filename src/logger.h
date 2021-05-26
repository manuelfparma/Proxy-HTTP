#ifndef __LOGGER_H__
#define __LOGGER_H__

typedef enum {DEBUG = 0, INFO, ERROR, FATAL} LEVEL;

void logger(LEVEL level, char *msg, int fd);

#endif