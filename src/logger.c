#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "logger.h"

void logger(LEVEL level, char *msg, int fd)
{
    char *description[] = {"[DEBUG] : ", "[INFO] : ", "[ERROR] : ", "[FATAL] : "};
    if(write(fd, description[level], strlen(description[level])) == -1 || write(fd, msg, strlen(msg)) == -1 || write(fd, "\n", 1) == -1){
        fprintf(stderr, "Log error");
        exit(EXIT_FAILURE);
    }
    if(level > 1)
        exit(EXIT_FAILURE);
}