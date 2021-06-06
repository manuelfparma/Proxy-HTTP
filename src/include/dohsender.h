#ifndef DOH_SENDER_H

#define DOH_SENDER_H

#include <unistd.h>

ssize_t write_doh_request(int fd, char *domain_name, char *host_name);

#endif
