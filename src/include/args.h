#ifndef __ARGS_H__
#define __ARGS_H__

#include <proxy.h>

typedef enum {
    DOH_IP,
    DOH_PORT,
    DOH_HOST,
    DOH_PATH,
    DOH_QUERY,
} long_opts_values;

void parse_args(const int argc, char **argv, arguments *args);

#endif
