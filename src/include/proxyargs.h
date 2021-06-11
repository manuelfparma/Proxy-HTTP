#ifndef __ARGS_H__
#define __ARGS_H__

#include <proxy.h>

typedef enum {
    DOH_IP,
    DOH_PORT,
    DOH_HOST,
    DOH_PATH,
} long_opts_values;

void parse_proxy_args(int argc, char **argv, proxy_arguments *args);

#endif
