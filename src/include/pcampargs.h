#ifndef PCAMPARGS_H
#define PCAMPARGS_H

#include <netutils.h>

#define PROXY_IP "127.0.0.1"
#define PROXY_PORT "9090"

addr_info parse_pcamp_args(int argc, char **argv);

#endif
