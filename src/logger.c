#include "logger.h"
#include "proxy/utils/proxyutils.h"

char * getLevelDescription(LEVEL level)
{
	char *description[] = {"[DEBUG]", "[INFO]", "[ERROR]", "[FATAL]"};
	return description[level];
}

char * getPeerDescription(PEER peer){
	char *description[] = {"[CLIENT]", "[SERVER]"};
	return description[peer];
}

