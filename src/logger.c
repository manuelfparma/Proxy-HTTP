#include "include/logger.h"

char *get_level_description(level level) {
	char *description[] = {"[DEBUG]", "[INFO]", "[ERROR]", "[FATAL]"};
	return description[level];
}

char *get_peer_description(peer peer) {
	char *description[] = {"[CLIENT]", "[SERVER]"};
	return description[peer];
}
