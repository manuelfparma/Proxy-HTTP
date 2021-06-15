// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include "include/logger.h"

char *get_level_description(level level) {
	char *description[] = {"[DEBUG]", "[INFO]", "[ERROR]", "[FATAL]"};
	return description[level];
}

char *get_peer_description(peer peer) {
	char *description[] = {"[CLIENT]", "[SERVER]"};
	return description[peer];
}
