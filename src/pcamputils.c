// This is a personal academic project. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com
#include <pcamputils.h>

ssize_t config_value_length[PCAMP_CONFIG_TYPE_COUNT] = {2, 2, 1, 17, 2, 256};
ssize_t query_answer_length[PCAMP_QUERY_TYPE_COUNT] = {8, 8, 8, 8, 8, 8};

void sha256_digest(const void *src, void *dest, size_t bytes) {
    SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, src, bytes);
	SHA256_Final(dest, &sha256);
}
