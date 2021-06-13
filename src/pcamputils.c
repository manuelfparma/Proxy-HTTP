#include <pcamputils.h>

void sha256_digest(const void *src, void *dest, size_t bytes) {
    SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, src, bytes);
	SHA256_Final(dest, &sha256);
}
