#include "nm_openssl_random.h"

#include <platform/np_error_code.h>
#include <platform/np_platform.h>

#include <limits.h>
#include <openssl/rand.h>

static np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize);

bool nm_openssl_random_init(struct np_platform* pl)
{
    // The OpenSSL default random generator is seeded and thread safe, no
    // state is kept in the platform.
    pl->randomData = NULL;
    pl->random.random = &make_random;
    return true;
}

void nm_openssl_random_deinit(struct np_platform* pl)
{
    (void)pl;
}

np_error_code make_random(struct np_platform* pl, void* buffer, size_t bufferSize)
{
    (void)pl;
    uint8_t* b = buffer;
    while (bufferSize > 0) {
        int n = bufferSize > INT_MAX ? INT_MAX : (int)bufferSize;
        if (RAND_bytes(b, n) != 1) {
            return NABTO_EC_UNKNOWN;
        }
        b += n;
        bufferSize -= (size_t)n;
    }
    return NABTO_EC_OK;
}
