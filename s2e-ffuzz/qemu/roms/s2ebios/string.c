#include "string.h"

void memcpy(void *dest, const void *src, unsigned size)
{
    char *cd = dest;
    const char *cs = src;

    for (unsigned i = 0; i < size; ++i) {
        *cd = *cs;
        cs++;
        cd++;
    }
}

void memset(void *dest, uint8_t c, unsigned size)
{
    char *cd = dest;

    for (unsigned i = 0; i < size; ++i) {
        *cd = c;
        cd++;
    }
}
