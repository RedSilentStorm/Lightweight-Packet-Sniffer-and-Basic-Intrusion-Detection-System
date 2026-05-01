#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "parse_utils.h"

int parse_positive_uint(const char *text, unsigned int *out_value) {
    char *end = NULL;
    unsigned long parsed = 0;

    if (text == NULL || out_value == NULL || text[0] == '\0') {
        return 0;
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }

    if (parsed == 0 || parsed > UINT_MAX) {
        return 0;
    }

    *out_value = (unsigned int)parsed;
    return 1;
}

int parse_positive_int(const char *text, int *out_value) {
    unsigned int tmp = 0;

    if (out_value == NULL) {
        return 0;
    }

    if (!parse_positive_uint(text, &tmp)) {
        return 0;
    }

    if (tmp > INT_MAX) {
        return 0;
    }

    *out_value = (int)tmp;
    return 1;
}
