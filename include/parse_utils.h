#ifndef PARSE_UTILS_H
#define PARSE_UTILS_H

#include <limits.h>

int parse_positive_uint(const char *text, unsigned int *out_value);
int parse_positive_int(const char *text, int *out_value);

#endif
