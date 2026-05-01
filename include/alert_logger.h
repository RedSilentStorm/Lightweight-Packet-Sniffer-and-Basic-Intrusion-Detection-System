#ifndef ALERT_LOGGER_H
#define ALERT_LOGGER_H

#include <stdio.h>

struct alert_logger {
    FILE *file;
};

int alert_logger_open(struct alert_logger *logger, const char *path);
void alert_logger_close(struct alert_logger *logger);
void alert_logger_log(struct alert_logger *logger, const char *message);

#endif
