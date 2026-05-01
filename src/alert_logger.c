#include <stdio.h>
#include <time.h>

#include "alert_logger.h"

int alert_logger_open(struct alert_logger *logger, const char *path) {
    logger->file = fopen(path, "a");
    if (logger->file == NULL) {
        return -1;
    }

    return 0;
}

void alert_logger_close(struct alert_logger *logger) {
    if (logger->file != NULL) {
        fclose(logger->file);
        logger->file = NULL;
    }
}

void alert_logger_log(struct alert_logger *logger, const char *message) {
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    char timestamp[32];

    if (local_time != NULL) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);
    } else {
        snprintf(timestamp, sizeof(timestamp), "unknown-time");
    }

    printf("[%s] ALERT: %s\n", timestamp, message);

    if (logger->file != NULL) {
        fprintf(logger->file, "[%s] ALERT: %s\n", timestamp, message);
        fflush(logger->file);
    }
}
