#ifndef IDS_TRACKER_H
#define IDS_TRACKER_H

#include <stdint.h>
#include <time.h>

#define IDS_MAX_TRACKED_IPS 2048

struct ids_entry {
    uint32_t source_ip;
    time_t window_start;
    unsigned int count;
    int alert_sent;
    int in_use;
};

struct ids_tracker {
    struct ids_entry entries[IDS_MAX_TRACKED_IPS];
    unsigned int threshold;
    unsigned int window_seconds;
};

void ids_tracker_init(struct ids_tracker *tracker, unsigned int threshold, unsigned int window_seconds);
int ids_tracker_record_packet(
    struct ids_tracker *tracker,
    uint32_t source_ip,
    time_t packet_time,
    unsigned int *out_count,
    time_t *out_window_start
);

#endif
