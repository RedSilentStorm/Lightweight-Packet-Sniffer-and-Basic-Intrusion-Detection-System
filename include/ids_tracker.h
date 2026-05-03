#ifndef IDS_TRACKER_H
#define IDS_TRACKER_H

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#define IDS_MAX_TRACKED_IPS 2048

struct ids_address_key {
    int family;
    uint8_t bytes[16];
};

struct ids_entry {
    struct ids_address_key source_address;
    time_t window_start;
    unsigned int count;
    int alert_sent;
    int in_use;
    double tokens; /* for sliding/token-bucket mode */
    time_t last_refill; /* last refill timestamp for tokens */
};

struct ids_tracker {
    struct ids_entry entries[IDS_MAX_TRACKED_IPS];
    unsigned int threshold;
    unsigned int window_seconds;
    int sliding_enabled; /* 0 = fixed-window (legacy), 1 = token-bucket sliding window */
    double refill_rate; /* tokens per second = threshold / window_seconds */
};

void ids_tracker_init(struct ids_tracker *tracker, unsigned int threshold, unsigned int window_seconds);
int ids_tracker_record_packet(
    struct ids_tracker *tracker,
    const struct ids_address_key *source_address,
    time_t packet_time,
    unsigned int *out_count,
    time_t *out_window_start
);

void ids_tracker_set_sliding(struct ids_tracker *tracker, int enabled);

#endif
