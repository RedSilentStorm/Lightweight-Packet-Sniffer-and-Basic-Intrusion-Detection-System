#include <stddef.h>

#include "ids_tracker.h"

static size_t find_or_allocate_entry(struct ids_tracker *tracker, uint32_t source_ip) {
    size_t i = 0;
    size_t free_index = IDS_MAX_TRACKED_IPS;
    size_t oldest_index = 0;
    time_t oldest_time = 0;
    int oldest_set = 0;

    for (i = 0; i < IDS_MAX_TRACKED_IPS; i++) {
        if (tracker->entries[i].in_use) {
            if (tracker->entries[i].source_ip == source_ip) {
                return i;
            }

            if (!oldest_set || tracker->entries[i].window_start < oldest_time) {
                oldest_set = 1;
                oldest_time = tracker->entries[i].window_start;
                oldest_index = i;
            }
        } else if (free_index == IDS_MAX_TRACKED_IPS) {
            free_index = i;
        }
    }

    if (free_index != IDS_MAX_TRACKED_IPS) {
        return free_index;
    }

    return oldest_index;
}

void ids_tracker_init(struct ids_tracker *tracker, unsigned int threshold, unsigned int window_seconds) {
    size_t i = 0;

    tracker->threshold = threshold;
    tracker->window_seconds = window_seconds;

    for (i = 0; i < IDS_MAX_TRACKED_IPS; i++) {
        tracker->entries[i].source_ip = 0;
        tracker->entries[i].window_start = 0;
        tracker->entries[i].count = 0;
        tracker->entries[i].alert_sent = 0;
        tracker->entries[i].in_use = 0;
    }
}

int ids_tracker_record_packet(
    struct ids_tracker *tracker,
    uint32_t source_ip,
    time_t packet_time,
    unsigned int *out_count,
    time_t *out_window_start
) {
    size_t index = find_or_allocate_entry(tracker, source_ip);
    struct ids_entry *entry = &tracker->entries[index];
    int should_alert = 0;

    if (!entry->in_use || entry->source_ip != source_ip) {
        entry->source_ip = source_ip;
        entry->window_start = packet_time;
        entry->count = 1;
        entry->alert_sent = 0;
        entry->in_use = 1;
    } else if ((unsigned int)(packet_time - entry->window_start) >= tracker->window_seconds) {
        entry->window_start = packet_time;
        entry->count = 1;
        entry->alert_sent = 0;
    } else {
        entry->count++;
    }

    if (!entry->alert_sent && entry->count > tracker->threshold) {
        entry->alert_sent = 1;
        should_alert = 1;
    }

    if (out_count != NULL) {
        *out_count = entry->count;
    }

    if (out_window_start != NULL) {
        *out_window_start = entry->window_start;
    }

    return should_alert;
}
