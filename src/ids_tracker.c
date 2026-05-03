#include <stddef.h>
#include <string.h>
#include <math.h>

#include "ids_tracker.h"

static int address_key_matches(const struct ids_address_key *lhs, const struct ids_address_key *rhs) {
    if (lhs->family != rhs->family) {
        return 0;
    }

    if (lhs->family == AF_INET) {
        return memcmp(lhs->bytes, rhs->bytes, 4) == 0;
    }

    if (lhs->family == AF_INET6) {
        return memcmp(lhs->bytes, rhs->bytes, 16) == 0;
    }

    return memcmp(lhs->bytes, rhs->bytes, sizeof(lhs->bytes)) == 0;
}

static void copy_address_key(struct ids_address_key *dst, const struct ids_address_key *src) {
    dst->family = src->family;
    memset(dst->bytes, 0, sizeof(dst->bytes));
    if (src->family == AF_INET) {
        memcpy(dst->bytes, src->bytes, 4);
    } else if (src->family == AF_INET6) {
        memcpy(dst->bytes, src->bytes, 16);
    } else {
        memcpy(dst->bytes, src->bytes, sizeof(dst->bytes));
    }
}

static size_t find_or_allocate_entry(struct ids_tracker *tracker, const struct ids_address_key *source_address) {
    size_t i = 0;
    size_t free_index = IDS_MAX_TRACKED_IPS;
    size_t oldest_index = 0;
    time_t oldest_time = 0;
    int oldest_set = 0;

    for (i = 0; i < IDS_MAX_TRACKED_IPS; i++) {
        if (tracker->entries[i].in_use) {
            if (address_key_matches(&tracker->entries[i].source_address, source_address)) {
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
    tracker->sliding_enabled = 0;
    tracker->refill_rate = (double)threshold / (double)(window_seconds ? window_seconds : 1);

    for (i = 0; i < IDS_MAX_TRACKED_IPS; i++) {
        tracker->entries[i].source_address.family = 0;
        memset(tracker->entries[i].source_address.bytes, 0, sizeof(tracker->entries[i].source_address.bytes));
        tracker->entries[i].window_start = 0;
        tracker->entries[i].count = 0;
        tracker->entries[i].alert_sent = 0;
        tracker->entries[i].in_use = 0;
        tracker->entries[i].tokens = 0.0;
        tracker->entries[i].last_refill = 0;
    }
}

int ids_tracker_record_packet(
    struct ids_tracker *tracker,
    const struct ids_address_key *source_address,
    time_t packet_time,
    unsigned int *out_count,
    time_t *out_window_start
) {
    size_t index = find_or_allocate_entry(tracker, source_address);
    struct ids_entry *entry = &tracker->entries[index];
    int should_alert = 0;

    /* If sliding window (token-bucket) mode enabled, use per-entry tokens */
    if (tracker->sliding_enabled) {
        if (!entry->in_use || !address_key_matches(&entry->source_address, source_address)) {
            copy_address_key(&entry->source_address, source_address);
            entry->tokens = (double)tracker->threshold; /* start full */
            entry->last_refill = packet_time;
            entry->alert_sent = 0;
            entry->in_use = 1;
        } else {
            /* refill tokens based on elapsed time */
            double dt = (double)(packet_time - entry->last_refill);
            if (dt > 0) {
                double add = dt * tracker->refill_rate;
                entry->tokens += add;
                if (entry->tokens > (double)tracker->threshold) entry->tokens = (double)tracker->threshold;
                entry->last_refill = packet_time;
                if (entry->tokens >= 1.0) {
                    entry->alert_sent = 0;
                }
            }
        }

        /* consume token for this packet */
        if (entry->tokens >= 1.0) {
            entry->tokens -= 1.0;
            should_alert = 0;
        } else {
            /* threshold exceeded in sliding window */
            if (!entry->alert_sent) {
                entry->alert_sent = 1;
                should_alert = 1;
            }
        }

        if (out_count != NULL) {
            /* approximate count in window = capacity - tokens */
            unsigned int approx = (unsigned int)((double)tracker->threshold - floor(entry->tokens + 0.000001));
            *out_count = approx;
        }

        if (out_window_start != NULL) {
            *out_window_start = entry->last_refill;
        }

        return should_alert;
    }

    /* Legacy fixed-window behavior */
    if (!entry->in_use || !address_key_matches(&entry->source_address, source_address)) {
        copy_address_key(&entry->source_address, source_address);
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

void ids_tracker_set_sliding(struct ids_tracker *tracker, int enabled) {
    if (!tracker) return;
    tracker->sliding_enabled = enabled ? 1 : 0;
    tracker->refill_rate = (double)tracker->threshold / (double)(tracker->window_seconds ? tracker->window_seconds : 1);
}
