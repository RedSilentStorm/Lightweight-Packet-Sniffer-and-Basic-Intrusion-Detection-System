#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ids_tracker.h"

static void make_ipv4_key(const char *ip_text, struct ids_address_key *out_key) {
    uint32_t ip = inet_addr(ip_text);
    memset(out_key, 0, sizeof(*out_key));
    out_key->family = AF_INET;
    memcpy(out_key->bytes, &ip, 4);
}

static int run_tracker_scenario(void) {
    struct ids_tracker tracker;
    struct ids_address_key key_a;
    struct ids_address_key key_b;
    unsigned int count = 0;
    time_t window_start = 0;
    int alerts = 0;

    ids_tracker_init(&tracker, 3, 5);

    make_ipv4_key("10.1.1.10", &key_a);
    make_ipv4_key("10.1.1.20", &key_b);

    alerts += ids_tracker_record_packet(&tracker, &key_a, 100, &count, &window_start);
    if (count != 1 || window_start != 100) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 101, &count, &window_start);
    if (count != 2 || window_start != 100) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 102, &count, &window_start);
    if (count != 3 || alerts != 0) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 103, &count, &window_start);
    if (count != 4 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 104, &count, &window_start);
    if (count != 5 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_b, 104, &count, &window_start);
    if (count != 1 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 106, &count, &window_start);
    if (count != 1 || window_start != 106 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 107, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, &key_a, 108, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, &key_a, 109, &count, &window_start);
    if (count != 4 || alerts != 2) {
        return 0;
    }

    return 1;
}

static int run_sliding_scenario(void) {
    struct ids_tracker tracker;
    struct ids_address_key key_a;
    unsigned int count = 0;
    time_t window_start = 0;
    int alerts = 0;

    ids_tracker_init(&tracker, 3, 5);
    ids_tracker_set_sliding(&tracker, 1);
    make_ipv4_key("10.1.1.10", &key_a);

    alerts += ids_tracker_record_packet(&tracker, &key_a, 100, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, &key_a, 100, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, &key_a, 100, &count, &window_start);
    if (alerts != 0) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 100, &count, &window_start);
    if (alerts != 1) {
        return 0;
    }

    /* After enough idle time, tokens refill and source can trigger again. */
    alerts += ids_tracker_record_packet(&tracker, &key_a, 106, &count, &window_start);
    if (alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, &key_a, 106, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, &key_a, 106, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, &key_a, 106, &count, &window_start);
    if (alerts != 2) {
        return 0;
    }

    return 1;
}

int main(void) {
    if (!run_tracker_scenario()) {
        fprintf(stderr, "ids_tracker_test: FAILED\n");
        return 1;
    }

    if (!run_sliding_scenario()) {
        fprintf(stderr, "ids_tracker_test (sliding): FAILED\n");
        return 1;
    }

    printf("ids_tracker_test: PASSED\n");
    return 0;
}
