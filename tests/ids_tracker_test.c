#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

#include "ids_tracker.h"

static int run_tracker_scenario(void) {
    struct ids_tracker tracker;
    uint32_t ip_a = inet_addr("10.1.1.10");
    uint32_t ip_b = inet_addr("10.1.1.20");
    unsigned int count = 0;
    time_t window_start = 0;
    int alerts = 0;

    ids_tracker_init(&tracker, 3, 5);

    alerts += ids_tracker_record_packet(&tracker, ip_a, 100, &count, &window_start);
    if (count != 1 || window_start != 100) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 101, &count, &window_start);
    if (count != 2 || window_start != 100) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 102, &count, &window_start);
    if (count != 3 || alerts != 0) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 103, &count, &window_start);
    if (count != 4 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 104, &count, &window_start);
    if (count != 5 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_b, 104, &count, &window_start);
    if (count != 1 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 106, &count, &window_start);
    if (count != 1 || window_start != 106 || alerts != 1) {
        return 0;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 107, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 108, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 109, &count, &window_start);
    if (count != 4 || alerts != 2) {
        return 0;
    }

    return 1;
}

int main(void) {
    if (!run_tracker_scenario()) {
        fprintf(stderr, "ids_tracker_test: FAILED\n");
        return 1;
    }

    printf("ids_tracker_test: PASSED\n");
    return 0;
}
