#include <sys/types.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/alert_logger.h"
#include "../include/capture_source.h"
#include "../include/ids_tracker.h"
#include "../include/packet_parser.h"
#include "../include/parse_utils.h"
#include "../include/alert_export.h"
#include "../include/perf_metrics.h"

struct app_config {
    int mode;
    const char *source;
    unsigned int threshold;
    unsigned int window_seconds;
    int max_packets;
};

struct app_state {
    struct app_config config;
    struct ids_tracker tracker;
    struct alert_logger logger;
    int packet_count;
    FILE *export_csv;
    FILE *export_json;
    int json_first;
    struct perf_stats perf;
};

static void usage(const char *program_name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s list\n"
            "  %s live <interface> <threshold> <window_seconds> [packet_count]\n"
            "  %s replay <pcap_file> <threshold> <window_seconds> [packet_count]\n"
            "  %s test\n",
            program_name,
            program_name,
            program_name,
            program_name);
}

static int list_interfaces(void) {
    pcap_if_t *interfaces = NULL;
    pcap_if_t *current = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int index = 0;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return 1;
    }

    if (interfaces == NULL) {
        printf("No interfaces found.\n");
        return 0;
    }

    printf("Available network interfaces:\n");
    for (current = interfaces; current != NULL; current = current->next) {
        index++;
        printf("%d) %s", index, current->name);

        if (current->description != NULL) {
            printf(" - %s", current->description);
        }

        printf("\n");
    }

    pcap_freealldevs(interfaces);
    return 0;
}

static int parse_capture_args(
    int argc,
    char **argv,
    int mode,
    struct app_config *out
) {
    if (argc < 5 || argc > 6) {
        usage(argv[0]);
        return 0;
    }

    out->mode = mode;
    out->source = argv[2];
    out->max_packets = 100;

    if (!parse_positive_uint(argv[3], &out->threshold) || !parse_positive_uint(argv[4], &out->window_seconds)) {
        fprintf(stderr, "threshold and window_seconds must be positive integers within range.\n");
        return 0;
    }

    if (argc == 6) {
        if (!parse_positive_int(argv[5], &out->max_packets)) {
            fprintf(stderr, "packet_count must be a positive integer within range.\n");
            return 0;
        }
    }

    return 1;
}

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct app_state *state = (struct app_state *)user_data;
    struct parsed_packet info;
    unsigned int count_in_window = 0;
    time_t window_start = 0;

    state->packet_count++;
    perf_stats_record_packet(&state->perf, pkthdr->len);

    if (!parse_packet_info(pkthdr, packet, &info)) {
        return;
    }

    if (!info.is_ipv4) {
        return;
    }

    if (info.is_supported_transport) {
        printf("%s %s:%u -> %s:%u\n",
               packet_protocol_name(info.protocol),
               info.source_ip_text,
               info.source_port,
               info.destination_ip_text,
               info.destination_port);
    } else {
        printf("%s %s -> %s\n",
               packet_protocol_name(info.protocol),
               info.source_ip_text,
               info.destination_ip_text);
    }

    struct timespec _t0, _t1;
    clock_gettime(CLOCK_MONOTONIC, &_t0);
    int alerted = ids_tracker_record_packet(
            &state->tracker,
            info.source_ip,
            (time_t)pkthdr->ts.tv_sec,
            &count_in_window,
            &window_start
        );
    clock_gettime(CLOCK_MONOTONIC, &_t1);
    unsigned int processing_latency_us = (unsigned int)((_t1.tv_sec - _t0.tv_sec) * 1000000u + (_t1.tv_nsec - _t0.tv_nsec) / 1000u);

    if (alerted) {
        char message[320];
        unsigned int elapsed = (unsigned int)((time_t)pkthdr->ts.tv_sec - window_start);

        if (info.is_supported_transport) {
            snprintf(
                message,
                sizeof(message),
                "source=%s protocol=%s src_port=%u dst=%s:%u count=%u threshold=%u elapsed=%us window=%us",
                info.source_ip_text,
                packet_protocol_name(info.protocol),
                info.source_port,
                info.destination_ip_text,
                info.destination_port,
                count_in_window,
                state->config.threshold,
                elapsed,
                state->config.window_seconds
            );
        } else {
            snprintf(
                message,
                sizeof(message),
                "source=%s protocol=%s dst=%s count=%u threshold=%u elapsed=%us window=%us",
                info.source_ip_text,
                packet_protocol_name(info.protocol),
                info.destination_ip_text,
                count_in_window,
                state->config.threshold,
                elapsed,
                state->config.window_seconds
            );
        }

        alert_logger_log(&state->logger, message);

        /* Structured export */
        if (state->export_csv != NULL) {
            struct alert_record rec;
            rec.timestamp = (time_t)pkthdr->ts.tv_sec;
            rec.source_ip = info.source_ip;
            rec.source_port = info.source_port;
            rec.destination_ip = info.destination_ip;
            rec.destination_port = info.destination_port;
            rec.protocol = info.protocol;
            rec.packet_count = count_in_window;
            rec.threshold = state->config.threshold;
            rec.window_seconds = state->config.window_seconds;
            rec.elapsed_seconds = (unsigned int)((time_t)pkthdr->ts.tv_sec - window_start);
            alert_export_csv_record(state->export_csv, &rec);
            alert_export_json_record(state->export_json, &rec, state->json_first);
            state->json_first = 0;
        }

        perf_stats_record_alert(&state->perf, processing_latency_us);
    }
}

static int run_capture(const struct app_config *config) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct app_state state;

    memset(&state, 0, sizeof(state));
    state.config = *config;

    ids_tracker_init(&state.tracker, state.config.threshold, state.config.window_seconds);

    /* init performance stats and exports */
    perf_stats_init(&state.perf);
    state.export_csv = fopen("logs/alerts.csv", "a");
    state.export_json = fopen("logs/alerts.json", "a");
    state.json_first = 0;
    if (state.export_csv) alert_export_csv_header(state.export_csv);
    if (state.export_json) { alert_export_json_header(state.export_json); state.json_first = 1; }

    if (alert_logger_open(&state.logger, "logs/alerts.log") != 0) {
        fprintf(stderr, "Failed to open logs/alerts.log for writing.\n");
        return 1;
    }

    handle = open_capture_source(state.config.mode, state.config.source, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open capture source '%s': %s\n", state.config.source, errbuf);
        alert_logger_close(&state.logger);
        return 1;
    }

    if (state.config.mode == CAPTURE_MODE_LIVE) {
        printf("Running live capture on '%s' (threshold=%u, window=%us, packets=%d)\n",
               state.config.source,
               state.config.threshold,
               state.config.window_seconds,
               state.config.max_packets);
    } else {
        printf("Running pcap replay on '%s' (threshold=%u, window=%us, packets=%d)\n",
               state.config.source,
               state.config.threshold,
               state.config.window_seconds,
               state.config.max_packets);
    }

    if (pcap_loop(handle, state.config.max_packets, packet_handler, (unsigned char *)&state) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        alert_logger_close(&state.logger);
        return 1;
    }

    pcap_close(handle);
    alert_logger_close(&state.logger);
    
    /* Close JSON export properly */
    if (state.export_json != NULL) {
        alert_export_json_footer(state.export_json);
        fclose(state.export_json);
    }
    if (state.export_csv != NULL) {
        fclose(state.export_csv);
    }
    
    /* End performance measurement and report */
    perf_stats_end(&state.perf);
    perf_stats_print_report(&state.perf);
    perf_stats_export_csv(&state.perf, "logs/perf_metrics.csv");
    
    printf("Run complete. Processed packets: %d\n", state.packet_count);
    return 0;
}

static int run_self_test(void) {
    struct ids_tracker tracker;
    uint32_t ip_a = inet_addr("10.1.1.10");
    uint32_t ip_b = inet_addr("10.1.1.20");
    unsigned int count = 0;
    time_t window_start = 0;
    int alerts = 0;

    ids_tracker_init(&tracker, 3, 5);

    alerts += ids_tracker_record_packet(&tracker, ip_a, 100, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 101, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 102, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 103, &count, &window_start);

    if (alerts != 1 || count != 4 || window_start != 100) {
        fprintf(stderr, "Self-test failed: threshold crossing did not match expected behavior.\n");
        return 1;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_b, 103, &count, &window_start);
    if (count != 1) {
        fprintf(stderr, "Self-test failed: independent source counter mismatch.\n");
        return 1;
    }

    alerts += ids_tracker_record_packet(&tracker, ip_a, 106, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 107, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 108, &count, &window_start);
    alerts += ids_tracker_record_packet(&tracker, ip_a, 109, &count, &window_start);

    if (alerts != 2 || count != 4 || window_start != 106) {
        fprintf(stderr, "Self-test failed: window reset behavior mismatch.\n");
        return 1;
    }

    printf("Self-test passed. IDS tracker behavior is correct.\n");
    return 0;
}

int main(int argc, char **argv) {
    struct app_config config;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        return list_interfaces();
    }

    if (strcmp(argv[1], "test") == 0) {
        return run_self_test();
    }

    if (strcmp(argv[1], "live") == 0) {
        if (!parse_capture_args(argc, argv, CAPTURE_MODE_LIVE, &config)) {
            return 1;
        }

        return run_capture(&config);
    }

    if (strcmp(argv[1], "replay") == 0) {
        if (!parse_capture_args(argc, argv, CAPTURE_MODE_PCAP, &config)) {
            return 1;
        }

        return run_capture(&config);
    }

    usage(argv[0]);
    return 1;
}
