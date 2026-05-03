#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ids_tracker.h"
#include "alert_logger.h"
#include "bpf_filter.h"
#include "parse_utils.h"
#include "packet_parser.h"
#include "capture_source.h"
#include "rule_engine.h"

enum input_mode {
    INPUT_MODE_LIVE = CAPTURE_MODE_LIVE,
    INPUT_MODE_PCAP = CAPTURE_MODE_PCAP
};

struct app_config {
    enum input_mode mode;
    const char *source;
    unsigned int threshold;
    unsigned int window_seconds;
    int max_packets;
    const char *bpf_filter;
    int sliding;
    struct ids_rule_engine rules;
};

struct app_state {
    struct app_config config;
    struct ids_tracker tracker;
    struct ids_tracker rule_trackers[IDS_MAX_RULES];
    struct alert_logger logger;
    int packet_count;
};

static void usage(const char *program_name) {
    fprintf(stderr,
            "Usage:\n"
            "  %s --live <interface> <threshold> <window_seconds> [packet_count] [--filter <bpf_expr>] [--sliding] [--rule <proto:port:threshold>]...\n"
            "  %s --pcap <pcap_file> <threshold> <window_seconds> [packet_count] [--filter <bpf_expr>] [--sliding] [--rule <proto:port:threshold>]...\n",
            program_name,
            program_name);
}

static int parse_args(int argc, char **argv, struct app_config *out) {
    int i = 5;
    int packet_count_set = 0;

    if (argc < 5) {
        usage(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--live") == 0) {
        out->mode = INPUT_MODE_LIVE;
    } else if (strcmp(argv[1], "--pcap") == 0) {
        out->mode = INPUT_MODE_PCAP;
    } else {
        usage(argv[0]);
        return 0;
    }

    out->source = argv[2];
    out->max_packets = 100;
    out->bpf_filter = NULL;
    out->sliding = 0;
    ids_rule_engine_init(&out->rules);

    if (!parse_positive_uint(argv[3], &out->threshold) || !parse_positive_uint(argv[4], &out->window_seconds)) {
        fprintf(stderr, "threshold and window_seconds must be positive integers within range.\n");
        return 0;
    }

    while (i < argc) {
        if (strcmp(argv[i], "--filter") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--filter requires a BPF expression.\n");
                return 0;
            }

            out->bpf_filter = argv[i + 1];
            i += 2;
            continue;
        }

        if (strcmp(argv[i], "--sliding") == 0) {
            out->sliding = 1;
            i++;
            continue;
        }

        if (strcmp(argv[i], "--rule") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--rule requires a value like tcp:53:10 (proto:port:threshold).\n");
                return 0;
            }

            if (!ids_rule_engine_add_from_spec(&out->rules, argv[i + 1])) {
                fprintf(stderr, "Invalid --rule '%s'. Expected proto:port:threshold (e.g., tcp:53:10).\n", argv[i + 1]);
                return 0;
            }

            i += 2;
            continue;
        }

        if (!packet_count_set) {
            if (!parse_positive_int(argv[i], &out->max_packets)) {
                fprintf(stderr, "packet_count must be a positive integer within range.\n");
                return 0;
            }

            packet_count_set = 1;
            i++;
            continue;
        }

        fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
        return 0;
    }

    return 1;
}

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct app_state *state = (struct app_state *)user_data;
    struct parsed_packet info;
    unsigned int count_in_window = 0;
    unsigned int active_threshold = state->config.threshold;
    struct ids_tracker *active_tracker = &state->tracker;
    int matched_rule = -1;
    time_t window_start = 0;

    state->packet_count++;

    if (!parse_packet_info(pkthdr, packet, &info)) {
        return;
    }

    if (!info.is_ipv4 && !info.is_ipv6) {
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

        matched_rule = ids_rule_engine_match(
            &state->config.rules,
            info.protocol,
            info.source_port,
            info.destination_port);

        if (matched_rule >= 0) {
        active_tracker = &state->rule_trackers[matched_rule];
        active_threshold = state->config.rules.rules[matched_rule].threshold;
        }

        if (ids_tracker_record_packet(
            active_tracker,
            &info.source_address,
            (time_t)pkthdr->ts.tv_sec,
            &count_in_window,
            &window_start
        )) {
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
                active_threshold,
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
                active_threshold,
                elapsed,
                state->config.window_seconds
            );
        }

        alert_logger_log(&state->logger, message);
    }
}

int main(int argc, char **argv) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct app_state state;

    memset(&state, 0, sizeof(state));

    if (!parse_args(argc, argv, &state.config)) {
        return 1;
    }

    ids_tracker_init(&state.tracker, state.config.threshold, state.config.window_seconds);
    if (state.config.sliding) {
        ids_tracker_set_sliding(&state.tracker, 1);
    }

    for (size_t i = 0; i < state.config.rules.count; i++) {
        ids_tracker_init(&state.rule_trackers[i], state.config.rules.rules[i].threshold, state.config.window_seconds);
        if (state.config.sliding) {
            ids_tracker_set_sliding(&state.rule_trackers[i], 1);
        }
    }

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

    if (state.config.bpf_filter != NULL) {
        if (apply_bpf_filter(handle, state.config.bpf_filter) != 0) {
            fprintf(stderr, "Failed to apply BPF filter: %s\n", state.config.bpf_filter);
            pcap_close(handle);
            alert_logger_close(&state.logger);
            return 1;
        }
    }

    if (state.config.rules.count > 0) {
        printf("Loaded %zu IDS override rule(s).\n", state.config.rules.count);
    }

    if (state.config.mode == INPUT_MODE_LIVE) {
        printf("IDS live mode on interface '%s' (threshold=%u, window=%us, packets=%d)\n",
               state.config.source,
               state.config.threshold,
               state.config.window_seconds,
               state.config.max_packets);
    } else {
        printf("IDS replay mode on pcap '%s' (threshold=%u, window=%us, packets=%d)\n",
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
    printf("Run complete. Processed packets: %d\n", state.packet_count);
    return 0;
}
