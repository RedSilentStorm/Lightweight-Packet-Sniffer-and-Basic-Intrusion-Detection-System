#include <sys/types.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "packet_headers.h"
#include "ids_tracker.h"
#include "alert_logger.h"
#include "parse_utils.h"

struct app_state {
    struct ids_tracker tracker;
    struct alert_logger logger;
    unsigned int threshold;
    unsigned int window_seconds;
    int packet_count;
};

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct app_state *state = (struct app_state *)user_data;
    const struct ethernet_header *eth = NULL;
    const struct ipv4_header *ip = NULL;
    uint16_t ether_type = 0;
    size_t offset = 0;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    unsigned int count_in_window = 0;
    time_t window_start = 0;

    state->packet_count++;

    if (pkthdr->caplen < sizeof(struct ethernet_header)) {
        return;
    }

    eth = (const struct ethernet_header *)packet;
    ether_type = ntohs(eth->ether_type);
    if (ether_type != ETHER_TYPE_IPV4) {
        return;
    }

    offset = sizeof(struct ethernet_header);
    if (pkthdr->caplen < offset + sizeof(struct ipv4_header)) {
        return;
    }

    ip = (const struct ipv4_header *)(packet + offset);
    if (ipv4_version(ip) != 4) {
        return;
    }

    {
        uint8_t ip_header_len = ipv4_header_length_bytes(ip);
        if (ip_header_len < sizeof(struct ipv4_header)) {
            return;
        }

        if (pkthdr->caplen < offset + ip_header_len) {
            return;
        }

        offset += ip_header_len;
    }

    if (inet_ntop(AF_INET, &ip->source_ip, src_ip, sizeof(src_ip)) == NULL) {
        strncpy(src_ip, "invalid", sizeof(src_ip));
        src_ip[sizeof(src_ip) - 1] = '\0';
    }

    if (inet_ntop(AF_INET, &ip->destination_ip, dst_ip, sizeof(dst_ip)) == NULL) {
        strncpy(dst_ip, "invalid", sizeof(dst_ip));
        dst_ip[sizeof(dst_ip) - 1] = '\0';
    }

    if (ip->protocol == IP_PROTOCOL_TCP) {
        const struct tcp_header *tcp = NULL;

        if (pkthdr->caplen >= offset + sizeof(struct tcp_header)) {
            tcp = (const struct tcp_header *)(packet + offset);
            printf("TCP %s:%u -> %s:%u\n",
                   src_ip,
                   ntohs(tcp->source_port),
                   dst_ip,
                   ntohs(tcp->destination_port));
        }
    } else if (ip->protocol == IP_PROTOCOL_UDP) {
        const struct udp_header *udp = NULL;

        if (pkthdr->caplen >= offset + sizeof(struct udp_header)) {
            udp = (const struct udp_header *)(packet + offset);
            printf("UDP %s:%u -> %s:%u\n",
                   src_ip,
                   ntohs(udp->source_port),
                   dst_ip,
                   ntohs(udp->destination_port));
        }
    }

    if (ids_tracker_record_packet(
            &state->tracker,
            ip->source_ip,
            (time_t)pkthdr->ts.tv_sec,
            &count_in_window,
            &window_start
        )) {
        char message[256];
        (void)window_start;

        snprintf(
            message,
            sizeof(message),
            "source=%s exceeded threshold: count=%u threshold=%u window=%us",
            src_ip,
            count_in_window,
            state->threshold,
            state->window_seconds
        );
        alert_logger_log(&state->logger, message);
    }
}

int main(int argc, char **argv) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interface_name = NULL;
    unsigned int threshold = 20;
    unsigned int window_seconds = 5;
    int max_packets = 100;
    struct app_state state;

    memset(&state, 0, sizeof(state));

    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s <interface> <threshold> <window_seconds> [packet_count]\n", argv[0]);
        return 1;
    }

    interface_name = argv[1];
    if (!parse_positive_uint(argv[2], &threshold) || !parse_positive_uint(argv[3], &window_seconds)) {
        fprintf(stderr, "threshold and window_seconds must be positive integers within range.\n");
        return 1;
    }

    if (argc == 5) {
        if (!parse_positive_int(argv[4], &max_packets)) {
            fprintf(stderr, "packet_count must be a positive integer within range.\n");
            return 1;
        }
    }

    ids_tracker_init(&state.tracker, threshold, window_seconds);
    state.threshold = threshold;
    state.window_seconds = window_seconds;

    if (alert_logger_open(&state.logger, "logs/alerts.log") != 0) {
        fprintf(stderr, "Failed to open logs/alerts.log for writing.\n");
        return 1;
    }

    handle = pcap_open_live(interface_name, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed for interface '%s': %s\n", interface_name, errbuf);
        alert_logger_close(&state.logger);
        return 1;
    }

    printf("IDS running on interface '%s' (threshold=%u, window=%us, packets=%d)\n",
           interface_name,
           threshold,
           window_seconds,
           max_packets);

    if (pcap_loop(handle, max_packets, packet_handler, (unsigned char *)&state) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        alert_logger_close(&state.logger);
        return 1;
    }

    pcap_close(handle);
    alert_logger_close(&state.logger);
    printf("Capture complete. Processed packets: %d\n", state.packet_count);
    return 0;
}
