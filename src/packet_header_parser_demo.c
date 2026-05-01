#include <sys/types.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packet_headers.h"

struct capture_state {
    int packet_count;
};

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct capture_state *state = (struct capture_state *)user_data;
    const struct ethernet_header *eth = NULL;
    const struct ipv4_header *ip = NULL;
    uint16_t ether_type = 0;
    size_t offset = 0;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    state->packet_count++;
    printf("packet #%d: ", state->packet_count);

    if (pkthdr->caplen < sizeof(struct ethernet_header)) {
        printf("truncated ethernet header\n");
        return;
    }

    eth = (const struct ethernet_header *)packet;
    ether_type = ntohs(eth->ether_type);
    offset = sizeof(struct ethernet_header);

    if (ether_type != ETHER_TYPE_IPV4) {
        printf("non-IPv4 packet (ether_type=0x%04x)\n", ether_type);
        return;
    }

    if (pkthdr->caplen < offset + sizeof(struct ipv4_header)) {
        printf("truncated IPv4 header\n");
        return;
    }

    ip = (const struct ipv4_header *)(packet + offset);
    if (ipv4_version(ip) != 4) {
        printf("not IPv4 (version=%u)\n", ipv4_version(ip));
        return;
    }

    {
        uint8_t ip_header_len = ipv4_header_length_bytes(ip);

        if (ip_header_len < sizeof(struct ipv4_header)) {
            printf("invalid IPv4 header length=%u\n", ip_header_len);
            return;
        }

        if (pkthdr->caplen < offset + ip_header_len) {
            printf("truncated IPv4 options/header\n");
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
        uint8_t tcp_header_len = 0;

        if (pkthdr->caplen < offset + sizeof(struct tcp_header)) {
            printf("IPv4 TCP %s -> %s (truncated TCP header)\n", src_ip, dst_ip);
            return;
        }

        tcp = (const struct tcp_header *)(packet + offset);
        tcp_header_len = tcp_header_length_bytes(tcp);

        if (tcp_header_len < sizeof(struct tcp_header)) {
            printf("IPv4 TCP %s -> %s (invalid TCP header length=%u)\n", src_ip, dst_ip, tcp_header_len);
            return;
        }

        if (pkthdr->caplen < offset + tcp_header_len) {
            printf("IPv4 TCP %s -> %s (truncated TCP options/header)\n", src_ip, dst_ip);
            return;
        }

        printf("IPv4 TCP %s:%u -> %s:%u\n",
               src_ip,
               ntohs(tcp->source_port),
               dst_ip,
               ntohs(tcp->destination_port));
        return;
    }

    if (ip->protocol == IP_PROTOCOL_UDP) {
        const struct udp_header *udp = NULL;

        if (pkthdr->caplen < offset + sizeof(struct udp_header)) {
            printf("IPv4 UDP %s -> %s (truncated UDP header)\n", src_ip, dst_ip);
            return;
        }

        udp = (const struct udp_header *)(packet + offset);
        printf("IPv4 UDP %s:%u -> %s:%u\n",
               src_ip,
               ntohs(udp->source_port),
               dst_ip,
               ntohs(udp->destination_port));
        return;
    }

    printf("IPv4 protocol=%u %s -> %s (no port parser in this step)\n", ip->protocol, src_ip, dst_ip);
}

int main(int argc, char **argv) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interface_name = NULL;
    int max_packets = 10;
    struct capture_state state;

    state.packet_count = 0;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <interface> [packet_count]\n", argv[0]);
        return 1;
    }

    interface_name = argv[1];

    if (argc == 3) {
        max_packets = atoi(argv[2]);
        if (max_packets <= 0) {
            fprintf(stderr, "packet_count must be a positive integer.\n");
            return 1;
        }
    }

    handle = pcap_open_live(interface_name, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live failed for interface '%s': %s\n", interface_name, errbuf);
        return 1;
    }

    printf("Capturing on '%s' and parsing headers (%d packet(s))...\n", interface_name, max_packets);

    if (pcap_loop(handle, max_packets, packet_handler, (unsigned char *)&state) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    printf("Done. Parsed packets: %d\n", state.packet_count);
    return 0;
}
