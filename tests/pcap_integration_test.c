#include <sys/types.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "packet_headers.h"

static int write_sample_pcap(const char *path) {
    pcap_t *dead = NULL;
    pcap_dumper_t *dumper = NULL;
    int i = 0;

    dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (dead == NULL) {
        return 0;
    }

    dumper = pcap_dump_open(dead, path);
    if (dumper == NULL) {
        pcap_close(dead);
        return 0;
    }

    for (i = 0; i < 4; i++) {
        unsigned char frame[sizeof(struct ethernet_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header)];
        struct ethernet_header *eth = (struct ethernet_header *)frame;
        struct ipv4_header *ip = (struct ipv4_header *)(frame + sizeof(struct ethernet_header));
        struct udp_header *udp = (struct udp_header *)(frame + sizeof(struct ethernet_header) + sizeof(struct ipv4_header));
        struct pcap_pkthdr hdr;

        memset(frame, 0, sizeof(frame));
        memset(&hdr, 0, sizeof(hdr));

        eth->ether_type = htons(ETHER_TYPE_IPV4);

        ip->version_ihl = 0x45;
        ip->ttl = 64;
        ip->protocol = IP_PROTOCOL_UDP;
        ip->total_length = htons((uint16_t)(sizeof(struct ipv4_header) + sizeof(struct udp_header)));
        ip->source_ip = inet_addr("10.0.0.9");
        ip->destination_ip = inet_addr("10.0.0.1");

        udp->source_port = htons((uint16_t)(40000 + i));
        udp->destination_port = htons(53);
        udp->length = htons((uint16_t)sizeof(struct udp_header));

        hdr.ts.tv_sec = 1000 + i;
        hdr.ts.tv_usec = 0;
        hdr.caplen = (bpf_u_int32)sizeof(frame);
        hdr.len = (bpf_u_int32)sizeof(frame);

        pcap_dump((unsigned char *)dumper, &hdr, frame);
    }

    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(dead);
    return 1;
}

static int file_contains_text(const char *path, const char *needle) {
    FILE *file = fopen(path, "r");
    char line[512];

    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, needle) != NULL) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

int main(void) {
    const char *pcap_path = "tests/data/ids_sample.pcap";
    const char *output_path = "tests/data/integration_run_output.txt";
    int system_result = 0;

    if (!write_sample_pcap(pcap_path)) {
        fprintf(stderr, "pcap_integration_test: FAILED (could not write pcap)\n");
        return 1;
    }

    remove("logs/alerts.log");

    system_result = system("./bin/ids_live_or_pcap --pcap tests/data/ids_sample.pcap 3 5 10 > tests/data/integration_run_output.txt 2>&1");
    if (system_result != 0) {
        fprintf(stderr, "pcap_integration_test: FAILED (replay run returned non-zero)\n");
        return 1;
    }

    if (!file_contains_text(output_path, "ALERT:")) {
        fprintf(stderr, "pcap_integration_test: FAILED (no console alert found)\n");
        return 1;
    }

    if (!file_contains_text(output_path, "source=10.0.0.9")) {
        fprintf(stderr, "pcap_integration_test: FAILED (expected source IP not found)\n");
        return 1;
    }

    if (!file_contains_text("logs/alerts.log", "source=10.0.0.9")) {
        fprintf(stderr, "pcap_integration_test: FAILED (no file alert found)\n");
        return 1;
    }

    printf("pcap_integration_test: PASSED\n");
    return 0;
}
