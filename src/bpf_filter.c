#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include "../include/bpf_filter.h"

int apply_bpf_filter(pcap_t *handle, const char *filter_string) {
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    if (!handle) return -1;
    if (!filter_string || strlen(filter_string) == 0) return 0;
    if (pcap_compile(handle, &fp, filter_string, 0, net) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

const char *get_filter_description(const char *filter_string) {
    if (!filter_string || strlen(filter_string) == 0) return "no filter (all packets)";
    if (strcmp(filter_string, "tcp") == 0) return "TCP packets only";
    if (strcmp(filter_string, "udp") == 0) return "UDP packets only";
    if (strcmp(filter_string, "tcp or udp") == 0) return "TCP or UDP packets";
    if (strcmp(filter_string, "ip") == 0) return "IP packets (IPv4)";
    return "custom BPF filter";
}
