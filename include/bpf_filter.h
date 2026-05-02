#ifndef BPF_FILTER_H
#define BPF_FILTER_H

#include <pcap/pcap.h>

int apply_bpf_filter(pcap_t *handle, const char *filter_string);
const char *get_filter_description(const char *filter_string);

#endif
