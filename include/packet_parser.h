#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap/pcap.h>
#include <stdint.h>

struct parsed_packet {
    int is_ipv4;
    int is_ipv6;
    int is_supported_transport;
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t source_ipv6[16];
    uint8_t destination_ipv6[16];
    char source_ip_text[46];
    char destination_ip_text[46];
    uint8_t protocol;
    uint16_t source_port;
    uint16_t destination_port;
};

const char *packet_protocol_name(uint8_t protocol);
int parse_packet_info(const struct pcap_pkthdr *pkthdr, const unsigned char *packet, struct parsed_packet *out);

#endif
