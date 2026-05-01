#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include <stdint.h>

#define ETHER_TYPE_IPV4 0x0800
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

struct ethernet_header {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t ether_type;
} __attribute__((packed));

struct ipv4_header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip;
    uint32_t destination_ip;
} __attribute__((packed));

struct tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

struct udp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

static inline uint8_t ipv4_version(const struct ipv4_header *header) {
    return (uint8_t)(header->version_ihl >> 4);
}

static inline uint8_t ipv4_header_length_bytes(const struct ipv4_header *header) {
    return (uint8_t)((header->version_ihl & 0x0F) * 4);
}

static inline uint8_t tcp_header_length_bytes(const struct tcp_header *header) {
    return (uint8_t)(((header->data_offset_reserved >> 4) & 0x0F) * 4);
}

#endif
