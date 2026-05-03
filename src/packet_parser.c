#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>

#include "packet_headers.h"
#include "packet_parser.h"

const char *packet_protocol_name(uint8_t protocol) {
    if (protocol == IP_PROTOCOL_TCP) {
        return "TCP";
    }

    if (protocol == IP_PROTOCOL_UDP) {
        return "UDP";
    }

    return "OTHER";
}

int parse_packet_info(const struct pcap_pkthdr *pkthdr, const unsigned char *packet, struct parsed_packet *out) {
    const struct ethernet_header *eth = NULL;
    const struct ipv4_header *ip = NULL;
    uint16_t ether_type = 0;
    size_t offset = 0;

    memset(out, 0, sizeof(*out));

    if (pkthdr->caplen < sizeof(struct ethernet_header)) {
        return 0;
    }

    eth = (const struct ethernet_header *)packet;
    ether_type = ntohs(eth->ether_type);

    memset(&out->source_address, 0, sizeof(out->source_address));
    memset(&out->destination_address, 0, sizeof(out->destination_address));
    
    /* Handle IPv6 (basic support - just capture addresses) */
    if (ether_type == 0x86dd) {
        const unsigned char *ipv6_header = NULL;
        if (pkthdr->caplen < sizeof(struct ethernet_header) + 40) {
            return 0;
        }
        
        offset = sizeof(struct ethernet_header);
        ipv6_header = packet + offset;
        
        out->is_ipv6 = 1;
        out->source_address.family = AF_INET6;
        out->destination_address.family = AF_INET6;
        memcpy(out->source_ipv6, ipv6_header + 8, 16);
        memcpy(out->destination_ipv6, ipv6_header + 24, 16);
        memcpy(out->source_address.bytes, out->source_ipv6, 16);
        memcpy(out->destination_address.bytes, out->destination_ipv6, 16);
        out->protocol = ipv6_header[6];  /* Next Header field */
        
        if (inet_ntop(AF_INET6, out->source_ipv6, out->source_ip_text, sizeof(out->source_ip_text)) == NULL) {
            strncpy(out->source_ip_text, "invalid-ipv6", sizeof(out->source_ip_text));
        }
        
        if (inet_ntop(AF_INET6, out->destination_ipv6, out->destination_ip_text, sizeof(out->destination_ip_text)) == NULL) {
            strncpy(out->destination_ip_text, "invalid-ipv6", sizeof(out->destination_ip_text));
        }
        
        offset += 40;
        
        /* Parse TCP/UDP port info from IPv6 */
        if (out->protocol == IP_PROTOCOL_TCP && pkthdr->caplen >= offset + sizeof(struct tcp_header)) {
            const struct tcp_header *tcp = (const struct tcp_header *)(packet + offset);
            out->source_port = ntohs(tcp->source_port);
            out->destination_port = ntohs(tcp->destination_port);
            out->is_supported_transport = 1;
        } else if (out->protocol == IP_PROTOCOL_UDP && pkthdr->caplen >= offset + sizeof(struct udp_header)) {
            const struct udp_header *udp = (const struct udp_header *)(packet + offset);
            out->source_port = ntohs(udp->source_port);
            out->destination_port = ntohs(udp->destination_port);
            out->is_supported_transport = 1;
        }
        
        return 1;
    }
    
    if (ether_type != ETHER_TYPE_IPV4) {
        return 0;
    }

    offset = sizeof(struct ethernet_header);
    if (pkthdr->caplen < offset + sizeof(struct ipv4_header)) {
        return 0;
    }

    ip = (const struct ipv4_header *)(packet + offset);
    if (ipv4_version(ip) != 4) {
        return 0;
    }

    {
        uint8_t ip_header_len = ipv4_header_length_bytes(ip);
        if (ip_header_len < sizeof(struct ipv4_header)) {
            return 0;
        }

        if (pkthdr->caplen < offset + ip_header_len) {
            return 0;
        }

        offset += ip_header_len;
    }

    out->is_ipv4 = 1;
    out->source_address.family = AF_INET;
    out->destination_address.family = AF_INET;
    memcpy(out->source_address.bytes, &ip->source_ip, 4);
    memcpy(out->destination_address.bytes, &ip->destination_ip, 4);
    out->source_ip = ip->source_ip;
    out->destination_ip = ip->destination_ip;
    out->protocol = ip->protocol;

    if (inet_ntop(AF_INET, &out->source_ip, out->source_ip_text, sizeof(out->source_ip_text)) == NULL) {
        strncpy(out->source_ip_text, "invalid", sizeof(out->source_ip_text));
        out->source_ip_text[sizeof(out->source_ip_text) - 1] = '\0';
    }

    if (inet_ntop(AF_INET, &out->destination_ip, out->destination_ip_text, sizeof(out->destination_ip_text)) == NULL) {
        strncpy(out->destination_ip_text, "invalid", sizeof(out->destination_ip_text));
        out->destination_ip_text[sizeof(out->destination_ip_text) - 1] = '\0';
    }

    if (out->protocol == IP_PROTOCOL_TCP) {
        const struct tcp_header *tcp = NULL;
        uint8_t tcp_header_len = 0;

        if (pkthdr->caplen < offset + sizeof(struct tcp_header)) {
            return 1;
        }

        tcp = (const struct tcp_header *)(packet + offset);
        tcp_header_len = tcp_header_length_bytes(tcp);
        if (tcp_header_len < sizeof(struct tcp_header)) {
            return 1;
        }

        if (pkthdr->caplen < offset + tcp_header_len) {
            return 1;
        }

        out->source_port = ntohs(tcp->source_port);
        out->destination_port = ntohs(tcp->destination_port);
        out->is_supported_transport = 1;
        return 1;
    }

    if (out->protocol == IP_PROTOCOL_UDP) {
        const struct udp_header *udp = NULL;

        if (pkthdr->caplen < offset + sizeof(struct udp_header)) {
            return 1;
        }

        udp = (const struct udp_header *)(packet + offset);
        out->source_port = ntohs(udp->source_port);
        out->destination_port = ntohs(udp->destination_port);
        out->is_supported_transport = 1;
        return 1;
    }

    return 1;
}
