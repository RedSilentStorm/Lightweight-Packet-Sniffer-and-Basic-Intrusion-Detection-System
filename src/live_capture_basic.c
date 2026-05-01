#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *header, const unsigned char *packet) {
    int *packet_count = (int *)user_data;
    time_t seconds = (time_t)header->ts.tv_sec;
    struct tm *local_time = localtime(&seconds);
    char time_buffer[32];

    (void)packet;

    if (local_time != NULL) {
        strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S", local_time);
    } else {
        snprintf(time_buffer, sizeof(time_buffer), "unknown");
    }

    (*packet_count)++;
    printf("[%s.%06ld] packet #%d captured, length=%u bytes\n",
           time_buffer,
           (long)header->ts.tv_usec,
           *packet_count,
           header->len);
}

int main(int argc, char **argv) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *interface_name = NULL;
    int max_packets = 10;
    int captured = 0;

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

    printf("Capturing on interface '%s' (%d packet(s))...\n", interface_name, max_packets);
    printf("Press Ctrl+C to stop early.\n");

    if (pcap_loop(handle, max_packets, packet_handler, (unsigned char *)&captured) == -1) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    printf("Capture finished. Total packets captured: %d\n", captured);
    return 0;
}
