#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>

int main(void) {
    const char *version = pcap_lib_version();

    if (version == NULL) {
        fprintf(stderr, "Failed to read libpcap version.\n");
        return 1;
    }

    printf("libpcap is available: %s\n", version);
    return 0;
}
