#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>

int main(void) {
    pcap_if_t *interfaces = NULL;
    pcap_if_t *current = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int index = 0;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return 1;
    }

    if (interfaces == NULL) {
        printf("No interfaces found.\n");
        return 0;
    }

    printf("Available network interfaces:\n");
    for (current = interfaces; current != NULL; current = current->next) {
        index++;
        printf("%d) %s", index, current->name);

        if (current->description != NULL) {
            printf(" - %s", current->description);
        }

        printf("\n");
    }

    pcap_freealldevs(interfaces);
    return 0;
}
