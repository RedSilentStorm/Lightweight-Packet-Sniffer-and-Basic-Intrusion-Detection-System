#include "capture_source.h"

pcap_t *open_capture_source(int mode, const char *source, char *errbuf) {
    if (mode == CAPTURE_MODE_LIVE) {
        return pcap_open_live(source, 65535, 1, 1000, errbuf);
    }

    if (mode == CAPTURE_MODE_PCAP) {
        return pcap_open_offline(source, errbuf);
    }

    return NULL;
}
