#ifndef CAPTURE_SOURCE_H
#define CAPTURE_SOURCE_H

#include <pcap/pcap.h>

#define CAPTURE_MODE_LIVE 1
#define CAPTURE_MODE_PCAP 2

pcap_t *open_capture_source(int mode, const char *source, char *errbuf);

#endif
