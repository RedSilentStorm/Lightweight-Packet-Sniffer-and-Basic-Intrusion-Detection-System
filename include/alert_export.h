#ifndef ALERT_EXPORT_H
#define ALERT_EXPORT_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>

struct alert_record {
    time_t timestamp;
    uint32_t source_ip;
    uint16_t source_port;
    uint32_t destination_ip;
    uint16_t destination_port;
    uint8_t protocol;
    unsigned int packet_count;
    unsigned int threshold;
    unsigned int window_seconds;
    unsigned int elapsed_seconds;
};

int alert_export_csv_header(FILE *fp);
int alert_export_csv_record(FILE *fp, const struct alert_record *record);
int alert_export_json_header(FILE *fp);
int alert_export_json_record(FILE *fp, const struct alert_record *record, int is_first);
int alert_export_json_footer(FILE *fp);

const char *ip_to_string(uint32_t ip, char *buf, int buflen);

#endif
