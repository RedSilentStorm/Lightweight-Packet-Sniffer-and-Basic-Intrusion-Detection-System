#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "../include/alert_export.h"

const char *ip_to_string(uint32_t ip, char *buf, int buflen) {
    if (buf == NULL || buflen < 16) return "invalid";
    struct in_addr addr;
    addr.s_addr = ip;
    const char *r = inet_ntoa(addr);
    if (r) snprintf(buf, buflen, "%s", r);
    else snprintf(buf, buflen, "unknown");
    return buf;
}

static const char *address_to_string(const struct ids_address_key *address, char *buf, size_t buflen) {
    if (buf == NULL || buflen == 0 || address == NULL) {
        return "invalid";
    }

    if (address->family == AF_INET) {
        struct in_addr addr4;
        memset(&addr4, 0, sizeof(addr4));
        memcpy(&addr4, address->bytes, 4);
        if (inet_ntop(AF_INET, &addr4, buf, buflen) != NULL) {
            return buf;
        }
    } else if (address->family == AF_INET6) {
        if (inet_ntop(AF_INET6, address->bytes, buf, buflen) != NULL) {
            return buf;
        }
    }

    snprintf(buf, buflen, "unknown");
    return buf;
}

int alert_export_csv_header(FILE *fp) {
    if (!fp) return -1;
    fprintf(fp, "timestamp,source_ip,source_port,dest_ip,dest_port,protocol,packet_count,threshold,window_seconds,elapsed_seconds\n");
    fflush(fp);
    return 0;
}

int alert_export_csv_record(FILE *fp, const struct alert_record *record) {
    if (!fp || !record) return -1;
    char src[46], dst[46], ts[32];
    struct tm *lt = localtime(&record->timestamp);
    if (lt) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", lt);
    else snprintf(ts, sizeof(ts), "unknown");
    address_to_string(&record->source_address, src, sizeof(src));
    address_to_string(&record->destination_address, dst, sizeof(dst));
    const char *proto = record->protocol == 6 ? "TCP" : (record->protocol == 17 ? "UDP" : "OTHER");
    fprintf(fp, "%s,%s,%u,%s,%u,%s,%u,%u,%u,%u\n",
            ts, src, record->source_port, dst, record->destination_port,
            proto, record->packet_count, record->threshold,
            record->window_seconds, record->elapsed_seconds);
    fflush(fp);
    return 0;
}

int alert_export_json_header(FILE *fp) {
    if (!fp) return -1;
    fprintf(fp, "{\n  \"alerts\": [\n");
    fflush(fp);
    return 0;
}

int alert_export_json_record(FILE *fp, const struct alert_record *record, int is_first) {
    if (!fp || !record) return -1;
    char src[46], dst[46], ts[32];
    struct tm *lt = localtime(&record->timestamp);
    if (lt) strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", lt);
    else snprintf(ts, sizeof(ts), "unknown");
    address_to_string(&record->source_address, src, sizeof(src));
    address_to_string(&record->destination_address, dst, sizeof(dst));
    const char *proto = record->protocol == 6 ? "TCP" : (record->protocol == 17 ? "UDP" : "OTHER");
    if (!is_first) fprintf(fp, ",\n");
    fprintf(fp, "    {\n      \"timestamp\": \"%s\",\n      \"source\": {\"ip\": \"%s\", \"port\": %u},\n      \"destination\": {\"ip\": \"%s\", \"port\": %u},\n      \"protocol\": \"%s\",\n      \"packet_count\": %u,\n      \"threshold\": %u,\n      \"window_seconds\": %u,\n      \"elapsed_seconds\": %u\n    }",
            ts, src, record->source_port, dst, record->destination_port,
            proto, record->packet_count, record->threshold,
            record->window_seconds, record->elapsed_seconds);
    fflush(fp);
    return 0;
}

int alert_export_json_footer(FILE *fp) {
    if (!fp) return -1;
    fprintf(fp, "\n  ]\n}\n");
    fflush(fp);
    return 0;
}
