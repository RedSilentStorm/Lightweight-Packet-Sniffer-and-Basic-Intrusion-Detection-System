#ifndef PERF_METRICS_H
#define PERF_METRICS_H

#include <time.h>
#include <stdint.h>

struct perf_stats {
    uint64_t total_packets;
    uint64_t total_alerts;
    uint64_t total_bytes_processed;
    time_t start_time;
    time_t end_time;
    unsigned int min_latency_us;
    unsigned int max_latency_us;
    uint64_t total_latency_us;
    unsigned int alert_count_for_latency;
};

void perf_stats_init(struct perf_stats *stats);
void perf_stats_record_packet(struct perf_stats *stats, unsigned int packet_size);
void perf_stats_record_alert(struct perf_stats *stats, unsigned int processing_latency_us);
void perf_stats_end(struct perf_stats *stats);
void perf_stats_print_report(const struct perf_stats *stats);
int perf_stats_export_csv(const struct perf_stats *stats, const char *filename);

#endif
