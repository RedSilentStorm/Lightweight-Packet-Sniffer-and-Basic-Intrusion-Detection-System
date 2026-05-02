#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "../include/perf_metrics.h"

void perf_stats_init(struct perf_stats *stats) {
    if (!stats) return;
    memset(stats, 0, sizeof(*stats));
    stats->start_time = time(NULL);
    stats->min_latency_us = UINT_MAX;
}

void perf_stats_record_packet(struct perf_stats *stats, unsigned int packet_size) {
    if (!stats) return;
    stats->total_packets++;
    stats->total_bytes_processed += packet_size;
}

void perf_stats_record_alert(struct perf_stats *stats, unsigned int processing_latency_us) {
    if (!stats) return;
    stats->total_alerts++;
    if (processing_latency_us < stats->min_latency_us) stats->min_latency_us = processing_latency_us;
    if (processing_latency_us > stats->max_latency_us) stats->max_latency_us = processing_latency_us;
    stats->total_latency_us += processing_latency_us;
    stats->alert_count_for_latency++;
}

void perf_stats_end(struct perf_stats *stats) {
    if (!stats) return;
    stats->end_time = time(NULL);
}

void perf_stats_print_report(const struct perf_stats *stats) {
    if (!stats) return;
    time_t elapsed = stats->end_time - stats->start_time;
    if (elapsed == 0) elapsed = 1;
    double pps = (double)stats->total_packets / elapsed;
    double throughput_mbps = (double)(stats->total_bytes_processed * 8) / (elapsed * 1000000.0);
    double avg_latency = stats->alert_count_for_latency ? (double)stats->total_latency_us / stats->alert_count_for_latency : 0.0;
    printf("\n====== PERFORMANCE REPORT ======\n");
    printf("Total Packets: %llu\n", (unsigned long long)stats->total_packets);
    printf("Total Alerts:  %llu\n", (unsigned long long)stats->total_alerts);
    printf("Elapsed (s):   %ld\n", (long)elapsed);
    printf("Packets/sec:   %.2f\n", pps);
    printf("Throughput(Mbps): %.2f\n", throughput_mbps);
    printf("Alert Latency (min/max/avg) us: %u / %u / %.2f\n", stats->min_latency_us == UINT_MAX ? 0 : stats->min_latency_us, stats->max_latency_us, avg_latency);
    printf("================================\n\n");
}

int perf_stats_export_csv(const struct perf_stats *stats, const char *filename) {
    if (!stats || !filename) return -1;
    FILE *fp = fopen(filename, "w");
    if (!fp) return -1;
    time_t elapsed = stats->end_time - stats->start_time;
    if (elapsed == 0) elapsed = 1;
    double pps = (double)stats->total_packets / elapsed;
    double throughput_mbps = (double)(stats->total_bytes_processed * 8) / (elapsed * 1000000.0);
    double avg_latency = stats->alert_count_for_latency ? (double)stats->total_latency_us / stats->alert_count_for_latency : 0.0;
    fprintf(fp, "metric,value\n");
    fprintf(fp, "total_packets,%llu\n", (unsigned long long)stats->total_packets);
    fprintf(fp, "total_alerts,%llu\n", (unsigned long long)stats->total_alerts);
    fprintf(fp, "elapsed_seconds,%ld\n", (long)elapsed);
    fprintf(fp, "packets_per_second,%.2f\n", pps);
    fprintf(fp, "throughput_mbps,%.2f\n", throughput_mbps);
    fprintf(fp, "avg_alert_latency_us,%.2f\n", avg_latency);
    fclose(fp);
    return 0;
}
