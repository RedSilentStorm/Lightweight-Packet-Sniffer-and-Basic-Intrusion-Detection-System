#!/usr/bin/env python3
"""
IDS Evaluation Metrics Tool
Analyzes alerts and calculates TPR, FPR, FNR, latency, etc.
Usage: python3 tools/evaluation_metrics.py logs/alerts.csv --scenario high-rate --output report.json
"""

import argparse
import json
import csv
import sys
from collections import defaultdict

class IDSEvaluator:
    def __init__(self):
        self.alerts = []
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
    
    def load_csv(self, filename):
        """Load alerts from CSV file"""
        try:
            with open(filename, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    alert = {
                        'timestamp': row.get('timestamp'),
                        'source_ip': row.get('source_ip'),
                        'source_port': int(row.get('source_port', 0)) if row.get('source_port') else 0,
                        'dest_ip': row.get('dest_ip'),
                        'dest_port': int(row.get('dest_port', 0)) if row.get('dest_port') else 0,
                        'protocol': row.get('protocol'),
                        'packet_count': int(row.get('packet_count', 0)) if row.get('packet_count') else 0,
                        'threshold': int(row.get('threshold', 0)) if row.get('threshold') else 0,
                        'window_seconds': int(row.get('window_seconds', 0)) if row.get('window_seconds') else 0,
                        'elapsed_seconds': int(row.get('elapsed_seconds', 0)) if row.get('elapsed_seconds') else 0
                    }
                    self.alerts.append(alert)
            print(f"Loaded {len(self.alerts)} alerts from {filename}")
            return True
        except FileNotFoundError:
            print(f"Error: File {filename} not found", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error reading {filename}: {e}", file=sys.stderr)
            return False
    
    def load_json(self, filename):
        """Load alerts from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.alerts = data.get('alerts', [])
            print(f"Loaded {len(self.alerts)} alerts from {filename}")
            return True
        except FileNotFoundError:
            print(f"Error: File {filename} not found", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error reading {filename}: {e}", file=sys.stderr)
            return False
    
    def evaluate_scenario(self, scenario):
        """Evaluate against expected scenario"""
        if scenario == "high-rate":
            # For high-rate scenario, we expect alerts from specific patterns
            burst_ips = {'203.0.113.50', '192.168.1.100'}
            alert_ips = set()
            for alert in self.alerts:
                alert_ips.add(alert['source_ip'])
            
            # TP: alerts from burst IPs
            self.true_positives = len(alert_ips & burst_ips)
            # FP: alerts from non-burst IPs  
            self.false_positives = len(alert_ips - burst_ips)
            # FN: expected burst IPs we didn't catch
            self.false_negatives = len(burst_ips - alert_ips)
            
        elif scenario == "normal":
            # Normal scenario expects few/no alerts
            self.false_positives = len(self.alerts)
            self.true_negatives = max(0, 100 - self.false_positives)
            
        elif scenario == "mixed":
            # Mixed: some burst IPs should be detected
            burst_ips = {'203.0.113.50'}
            alert_ips = set(a['source_ip'] for a in self.alerts)
            self.true_positives = len(alert_ips & burst_ips)
            self.false_positives = len(alert_ips - burst_ips)
            self.false_negatives = len(burst_ips - alert_ips)
    
    def calculate_rates(self):
        """Calculate TPR, FPR, FNR"""
        tp_fn = self.true_positives + self.false_negatives
        fp_tn = self.false_positives + self.true_negatives
        
        tpr = (self.true_positives / tp_fn) if tp_fn > 0 else 0.0
        fpr = (self.false_positives / fp_tn) if fp_tn > 0 else 0.0
        fnr = (self.false_negatives / tp_fn) if tp_fn > 0 else 0.0
        
        return tpr, fpr, fnr
    
    def calculate_latency_stats(self):
        """Calculate alert latency statistics"""
        if not self.alerts:
            return 0, 0, 0
        
        latencies = []
        for alert in self.alerts:
            elapsed = alert.get('elapsed_seconds', 0)
            if elapsed >= 0:
                latencies.append(elapsed)
        
        if not latencies:
            return 0, 0, 0
        
        min_lat = min(latencies)
        max_lat = max(latencies)
        avg_lat = sum(latencies) / len(latencies)
        
        return min_lat, max_lat, avg_lat
    
    def print_report(self):
        """Print formatted evaluation report"""
        tpr, fpr, fnr = self.calculate_rates()
        min_lat, max_lat, avg_lat = self.calculate_latency_stats()
        
        print("\n" + "="*50)
        print("IDS EVALUATION METRICS REPORT")
        print("="*50)
        print(f"Total Alerts Generated: {len(self.alerts)}")
        
        # Unique sources
        unique_sources = len(set(a['source_ip'] for a in self.alerts))
        print(f"Unique Source IPs: {unique_sources}")
        
        print("\n--- Confusion Matrix ---")
        print(f"True Positives (TP):   {self.true_positives}")
        print(f"False Positives (FP):  {self.false_positives}")
        print(f"True Negatives (TN):   {self.true_negatives}")
        print(f"False Negatives (FN):  {self.false_negatives}")
        
        print("\n--- Detection Rates ---")
        print(f"True Positive Rate (TPR):  {tpr:.2%}")
        print(f"False Positive Rate (FPR): {fpr:.2%}")
        print(f"False Negative Rate (FNR): {fnr:.2%}")
        
        print("\n--- Latency Stats (seconds) ---")
        print(f"Min Latency: {min_lat}")
        print(f"Max Latency: {max_lat}")
        print(f"Avg Latency: {avg_lat:.2f}")
        
        print("\n--- Sample Alerts (first 5) ---")
        for i, alert in enumerate(self.alerts[:5], 1):
            print(f"{i}. {alert['source_ip']}:{alert['source_port']} -> {alert['dest_ip']}:{alert['dest_port']} "
                  f"({alert['protocol']}) packets={alert['packet_count']}")
        
        if len(self.alerts) > 5:
            print(f"... and {len(self.alerts) - 5} more")
        
        print("="*50 + "\n")
        
        return tpr, fpr, fnr
    
    def export_json_report(self, filename):
        """Export evaluation report to JSON"""
        tpr, fpr, fnr = self.calculate_rates()
        min_lat, max_lat, avg_lat = self.calculate_latency_stats()
        
        report = {
            'total_alerts': len(self.alerts),
            'unique_sources': len(set(a['source_ip'] for a in self.alerts)),
            'confusion_matrix': {
                'tp': self.true_positives,
                'fp': self.false_positives,
                'tn': self.true_negatives,
                'fn': self.false_negatives
            },
            'detection_rates': {
                'tpr': tpr,
                'fpr': fpr,
                'fnr': fnr
            },
            'latency_stats': {
                'min': min_lat,
                'max': max_lat,
                'avg': avg_lat
            },
            'alerts_sample': self.alerts[:10]
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report exported to {filename}")
            return True
        except Exception as e:
            print(f"Error exporting report: {e}", file=sys.stderr)
            return False

def main():
    parser = argparse.ArgumentParser(description='Evaluate IDS alert performance')
    parser.add_argument('input', help='Alert file (CSV or JSON)')
    parser.add_argument('--format', choices=['csv', 'json'], help='File format (auto-detect if omitted)')
    parser.add_argument('--scenario', choices=['high-rate', 'normal', 'mixed'], 
                       help='Expected traffic scenario for evaluation')
    parser.add_argument('--output', help='Export report to JSON file')
    
    args = parser.parse_args()
    
    evaluator = IDSEvaluator()
    
    # Auto-detect format
    fmt = args.format
    if not fmt:
        fmt = 'json' if args.input.endswith('.json') else 'csv'
    
    # Load alerts
    if fmt == 'json':
        if not evaluator.load_json(args.input):
            sys.exit(1)
    else:
        if not evaluator.load_csv(args.input):
            sys.exit(1)
    
    # Evaluate scenario if specified
    if args.scenario:
        evaluator.evaluate_scenario(args.scenario)
    
    # Print report
    evaluator.print_report()
    
    # Export if requested
    if args.output:
        evaluator.export_json_report(args.output)

if __name__ == '__main__':
    main()
