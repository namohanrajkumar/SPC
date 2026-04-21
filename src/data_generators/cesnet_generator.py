#!/usr/bin/env python3
"""
CESNET Dataset Generator
Generates CESNET-inspired network traffic data
"""

import json
import os
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import time


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder for numpy data types"""
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)


class CESNETDataGenerator:
    """Generate CESNET-inspired network traffic data"""
    
    def __init__(self, num_ips=500, num_institutions=10, num_days=7):
        self.num_ips = num_ips
        self.num_institutions = num_institutions
        self.num_days = num_days
        self.output_dir = Path('/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Code1/livedataoutputs/cesnetdata')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate synthetic data specifications
        self.ip_types = ['server', 'workstation', 'nat', 'wifi_router', 'honeypot', 'game_console']
        self.protocols = ['tcp', 'udp', 'icmp']
        
        print(f"\n[✓] CESNET Data Generator initialized:")
        print(f"    • IPs to simulate: {num_ips}")
        print(f"    • Institutions: {num_institutions}")
        print(f"    • Days of data: {num_days}")
        print(f"    • Output directory: {self.output_dir}")
    
    def generate_ip_timeseries(self):
        """Generate IP-level time series data (similar to CESNET)"""
        print("\n[▶] Generating IP-level time series data...")
        
        timeseries_data = []
        base_time = datetime(2024, 1, 1, 0, 0, 0)
        
        # Generate 10-minute aggregated data
        intervals_per_day = 24 * 6  # 144 intervals per day
        total_intervals = intervals_per_day * self.num_days
        
        for ip_idx in range(self.num_ips):
            ip_id = f"ip_{ip_idx:06d}"
            ip_type = np.random.choice(self.ip_types)
            institution_id = f"inst_{np.random.randint(0, self.num_institutions):03d}"
            subnet_id = f"subnet_{np.random.randint(0, 50):03d}"
            
            for interval in range(total_intervals):
                timestamp = base_time + timedelta(minutes=10*interval)
                
                # Generate realistic network metrics
                # Different patterns for different IP types
                if ip_type == 'server':
                    base_flows = 2000
                    base_bytes = 500e6
                    dest_ips = np.random.randint(50, 200)
                elif ip_type == 'workstation':
                    base_flows = 500
                    base_bytes = 50e6
                    dest_ips = np.random.randint(5, 30)
                elif ip_type == 'nat':
                    base_flows = 5000
                    base_bytes = 1e9
                    dest_ips = np.random.randint(100, 500)
                else:
                    base_flows = np.random.randint(100, 1000)
                    base_bytes = np.random.uniform(10e6, 200e6)
                    dest_ips = np.random.randint(2, 50)
                
                # Add temporal variation and anomalies
                hour = timestamp.hour
                
                # Reduced traffic during night hours
                if hour < 6 or hour > 22:
                    multiplier = np.random.uniform(0.3, 0.7)
                # Higher traffic during business hours
                elif 9 <= hour <= 17:
                    multiplier = np.random.uniform(1.2, 1.8)
                else:
                    multiplier = np.random.uniform(0.8, 1.2)
                
                # Random anomalies (5% of the time)
                if np.random.random() < 0.05:
                    multiplier *= np.random.uniform(3, 8)
                
                n_flows = int(base_flows * multiplier + np.random.normal(0, max(1, base_flows*0.1)))
                n_bytes = int(base_bytes * multiplier + np.random.normal(0, max(1, base_bytes*0.1)))
                n_packets = int(n_bytes / 500 + np.random.normal(0, max(1, n_bytes/5000)))
                
                record = {
                    'timestamp': timestamp.isoformat() + 'Z',
                    'ip_id': ip_id,
                    'ip_type': ip_type,
                    'institution_id': institution_id,
                    'subnet_id': subnet_id,
                    'id_time': interval,
                    'n_flows': max(0, n_flows),
                    'n_packets': max(0, n_packets),
                    'n_bytes': max(0, int(n_bytes)),
                    'n_dest_ip': max(1, dest_ips + np.random.randint(-5, 5)),
                    'n_dest_asn': np.random.randint(5, 30),
                    'n_dest_port': np.random.randint(10, 100),
                    'tcp_udp_ratio_packets': np.random.uniform(0.6, 0.95),
                    'tcp_udp_ratio_bytes': np.random.uniform(0.5, 0.90),
                    'dir_ratio_packets': np.random.uniform(0.2, 0.8),
                    'dir_ratio_bytes': np.random.uniform(0.15, 0.75),
                    'avg_duration': np.random.uniform(10, 300),
                    'avg_ttl': np.random.uniform(50, 255),
                    'estimated_bandwidth_mbps': (int(n_bytes) * 8) / (600 * 1e6),
                    'packet_rate_pps': n_packets / 600,
                    'flow_rate_fps': n_flows / 600
                }
                
                timeseries_data.append(record)
        
        # Save to JSON
        filepath = self.output_dir / 'cesnet_ip_timeseries.json'
        with open(filepath, 'w') as f:
            json.dump(timeseries_data, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(timeseries_data):,} IP time series records")
        print(f"    Saved to {filepath.name}")
        
        return timeseries_data
    
    def generate_institution_data(self, timeseries_data):
        """Generate institution-level aggregated data"""
        print("\n[▶] Generating institution-level aggregated data...")
        
        # Group by institution and time
        df = pd.DataFrame(timeseries_data)
        institution_data = []
        
        # Aggregate by institution and time interval
        for institution_id in df['institution_id'].unique():
            inst_df = df[df['institution_id'] == institution_id]
            
            for interval in inst_df['id_time'].unique():
                interval_df = inst_df[inst_df['id_time'] == interval]
                
                record = {
                    'timestamp': interval_df.iloc[0]['timestamp'],
                    'institution_id': institution_id,
                    'id_time': interval,
                    'total_flows': int(interval_df['n_flows'].sum()),
                    'total_bytes': int(interval_df['n_bytes'].sum()),
                    'total_packets': int(interval_df['n_packets'].sum()),
                    'unique_sources': len(interval_df),
                    'unique_destinations': int(interval_df['n_dest_ip'].sum()),
                    'avg_bandwidth_mbps': interval_df['estimated_bandwidth_mbps'].mean(),
                    'max_bandwidth_mbps': interval_df['estimated_bandwidth_mbps'].max(),
                    'anomaly_count': np.random.randint(0, 5)
                }
                
                institution_data.append(record)
        
        # Save to JSON
        filepath = self.output_dir / 'cesnet_institution_data.json'
        with open(filepath, 'w') as f:
            json.dump(institution_data, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(institution_data):,} institution-level records")
        print(f"    Saved to {filepath.name}")
        
        return institution_data
    
    def generate_network_graph(self, timeseries_data):
        """Generate network graph data (IP relationships)"""
        print("\n[▶] Generating network graph data...")
        
        df = pd.DataFrame(timeseries_data)
        unique_ips = df['ip_id'].unique()
        
        # Create relationships between IPs based on communication
        relationships = []
        
        for ip_idx, ip_id in enumerate(unique_ips):
            ip_data = df[df['ip_id'] == ip_id]
            
            relationship = {
                'ip_id': ip_id,
                'ip_type': ip_data['ip_type'].iloc[0],
                'institution_id': ip_data['institution_id'].iloc[0],
                'subnet_id': ip_data['subnet_id'].iloc[0],
                'avg_flows': ip_data['n_flows'].mean(),
                'avg_bytes': ip_data['n_bytes'].mean(),
                'avg_destinations': ip_data['n_dest_ip'].mean(),
                'anomaly_score': np.random.uniform(0, 1),
                'is_critical': ip_data['estimated_bandwidth_mbps'].mean() > 50
            }
            
            relationships.append(relationship)
        
        # Save to JSON
        filepath = self.output_dir / 'cesnet_network_graph.json'
        with open(filepath, 'w') as f:
            json.dump(relationships, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(relationships):,} network graph nodes")
        print(f"    Saved to {filepath.name}")
        
        return relationships
    
    def generate_anomalies(self, timeseries_data):
        """Generate detected anomalies"""
        print("\n[▶] Generating anomaly detection results...")
        
        df = pd.DataFrame(timeseries_data)
        anomalies = []
        
        # Detect anomalies using simple z-score method
        for ip_id in df['ip_id'].unique():
            ip_data = df[df['ip_id'] == ip_id]
            
            for metric in ['n_flows', 'n_bytes', 'n_dest_ip']:
                mean = ip_data[metric].mean()
                std = ip_data[metric].std()
                
                if std > 0:
                    z_scores = (ip_data[metric] - mean) / std
                    
                    # Find anomalies (|z| > 2.5)
                    anomaly_mask = z_scores.abs() > 2.5
                    
                    for idx, is_anomaly in anomaly_mask.items():
                        if is_anomaly:
                            anomalies.append({
                                'timestamp': ip_data.loc[idx, 'timestamp'],
                                'ip_id': ip_id,
                                'metric': metric,
                                'value': ip_data.loc[idx, metric],
                                'mean': mean,
                                'std': std,
                                'z_score': z_scores[idx],
                                'confidence': min(1.0, abs(z_scores[idx]) / 4)
                            })
        
        # Save to JSON
        filepath = self.output_dir / 'cesnet_anomalies.json'
        with open(filepath, 'w') as f:
            json.dump(anomalies, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Detected {len(anomalies):,} anomalies")
        print(f"    Saved to {filepath.name}")
        
        return anomalies
    
    def generate_psc_input_format(self, timeseries_data, relationships):
        """Convert to PSC input format"""
        print("\n[▶] Converting to PSC input format...")
        
        # Create PSC network topology
        psc_topology = {
            'nodes': [],
            'edges': []
        }
        
        # Add nodes
        for rel in relationships:
            psc_topology['nodes'].append({
                'id': rel['ip_id'],
                'label': rel['ip_id'],
                'type': rel['ip_type'],
                'institution': rel['institution_id'],
                'subnet': rel['subnet_id'],
                'criticality': 1.0 if rel['is_critical'] else 0.5,
                'anomaly_score': rel['anomaly_score']
            })
        
        # Create edges based on traffic patterns
        num_edges = min(len(relationships) * 3, len(relationships) ** 2 // 10)
        for _ in range(num_edges):
            src = np.random.choice(relationships)['ip_id']
            dst = np.random.choice(relationships)['ip_id']
            
            if src != dst:
                psc_topology['edges'].append({
                    'source': src,
                    'target': dst,
                    'capacity': np.random.uniform(10, 1000),
                    'utilization': np.random.uniform(0, 1),
                    'latency_ms': np.random.uniform(1, 100)
                })
        
        # Save to JSON
        filepath = self.output_dir / 'psc_network_topology.json'
        with open(filepath, 'w') as f:
            json.dump(psc_topology, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated PSC topology with {len(psc_topology['nodes']):,} nodes and {len(psc_topology['edges']):,} edges")
        print(f"    Saved to {filepath.name}")
        
        return psc_topology


if __name__ == "__main__":
    generator = CESNETDataGenerator()
    timeseries_data = generator.generate_ip_timeseries()
    institution_data = generator.generate_institution_data(timeseries_data)
    relationships = generator.generate_network_graph(timeseries_data)
    anomalies = generator.generate_anomalies(timeseries_data)
    psc_topology = generator.generate_psc_input_format(timeseries_data, relationships)
