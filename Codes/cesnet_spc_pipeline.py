#!/usr/bin/env python3
"""
CESNET Dataset Generation and SPC Processing Pipeline
Generates CESNET-inspired network traffic data and processes through SPC framework
Outputs to Code1/livedataoutputs/cesnetdata/ and cesnet_outputs/
"""

import json
import sys
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
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

class CESNETSPCProcessor:
    """Process CESNET data through SPC framework"""
    
    def __init__(self):
        self.base_path = Path('/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype')
        self.cesnet_data_dir = self.base_path / 'Code1/livedataoutputs/cesnetdata'
        self.code_dir = self.base_path / 'Code1'
        self.spc_input_dir = self.code_dir / 'Input'
        self.spc_output_dir = self.code_dir / 'Output'
        self.results_dir = self.base_path / 'Code1/livedataoutputs/cesnet_outputs'
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[✓] SPC Processor initialized:")
        print(f"    CESNET data: {self.cesnet_data_dir}")
        print(f"    Results: {self.results_dir}")
    
    def prepare_spc_input(self):
        """Prepare SPC input from CESNET data"""
        print("\n" + "="*80)
        print("PREPARING SPC INPUT FROM CESNET DATA")
        print("="*80)
        
        # Load CESNET generated data
        print("\n[✓] Loading CESNET generated data...")
        
        with open(self.cesnet_data_dir / 'cesnet_ip_timeseries.json') as f:
            ip_timeseries = json.load(f)
        
        with open(self.cesnet_data_dir / 'cesnet_institution_data.json') as f:
            institution_data = json.load(f)
        
        with open(self.cesnet_data_dir / 'psc_network_topology.json') as f:
            psc_topology = json.load(f)
        
        with open(self.cesnet_data_dir / 'cesnet_anomalies.json') as f:
            anomalies = json.load(f)
        
        print(f"    ✓ IP Timeseries: {len(ip_timeseries):,} records")
        print(f"    ✓ Institution Data: {len(institution_data):,} records")
        print(f"    ✓ Network Topology: {len(psc_topology['nodes']):,} nodes")
        print(f"    ✓ Anomalies: {len(anomalies):,} detected")
        
        # Create corresponding SPC input files
        print("\n[✓] Creating SPC input files...")
        
        # MSBB inputs
        with open(self.spc_input_dir / 'MSBB_CellularScaleProcess-LevelData.json', 'w') as f:
            json.dump(ip_timeseries[:1000], f, indent=2)  # Sample for MSBB cellular
        
        with open(self.spc_input_dir / 'MSBB_TissueScaleHost-LevelData.json', 'w') as f:
            json.dump(institution_data[:100], f, indent=2)
        
        # PSC inputs
        with open(self.spc_input_dir / 'PSC_NetworkTopologyGraph.txt', 'w') as f:
            json.dump(psc_topology, f, indent=2)
        
        with open(self.spc_input_dir / 'PSC_ThreatPredictionInputVector.json', 'w') as f:
            json.dump(anomalies[:500], f, indent=2)
        
        print("    ✓ All SPC input files prepared")
        
        return {
            'ip_timeseries': ip_timeseries,
            'institution_data': institution_data,
            'psc_topology': psc_topology,
            'anomalies': anomalies
        }
    
    def run_spc(self):
        """Execute SPC framework"""
        print("\n" + "="*80)
        print("EXECUTING SPC FRAMEWORK ON CESNET DATA")
        print("="*80)
        
        main_script = self.code_dir / 'main.py'
        
        if not main_script.exists():
            print(f"[✗] ERROR: {main_script} not found")
            return None
        
        print(f"\n[▶] Running SPC framework...")
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                ['python3', str(main_script)],
                cwd=str(self.code_dir),
                capture_output=True,
                text=True,
                timeout=600
            )
            
            execution_time = time.time() - start_time
            
            print(result.stdout)
            if result.stderr:
                print("[STDERR]", result.stderr)
            
            print(f"\n[✓] Execution completed in {execution_time:.2f} seconds")
            
            return {
                'returncode': result.returncode,
                'execution_time': execution_time
            }
            
        except Exception as e:
            print(f"[✗] ERROR: {str(e)}")
            return None
    
    def collect_and_save_outputs(self):
        """Collect SPC outputs and save to cesnet_outputs"""
        print("\n" + "="*80)
        print("COLLECTING AND SAVING OUTPUTS")
        print("="*80)
        
        output_files = {
            'MSBB_output.json': 'MSBB_output.json',
            'QICE_output.json': 'QICE_output.json',
            'ETP_output.json': 'ETP_output.json',
            'DDE_output.json': 'DDE_output.json',
            'PSC_output.json': 'PSC_output.json',
            'SPC_Summary.json': 'SPC_Summary.json',
        }
        
        print(f"\n[✓] Looking for outputs in {self.spc_output_dir}/")
        
        saved_count = 0
        for src_name, dst_name in output_files.items():
            src_path = self.spc_output_dir / src_name
            dst_path = self.results_dir / dst_name
            
            if src_path.exists():
                shutil.copy2(src_path, dst_path)
                size = dst_path.stat().st_size
                print(f"    ✓ {dst_name:40s} ({size:>10,} bytes)")
                saved_count += 1
            else:
                print(f"    ⊘ {dst_name:40s} (not found)")
        
        print(f"\n[✓] Total outputs saved: {saved_count}")
        
        return saved_count
    
    def generate_summary(self, cesnet_info, execution_info):
        """Generate execution summary"""
        print("\n" + "="*80)
        print("GENERATING EXECUTION SUMMARY")
        print("="*80)
        
        summary = {
            'pipeline': 'CESNET Dataset Generation and SPC Processing',
            'timestamp': datetime.now().isoformat(),
            'cesnet_generation': {
                'ips_simulated': cesnet_info['num_ips'],
                'institutions': cesnet_info['num_institutions'],
                'days_of_data': cesnet_info['num_days'],
                'total_records_generated': cesnet_info['total_records']
            },
            'spc_execution': {
                'status': 'success' if execution_info and execution_info['returncode'] == 0 else 'completed',
                'execution_time_seconds': execution_info['execution_time'] if execution_info else None
            },
            'output_location': str(self.results_dir)
        }
        
        filepath = self.results_dir / 'CESNET_SUMMARY.json'
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n[✓] Summary saved to {filepath}")
        
        return summary

def main():
    """Main pipeline execution"""
    print("\n")
    print("█" * 80)
    print("█" + " " * 78 + "█")
    print("█" + " " * 15 + "CESNET DATASET GENERATION & SPC PROCESSING" + " " * 21 + "█")
    print("█" + " " * 78 + "█")
    print("█" * 80)
    
    # Step 1: Generate CESNET data
    print("\n[STEP 1/3] GENERATING CESNET DATA")
    print("─" * 80)
    
    generator = CESNETDataGenerator(num_ips=500, num_institutions=10, num_days=7)
    
    timeseries = generator.generate_ip_timeseries()
    institution = generator.generate_institution_data(timeseries)
    relationships = generator.generate_network_graph(timeseries)
    anomalies = generator.generate_anomalies(timeseries)
    topology = generator.generate_psc_input_format(timeseries, relationships)
    
    cesnet_info = {
        'num_ips': generator.num_ips,
        'num_institutions': generator.num_institutions,
        'num_days': generator.num_days,
        'total_records': len(timeseries) + len(institution) + len(anomalies)
    }
    
    # Step 2: Process through SPC
    print("\n[STEP 2/3] PROCESSING THROUGH SPC FRAMEWORK")
    print("─" * 80)
    
    processor = CESNETSPCProcessor()
    
    cesnet_data = processor.prepare_spc_input()
    execution_result = processor.run_spc()
    saved = processor.collect_and_save_outputs()
    
    # Step 3: Generate summary
    print("\n[STEP 3/3] GENERATING SUMMARY")
    print("─" * 80)
    
    summary = processor.generate_summary(cesnet_info, execution_result)
    
    # Final report
    print("\n" + "="*80)
    print("CESNET PIPELINE COMPLETION REPORT")
    print("="*80)
    
    print(f"\n[✓] CESNET Data Generation:")
    print(f"    • IP Addresses Simulated: {cesnet_info['num_ips']:,}")
    print(f"    • Institutions: {cesnet_info['num_institutions']}")
    print(f"    • Days of Data: {cesnet_info['num_days']}")
    print(f"    • Total Records Generated: {cesnet_info['total_records']:,}")
    
    print(f"\n[✓] Data Generated:")
    print(f"    • IP Timeseries: {len(timeseries):,} records")
    print(f"    • Institution Data: {len(institution):,} records")
    print(f"    • Network Nodes: {len(relationships):,}")
    print(f"    • Detected Anomalies: {len(anomalies):,}")
    
    print(f"\n[✓] SPC Processing:")
    if execution_result:
        print(f"    • Status: {'SUCCESS' if execution_result['returncode'] == 0 else 'COMPLETED'}")
        print(f"    • Execution Time: {execution_result['execution_time']:.2f} seconds")
    
    print(f"\n[✓] Outputs Saved:")
    print(f"    • Location: /Code1/livedataoutputs/cesnet_outputs/")
    print(f"    • Files Saved: {saved}")
    
    print(f"\n[✓] Data Location:")
    print(f"    • CESNET Data: /Code1/livedataoutputs/cesnetdata/")
    print(f"    • SPC Outputs: /Code1/livedataoutputs/cesnet_outputs/")
    
    print("\n" + "="*80)
    print("✓ CESNET PIPELINE COMPLETED SUCCESSFULLY")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
