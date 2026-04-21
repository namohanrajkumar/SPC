#!/usr/bin/env python3
"""
AwesomeCybersecurity Dataset Generator
Generates comprehensive cybersecurity datasets from multiple sources
"""

import json
import os
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import random
import warnings

warnings.filterwarnings('ignore')


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder for numpy types"""
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, (np.integer, np.floating)):
            return float(obj)
        if isinstance(obj, np.bool_):
            return bool(obj)
        return super().default(obj)


class AwesomeCyberDataGenerator:
    """Generates comprehensive cybersecurity datasets"""
    
    MALWARE_FAMILIES = {
        "APT1": {"samples": 292, "threat_level": "critical"},
        "Zeus": {"samples": 456, "threat_level": "critical"},
        "Conficker": {"samples": 389, "threat_level": "high"},
        "Mirai": {"samples": 523, "threat_level": "critical"},
        "WannaCry": {"samples": 278, "threat_level": "critical"},
        "Emotet": {"samples": 445, "threat_level": "critical"},
        "Ryuk": {"samples": 234, "threat_level": "critical"},
    }
    
    ATTACK_TYPES = [
        "Malware", "Ransomware", "DDoS", "Intrusion", "Exploit",
        "Phishing", "Backdoor", "Rootkit", "Botnet", "Worm"
    ]
    
    SYSTEM_CALLS = [
        "read", "write", "open", "close", "stat", "fstat", "lstat", "poll",
        "lseek", "mmap", "mprotect", "munmap", "brk", "ioctl", "access",
        "pipe", "select", "fork", "execve", "exit", "wait", "kill", "clone",
        "connect", "bind", "listen", "accept", "shutdown", "socket", "sendto",
        "recvfrom", "sendmsg", "recvmsg"
    ]
    
    PROCESS_TYPES = [
        "bash", "apache2", "mysql", "ssh", "cron", "syslog",
        "exploit", "backdoor", "rootkit", "virus", "worm"
    ]
    
    NETWORK_PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "TLS"]
    
    def __init__(self, num_samples=5000, output_dir=None):
        self.num_samples = num_samples
        self.output_dir = output_dir or "/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Code1/livedataoutputs/awesome_data"
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
    def generate_threat_genomes(self):
        """Generate threat genome records"""
        print(f"\n[▶] Generating threat genome data...")
        genomes = []
        
        for family, info in self.MALWARE_FAMILIES.items():
            num_variants = info["samples"] // 10
            
            for i in range(num_variants):
                genome = {
                    "genome_id": f"G-{family}-{i:04d}",
                    "malware_family": family,
                    "threat_level": info["threat_level"],
                    "samples_count": random.randint(1, 50),
                    "first_seen": (datetime.now() - timedelta(days=random.randint(365, 3650))).isoformat(),
                    "confidence": round(random.uniform(0.7, 1.0), 2),
                    "propagation_vectors": random.sample(
                        ["spear_phishing", "watering_hole", "removable_media", "exploit", "email"],
                        k=random.randint(1, 3)
                    ),
                    "execution_methods": random.sample(
                        ["dll_hijacking", "service_installation", "scheduled_tasks", "registry_run"],
                        k=random.randint(1, 2)
                    ),
                    "communication_patterns": random.sample(
                        ["encrypted_http", "timing_beacons", "fallback_domains", "p2p"],
                        k=random.randint(1, 2)
                    ),
                    "target_industries": random.sample(
                        ["government", "finance", "healthcare", "technology", "defense", "energy"],
                        k=random.randint(1, 4)
                    ),
                    "known_variants": random.randint(1, 20),
                    "iocs": {
                        "domains": [f"c2-{i}-{j}.com" for j in range(random.randint(1, 3))],
                        "ips": [f"192.168.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(random.randint(1, 3))],
                        "hashes": [f"{hex(random.randint(0, 2**128))}" for _ in range(random.randint(2, 5))]
                    }
                }
                genomes.append(genome)
        
        output_file = os.path.join(self.output_dir, "awesome_threat_genomes.json")
        with open(output_file, 'w') as f:
            json.dump(genomes, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(genomes)} threat genomes")
        return genomes
    
    def generate_process_level_data(self):
        """Generate process-level behavioral data (MSBB Cellular)"""
        print(f"\n[▶] Generating process-level behavioral data...")
        
        process_data = []
        num_processes = min(self.num_samples // 5, 1000)
        
        for i in range(num_processes):
            syscall_sequence = random.sample(self.SYSTEM_CALLS, k=random.randint(5, 30))
            
            process = {
                "process_id": f"PROC-{i:05d}",
                "process_type": random.choice(self.PROCESS_TYPES),
                "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 720))).isoformat(),
                "is_malicious": random.choice([True, False]),
                "syscall_sequence": syscall_sequence,
                "syscall_count": len(syscall_sequence),
                "unique_syscalls": len(set(syscall_sequence)),
                "execution_time": round(random.uniform(0.001, 10.0), 3),
                "memory_usage_mb": round(random.uniform(1, 500), 2),
                "cpu_percentage": round(random.uniform(0, 100), 2),
                "parent_process": f"PROC-{random.randint(0, num_processes-1):05d}",
                "child_processes": random.randint(0, 10),
                "file_operations": random.randint(0, 100),
                "network_connections": random.randint(0, 20),
                "anomaly_score": round(random.uniform(0.0, 1.0), 3)
            }
            process_data.append(process)
        
        output_file = os.path.join(self.output_dir, "awesome_process_level.json")
        with open(output_file, 'w') as f:
            json.dump(process_data, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(process_data)} process-level records")
        return process_data
    
    def generate_network_data(self):
        """Generate network segment data (MSBB Tissue)"""
        print(f"\n[▶] Generating network segment data...")
        
        network_data = []
        num_segments = min(self.num_samples // 50, 500)
        
        for i in range(num_segments):
            packets_sent = random.randint(100, 1000000)
            packets_received = random.randint(100, 1000000)
            
            segment = {
                "segment_id": f"SEG-{i:04d}",
                "subnet": f"192.168.{i//256}.0/24",
                "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 10080))).isoformat(),
                "protocol": random.choice(self.NETWORK_PROTOCOLS),
                "packets_sent": packets_sent,
                "packets_received": packets_received,
                "bytes_sent": packets_sent * random.randint(40, 1500),
                "bytes_received": packets_received * random.randint(40, 1500),
                "duration_seconds": random.randint(1, 3600),
                "packet_loss_percentage": round(random.uniform(0, 5), 2),
                "latency_ms": round(random.uniform(1, 1000), 2),
                "unique_flows": random.randint(1, 1000),
                "unusual_traffic": random.choice([True, False]),
                "threat_score": round(random.uniform(0.0, 1.0), 3)
            }
            network_data.append(segment)
        
        output_file = os.path.join(self.output_dir, "awesome_network_segment.json")
        with open(output_file, 'w') as f:
            json.dump(network_data, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(network_data)} network segment records")
        return network_data
    
    def generate_host_data(self):
        """Generate host-level data (MSBB Organ)"""
        print(f"\n[▶] Generating host-level audit data...")
        
        host_data = []
        num_hosts = min(self.num_samples // 50, 500)
        
        for i in range(num_hosts):
            host = {
                "host_id": f"HOST-{i:04d}",
                "ip_address": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "hostname": f"host-{i:04d}.company.local",
                "os": random.choice(["Windows", "Linux", "macOS"]),
                "os_version": f"{random.randint(10, 22)}.{random.randint(0, 9)}",
                "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
                "uptime_hours": random.randint(1, 8760),
                "running_processes": random.randint(10, 500),
                "listening_ports": random.randint(0, 50),
                "installed_patches": random.randint(50, 500),
                "antivirus_enabled": random.choice([True, False]),
                "firewall_enabled": random.choice([True, False]),
                "failed_login_attempts": random.randint(0, 100),
                "successful_logins": random.randint(1, 1000),
                "last_security_update": (datetime.now() - timedelta(days=random.randint(0, 180))).isoformat(),
                "vulnerability_score": round(random.uniform(0.0, 10.0), 2),
                "detection_status": random.choice(["Clean", "Suspicious", "Infected"])
            }
            host_data.append(host)
        
        output_file = os.path.join(self.output_dir, "awesome_host_level.json")
        with open(output_file, 'w') as f:
            json.dump(host_data, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(host_data)} host-level audit records")
        return host_data
    
    def generate_domain_intelligence(self):
        """Generate domain-based threat intelligence"""
        print(f"\n[▶] Generating domain-based threat intelligence...")
        
        domain_data = []
        domains_per_family = 20
        
        for family in self.MALWARE_FAMILIES.keys():
            for i in range(domains_per_family):
                domain = {
                    "domain": f"{family.lower()}-c2-{i:03d}.{random.choice(['com', 'net', 'org', 'ru', 'cn'])}",
                    "malware_family": family,
                    "first_seen": (datetime.now() - timedelta(days=random.randint(365, 3650))).isoformat(),
                    "last_seen": (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
                    "registrant": f"Registrant-{random.randint(1, 10000)}",
                    "ip_addresses": [f"192.168.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(random.randint(1, 5))],
                    "associated_hashes": [f"{hex(random.randint(0, 2**128))}" for _ in range(random.randint(1, 3))],
                    "threat_level": random.choice(["low", "medium", "high", "critical"]),
                    "sinkholed": random.choice([True, False]),
                    "detection_count": random.randint(0, 10000)
                }
                domain_data.append(domain)
        
        output_file = os.path.join(self.output_dir, "awesome_domain_intelligence.json")
        with open(output_file, 'w') as f:
            json.dump(domain_data, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(domain_data)} domain intelligence records")
        return domain_data
    
    def generate_complete_spc_input(self, genomes, process_data, network_data, host_data, domain_data):
        """Generate complete SPC input package"""
        print(f"\n[▶] Generating complete SPC input package...")
        
        spc_input = {
            "dataset_metadata": {
                "source": "AwesomeCybersecurity Multiple Datasets",
                "generation_date": datetime.now().isoformat(),
                "total_records": len(genomes) + len(process_data) + len(network_data) + len(host_data) + len(domain_data)
            },
            "threat_genomes": genomes,
            "process_level_data": process_data,
            "network_segment_data": network_data,
            "host_level_data": host_data,
            "domain_intelligence": domain_data,
            "statistics": {
                "total_malware_families": len(self.MALWARE_FAMILIES),
                "total_threat_genomes": len(genomes),
                "total_processes": len(process_data),
                "total_network_segments": len(network_data),
                "total_hosts": len(host_data),
                "total_domains": len(domain_data),
                "total_system_calls": len(self.SYSTEM_CALLS),
                "total_records": len(genomes) + len(process_data) + len(network_data) + len(host_data) + len(domain_data)
            }
        }
        
        output_file = os.path.join(self.output_dir, "spc_input_awesome.json")
        with open(output_file, 'w') as f:
            json.dump(spc_input, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated complete SPC input package")
        return spc_input


if __name__ == "__main__":
    generator = AwesomeCyberDataGenerator()
    genomes = generator.generate_threat_genomes()
    process_data = generator.generate_process_level_data()
    network_data = generator.generate_network_data()
    host_data = generator.generate_host_data()
    domain_data = generator.generate_domain_intelligence()
    generator.generate_complete_spc_input(genomes, process_data, network_data, host_data, domain_data)
