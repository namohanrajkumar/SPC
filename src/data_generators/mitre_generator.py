#!/usr/bin/env python3
"""
MITRE ATT&CK Dataset Generator
Generates threat intelligence data from MITRE ATT&CK framework
"""

import json
import os
import numpy as np
import pandas as pd
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


class MITREDataGenerator:
    """Generates MITRE ATT&CK threat intelligence datasets"""
    
    # MITRE ATT&CK Groups
    APT_GROUPS = {
        "APT29": {"id": "G0016", "aliases": ["Cozy Bear", "The Dukes", "YTTRIUM"], "active_since": 2008},
        "APT28": {"id": "G0007", "aliases": ["Fancy Bear", "Sofacy"], "active_since": 2007},
        "APT41": {"id": "G0096", "aliases": ["Winnti Group"], "active_since": 2010},
        "Lazarus": {"id": "G0009", "aliases": ["Hidden Cobra", "ZINC"], "active_since": 2009},
        "APT1": {"id": "G0006", "aliases": ["Comment Crew", "PLA Unit 61398"], "active_since": 2006},
        "APT40": {"id": "G0065", "aliases": ["Leviathan"], "active_since": 2009},
        "Turla": {"id": "G0010", "aliases": ["Snake", "Venomous Bear"], "active_since": 2008},
    }
    
    # MITRE ATT&CK Tactics
    TACTICS = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]
    
    # MITRE ATT&CK Techniques
    TECHNIQUES = {
        "Reconnaissance": ["T1590", "T1592", "T1595", "T1598", "T1597"],
        "Initial Access": ["T1566", "T1091", "T1195", "T1199", "T1190"],
        "Execution": ["T1059", "T1609", "T1106", "T1053", "T1648"],
        "Persistence": ["T1098", "T1197", "T1547", "T1547.001", "T1547.014"],
        "Privilege Escalation": ["T1548", "T1134", "T1547", "T1548.002", "T1068"],
        "Defense Evasion": ["T1548", "T1197", "T1197", "T1140", "T1197"],
        "Credential Access": ["T1110", "T1187", "T1056", "T1056.001", "T1557"],
        "Discovery": ["T1087", "T1010", "T1217", "T1526", "T1538"],
        "Lateral Movement": ["T1570", "T1570", "T1021", "T1021.001", "T1570"],
        "Collection": ["T1557", "T1123", "T1119", "T1185", "T1115"],
        "Command and Control": ["T1071", "T1092", "T1132", "T1001", "T1568"],
        "Exfiltration": ["T1020", "T1030", "T1048", "T1041", "T1011"],
        "Impact": ["T1531", "T1485", "T1491", "T1561", "T1561.001"]
    }
    
    # MITRE Software
    SOFTWARE = ["S0049", "S0089", "S0187", "S0236", "S0249", "S0250", "S0337",
                "S0089", "S0074", "S0160", "S0305", "S0381"]
    
    def __init__(self, num_samples=5000, output_dir=None):
        self.num_samples = num_samples
        self.output_dir = output_dir or "/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Code1/livedataoutputs/mitredata"
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
    def generate_threat_genomes(self):
        """Generate threat genome records from MITRE groups"""
        print(f"\n[▶] Generating MITRE threat genome data...")
        genomes = []
        
        for group_name, group_info in self.APT_GROUPS.items():
            # Create multiple variants per group
            variants_per_group = self.num_samples // len(self.APT_GROUPS)
            
            for i in range(variants_per_group):
                # Select random techniques for this genome
                selected_tactics = random.sample(self.TACTICS, k=random.randint(4, 8))
                techniques = []
                
                for tactic in selected_tactics:
                    tactic_techniques = self.TECHNIQUES.get(tactic, [])
                    if tactic_techniques:
                        techniques.extend(random.sample(tactic_techniques, k=min(2, len(tactic_techniques))))
                
                genome = {
                    "genome_id": f"G-{group_name}-{i:04d}",
                    "group_name": group_name,
                    "mitre_group_id": group_info["id"],
                    "aliases": group_info["aliases"],
                    "first_seen": (datetime.now() - timedelta(days=random.randint(365, 5000))).isoformat(),
                    "last_seen": (datetime.now() - timedelta(days=random.randint(0, 365))).isoformat(),
                    "techniques": list(set(techniques)),
                    "tactics": selected_tactics,
                    "software_used": random.sample(self.SOFTWARE, k=random.randint(2, 5)),
                    "confidence_score": round(random.uniform(0.6, 1.0), 2),
                    "target_industries": random.sample(
                        ["government", "technology", "finance", "healthcare", "energy", "defense"],
                        k=random.randint(1, 4)
                    ),
                    "attack_count": random.randint(5, 200),
                    "known_variants": random.randint(1, 50)
                }
                genomes.append(genome)
        
        output_file = os.path.join(self.output_dir, "mitre_threat_genomes.json")
        with open(output_file, 'w') as f:
            json.dump(genomes, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(genomes)} threat genomes")
        print(f"    Saved to mitre_threat_genomes.json")
        return genomes
    
    def generate_technique_evolution(self, genomes):
        """Generate technique evolution over time"""
        print(f"\n[▶] Generating technique evolution data...")
        
        evolution_records = []
        base_date = datetime(2015, 1, 1)
        
        for genome in genomes[:len(genomes)//5]:  # Sample of genomes
            group_name = genome["group_name"]
            techniques = genome["techniques"]
            
            # Generate monthly evolution data
            for month in range(0, 108):  # 9 years
                period_date = base_date + timedelta(days=30*month)
                
                evolution = {
                    "period": period_date.strftime("%Y-%m"),
                    "group": group_name,
                    "techniques_active": random.sample(techniques, k=max(1, len(techniques)//2)),
                    "new_techniques": random.sample(self.TACTICS, k=random.randint(0, 2)),
                    "mutation_rate": round(random.uniform(0.05, 0.25), 2),
                    "detected_incidents": random.randint(0, 50),
                    "evasion_score": round(random.uniform(0.3, 0.95), 2),
                    "success_rate": round(random.uniform(0.2, 0.9), 2)
                }
                evolution_records.append(evolution)
        
        output_file = os.path.join(self.output_dir, "mitre_technique_evolution.json")
        with open(output_file, 'w') as f:
            json.dump(evolution_records, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(evolution_records)} evolution records")
        print(f"    Saved to mitre_technique_evolution.json")
        return evolution_records
    
    def generate_campaign_data(self, genomes):
        """Generate campaign intelligence data"""
        print(f"\n[▶] Generating campaign intelligence data...")
        
        campaigns = []
        for genome in genomes:
            num_campaigns = random.randint(2, 8)
            group_name = genome["group_name"]
            
            for i in range(num_campaigns):
                campaign_start = datetime.now() - timedelta(days=random.randint(30, 1000))
                
                campaign = {
                    "campaign_id": f"CAMP-{group_name}-{i:03d}",
                    "group": group_name,
                    "name": f"{group_name}_Campaign_{i}",
                    "start_date": campaign_start.isoformat(),
                    "end_date": (campaign_start + timedelta(days=random.randint(10, 365))).isoformat(),
                    "targets": random.randint(5, 500),
                    "success_count": random.randint(1, 100),
                    "techniques_used": random.sample(genome["techniques"], k=min(5, len(genome["techniques"]))),
                    "malware_families": random.sample(self.SOFTWARE, k=random.randint(1, 3)),
                    "impact_level": random.choice(["low", "medium", "high", "critical"]),
                    "attributed": random.choice([True, False])
                }
                campaigns.append(campaign)
        
        output_file = os.path.join(self.output_dir, "mitre_campaigns.json")
        with open(output_file, 'w') as f:
            json.dump(campaigns, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(campaigns)} campaigns")
        print(f"    Saved to mitre_campaigns.json")
        return campaigns
    
    def generate_feature_vectors(self, genomes):
        """Generate ML-ready feature vectors for genomes"""
        print(f"\n[▶] Generating vectorized features...")
        
        vectors = []
        for genome in genomes:
            # Create 50-dimensional feature vector
            feature_vector = [
                len(genome["techniques"]) / len(self.TECHNIQUES),  # Technique diversity
                len(genome["tactics"]) / len(self.TACTICS),  # Tactic coverage
                genome["confidence_score"],  # Confidence
                genome["attack_count"] / 200,  # Attack frequency (normalized)
                len(genome["software_used"]) / 5,  # Tool diversity
                genome["known_variants"] / 50,  # Variant count (normalized)
                len(genome["target_industries"]) / 6,  # Industry targeting
                *[random.random() for _ in range(43)]  # Additional learned features
            ]
            
            vector_record = {
                "genome_id": genome["genome_id"],
                "group": genome["group_name"],
                "feature_vector": feature_vector,
                "vector_norm": np.linalg.norm(feature_vector),
                "technique_codes": genome["techniques"],
                "tactic_codes": genome["tactics"]
            }
            vectors.append(vector_record)
        
        output_file = os.path.join(self.output_dir, "mitre_feature_vectors.json")
        with open(output_file, 'w') as f:
            json.dump(vectors, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated {len(vectors)} feature vectors")
        print(f"    Saved to mitre_feature_vectors.json")
        return vectors
    
    def generate_etp_input(self, genomes, evolution, campaigns):
        """Convert to ETP input format"""
        print(f"\n[▶] Converting to ETP input format...")
        
        etp_input = {
            "dataset_metadata": {
                "source": "MITRE ATT&CK",
                "generation_date": datetime.now().isoformat(),
                "threat_genomes_count": len(genomes),
                "evolution_records": len(evolution),
                "campaigns": len(campaigns)
            },
            "threat_genomes": genomes,
            "evolution_records": evolution,
            "campaigns": campaigns,
            "statistics": {
                "total_groups": len(set(g["group_name"] for g in genomes)),
                "total_techniques": len(set(t for g in genomes for t in g["techniques"])),
                "total_tactics": len(set(t for g in genomes for t in g["tactics"])),
                "active_campaigns": len([c for c in campaigns if c["attributed"]])
            }
        }
        
        output_file = os.path.join(self.output_dir, "etp_input_mitre.json")
        with open(output_file, 'w') as f:
            json.dump(etp_input, f, cls=NumpyEncoder, indent=2)
        
        print(f"[✓] Generated ETP input with:")
        print(f"    • {len(genomes)} threat genomes")
        print(f"    • {len(evolution)} evolution markers")
        print(f"    • {len(campaigns)} campaigns")
        print(f"    Saved to etp_input_mitre.json")
        return etp_input


if __name__ == "__main__":
    generator = MITREDataGenerator()
    genomes = generator.generate_threat_genomes()
    evolution = generator.generate_technique_evolution(genomes)
    campaigns = generator.generate_campaign_data(genomes)
    vectors = generator.generate_feature_vectors(genomes)
    generator.generate_etp_input(genomes, evolution, campaigns)
