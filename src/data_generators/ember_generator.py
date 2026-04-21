#!/usr/bin/env python3
"""
EMBER Dataset Generator
Generates EMBER-inspired malware feature data
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


class EMBERDataGenerator:
    """Generate EMBER-inspired malware feature data"""
    
    def __init__(self, num_samples=5000, num_features=100, malware_ratio=0.5):
        self.num_samples = num_samples
        self.num_features = num_features
        self.malware_ratio = malware_ratio
        self.output_dir = Path('/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Code1/livedataoutputs/emberdata')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # EMBER-specific feature names
        self.pe_sections = ['.text', '.data', '.rdata', '.rsrc', '.reloc', '.debug']
        self.malware_families = ['Zeus', 'Conficker', 'Mirai', 'WannaCry', 'Emotet', 'Dridex', 'TrickBot']
        self.pe_imports = ['KERNEL32.DLL', 'USER32.DLL', 'ADVAPI32.DLL', 'NTDLL.DLL', 'WS2_32.DLL', 'SHELL32.DLL']
        
        print(f"\n[✓] EMBER Data Generator initialized:")
        print(f"    • Samples to generate: {num_samples}")
        print(f"    • Features per sample: {num_features}")
        print(f"    • Malware ratio: {malware_ratio*100:.1f}%")
        print(f"    • Output directory: {self.output_dir}")
    
    def generate_malware_features(self):
        """Generate EMBER malware feature data"""
        print("\n[▶] Generating malware feature data...")
        
        feature_data = []
        base_date = datetime(2017, 1, 1)
        
        for sample_idx in range(self.num_samples):
            # Determine if malware or benign
            is_malware = np.random.random() < self.malware_ratio
            label = 1 if is_malware else 0
            
            # Generate sample timestamp (spread over ~2 years)
            days_offset = np.random.randint(0, 730)
            appeared_date = base_date + timedelta(days=days_offset)
            
            # Generate PE header features
            sample = {
                'sha256': f"sha_{sample_idx:08d}{'m' if is_malware else 'b'}",
                'appeared': appeared_date.isoformat(),
                'label': label,
                'family': np.random.choice(self.malware_families) if is_malware else 'benign',
                
                # PE Header features (static structural characteristics)
                'pe_header': {
                    'numberof_sections': np.random.randint(2, 15),
                    'compile_timestamp': int(appeared_date.timestamp()),
                    'machine': np.random.choice([0x14c, 0x8664]),  # x86 or x64
                    'characteristics': np.random.randint(0, 65536),
                    'sizeof_image': np.random.randint(4096, 10*1024*1024)
                },
                
                # Section features (behavioral characteristics)
                'sections': []
            }
            
            # Generate section data (like behavioral traits)
            num_sections = sample['pe_header']['numberof_sections']
            for sec_idx in range(num_sections):
                section_name = np.random.choice(self.pe_sections)
                
                # Malware samples tend to have higher entropy sections
                if is_malware and np.random.random() < 0.6:
                    entropy = np.random.uniform(6.5, 7.8)  # High entropy = packed/encrypted
                else:
                    entropy = np.random.uniform(2.0, 5.0)
                
                section = {
                    'name': section_name,
                    'size': np.random.randint(1024, 5*1024*1024),
                    'entropy': float(entropy),
                    'virtual_size': np.random.randint(1024, 5*1024*1024),
                    'properties': np.random.randint(0, 256)
                }
                
                sample['sections'].append(section)
            
            # Generate import features (API usage patterns - behavioral genes)
            sample['imports'] = {
                'libraries': list(np.random.choice(self.pe_imports, size=np.random.randint(3, 6), replace=False)),
                'api_count': np.random.randint(10, 200) if is_malware else np.random.randint(5, 50),
                'suspicious_apis': np.random.randint(0, 50) if is_malware else np.random.randint(0, 5)
            }
            
            # Generate numeric feature vector (like genetic code)
            features = []
            for feat_idx in range(self.num_features):
                if is_malware:
                    # Malware features tend to have different distributions
                    features.append(float(np.random.uniform(0.3, 1.0)))
                else:
                    features.append(float(np.random.uniform(0.0, 0.3)))
            
            sample['feature_vector'] = features
            
            # Add evolutionary markers
            sample['entropy_mean'] = float(np.mean([s['entropy'] for s in sample['sections']]))
            sample['packing_score'] = float(sample['entropy_mean'] / 8.0)  # Normalized packing indicator
            sample['api_diversity'] = float(len(sample['imports']['libraries']) / 6.0)  # Import diversity
            sample['mutation_probability'] = float(np.random.uniform(0.0, 1.0))
            
            feature_data.append(sample)
        
        # Save to JSON
        filepath = self.output_dir / 'ember_malware_features.json'
        with open(filepath, 'w') as f:
            json.dump(feature_data, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(feature_data):,} malware feature samples")
        print(f"    Malware: {sum(1 for s in feature_data if s['label']==1):,} | Benign: {sum(1 for s in feature_data if s['label']==0):,}")
        print(f"    Saved to {filepath.name}")
        
        return feature_data
    
    def generate_family_evolution(self, feature_data):
        """Generate malware family evolution data"""
        print("\n[▶] Generating malware family evolution data...")
        
        df = pd.DataFrame(feature_data)
        evolution_data = []
        
        # Group by family and time period
        df['appeared_date'] = pd.to_datetime(df['appeared'])
        df['period'] = df['appeared_date'].dt.to_period('M')
        
        for family in df[df['label']==1]['family'].unique():
            family_df = df[(df['family']==family) & (df['label']==1)]
            
            for period in sorted(family_df['period'].unique()):
                period_df = family_df[family_df['period']==period]
                
                evo = {
                    'family': family,
                    'period': str(period),
                    'sample_count': len(period_df),
                    'avg_entropy': float(period_df['entropy_mean'].mean()),
                    'avg_packing_score': float(period_df['packing_score'].mean()),
                    'avg_api_diversity': float(period_df['api_diversity'].mean()),
                    'mutation_rate': float(period_df['mutation_probability'].mean()),
                    'variants': len(period_df)  # Count unique samples instead
                }
                
                evolution_data.append(evo)
        
        # Save to JSON
        filepath = self.output_dir / 'ember_family_evolution.json'
        with open(filepath, 'w') as f:
            json.dump(evolution_data, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(evolution_data):,} family evolution records")
        print(f"    Saved to {filepath.name}")
        
        return evolution_data
    
    def generate_threat_variants(self, feature_data):
        """Generate threat variant/mutation data"""
        print("\n[▶] Generating threat variant data...")
        
        variants_data = []
        malware_samples = [s for s in feature_data if s['label'] == 1]
        
        # Group samples by family and create variant chains
        df = pd.DataFrame(malware_samples)
        
        for family in df['family'].unique():
            family_samples = df[df['family']==family].sort_values('appeared')
            
            for idx, (_, sample) in enumerate(family_samples.iterrows()):
                variant = {
                    'variant_id': sample['sha256'],
                    'family': family,
                    'appeared': sample['appeared'],
                    'generation': idx + 1,
                    'feature_changes': {
                        'entropy_change': float(np.random.uniform(-0.5, 1.5)),
                        'section_count_change': np.random.randint(-2, 3),
                        'api_count_change': np.random.randint(-20, 50),
                        'packing_change': float(np.random.uniform(-0.3, 0.5))
                    },
                    'evasion_techniques': np.random.randint(0, 10),
                    'confidence': float(np.random.uniform(0.6, 1.0))
                }
                
                variants_data.append(variant)
        
        # Save to JSON
        filepath = self.output_dir / 'ember_threat_variants.json'
        with open(filepath, 'w') as f:
            json.dump(variants_data, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(variants_data):,} threat variant records")
        print(f"    Saved to {filepath.name}")
        
        return variants_data
    
    def generate_feature_vectors(self, feature_data):
        """Generate ML-ready feature vectors for ETP"""
        print("\n[▶] Generating vectorized features...")
        
        vectors_data = []
        
        for sample in feature_data:
            vector_record = {
                'sha256': sample['sha256'],
                'label': sample['label'],
                'family': sample['family'],
                'appeared': sample['appeared'],
                'features': sample['feature_vector'],
                'feature_dim': len(sample['feature_vector']),
                'vector_norm': float(np.linalg.norm(sample['feature_vector'])),
                'feature_stats': {
                    'mean': float(np.mean(sample['feature_vector'])),
                    'std': float(np.std(sample['feature_vector'])),
                    'min': float(np.min(sample['feature_vector'])),
                    'max': float(np.max(sample['feature_vector']))
                }
            }
            
            vectors_data.append(vector_record)
        
        # Save to JSON
        filepath = self.output_dir / 'ember_feature_vectors.json'
        with open(filepath, 'w') as f:
            json.dump(vectors_data, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated {len(vectors_data):,} vectorized feature records")
        print(f"    Saved to {filepath.name}")
        
        return vectors_data
    
    def generate_etp_input(self, feature_data, evolution_data, variants_data):
        """Convert to ETP input format"""
        print("\n[▶] Converting to ETP input format...")
        
        etp_input = {
            'threat_genomes': [],
            'evolution_markers': []
        }
        
        # Create threat genomes (base organisms)
        for sample in feature_data:
            genome = {
                'genome_id': sample['sha256'],
                'label': sample['label'],
                'family': sample['family'],
                'pe_characteristics': {
                    'sections': len(sample['sections']),
                    'entropy': sample['entropy_mean'],
                    'packing_score': sample['packing_score'],
                    'api_set': sample['imports']['libraries']
                },
                'feature_vector': sample['feature_vector'][:50]  # First 50 for summary
            }
            
            etp_input['threat_genomes'].append(genome)
        
        # Create evolution markers
        for evo in evolution_data:
            marker = {
                'family': evo['family'],
                'period': evo['period'],
                'evolution_metrics': {
                    'avg_entropy': evo['avg_entropy'],
                    'avg_packing': evo['avg_packing_score'],
                    'api_diversity': evo['avg_api_diversity'],
                    'mutation_rate': evo['mutation_rate']
                },
                'variants_detected': evo['variants']
            }
            
            etp_input['evolution_markers'].append(marker)
        
        # Save to JSON
        filepath = self.output_dir / 'etp_input_format.json'
        with open(filepath, 'w') as f:
            json.dump(etp_input, f, indent=2, cls=NumpyEncoder)
        
        print(f"[✓] Generated ETP input with {len(etp_input['threat_genomes']):,} threat genomes")
        print(f"    and {len(etp_input['evolution_markers']):,} evolution markers")
        print(f"    Saved to {filepath.name}")
        
        return etp_input


if __name__ == "__main__":
    generator = EMBERDataGenerator()
    feature_data = generator.generate_malware_features()
    evolution_data = generator.generate_family_evolution(feature_data)
    variants_data = generator.generate_threat_variants(feature_data)
    vectors_data = generator.generate_feature_vectors(feature_data)
    generator.generate_etp_input(feature_data, evolution_data, variants_data)
