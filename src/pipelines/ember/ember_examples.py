#!/usr/bin/env python3
"""
EMBER SPC Pipeline - Usage Examples
Demonstrates various ways to use the EMBER dataset generation and SPC processing pipeline
"""

import sys
import json
from pathlib import Path

# Add Code1 to path for imports
sys.path.insert(0, '/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Code1')

from ember_spc_pipeline import EMBERDataGenerator, EMBERSPCProcessor, NumpyEncoder


def example_1_basic_generation():
    """Example 1: Basic EMBER data generation"""
    print("\n" + "="*80)
    print("EXAMPLE 1: BASIC EMBER DATA GENERATION")
    print("="*80)
    
    print("\n[✓] Creating EMBER generator with default parameters...")
    
    # Create generator with default parameters
    generator = EMBERDataGenerator(
        num_samples=1000,      # Generate 1000 samples
        num_features=50,       # 50-dimensional feature vectors
        malware_ratio=0.5      # 50% malware, 50% benign
    )
    
    print("\n[✓] Generating malware features...")
    features = generator.generate_malware_features()
    
    # Show sample statistics
    malware_count = sum(1 for f in features if f['label'] == 1)
    families = set(f['family'] for f in features if f['label'] == 1)
    
    print(f"\n[✓] Sample Summary:")
    print(f"    Total samples: {len(features)}")
    print(f"    Malware: {malware_count}")
    print(f"    Benign: {len(features) - malware_count}")
    print(f"    Families: {len(families)} ({', '.join(sorted(families))})")
    
    # Display first record
    print(f"\n[✓] First record sample:")
    print(json.dumps(features[0], indent=2, cls=NumpyEncoder)[:500] + "...")
    
    return features


def example_2_family_evolution_analysis():
    """Example 2: Analyze family evolution patterns"""
    print("\n" + "="*80)
    print("EXAMPLE 2: FAMILY EVOLUTION ANALYSIS")
    print("="*80)
    
    # Generate base data
    print("\n[✓] Generating data...")
    generator = EMBERDataGenerator(num_samples=2000, num_features=50, malware_ratio=0.6)
    features = generator.generate_malware_features()
    
    # Generate family evolution
    print("[✓] Analyzing family evolution...")
    evolution = generator.generate_family_evolution(features)
    
    # Group by family
    from collections import defaultdict
    families = defaultdict(list)
    for evo in evolution:
        families[evo['family']].append(evo)
    
    print(f"\n[✓] Family Evolution Summary:")
    print(f"    Total families: {len(families)}")
    
    for family in sorted(families.keys()):
        records = families[family]
        print(f"\n    {family}:")
        print(f"        Periods tracked: {len(records)}")
        print(f"        Total samples: {sum(r['sample_count'] for r in records)}")
        print(f"        Avg entropy: {sum(r['avg_entropy'] for r in records)/len(records):.2f}")
        print(f"        Variants: {sum(r['variants'] for r in records)}")
        print(f"        Mutation rate: {sum(r['mutation_rate'] for r in records)/len(records):.3f}")
    
    return features, evolution


def example_3_threat_variant_tracking():
    """Example 3: Track threat variant mutations"""
    print("\n" + "="*80)
    print("EXAMPLE 3: THREAT VARIANT TRACKING AND MUTATIONS")
    print("="*80)
    
    # Generate data
    print("\n[✓] Generating malware samples...")
    generator = EMBERDataGenerator(num_samples=1500, num_features=50, malware_ratio=0.7)
    features = generator.generate_malware_features()
    
    print("[✓] Tracking variant mutations...")
    variants = generator.generate_threat_variants(features)
    
    # Analyze variant chains
    from collections import defaultdict
    variant_chains = defaultdict(list)
    for var in variants:
        variant_chains[var['family']].append(var)
    
    print(f"\n[✓] Variant Analysis:")
    print(f"    Total variants: {len(variants)}")
    
    for family in sorted(variant_chains.keys())[:3]:  # Show top 3 families
        chain = sorted(variant_chains[family], key=lambda x: x['generation'])
        print(f"\n    {family} evolution chain:")
        print(f"        Generations tracked: {len(chain)}")
        print(f"        Generation range: 1-{max(v['generation'] for v in chain)}")
        
        # Show changes across generations
        if len(chain) > 1:
            first_gen = chain[0]['feature_changes']
            latest_gen = chain[-1]['feature_changes']
            print(f"        Entropy evolution:")
            print(f"            First gen change: {first_gen['entropy_change']:+.2f}")
            print(f"            Latest gen change: {latest_gen['entropy_change']:+.2f}")
    
    return features, variants


def example_4_feature_vector_analysis():
    """Example 4: ML-ready feature vector generation and analysis"""
    print("\n" + "="*80)
    print("EXAMPLE 4: FEATURE VECTOR ANALYSIS FOR ML")
    print("="*80)
    
    # Generate data
    print("\n[✓] Generating feature vectors...")
    generator = EMBERDataGenerator(num_samples=1000, num_features=100, malware_ratio=0.5)
    features = generator.generate_malware_features()
    vectors = generator.generate_feature_vectors(features)
    
    print(f"\n[✓] Feature Vector Statistics:")
    print(f"    Total vectors: {len(vectors)}")
    print(f"    Feature dimension: {vectors[0]['feature_dim']}")
    
    # Analyze feature statistics
    import numpy as np
    
    malware_vectors = [v['features'] for v in vectors if v['label'] == 1]
    benign_vectors = [v['features'] for v in vectors if v['label'] == 0]
    
    if malware_vectors and benign_vectors:
        malware_mean = np.mean(malware_vectors)
        benign_mean = np.mean(benign_vectors)
        
        print(f"\n    Malware vectors ({len(malware_vectors)}):")
        print(f"        Mean feature value: {malware_mean:.4f}")
        print(f"        Std deviation: {np.std(malware_vectors):.4f}")
        print(f"        Min: {np.min(malware_vectors):.4f}")
        print(f"        Max: {np.max(malware_vectors):.4f}")
        
        print(f"\n    Benign vectors ({len(benign_vectors)}):")
        print(f"        Mean feature value: {benign_mean:.4f}")
        print(f"        Std deviation: {np.std(benign_vectors):.4f}")
        print(f"        Min: {np.min(benign_vectors):.4f}")
        print(f"        Max: {np.max(benign_vectors):.4f}")
        
        print(f"\n    Feature separation (L2 distance):")
        print(f"        Malware vs Benign: {abs(malware_mean - benign_mean):.4f}")
    
    return vectors


def example_5_spc_full_pipeline():
    """Example 5: Full EMBER to SPC processing pipeline"""
    print("\n" + "="*80)
    print("EXAMPLE 5: FULL EMBER TO SPC PIPELINE EXECUTION")
    print("="*80)
    
    # Step 1: Generate EMBER data
    print("\n[STEP 1] Generating EMBER data...")
    generator = EMBERDataGenerator(num_samples=2000, num_features=100, malware_ratio=0.5)
    features = generator.generate_malware_features()
    evolution = generator.generate_family_evolution(features)
    variants = generator.generate_threat_variants(features)
    vectors = generator.generate_feature_vectors(features)
    etp_input = generator.generate_etp_input(features, evolution, variants)
    
    print(f"[✓] Generated {len(features):,} samples across {len(evolution)} evolution records")
    
    # Step 2: Process through SPC
    print("\n[STEP 2] Processing through SPC framework...")
    processor = EMBERSPCProcessor()
    
    data = processor.prepare_spc_input()
    print("[✓] SPC input files prepared")
    
    result = processor.run_spc()
    if result:
        print(f"[✓] SPC execution completed in {result['execution_time']:.2f} seconds")
    
    # Step 3: Collect outputs
    print("\n[STEP 3] Collecting outputs...")
    saved = processor.collect_and_save_outputs()
    print(f"[✓] {saved} output files saved")
    
    # Summary
    print("\n[✓] FULL PIPELINE COMPLETE")
    print(f"    Data location: /Code1/livedataoutputs/emberdata/")
    print(f"    Results location: /Code1/livedataoutputs/ember_outputs/")


def example_6_comparative_analysis():
    """Example 6: Compare different malware family characteristics"""
    print("\n" + "="*80)
    print("EXAMPLE 6: COMPARATIVE MALWARE FAMILY ANALYSIS")
    print("="*80)
    
    # Generate data with higher malware ratio for better family coverage
    print("\n[✓] Generating data with focus on families...")
    generator = EMBERDataGenerator(num_samples=3000, num_features=50, malware_ratio=0.8)
    features = generator.generate_malware_features()
    
    # Extract malware only
    malware_only = [f for f in features if f['label'] == 1]
    
    # Group by family
    from collections import defaultdict
    by_family = defaultdict(list)
    for sample in malware_only:
        by_family[sample['family']].append(sample)
    
    print(f"\n[✓] Family Characteristics:")
    print(f"    Total families: {len(by_family)}")
    
    # Analyze each family
    import numpy as np
    for family in sorted(by_family.keys()):
        samples = by_family[family]
        entropies = [s['entropy_mean'] for s in samples]
        packings = [s['packing_score'] for s in samples]
        apis = [s['api_diversity'] for s in samples]
        
        print(f"\n    {family} ({len(samples)} samples):")
        print(f"        Entropy: {np.mean(entropies):.2f} ± {np.std(entropies):.2f}")
        print(f"        Packing: {np.mean(packings):.2f} ± {np.std(packings):.2f}")
        print(f"        API Diversity: {np.mean(apis):.2f} ± {np.std(apis):.2f}")
        print(f"        Sections avg: {np.mean([len(s['sections']) for s in samples]):.1f}")


def example_7_custom_scale_analysis():
    """Example 7: Analyze data at different SPC scales"""
    print("\n" + "="*80)
    print("EXAMPLE 7: MULTI-SCALE ANALYSIS")
    print("="*80)
    
    # Generate data
    print("\n[✓] Generating data...")
    generator = EMBERDataGenerator(num_samples=2000, num_features=50, malware_ratio=0.5)
    features = generator.generate_malware_features()
    
    print("\n[✓] Analyzing at different scales:")
    
    # Quantum scale (individual features)
    print("\n    QUANTUM SCALE (individual PE features):")
    sample = features[0]
    print(f"        PE sections: {len(sample['sections'])}")
    print(f"        Imports: {len(sample['imports']['libraries'])}")
    print(f"        Feature vector dim: {len(sample['feature_vector'])}")
    
    # Cellular scale (process/behavioral level)
    print("\n    CELLULAR SCALE (process-level behavior):")
    api_counts = [f['imports']['api_count'] for f in features]
    import numpy as np
    print(f"        Average APIs per sample: {np.mean(api_counts):.1f}")
    print(f"        API count range: {np.min(api_counts)}-{np.max(api_counts)}")
    
    # Tissue scale (host-level aggregation)
    print("\n    TISSUE SCALE (host-level aggregation):")
    entropy_values = [f['entropy_mean'] for f in features]
    print(f"        Average entropy: {np.mean(entropy_values):.2f}")
    print(f"        Entropy distribution: {np.std(entropy_values):.2f}")
    
    # Organ scale (family characteristics)
    print("\n    ORGAN SCALE (family-level characteristics):")
    from collections import defaultdict
    by_family = defaultdict(list)
    for f in features:
        if f['label'] == 1:
            by_family[f['family']].append(f)
    print(f"        Families identified: {len(by_family)}")
    print(f"        Avg samples per family: {np.mean([len(v) for v in by_family.values()]):.1f}")
    
    # Organism scale (ecosystem level)
    print("\n    ORGANISM SCALE (ecosystem-level patterns):")
    evolution = generator.generate_family_evolution(features)
    print(f"        Evolution periods: {len(evolution)}")
    print(f"        Mutation tracking: Yes")


def main():
    """Run all examples"""
    import argparse
    
    parser = argparse.ArgumentParser(description='EMBER SPC Pipeline Examples')
    parser.add_argument('--example', type=int, choices=[1,2,3,4,5,6,7,0],
                       help='Run specific example (1-7), or 0 for all')
    parser.add_argument('--quick', action='store_true', help='Run with smaller datasets')
    
    args = parser.parse_args()
    
    print("\n" + "█"*80)
    print("█" + " "*78 + "█")
    print("█" + " "*15 + "EMBER SPC PIPELINE - USAGE EXAMPLES DEMONSTRATION" + " "*14 + "█")
    print("█" + " "*78 + "█")
    print("█"*80)
    
    examples = {
        1: example_1_basic_generation,
        2: example_2_family_evolution_analysis,
        3: example_3_threat_variant_tracking,
        4: example_4_feature_vector_analysis,
        5: example_5_spc_full_pipeline,
        6: example_6_comparative_analysis,
        7: example_7_custom_scale_analysis,
    }
    
    # Run selected examples
    if args.example == 0 or args.example is None:
        # Run all
        for num in range(1, 8):
            try:
                examples[num]()
                print("\n[✓] Example completed\n")
            except Exception as e:
                print(f"\n[✗] Example failed: {str(e)}\n")
    else:
        # Run specific
        try:
            examples[args.example]()
            print("\n[✓] Example completed\n")
        except Exception as e:
            print(f"\n[✗] Example failed: {str(e)}\n")
    
    print("\n" + "█"*80)
    print("█" + " "*78 + "█")
    print("█" + " "*25 + "EXAMPLES DEMONSTRATION COMPLETE" + " "*22 + "█")
    print("█" + " "*78 + "█")
    print("█"*80 + "\n")


if __name__ == '__main__':
    main()
