"""
Main executable script for SPC Framework

Usage:
    python3 main.py
"""

import sys
import yaml
from pathlib import Path

# Add source to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.orchestrator import SPCOrchestrator


def load_config(config_path: str = 'src/config/spc_config.yaml') -> dict:
    """Load SPC configuration"""
    config_file = Path(config_path)
    
    if not config_file.exists():
        print(f"Note: Config file not found at {config_path}, using defaults")
        return get_default_config()
    
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"Note: Could not load config file ({e}), using defaults")
        return get_default_config()
    
    # Add default paths
    config['input_path'] = config.get('input_path', 'Input')
    config['output_path'] = config.get('output_path', 'Output')
    
    return config


def get_default_config() -> dict:
    """Get default configuration"""
    return {
        'input_path': 'Input',
        'output_path': 'Output',
        'msbb': {
            'autoencoder_dim': 128,
            'isolation_contamination': 0.1,
            'anomaly_threshold': 0.85,
            'learning_rate': 0.001,
            'training_epochs': 100
        },
        'etp': {
            'population_size': 100,
            'mutation_rate': 0.1,
            'crossover_rate': 0.8,
            'generations': 25,
            'elitism_count': 5
        },
        'qice': {
            'attention_heads': 8,
            'hidden_dim': 64,
            'correlation_threshold': 0.7,
            'learning_rate': 0.01,
            'training_epochs': 100
        },
        'dde': {
            'population_size': 50,
            'elitism_rate': 0.2,
            'mutation_strength': 0.1,
            'generations': 25,
            'fitness_weights': {
                'success': 0.7,
                'cost': 0.2,
                'speed': 0.1
            }
        },
        'psc': {
            'min_cut_algorithm': 'edmonds_karp',
            'containment_verification': True,
            'fallback_expansion': True
        }
    }


def main():
    """Main execution function"""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "STATEFUL PROPAGATION CONTAINMENT (SPC)" + " "*15 + "║")
    print("║" + " "*18 + "Bio-Inspired Cyber Threat Detection" + " "*16 + "║")
    print("║" + " "*23 + "Research Prototype v1.0" + " "*21 + "║")
    print("╚" + "="*68 + "╝")
    
    try:
        # Load configuration
        config = load_config()
        
        # Create orchestrator
        orchestrator = SPCOrchestrator(config)
        
        # Initialize components
        if not orchestrator.initialize():
            print("\n⚠ Note: Some components initialized with minimal data.")
            print("  This is expected when running without the full Input dataset.")
        
        # Run security cycle
        print("\n" + "="*70)
        results = orchestrator.run_security_cycle()
        
        # Finalize
        orchestrator.finalize()
        
        print("\n✓ SPC Prototype execution completed successfully!")
        print("✓ Check the Output/ directory for detailed component results:")
        print("  - DDE_output.json       : Defense evolution results")
        print("  - ETP_output.json       : Threat prediction variants")
        print("  - QICE_output.json      : Event correlation clusters")
        print("  - MSSB_*.json           : Behavioral anomaly analysis")
        print("  - PSC_output.json       : Containment strategies")
        print("  - SPC_Summary.json      : Execution summary")
        print("\n")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n✗ Execution interrupted by user")
        return 130
    except Exception as e:
        print(f"\n✗ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
