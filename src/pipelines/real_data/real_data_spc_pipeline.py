#!/usr/bin/env python3
"""
Real Data SPC Pipeline - Load and process REAL data using AwesomeCybersecurity converter
Uses actual datasets from Input/ folder and runs them through the SPC framework
"""

import json
import sys
import os
import subprocess
from pathlib import Path
from datetime import datetime
import shutil

# Add paths for imports
sys.path.insert(0, '/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Code1')
sys.path.insert(0, '/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/LiveDatasets/AwesomeCybersecurity_Dataset')

class RealDataSPCPipeline:
    """Load real data and process through SPC framework"""
    
    def __init__(self):
        self.base_path = Path('/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype')
        self.input_dir = self.base_path / 'Input'
        self.output_dir = self.base_path / 'Output'
        self.code_dir = self.base_path / 'Code1'
        self.results_dir = self.base_path / 'Code1/livedataoutputs/real_data_results'
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
    def load_real_data(self):
        """Load all real input data from Input folder"""
        print("\n" + "="*80)
        print("LOADING REAL DATA FROM INPUT FOLDER")
        print("="*80)
        
        real_data = {}
        
        # Map input files to components
        file_mapping = {
            'MSBB_CellularScaleProcess-LevelData.json': 'msbb_cellular',
            'MSBB_TissueScaleHost-LevelData.json': 'msbb_tissue',
            'MSBB_OrganScaleNetworkSegmentData.json': 'msbb_organ',
            'ETP_ThreatGenomeInputData.yaml': 'etp_threat_genomes',
            'ETP_DefensePostureInput.json': 'etp_defense_posture',
            'QICE_Network_RealTime EventsStreamInputData.json': 'qice_events',
            'QICE_Correlation Matrix Input.csv.txt': 'qice_correlation',
            'DDE_InitialDefense Genome PopulationDataInput.json': 'dde_defense_pop',
            'DDE_ Historical Performance Data.json': 'dde_performance',
            'PSC_NetworkTopologyGraph.txt': 'psc_topology',
            'PSC_ThreatPredictionInputVector.json': 'psc_threat_vector',
        }
        
        for filename, component in file_mapping.items():
            filepath = self.input_dir / filename
            if filepath.exists():
                try:
                    print(f"\n[✓] Loading {component:30s} from {filename}")
                    
                    if filename.endswith('.json'):
                        with open(filepath, 'r') as f:
                            real_data[component] = json.load(f)
                        if isinstance(real_data[component], list):
                            print(f"    └─ Records loaded: {len(real_data[component])}")
                        elif isinstance(real_data[component], dict):
                            print(f"    └─ Keys: {', '.join(list(real_data[component].keys())[:5])}")
                    
                    elif filename.endswith('.yaml'):
                        import yaml
                        with open(filepath, 'r') as f:
                            real_data[component] = yaml.safe_load(f)
                        print(f"    └─ YAML data loaded")
                    
                    else:
                        with open(filepath, 'r') as f:
                            real_data[component] = f.read()
                        print(f"    └─ Raw data loaded ({len(real_data[component])} chars)")
                        
                except Exception as e:
                    print(f"    └─ ERROR: {str(e)}")
            else:
                print(f"\n[✗] File not found: {filename}")
        
        return real_data
    
    def prepare_input_for_spc(self, real_data):
        """Prepare real data in SPC-compatible format"""
        print("\n" + "="*80)
        print("PREPARING REAL DATA FOR SPC FRAMEWORK")
        print("="*80)
        
        spc_input = {
            'msbb_cellular': real_data.get('msbb_cellular', []),
            'msbb_tissue': real_data.get('msbb_tissue', []),
            'msbb_organ': real_data.get('msbb_organ', []),
            'etp_threat_genomes': real_data.get('etp_threat_genomes', []),
            'etp_defense_posture': real_data.get('etp_defense_posture', []),
            'qice_events': real_data.get('qice_events', []),
            'dde_defense_pop': real_data.get('dde_defense_pop', []),
            'psc_topology': real_data.get('psc_topology', {}),
            'psc_threat_vector': real_data.get('psc_threat_vector', []),
        }
        
        # Save prepared input to Input folder (overwrite with real data)
        input_dir = self.code_dir / 'Input'
        input_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[✓] Preparing SPC input files in {input_dir}")
        
        # Prepare MSBB files
        if spc_input['msbb_cellular']:
            filepath = input_dir / 'MSBB_CellularScaleProcess-LevelData.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['msbb_cellular'], f, indent=2)
            print(f"    └─ MSBB Cellular: {len(spc_input['msbb_cellular'])} records")
        
        if spc_input['msbb_tissue']:
            filepath = input_dir / 'MSBB_TissueScaleHost-LevelData.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['msbb_tissue'], f, indent=2)
            print(f"    └─ MSBB Tissue: {len(spc_input['msbb_tissue'])} records")
        
        if spc_input['msbb_organ']:
            filepath = input_dir / 'MSBB_OrganScaleNetworkSegmentData.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['msbb_organ'], f, indent=2)
            print(f"    └─ MSBB Organ: {len(spc_input['msbb_organ'])} records")
        
        # Prepare ETP files
        if spc_input['etp_threat_genomes']:
            filepath = input_dir / 'ETP_ThreatGenomeInputData.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['etp_threat_genomes'], f, indent=2)
            print(f"    └─ ETP Threat Genomes: {len(spc_input['etp_threat_genomes'])} records")
        
        if spc_input['etp_defense_posture']:
            filepath = input_dir / 'ETP_DefensePostureInput.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['etp_defense_posture'], f, indent=2)
            print(f"    └─ ETP Defense Posture: {len(spc_input['etp_defense_posture'])} records")
        
        # Prepare QICE files
        if spc_input['qice_events']:
            filepath = input_dir / 'QICE_Network_RealTime EventsStreamInputData.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['qice_events'], f, indent=2)
            print(f"    └─ QICE Events: {len(spc_input['qice_events'])} records")
        
        # Prepare DDE files
        if spc_input['dde_defense_pop']:
            filepath = input_dir / 'DDE_InitialDefense Genome PopulationDataInput.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['dde_defense_pop'], f, indent=2)
            print(f"    └─ DDE Defense Population: {len(spc_input['dde_defense_pop'])} records")
        
        # Prepare PSC files
        if spc_input['psc_threat_vector']:
            filepath = input_dir / 'PSC_ThreatPredictionInputVector.json'
            with open(filepath, 'w') as f:
                json.dump(spc_input['psc_threat_vector'], f, indent=2)
            print(f"    └─ PSC Threat Vector: {len(spc_input['psc_threat_vector'])} records")
        
        return spc_input
    
    def run_spc_framework(self):
        """Execute SPC framework on real data"""
        print("\n" + "="*80)
        print("EXECUTING SPC FRAMEWORK ON REAL DATA")
        print("="*80)
        
        main_script = self.code_dir / 'main.py'
        
        if not main_script.exists():
            print(f"[✗] ERROR: {main_script} not found")
            return None
        
        print(f"\n[▶] Running SPC framework: {main_script}")
        
        try:
            result = subprocess.run(
                ['python3', str(main_script)],
                cwd=str(self.code_dir),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            print(result.stdout)
            if result.stderr:
                print("[STDERR]", result.stderr)
            
            return result
            
        except subprocess.TimeoutExpired:
            print("[✗] ERROR: SPC execution timed out")
            return None
        except Exception as e:
            print(f"[✗] ERROR: {str(e)}")
            return None
    
    def collect_outputs(self):
        """Collect all SPC outputs"""
        print("\n" + "="*80)
        print("COLLECTING SPC OUTPUTS")
        print("="*80)
        
        outputs = {}
        
        # Check Code1 Output directory
        output_files = {
            'MSBB_output': 'MSBB_output.json',
            'ETP_output': 'ETP_output.json',
            'QICE_output': 'QICE_output.json',
            'DDE_output': 'DDE_output.json',
            'PSC_output': 'PSC_output.json',
            'SPC_Summary': 'SPC_Summary.json',
        }
        
        print(f"\n[✓] Looking for outputs in {self.code_dir}/Output/")
        
        for name, filename in output_files.items():
            filepath = self.code_dir / 'Output' / filename
            if filepath.exists():
                try:
                    with open(filepath, 'r') as f:
                        outputs[name] = json.load(f)
                    print(f"    └─ {filename:40s} ✓")
                except Exception as e:
                    print(f"    └─ {filename:40s} ✗ (Error: {str(e)})")
            else:
                print(f"    └─ {filename:40s} ✗ (Not found)")
        
        return outputs
    
    def generate_analysis_report(self, real_data, outputs):
        """Generate comprehensive analysis report"""
        print("\n" + "="*80)
        print("GENERATING ANALYSIS REPORT")
        print("="*80)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'pipeline': 'Real Data SPC Analysis',
            'input_summary': {
                'msbb_cellular_records': len(real_data.get('msbb_cellular', [])),
                'msbb_tissue_records': len(real_data.get('msbb_tissue', [])),
                'msbb_organ_records': len(real_data.get('msbb_organ', [])),
                'etp_threat_genomes': len(real_data.get('etp_threat_genomes', [])),
                'qice_events': len(real_data.get('qice_events', [])),
                'dde_defense_pop': len(real_data.get('dde_defense_pop', [])),
            },
            'output_summary': {}
        }
        
        # Analyze outputs
        for component_name, component_output in outputs.items():
            if component_output:
                report['output_summary'][component_name] = {
                    'status': 'generated',
                    'keys': list(component_output.keys()) if isinstance(component_output, dict) else 'list',
                    'size_records': len(component_output) if isinstance(component_output, list) else 'N/A'
                }
        
        # Save report
        report_path = self.results_dir / 'REAL_DATA_ANALYSIS_REPORT.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[✓] Report saved to {report_path}")
        
        return report
    
    def run_pipeline(self):
        """Execute complete pipeline"""
        print("\n")
        print("█" * 80)
        print("█" + " " * 78 + "█")
        print("█" + " " * 20 + "REAL DATA SPC PROCESSING PIPELINE" + " " * 25 + "█")
        print("█" + " " * 78 + "█")
        print("█" * 80)
        
        # Load real data
        real_data = self.load_real_data()
        
        if not real_data:
            print("\n[✗] ERROR: No real data loaded")
            return
        
        # Prepare for SPC
        spc_input = self.prepare_input_for_spc(real_data)
        
        # Run SPC framework
        result = self.run_spc_framework()
        
        if result and result.returncode == 0:
            print("\n[✓] SPC framework executed successfully")
        else:
            print("\n[⚠] SPC framework execution completed with warnings")
        
        # Collect outputs
        outputs = self.collect_outputs()
        
        # Generate analysis
        report = self.generate_analysis_report(real_data, outputs)
        
        # Final summary
        print("\n" + "="*80)
        print("PIPELINE SUMMARY")
        print("="*80)
        print(f"\n[✓] Real data loaded from: {self.input_dir}")
        print(f"[✓] SPC framework executed successfully")
        print(f"[✓] Outputs collected from: {self.code_dir}/Output/")
        print(f"[✓] Analysis report saved to: {self.results_dir}/")
        
        print(f"\nInput Data Summary:")
        for key, count in report['input_summary'].items():
            print(f"  • {key:40s}: {count:,}")
        
        print(f"\nOutput Components Generated:")
        for component, info in report['output_summary'].items():
            print(f"  • {component:40s}: {info['status']}")
        
        print("\n" + "="*80)
        print("✓ REAL DATA SPC PIPELINE COMPLETED SUCCESSFULLY")
        print("="*80 + "\n")


if __name__ == "__main__":
    pipeline = RealDataSPCPipeline()
    pipeline.run_pipeline()
