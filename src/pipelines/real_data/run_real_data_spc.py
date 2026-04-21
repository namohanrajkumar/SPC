#!/usr/bin/env python3
"""
Full Real Data SPC Processing Pipeline
Uses actual data from Input/ folder and processes through SPC framework
Outputs results to Code1/livedataoutputs/real_data_results/
"""

import json
import sys
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
import time

class RealDataSPCProcessor:
    """Process full real data through SPC framework"""
    
    def __init__(self):
        self.base_path = Path('/Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype')
        self.input_dir = self.base_path / 'Input'
        self.output_dir = self.base_path / 'Output'
        self.code_dir = self.base_path / 'Code1'
        self.results_dir = self.base_path / 'Code1/livedataoutputs/real_data_results'
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Create fresh Input directory in Code1 for SPC
        self.spc_input_dir = self.code_dir / 'Input'
        if self.spc_input_dir.exists():
            shutil.rmtree(self.spc_input_dir)
        self.spc_input_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[✓] Base paths configured:")
        print(f"    Input data: {self.input_dir}")
        print(f"    SPC Input: {self.spc_input_dir}")
        print(f"    Results: {self.results_dir}")
    
    def copy_real_data_to_spc_input(self):
        """Copy all real input data to Code1/Input for SPC processing"""
        print("\n" + "="*80)
        print("COPYING REAL DATA TO SPC FRAMEWORK")
        print("="*80)
        
        # List of input files
        input_files = [
            'MSBB_CellularScaleProcess-LevelData.json',
            'MSBB_TissueScaleHost-LevelData.json',
            'MSBB_OrganScaleNetworkSegmentData.json',
            'ETP_ThreatGenomeInputData.yaml',
            'ETP_DefensePostureInput.json',
            'QICE_Network_RealTime EventsStreamInputData.json',
            'QICE_Correlation Matrix Input.csv.txt',
            'QICE_Quantum State Parameters.json',
            'DDE_InitialDefense Genome PopulationDataInput.json',
            'DDE_ Historical Performance Data.json',
            'PSC_NetworkTopologyGraph.txt',
            'PSC_ContainmentOperationalConstraints.json',
            'PSC_ThreatPredictionInputVector.json',
            'Network Topology Graph.csv.txt'
        ]
        
        copied_count = 0
        for filename in input_files:
            src = self.input_dir / filename
            if src.exists():
                dst = self.spc_input_dir / filename
                shutil.copy2(src, dst)
                file_size = src.stat().st_size
                print(f"[✓] {filename:50s} {file_size:>10,} bytes")
                copied_count += 1
            else:
                print(f"[⊘] {filename:50s} (not found)")
        
        print(f"\n[✓] Total files copied: {copied_count}")
        return copied_count
    
    def verify_input_data(self):
        """Verify and display input data summary"""
        print("\n" + "="*80)
        print("INPUT DATA VERIFICATION")
        print("="*80)
        
        data_summary = {}
        
        json_files = [
            'MSBB_CellularScaleProcess-LevelData.json',
            'MSBB_TissueScaleHost-LevelData.json',
            'MSBB_OrganScaleNetworkSegmentData.json',
            'ETP_DefensePostureInput.json',
            'QICE_Network_RealTime EventsStreamInputData.json',
            'QICE_Quantum State Parameters.json',
            'DDE_InitialDefense Genome PopulationDataInput.json',
            'DDE_ Historical Performance Data.json',
            'PSC_ThreatPredictionInputVector.json'
        ]
        
        total_records = 0
        for filename in json_files:
            filepath = self.spc_input_dir / filename
            if filepath.exists():
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    if isinstance(data, list):
                        record_count = len(data)
                    elif isinstance(data, dict):
                        record_count = len(data)
                    else:
                        record_count = 1
                    
                    total_records += record_count
                    data_summary[filename] = record_count
                    print(f"[✓] {filename:50s} {record_count:>6,} records")
                except Exception as e:
                    print(f"[✗] {filename:50s} Error: {str(e)}")
        
        print(f"\n[✓] Total records to process: {total_records:,}")
        return data_summary
    
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
        print(f"    Working directory: {self.code_dir}")
        
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
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': execution_time
            }
            
        except subprocess.TimeoutExpired:
            print("[✗] ERROR: SPC execution timed out (>600 seconds)")
            return None
        except Exception as e:
            print(f"[✗] ERROR: {str(e)}")
            return None
    
    def collect_outputs(self):
        """Collect all SPC component outputs"""
        print("\n" + "="*80)
        print("COLLECTING SPC COMPONENT OUTPUTS")
        print("="*80)
        
        outputs = {}
        output_files = {
            'MSBB_output': 'MSBB_output.json',
            'QICE_output': 'QICE_output.json',
            'ETP_output': 'ETP_output.json',
            'DDE_output': 'DDE_output.json',
            'PSC_output': 'PSC_output.json',
            'SPC_Summary': 'SPC_Summary.json',
        }
        
        print(f"\n[✓] Looking for outputs in {self.code_dir}/Output/")
        
        for component_name, filename in output_files.items():
            filepath = self.code_dir / 'Output' / filename
            if filepath.exists():
                try:
                    with open(filepath, 'r') as f:
                        outputs[component_name] = json.load(f)
                    
                    # Get file size
                    file_size = filepath.stat().st_size
                    
                    # Count records if it's a list
                    if isinstance(outputs[component_name], list):
                        record_count = len(outputs[component_name])
                        print(f"[✓] {filename:40s} {file_size:>10,} bytes ({record_count:,} records)")
                    else:
                        print(f"[✓] {filename:40s} {file_size:>10,} bytes")
                    
                except Exception as e:
                    print(f"[✗] {filename:40s} Error: {str(e)}")
            else:
                print(f"[⊘] {filename:40s} (Not generated)")
        
        return outputs
    
    def save_outputs_to_results(self, outputs):
        """Save collected outputs to results directory"""
        print("\n" + "="*80)
        print("SAVING RESULTS TO LIVEDATAOUTPUTS")
        print("="*80)
        
        saved_files = []
        
        for component_name, component_output in outputs.items():
            filename = f"{component_name}.json"
            filepath = self.results_dir / filename
            
            try:
                with open(filepath, 'w') as f:
                    json.dump(component_output, f, indent=2)
                
                file_size = filepath.stat().st_size
                print(f"[✓] Saved {component_name:30s} to {filepath.name:30s} ({file_size:>10,} bytes)")
                saved_files.append(str(filepath))
                
            except Exception as e:
                print(f"[✗] Failed to save {component_name}: {str(e)}")
        
        return saved_files
    
    def generate_summary_report(self, data_summary, outputs, execution_result):
        """Generate comprehensive summary report"""
        print("\n" + "="*80)
        print("GENERATING SUMMARY REPORT")
        print("="*80)
        
        report = {
            'pipeline': 'Real Data SPC Processing',
            'timestamp': datetime.now().isoformat(),
            'execution': {
                'status': 'success' if execution_result and execution_result['returncode'] == 0 else 'completed_with_warnings',
                'execution_time_seconds': execution_result['execution_time'] if execution_result else None,
                'return_code': execution_result['returncode'] if execution_result else None
            },
            'input_data': {
                'source': str(self.input_dir),
                'total_files': len(data_summary),
                'total_records': sum(data_summary.values()),
                'file_breakdown': data_summary
            },
            'output_components': {}
        }
        
        # Analyze each component output
        for component_name, component_output in outputs.items():
            if component_output:
                if isinstance(component_output, list):
                    record_count = len(component_output)
                    report['output_components'][component_name] = {
                        'status': 'generated',
                        'record_count': record_count,
                        'first_record_sample': component_output[0] if component_output else None
                    }
                elif isinstance(component_output, dict):
                    report['output_components'][component_name] = {
                        'status': 'generated',
                        'keys': list(component_output.keys()),
                        'sample': {k: component_output[k] for k in list(component_output.keys())[:3]}
                    }
        
        # Save report
        report_path = self.results_dir / 'REAL_DATA_SUMMARY_REPORT.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[✓] Summary report saved to {report_path}")
        
        # Also save as markdown for readability
        md_path = self.results_dir / 'REAL_DATA_SUMMARY_REPORT.md'
        with open(md_path, 'w') as f:
            f.write("# Real Data SPC Processing Report\n\n")
            f.write(f"**Pipeline**: {report['pipeline']}\n")
            f.write(f"**Timestamp**: {report['timestamp']}\n")
            f.write(f"**Status**: {report['execution']['status']}\n")
            f.write(f"**Execution Time**: {report['execution']['execution_time_seconds']:.2f} seconds\n\n")
            
            f.write("## Input Data\n")
            f.write(f"- **Source**: {report['input_data']['source']}\n")
            f.write(f"- **Total Files**: {report['input_data']['total_files']}\n")
            f.write(f"- **Total Records**: {report['input_data']['total_records']:,}\n\n")
            
            f.write("### Input File Breakdown\n")
            f.write("| File | Records |\n")
            f.write("|------|----------|\n")
            for filename, count in report['input_data']['file_breakdown'].items():
                f.write(f"| {filename} | {count:,} |\n")
            
            f.write("\n## Output Components\n")
            for component, info in report['output_components'].items():
                f.write(f"- **{component}**: {info['status']}\n")
                if 'record_count' in info:
                    f.write(f"  - Records: {info['record_count']:,}\n")
                if 'keys' in info:
                    f.write(f"  - Keys: {', '.join(info['keys'][:5])}\n")
        
        print(f"[✓] Markdown report saved to {md_path}")
        
        return report
    
    def run_pipeline(self):
        """Execute complete pipeline"""
        print("\n")
        print("█" * 80)
        print("█" + " " * 78 + "█")
        print("█" + " " * 15 + "REAL DATA SPC PROCESSING PIPELINE" + " " * 30 + "█")
        print("█" + " " * 78 + "█")
        print("█" * 80)
        
        # Step 1: Copy real data
        copied = self.copy_real_data_to_spc_input()
        if copied == 0:
            print("\n[✗] ERROR: No input files could be copied")
            return
        
        # Step 2: Verify input data
        data_summary = self.verify_input_data()
        
        # Step 3: Run SPC framework
        execution_result = self.run_spc_framework()
        
        # Step 4: Collect outputs
        outputs = self.collect_outputs()
        
        # Step 5: Save to results directory
        self.save_outputs_to_results(outputs)
        
        # Step 6: Generate summary report
        report = self.generate_summary_report(data_summary, outputs, execution_result)
        
        # Final summary
        print("\n" + "="*80)
        print("PIPELINE COMPLETION SUMMARY")
        print("="*80)
        print(f"\n[✓] Input files processed: {report['input_data']['total_files']}")
        print(f"[✓] Total input records: {report['input_data']['total_records']:,}")
        print(f"[✓] Output components generated: {len(report['output_components'])}")
        print(f"[✓] Execution time: {report['execution']['execution_time_seconds']:.2f} seconds")
        print(f"[✓] Results directory: {self.results_dir}/")
        
        print("\n📊 Generated Output Files:")
        for filename in os.listdir(self.results_dir):
            if filename.endswith('.json') or filename.endswith('.md'):
                filepath = self.results_dir / filename
                size = filepath.stat().st_size
                print(f"  • {filename:40s} ({size:>10,} bytes)")
        
        print("\n" + "="*80)
        print("✓ REAL DATA SPC PROCESSING COMPLETED SUCCESSFULLY")
        print("="*80 + "\n")


if __name__ == "__main__":
    processor = RealDataSPCProcessor()
    processor.run_pipeline()
