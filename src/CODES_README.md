# Live Data Codes - Dataset Generators & SPC Processing Pipeline

This folder contains all the code files that generate the outputs stored in the `livedataoutputs` folder. The generators process various cybersecurity datasets through the **Stateful Propagation Containment (SPC) Framework**, producing multi-layered threat analysis outputs.

## Overview

The SPC Framework processes security datasets through 5 bio-inspired analysis layers:
- **DDE**: Defense Defense Emergence
- **ETP**: Evolutionary Threat Prediction  
- **MSBB**: Multi-Scale Bio-Behavioral
- **QICE**: Quantum Intelligence Correlation Engine
- **PSC**: Propagation and Security Containment

---

## Dataset Generators

### 1. **ADFA-IDS Dataset Generator**
**File:** `adfa_ids_generator.py`

**Dataset Description:**
- Australian Defence Force Academy Intrusion Detection System data
- Focused on behavioral analysis from system call traces
- Contains normal and attack scenarios

**How to Run:**
```bash
python adfa_ids_generator.py
```

**Output Location:** `../livedataoutputs/adfa_ids_data/` and `../livedataoutputs/adfa_ids_outputs/`

**Output Details:**
- `adfa_host_level_data.json` - Host-level behavioral metrics
- `adfa_network_segment_data.json` - Network segment analysis
- `adfa_process_level_traces.json` - Process-level call traces
- `DDE_output.json` - Defense Defense Emergence analysis
- `ETP_output.json` - Evolutionary threat predictions
- `MSBB_output.json` - Multi-scale bio-behavioral analysis
- `PSC_output.json` - Propagation containment strategies
- `QICE_output.json` - Quantum intelligence correlation

---

### 2. **CIC-IDS2017 (Canadian Institute for Cybersecurity)**
**File:** `cic_ids_generator.py`

**Dataset Description:**
- Traffic data from Canadian Institute for Cybersecurity
- Contains 11 types of network attacks
- Includes benign and malicious network flows

**How to Run:**
```bash
python cic_ids_generator.py
```

**Output Location:** `../livedataoutputs/canadian_data/` and `../livedataoutputs/canadian_outputs/`

**Output Details:**
- `cic_host_level_data.json` - Host-level metrics
- `cic_network_flows.json` - Network flow information
- `cic_network_segments.json` - Segmented network data
- `cic_threat_genomes.json` - Threat patterns
- `DDE_output.json`, `ETP_output.json`, `MSBB_output.json`, `PSC_output.json`, `QICE_output.json` - SPC framework outputs
- `CIC_IDS2017_SUMMARY.json` - Summary statistics

---

### 3. **EMBER (Endgame Malware BEnchmark for Research)**
**Files:** `ember_spc_pipeline.py`, `ember_config.py`, `ember_examples.py`

**Dataset Description:**
- Machine learning dataset for malware detection
- PE (Portable Executable) file features from Windows binaries
- 500,000 malware and 500,000 benign samples

**How to Run:**
```bash
python ember_spc_pipeline.py
```

**Output Location:** `../livedataoutputs/emberdata/` and `../livedataoutputs/ember_outputs/`

**Output Details:**
- `ember_feature_vectors.json` - Feature vector representation
- `ember_malware_features.json` - Malware-specific feature analysis
- `ember_family_evolution.json` - Malware family evolution tracking
- `ember_threat_variants.json` - Variant analysis
- `DDE_output.json`, `ETP_output.json`, `MSBB_output.json`, `PSC_output.json`, `QICE_output.json` - SPC outputs
- `EMBER_SUMMARY.json` - Analysis summary

---

### 4. **CESNET Dataset Generator**
**File:** `cesnet_spc_pipeline.py`

**Dataset Description:**
- Czech national research network security data
- Real-world network traffic with anonymized IP addresses
- Time-series anomaly data

**How to Run:**
```bash
python cesnet_spc_pipeline.py
```

**Output Location:** `../livedataoutputs/cesnetdata/` and `../livedataoutputs/cesnet_outputs/`

**Output Details:**
- `cesnet_anomalies.json` - Detected anomalies
- `cesnet_institution_data.json` - Institution-level metrics
- `cesnet_ip_timeseries.json` - Time-series flow data
- `cesnet_network_graph.json` - Network topology graph
- `psc_network_topology.json` - Network topology for PSC
- `DDE_output.json`, `ETP_output.json`, `PSC_output.json`, `QICE_output.json` - SPC outputs
- `CESNET_SUMMARY.json` - Summary report

---

### 5. **LANL (Los Alamos National Laboratory)**
**File:** `lanl_generator.py`

**Dataset Description:**
- Cyber-security data from Los Alamos National Laboratory
- Includes authentication events, process execution, and network flows
- Real enterprise network data

**How to Run:**
```bash
python lanl_generator.py
```

**Output Location:** `../livedataoutputs/losalamos_data/` and `../livedataoutputs/losalamos_outputs/`

**Output Details:**
- `lanl_attack_genomes.json` - Attack patterns identified
- `lanl_host_data.json` - Host-level data
- `lanl_network_flows.json` - Network flow data
- `lanl_process_events.json` - Process execution events
- `DDE_output.json`, `ETP_output.json`, `MSBB_output.json`, `PSC_output.json`, `QICE_output.json` - SPC outputs
- `LANL_SUMMARY.json` - Analysis summary

---

### 6. **MITRE ATT&CK Framework Dataset**
**File:** `mitre_spc_pipeline.py`

**Dataset Description:**
- Threat data mapped to MITRE ATT&CK techniques
- Real-world adversary tactics, techniques, and procedures
- Enterprise network attack scenarios

**How to Run:**
```bash
python mitre_spc_pipeline.py
```

**Output Location:** `../livedataoutputs/mitredata/` and `../livedataoutputs/mitre_outputs/`

**Output Details:**
- `mitre_campaigns.json` - Known campaigns
- `mitre_feature_vectors.json` - Feature vectors for attacks
- `mitre_techniques_mapping.json` - Technique mappings
- `DDE_output.json`, `ETP_output.json`, `MSBB_output.json`, `PSC_output.json`, `QICE_output.json` - SPC outputs
- `MITRE_SUMMARY.json` - Attack analysis summary

---

### 7. **NIST Dataset Generators**
**Files:** `nist_generator.py`, `nist_spc_pipeline.py`

**Dataset Description:**
- National Institute of Standards and Technology reference datasets
- Standardized cybersecurity benchmark data
- Vulnerability and threat information

**How to Run:**
```bash
python nist_generator.py
# OR
python nist_spc_pipeline.py
```

**Output Location:** `../livedataoutputs/nist_data/` and `../livedataoutputs/nist_outputs/`

**Output Details:**
- NIST vulnerability and threat assessment data
- `DDE_output.json`, `ETP_output.json`, `PSC_output.json`, `QICE_output.json` - SPC outputs
- `NIST_SUMMARY.json` - Assessment results

---

### 8. **AwesomeCybersecurity Dataset**
**File:** `awesomecyber_spc_pipeline.py`

**Dataset Description:**
- Curated threat intelligence from multiple public sources
- Domain intelligence and threat genome data
- Comprehensive security threat dataset

**How to Run:**
```bash
python awesomecyber_spc_pipeline.py
```

**Output Location:** `../livedataoutputs/awesome_data/` and `../livedataoutputs/awesome_outputs/`

**Output Details:**
- `awesome_host_level.json` - Host analysis
- `awesome_network_segment.json` - Network segments
- `awesome_process_level.json` - Process information
- `awesome_threat_genomes.json` - Threat classifications
- `awesome_domain_intelligence.json` - Domain threat intel
- `DDE_output.json`, `ETP_output.json`, `MSBB_output.json`, `PSC_output.json`, `QICE_output.json` - SPC outputs
- `AWESOME_SUMMARY.json` - Threat summary

---

### 9. **SecRepo Dataset Generator**
**File:** `secrepo_generator.py`

**Dataset Description:**
- Open-source security dataset from secrepo.com
- Legitimate and malicious traffic samples
- Various attack scenarios and payloads

**How to Run:**
```bash
python secrepo_generator.py
```

**Output Location:** `../livedataoutputs/secrepo_data/` and `../livedataoutputs/secrepo_outputs/`

**Output Details:**
- Security event data and analysis
- Various threat and attack patterns
- SPC framework analysis outputs

---

### 10. **ToN-IoT (Taxonomy of Network-based IoT intrusions) Dataset**
**Files:** `toniot_generator.py`, `toniot_generator_pipeline.py`, `toniot_spc_pipeline.py`

**Dataset Description:**
- Internet of Things (IoT) and Industrial IoT (IIoT) attack scenarios
- Real-world IoT device behaviors and anomalies
- Threat intelligence for smart devices

**How to Run:**
```bash
# Option 1: Basic generator
python toniot_generator.py

# Option 2: Generator pipeline
python toniot_generator_pipeline.py

# Option 3: SPC pipeline
python toniot_spc_pipeline.py
```

**Output Location:** `../livedataoutputs/toniot_data/` and `../livedataoutputs/toniot_output/`

**Output Details:**
- IoT device threat data and anomalies
- Network-based intrusion patterns
- SPC framework analysis of IoT threats

---

### 11. **Real Data SPC Pipeline**
**Files:** `real_data_spc_pipeline.py`, `run_real_data_spc.py`

**Dataset Description:**
- Production real-world security data
- Combined threat intelligence from multiple sources
- Live security events and patterns

**How to Run:**
```bash
# Option 1: Direct pipeline
python real_data_spc_pipeline.py

# Option 2: Run wrapper
python run_real_data_spc.py
```

**Output Location:** `../livedataoutputs/real_data_results/`

**Output Details:**
- Real-time threat analysis
- Multi-source correlation
- Actionable security intelligence

---

## SPC Framework Analysis Layers

Each dataset generates outputs from the following SPC components:

### **DDE (Defense Defense Emergence)**
- Simulates defense mechanisms
- Tracks defense strategy evolution
- Identifies optimal defense postures

### **ETP (Evolutionary Threat Prediction)**
- Predicts threat evolution patterns
- Evolves threat genomes across generations
- Identifies emerging threat variants

### **MSBB (Multi-Scale Bio-Behavioral)**
- Analyzes behavior at multiple scales (cell/tissue/organism equivalent)
- Autoencoder-based anomaly detection
- Health score computation

### **QICE (Quantum Intelligence Correlation Engine)**
- Correlates security events using quantum-inspired correlation
- Identifies complex event patterns
- Attention-weighted threat assessment

### **PSC (Propagation and Security Containment)**
- Computes network min-cut for containment
- Develops containment strategies
- Validates containment effectiveness

---

## Setup Instructions

### Prerequisites
- Python 3.7+
- Required dependencies (see below)

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure Input data exists:
```bash
# Input data should be in ../Input/ directory
ls ../Input/
```

### Dependencies
```
numpy>=1.21.0
PyYAML>=5.4.0
networkx>=2.6.0
scikit-learn>=1.0.0
tensorflow>=2.8.0
torch>=1.9.0
python-dateutil>=2.8.0
```

---

## File Structure

```
livedatacodes/
├── adfa_ids_generator.py          # ADFA-IDS dataset generator
├── awesomecyber_spc_pipeline.py   # AwesomeCyber pipeline
├── cic_ids_generator.py           # CIC-IDS2017 generator
├── cesnet_spc_pipeline.py         # CESNET pipeline
├── ember_spc_pipeline.py          # EMBER pipeline
├── ember_config.py                # EMBER configuration
├── ember_examples.py              # EMBER examples
├── lanl_generator.py              # LANL generator
├── mitre_spc_pipeline.py          # MITRE pipeline
├── nist_generator.py              # NIST generator
├── nist_spc_pipeline.py           # NIST SPC pipeline
├── real_data_spc_pipeline.py      # Real data pipeline
├── secrepo_generator.py           # SecRepo generator
├── toniot_generator.py            # ToN-IoT generator
├── toniot_generator_pipeline.py   # ToN-IoT generator pipeline
├── toniot_spc_pipeline.py         # ToN-IoT SPC pipeline
├── run_real_data_spc.py           # Real data runner
├── main.py                        # Main orchestrator
├── requirements.txt               # Python dependencies
└── README.md                      # This file
```

---

## Running All Generators

To run all generators sequentially:

```bash
python main.py
```

This orchestrator will process all datasets through the complete SPC framework.

---

## Output Structure

Generated outputs are stored in:
```
../livedataoutputs/
├── adfa_ids_data/ + adfa_ids_outputs/
├── awesome_data/ + awesome_outputs/
├── canadian_data/ + canadian_outputs/
├── cesnetdata/ + cesnet_outputs/
├── emberdata/ + ember_outputs/
├── losalamos_data/ + losalamos_outputs/
├── mitredata/ + mitre_outputs/
├── nist_data/ + nist_outputs/
├── real_data_results/
├── secrepo_data/ + secrepo_outputs/
└── toniot_data/ + toniot_output/
```

---

## Troubleshooting

### Import Errors
```bash
# Ensure all dependencies are installed
pip install -r requirements.txt --upgrade
```

### Path Issues
Ensure you run generators from within the `livedatacodes` folder:
```bash
cd /path/to/Code1/livedatacodes
python [generator_name].py
```

### Missing Input Data
Check that input files exist in `../Input/` directory. Some generators may create synthetic data if inputs are missing.

### Memory Issues
Large datasets (EMBER, LANL) may require significant RAM. Monitor system resources during execution.

---

## Documentation Files

Key documentation in the parent Code1 directory:
- `PROTOTYPE_README.md` - SPC prototype overview
- `QUICKSTART.md` - Quick start guide
- `Complete SPC Framework File Structure.txt` - Detailed structure
- `DELIVERY_SUMMARY.txt` - Project delivery notes

---

## Version Information

**Framework:** Stateful Propagation Containment (SPC)  
**Research Prototype:** v1.0  
**Date:** 2024-2025  

---

## Notes

- Each generator creates both raw data and SPC-processed outputs
- Outputs are JSON-formatted for compatibility and parsing
- Execution time varies by dataset size (minutes to hours on typical hardware)
- SPC framework components are modular and can be configured via YAML files in `src/config/`

---

## Support

For issues or questions about specific datasets:
1. Check the individual generator docstrings
2. Review SPC framework documentation in parent directory
3. Examine sample SUMMARY.json files in output folders for result format

---
