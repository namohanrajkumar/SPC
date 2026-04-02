# Stateful Propagation Containment (SPC) Framework

A bio-inspired cybersecurity framework for threat detection, analysis, and containment across multiple network and system scales.

---

## 📌 SPC Model Overview

The **Stateful Propagation Containment (SPC)** framework simulates biological immune system mechanisms to detect, analyze, and contain cyber threats. It processes security datasets through **5 core components** that work together to provide comprehensive threat analysis.

### 5 Core Components

| Component | Purpose | Focus |
|-----------|---------|-------|
| **DDE** (Defense Defense Emergence) | Simulates adaptive defense mechanisms | Defense strategy evolution and optimization |
| **ETP** (Evolutionary Threat Prediction) | Predicts emerging threat variants | Threat genome evolution and mutation patterns |
| **MSBB** (Multi-Scale Bio-Behavioral) | Analyzes behavior at multiple scales | Anomaly detection across host/network/process levels |
| **QICE** (Quantum Intelligence Correlation Engine) | Correlates security events intelligently | Event pattern recognition and threat scoring |
| **PSC** (Propagation Security Containment) | Develops containment strategies | Threat containment and network isolation plans |

---

## 📂 Folder Structure

```
github/
├── Datasets/          # Raw security datasets (input data)
├── Outputs/           # SPC framework analysis results
├── Codes/             # Generator scripts and executables
└── README.md          # This file
```

### Datasets/
Contains 10 real-world and synthetic cybersecurity datasets:
- **ADFA-IDS**: System call traces from Australian Defence Force Academy
- **CIC-IDS2017**: Network traffic with 11 attack types (Canadian Institute for Cybersecurity)
- **EMBER**: Malware features from 1M Windows executables
- **CESNET**: Real enterprise network anomalies
- **LANL**: Los Alamos National Laboratory enterprise security data
- **MITRE**: ATT&CK framework threat intelligence
- **NIST**: Standardized cybersecurity benchmark data
- **AwesomeCyber**: Curated threat intelligence from multiple sources
- **SecRepo**: Open-source security samples
- **ToN-IoT**: IoT/IIoT attack scenarios

### Outputs/
SPC framework analysis results for each dataset:
- **DDE_output.json** - Defense strategies and emergence analysis
- **ETP_output.json** - Threat evolution predictions
- **MSBB_output.json** - Multi-scale behavioral anomaly scores
- **QICE_output.json** - Correlated threat intelligence
- **PSC_output.json** - Containment strategies and recommendations
- **SUMMARY.json** - Executive summary of findings

### Codes/
Python scripts to regenerate datasets and outputs:
- Dataset generators (e.g., `adfa_ids_generator.py`, `cic_ids_generator.py`)
- SPC pipeline processors (e.g., `ember_spc_pipeline.py`)
- Support files (`requirements.txt`, `main.py`)
- See `CODES_README.md` for detailed documentation

---

## 🚀 Quick Start

### 1. Setup
```bash
cd Codes/
pip install -r requirements.txt
```

### 2. Run All Generators
```bash
python main.py
```

### 3. Run Individual Dataset
```bash
# Example: Run ADFA-IDS dataset generator
python adfa_ids_generator.py

# Example: Run CIC-IDS2017 generator
python cic_ids_generator.py

# Example: Run EMBER malware analyzer
python ember_spc_pipeline.py
```

---

## 📊 Data Flow

```
Raw Dataset (in Datasets/)
        ↓
Generator Script (in Codes/)
        ↓
Data Transformation & Preparation
        ↓
SPC Framework Processing
   ├── DDE (Defense Analysis)
   ├── ETP (Threat Prediction)
   ├── MSBB (Behavioral Analysis)
   ├── QICE (Correlation)
   └── PSC (Containment)
        ↓
Analysis Output (in Outputs/)
        ↓
Actionable Security Intelligence
```

---

## 📋 Understanding the Outputs

Each dataset generates outputs from all 5 SPC components:

### **DDE Output**
- Defense mechanisms against detected threats
- Evolutionary defense strategy optimization
- Success rates and effectiveness scores

### **ETP Output**
- Predicted threat evolution patterns
- Variant generation and mutation tracking
- Future threat landscape predictions

### **MSBB Output**
- Anomaly detection at host/network/process levels
- Health scores (0-1 scale)
- Behavioral deviation metrics

### **QICE Output**
- Correlated security events
- Threat correlation strength
- Multi-event attack patterns

### **PSC Output**
- Minimal network cuts for containment
- Isolation strategies
- Containment effectiveness validation

---

## 🔍 Dataset Details

| Dataset | Size | Type | Samples | Focus |
|---------|------|------|---------|-------|
| ADFA-IDS | - | System Calls | Normal + Attacks | Host Behavior |
| CIC-IDS2017 | - | Network Traffic | 11 Attack Types | Network Flow |
| EMBER | 1M | Malware PE Features | 500k Malware + 500k Benign | Malware Detection |
| CESNET | - | Network Flows | Real Enterprise | Network Anomalies |
| LANL | - | Enterprise Events | Auth + Process + Network | Enterprise Security |
| MITRE | - | Threat Intelligence | 200+ Techniques | Adversary Tactics |
| NIST | - | Benchmark Data | Standardized | Security Standards |
| AwesomeCyber | - | Threat Intelligence | Multi-source | General Threats |
| SecRepo | - | Public Samples | Benign + Malicious | Security Events |
| ToN-IoT | - | IoT Traffic | Normal + Attacks | IoT Security |

---

## 💻 Code Structure

```
Codes/
├── Generators (14 files)
│   ├── adfa_ids_generator.py
│   ├── cic_ids_generator.py
│   ├── ember_spc_pipeline.py
│   ├── cesnet_spc_pipeline.py
│   ├── lanl_generator.py
│   ├── mitre_spc_pipeline.py
│   ├── nist_generator.py
│   ├── awesomecyber_spc_pipeline.py
│   ├── secrepo_generator.py
│   ├── toniot_generator.py
│   ├── toniot_spc_pipeline.py
│   ├── real_data_spc_pipeline.py
│   └── main.py (Orchestrator)
├── Configuration
│   ├── ember_config.py
│   ├── ember_examples.py
│   └── requirements.txt
└── CODES_README.md (Detailed docs)
```

---

## ⚙️ System Requirements

- **Python 3.7+**
- **RAM**: 4GB minimum (8GB+ recommended for large datasets)
- **Storage**: ~2-5GB for full dataset + outputs
- **Dependencies**: numpy, scikit-learn, pytorch, tensorflow, networkx, pyyaml

See `Codes/requirements.txt` for exact versions.

---

## 🔧 Common Commands

```bash
# Install dependencies
pip install -r Codes/requirements.txt

# Run all datasets through SPC framework
cd Codes && python main.py

# Run specific dataset
python Codes/adfa_ids_generator.py

# Check Python version
python --version
```

---

## 📖 Output Format

All outputs are in **JSON** format for easy parsing and integration:

```json
{
  "timestamp": "2024-01-15T10:30:00",
  "dataset": "adfa_ids",
  "dde": {
    "defense_strategies": [...],
    "effectiveness": 0.87,
    "emergence_score": 0.92
  },
  "etp": {
    "threat_variants": [...],
    "evolution_rate": 0.65
  },
  "msbb": {
    "anomaly_scores": [...],
    "health_score": 0.78
  },
  "qice": {
    "correlated_events": [...],
    "correlation_strength": 0.81
  },
  "psc": {
    "containment_strategies": [...],
    "min_cut_size": 12
  }
}
```

---

## 📚 For More Information

- **Detailed Code Documentation**: See `Codes/CODES_README.md`
- **Individual Dataset Analysis**: Check `Outputs/[dataset_name]/SUMMARY.json`
- **Raw Data**: Browse `Datasets/[dataset_name]/` folders

---

## 🎯 Key Features

✅ **Multi-layered Analysis** - 5 complementary threat analysis perspectives  
✅ **Real-world Datasets** - 10 established cybersecurity datasets  
✅ **Actionable Insights** - Containment strategies and defense recommendations  
✅ **Scalable Architecture** - Process datasets from kilobytes to gigabytes  
✅ **Bio-inspired Approach** - Applies immune system principles to cybersecurity  

---

## 📝 License & Attribution

Research Prototype v1.0 (2024-2025)

Datasets sourced from:
- Australian Defence Force Academy (ADFA)
- Canadian Institute for Cybersecurity (CIC)
- Endgame (EMBER)
- CESNET
- Los Alamos National Laboratory
- MITRE Framework
- NIST
- SecRepo
- Academic IoT research

---

## ❓ Troubleshooting

| Issue | Solution |
|-------|----------|
| Import errors | Run `pip install -r Codes/requirements.txt --upgrade` |
| Memory issues | Process smaller datasets first, or increase RAM |
| Missing outputs | Ensure generators complete successfully, check terminal for errors |
| Path errors | Run generators from within `Codes/` directory |

---

## 📞 Support

For detailed information about specific datasets or components, refer to:
1. `Codes/CODES_README.md` - Complete code documentation
2. `Outputs/*/SUMMARY.json` - Individual analysis summaries
3. Individual dataset readmes in `Datasets/` (where available)

---

**Ready to analyze threats with SPC?** Start with the Quick Start section above! 🚀
