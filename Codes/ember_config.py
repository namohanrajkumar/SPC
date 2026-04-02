#!/usr/bin/env python3
"""
EMBER Dataset Input Configuration
Provides schema and templates for EMBER malware feature data
"""

EMBER_CONFIG = {
    "dataset_name": "EMBER (Endgame Malware BEnchmark for Research)",
    "description": "Machine learning dataset for malware detection with PE file features",
    "year_released": 2018,
    "samples_total": 1000000,
    "malware_samples": 500000,
    "benign_samples": 500000,
    
    "feature_types": {
        "static_analysis": {
            "pe_header": [
                "Machine",
                "NumberOfSections", 
                "Timestamp",
                "SizeOfImage",
                "SizeOfHeaders",
                "SizeOfCode",
                "SizeOfInitializedData"
            ],
            "pe_sections": [
                "Number of Sections",
                "Section Entropy",
                "Section Virtual Size",
                "Section Raw Size",
                "Section Properties"
            ],
            "pe_imports": [
                "Number of Imported Libraries",
                "Number of Imported Functions",
                "Imported APIs",
                "Suspicious API Calls"
            ],
            "pe_resources": [
                "Resource Type Count",
                "Resource Size",
                "Resource Entropy"
            ]
        },
        "dynamic_analysis": {
            "behavioral": [
                "File Operations",
                "Registry Operations",
                "Network Connections",
                "Process Creation",
                "DLL Injection"
            ],
            "api_calls": [
                "API Call Frequency",
                "Suspicious API Patterns",
                "API Argument Analysis"
            ]
        }
    },
    
    "feature_engineering": {
        "derived_features": [
            "Packing Indicator (High Entropy)",
            "Obfuscation Score",
            "API Set Diversity",
            "Import Table Complexity",
            "Section Anomaly Score"
        ],
        "temporal_features": [
            "Sample Appearance Date",
            "Family Evolution Period",
            "Mutation Generation Number"
        ]
    },
    
    "malware_families": [
        "Zeus",        # Banking trojan
        "Conficker",   # Worm
        "Mirai",       # IoT botnet
        "WannaCry",    # Ransomware
        "Emotet",      # Trojan
        "Dridex",      # Banking trojan
        "TrickBot",    # Banking trojan
        "Locky",       # Ransomware
        "Petya",       # Ransomware
        "NotPetya"     # Ransomware/Wiper
    ],
    
    "detection_metrics": {
        "static_features": 2381,
        "byte_histogram": 256,
        "entropy_histogram": 128,
        "string_features": 500,
        "total_features": 3265
    },
    
    "output_format": {
        "sha256": "string (file hash identifier)",
        "appeared": "ISO8601 (timestamp of first detection)",
        "label": "binary (1=malware, 0=benign)",
        "family": "string (malware family classification)",
        "feature_vector": "array of float (ML feature vector)"
    },
    
    "use_cases": [
        "Static Malware Detection",
        "Malware Family Classification",
        "Malware Evolution Analysis",
        "Adversarial ML Research",
        "Zero-day Malware Detection"
    ]
}

# Sample EMBER record structure
SAMPLE_EMBER_RECORD = {
    "sha256": "abc123def456...",
    "appeared": "2017-02-15T10:30:45Z",
    "label": 1,  # 1 = malware, 0 = benign
    "family": "Zeus",
    
    "pe_header": {
        "Machine": 0x14c,  # i386
        "NumberOfSections": 5,
        "Timestamp": 1487075445,
        "SizeOfImage": 2097152,
        "SizeOfHeaders": 4096,
        "Characteristics": 0x0102  # EXECUTABLE_IMAGE | MACHINE_32BIT
    },
    
    "sections": [
        {
            "name": ".text",
            "VirtualSize": 1048576,
            "RawSize": 1048576,
            "Entropy": 7.2,
            "Properties": 0x60000020  # CODE | READABLE | EXECUTABLE
        },
        {
            "name": ".data",
            "VirtualSize": 524288,
            "RawSize": 524288,
            "Entropy": 3.1,
            "Properties": 0xC0000040  # INITIALIZED_DATA | READABLE | WRITABLE
        }
    ],
    
    "imports": {
        "libraries": ["KERNEL32.DLL", "USER32.DLL", "ADVAPI32.DLL"],
        "function_count": 45,
        "suspicious_apis": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"]
    },
    
    "feature_vector": [
        0.15, 0.22, 0.31, 0.08, 0.91, 0.44, 0.55,  # ... 2381 total
    ],
    
    # Derived/engineered features for SPC
    "entropy_mean": 6.3,
    "packing_score": 0.79,  # Normalized entropy (entropy/8)
    "api_diversity": 0.5,
    "mutation_probability": 0.35
}

# Mapping EMBER to SPC cellular scales
SCALE_MAPPING = {
    "quantum_scale": {
        "description": "Individual PE feature level",
        "features": ["Byte Histogram", "Entropy values"]
    },
    "cellular_scale": {
        "description": "Process-level behavioral features", 
        "source": "MSBB_CellularScaleProcess-LevelData.json",
        "features": ["API sequences", "Section characteristics"]
    },
    "tissue_scale": {
        "description": "Host-level behavioral aggregation",
        "source": "MSBB_TissueScaleHost-LevelData.json",
        "features": ["Family characteristics", "Evolution markers"]
    },
    "organ_scale": {
        "description": "Network-level threat propagation",
        "source": "MSBB_OrganScaleNetworkSegmentData.json",
        "features": ["Variant distribution", "Family evolution"]
    },
    "organism_scale": {
        "description": "Malware ecosystem threats",
        "features": ["Family evolution over time", "Mutation rates"]
    }
}

# Evolution tracking
EVOLUTION_TEMPLATE = {
    "family": "Zeus",
    "period": "2017-02",
    "generation": 1,
    "sample_count": 150,
    "avg_entropy": 6.8,
    "avg_packing_score": 0.85,
    "avg_api_diversity": 0.45,
    "mutation_rate": 0.12,
    "variants": 12,
    "evasion_techniques": ["packing", "obfuscation", "code_injection"]
}

# Variant tracking for evolutionary algorithms
VARIANT_TEMPLATE = {
    "variant_id": "sha256_hash",
    "family": "Zeus",
    "appeared": "2017-02-15T10:30:45Z",
    "generation": 2,
    "parent_variant": "parent_sha256",
    "feature_changes": {
        "entropy_change": +0.5,
        "section_count_change": +1,
        "api_count_change": +5,
        "packing_change": +0.1
    },
    "evasion_techniques": 3,
    "detection_evasion_score": 0.75,
    "survival_probability": 0.65
}
