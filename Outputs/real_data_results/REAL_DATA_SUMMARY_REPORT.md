# Real Data SPC Processing Report

**Pipeline**: Real Data SPC Processing
**Timestamp**: 2026-03-08T23:21:01.424208
**Status**: success
**Execution Time**: 4.60 seconds

## Input Data
- **Source**: /Users/harshil/SNUC_Subjects/Mohan Raj sir_Prototype/Input
- **Total Files**: 8
- **Total Records**: 34

### Input File Breakdown
| File | Records |
|------|----------|
| MSBB_CellularScaleProcess-LevelData.json | 6 |
| MSBB_TissueScaleHost-LevelData.json | 6 |
| MSBB_OrganScaleNetworkSegmentData.json | 6 |
| ETP_DefensePostureInput.json | 2 |
| QICE_Quantum State Parameters.json | 5 |
| DDE_InitialDefense Genome PopulationDataInput.json | 4 |
| DDE_ Historical Performance Data.json | 1 |
| PSC_ThreatPredictionInputVector.json | 4 |

## Output Components
- **QICE_output**: generated
  - Keys: correlation_id, timestamp, clusters_detected, correlation_metrics, configuration
- **ETP_output**: generated
  - Keys: prediction_id, timestamp, generations_simulated, confidence_level, predicted_variants
- **DDE_output**: generated
  - Keys: component, status, error
- **PSC_output**: generated
  - Keys: containment_id, timestamp, threat_prediction_id, status, containment_analysis
- **SPC_Summary**: generated
  - Keys: execution_id, timestamp, execution_time_seconds, components_executed, status
