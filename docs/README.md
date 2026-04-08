# SecureComply+ GDPR Auditor

## Overview

SecureComply+ is a command-line tool designed to assess GDPR compliance for Small and Medium Enterprises (SMEs). It analyses structured input data and produces a detailed audit report, including compliance scores, risk bands, and actionable recommendations.

The tool is built to be simple & explainable, focusing on usability and transparency of scoring.

---

## Key Features

* GDPR-inspired compliance scoring engine
* Structured JSON input validation
* Risk classification (Strong, Moderate, Weak, High Risk)
* Actionable recommendations based on scoring gaps
* HTML and JSON report generation
* Optional AI-generated executive summary (CISO-style)
* Clear CLI interface with help and usage commands

---


## Project Structure
```
/VERSION_06
│
├── data/                      # Input GDPR JSON datasets
├── reports/                   # Generated audit outputs (HTML + JSON)
├── benchmark/
│   ├── benchmark.json         # Generated SME baseline metrics
│   ├── generate_benchmark.py  # Script to generate benchmark data
│
├── report_generator/          # Report generation logic
│   ├── report_generator.py    # HTML report builder
│   ├── ai_narrative.py        # AI CISO summary generation
│
├── compliance_engine.py       # Core GDPR scoring engine
├── validate_gdpr.py           # Input validation + error handling
├── ingestion_module.py        # JSON ingestion and preprocessing
├── pipeline.py                # Main audit pipeline (ingest → validate → score)
├── run.py                     # CLI entry point for running the tool
│
├── host_scan.sh               # Host-based data collection (optional telemetry)
├── merge_host_data.py         # Merges host scan data with SME dataset
│
├── generation.py              # Synthetic SME data generator
├── config.py                  # Configuration settings
│
├── .venv / venv               # Virtual environments (ignore in submission)
├── __pycache__/               # Python cache (ignore)

```

---

## How It Works

SecureComply+ operates through a structured 5-stage pipeline designed for accuracy, transparency, and modularity.

---

### 1. Data Ingestion

- Loads SME GDPR data from a JSON file
- Processes input using `ingestion_module.py`
- Performs:
  - Data flattening (nested → flat structure)
  - Default value handling for missing fields
  - Normalisation of data types (booleans, enums, integers)

This ensures a consistent format before validation and scoring.

---

### 2. Validation

- Performed by `validate_gdpr.py`
- Ensures:
  - Required fields exist
  - Values match predefined allowed inputs
  - Data types are correct

If validation fails:
- Detailed CLI error messages are displayed
- Invalid records are excluded from scoring

---

### 3. Compliance Scoring Engine

- Implemented in `compliance_engine.py`
- Evaluates GDPR-inspired controls across 3 categories:

**Basic Security Measures (30 points)**
- HTTPS enforcement
- Password storage strength
- Security testing frequency
- Encryption at rest
- MFA enforcement

**Transparency & User Rights (40 points)**
- Cookie consent mechanism
- Privacy policy presence and clarity
- Lawful basis for processing
- Third-party data sharing disclosure
- DSAR handling capability

**Internal Controls (30 points)**
- Data breach response maturity
- Breach notification timelines
- Data retention policies
- Record of Processing Activities (RoPA)
- DPIA processes
- DPO assignment

Each control:
- Uses deterministic scoring rules
- Produces traceable outputs (rule + justification)
- Contributes to both category and overall scores

---

### 4. Risk Classification

- Final score (0–100) is mapped to a compliance band:

| Score Range | Band        |
|------------|------------|
| 85–100     | Strong     |
| 70–84      | Moderate   |
| 50–69      | Weak       |
| <50        | High Risk  |

This provides a clear, interpretable risk level.

---

### 5. Report Generation

- Generates outputs using `report_generator/`
- Produces:

  - **JSON Report**
    - Full audit results
    - Control-level breakdown
    - Recommendations

  - **HTML Report**
    - Visual dashboard
    - Score breakdowns
    - Benchmark comparison
    - Remediation plan

- Optional:
  - AI-generated CISO summary (`ai_narrative.py`)
  - Falls back to deterministic output if AI is unavailable

---

## Getting Started

### 1. Prepare Input Data

Place your JSON file inside the `/data` folder.

See:

```
docs/DATA_INSTRUCTIONS.md
```

for the required format and allowed values.

---

### 2. Run the Tool

```bash
python run.py data/your_file.json
```

---

### 3. Output

Results will be saved in:

```
/reports/
```

* `audit_result.json` → structured results
* `audit_report.html` → formatted report

---

## Command Line Options

### Help

```bash
python run.py --help, -h
```

Displays available commands and options.

---

### Usage Guide

```bash
python run.py --usage
```

Provides examples and instructions for running the tool.

---

### Disable AI (Optional)

```bash
python run.py data/input.json --no-ai
```

Runs the tool without AI-generated narrative.

---

## Input Data

* Must be valid JSON
* Must follow predefined schema
* Invalid inputs will produce detailed validation errors

See:

```
docs/DATA_INSTRUCTIONS.md
```

---

## Output Explanation

### Overall Score

Total compliance score out of 100.

### Category Scores

Breakdown across:

* Security
* Transparency
* Internal Controls

### Recommendations

Top priority improvements based on:

* Points lost per control

---

## Design Goals

* **Usability** → Simple CLI for examiners
* **Transparency** → Clear scoring logic
* **Modularity** → Separated pipeline, validation, and scoring
* **Extensibility** → Easy to add new controls or data sources

---

## Limitations

* Uses synthetic SME data
* Not a full legal GDPR compliance tool
* Designed for educational and demonstration purposes

---

## Future Improvements

* Integration with real host telemetry
* Dashboard interface (web-based)
* Expanded regulatory frameworks
* Enhanced AI reporting

---

## Author

Namke: Cormac Casey
Student No: C00283808
email: C00283808@setu.ie
SecureComply+ GDPR Auditor

---

## Notes for Examiner

* Use `--help` or `--usage` for quick guidance
* Ensure input JSON follows the required format
* All outputs are generated in the `/reports` folder
