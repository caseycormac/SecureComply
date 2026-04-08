import os
import json

from ingestion_module import ingest_gdpr_json
from validate_gdpr import validate_gdpr_record
from compliance_engine import compute_audit
from config import PROJECT_VERSION

INPUT_FILE = "data/merged_input_v4.json"
OUTPUT_FILE = "reports/audit_result_v3.json"


def run_pipeline():
    print(f"[+] Starting GDPR audit pipeline ({PROJECT_VERSION})")

    os.makedirs("reports", exist_ok=True)

    records = ingest_gdpr_json(INPUT_FILE)
    print(f"[+] Ingested {len(records)} record(s)")

    if not records:
        raise RuntimeError("No records ingested. Check the input file path and JSON structure.")

    valid_records = []
    invalid_records = []

    for i, record in enumerate(records):
        errors = validate_gdpr_record(record)
        if errors:
            invalid_records.append({
                "record_index": i,
                "errors": errors,
                "record_preview": record
            })
        else:
            valid_records.append(record)

    print(f"[+] Valid records: {len(valid_records)}")
    print(f"[+] Invalid records: {len(invalid_records)}")

    if not valid_records:
        output = {"audit_results": [], "invalid_records": invalid_records}
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4)
        raise RuntimeError(f"No valid records after validation. See {OUTPUT_FILE} for details.")

    audit_results = []
    for record in valid_records:

        audit = compute_audit(record)

        # Preserve host telemetry for report (non-scoring)
        audit["extra_security_signals"] = record.get("extra_security_signals", {})
        audit["host_scan_timestamp"] = record.get("host_scan_timestamp")

        audit_results.append(audit)

    output = {
        "audit_results": audit_results,
        "invalid_records": invalid_records
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    print(f"[+] Audit completed → {OUTPUT_FILE}")


if __name__ == "__main__":
    run_pipeline()
