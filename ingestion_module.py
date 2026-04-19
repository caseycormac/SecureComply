import json
import sys

# --------------------------------------------------
# NEW: Fill missing / empty values
# --------------------------------------------------
def fill_empty_fields(obj):
    """
    Recursively replaces empty or missing values with "empty".

    Why:
    - Ensures pipeline never breaks on missing data
    - Standardises input for validation + scoring
    - "empty" will automatically score 0 later

    Handles:
    - None
    - ""
    - Nested dictionaries
    - Lists

    This is CRITICAL for robustness in real-world datasets.
    """

    # If it's a dictionary → process each key/value
    if isinstance(obj, dict):
        return {
            k: fill_empty_fields(v if v not in [None, ""] else "empty")
            for k, v in obj.items()
        }

    # If it's a list → process each item
    elif isinstance(obj, list):
        return [fill_empty_fields(i) for i in obj]

    # Otherwise return value as-is
    else:
        return obj

#Normalise N/A
def normalise_na_values(record: dict) -> dict:
    """
    Converts all variations of N/A into a standard 'na' value.
    """

    NA_VALUES = {"na", "n/a", "NA", "N/A"}

    for key, value in record.items():

        if isinstance(value, str):
            if value.strip().lower() in NA_VALUES:
                record[key] = "na"

    return record

def normalise_record(record):
    boolean_map = {
        "true": True, "false": False,
        "yes": True, "no": False,
        "y": True, "n": False,
        "1": True, "0": False
    }

    # V2: only https_enabled is boolean by default (others moved to enums)
    boolean_fields = [
    "https_enabled",
    "privacy_policy_present",
]


    for field in boolean_fields:
        value = record.get(field)
        if isinstance(value, str):
            record[field] = boolean_map.get(value.lower(), value)
        elif isinstance(value, int):
            record[field] = bool(value)

    # Integer fields (V2 expanded)
    int_fields = [
        "dsar_response_time_days",
        "retention_period_days",
        "breach_notification_hours",
    ]

    for field in int_fields:
        value = record.get(field)
        if isinstance(value, str) and value.isdigit():
            record[field] = int(value)

    # Enum/string fields to clean (strip/lower)
    enum_fields = [
        "password_storage_method",
        "regular_security_testing",
        "encryption_at_rest",
        "mfa_enforced",
        "patch_management_frequency",
        "cookie_consent_mechanism",
        "privacy_policy_clarity",
        "lawful_basis",
        "third_party_sharing_disclosed",
        "dsar_process",
        "dsar_identity_verification",
        "data_breach_process_maturity",
        "data_retention_policy",
        "record_of_processing",
        "dpia_process",
        "has_dpo",
    ]

    for field in enum_fields:
        value = record.get(field)
        if isinstance(value, str):
            record[field] = value.strip().lower()

    return record


def flatten_gdpr_record(record):

    flat_record = {}

    basic = record.get("basic_security_measures", {})
    flat_record.update(basic)

    transparency = record.get("transparency_user_rights", {})
    flat_record.update(transparency)

    internal = record.get("internal_controls", {})
    flat_record.update(internal)

    # Preserve host telemetry if present
    if "extra_security_signals" in record:
        flat_record["extra_security_signals"] = record["extra_security_signals"]

    if "host_scan_timestamp" in record:
        flat_record["host_scan_timestamp"] = record["host_scan_timestamp"]

    return flat_record


def ingest_gdpr_json(json_file):
    try:
        with open(json_file, "r") as f:
            raw_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{json_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{json_file}' please check values are correct.")
        sys.exit(1)

    if isinstance(raw_data, dict):
        raw_data = [raw_data]
    elif not isinstance(raw_data, list):
        print("Error: Unsupported GDPR JSON structure.")
        sys.exit(1)

    processed = []
    for record in raw_data:
# Step 1: Flatten nested GDPR structure
        flat = flatten_gdpr_record(record)

        # Step 2: Fill missing/empty values BEFORE normalisation
        flat = fill_empty_fields(flat)

        flat = normalise_na_values(flat)
        
        # Step 3: Normalise data types (booleans, ints, enums)
        flat = normalise_record(flat)

        # Add cleaned record to processed list
        processed.append(flat)

    return processed


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ingestion_module.py <gdpr_json_file>")
        sys.exit(1)

    records = ingest_gdpr_json(sys.argv[1])
    print(f"Ingestion successful: {len(records)} GDPR record(s) processed")
