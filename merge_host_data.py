import json

SME_FILE = "data/synthetic_sme_gdpr_data_v2.json"
HOST_FILE = "data/host_scan.json"
OUTPUT_FILE = "data/merged_input_v4.json"

with open(SME_FILE) as f:
    sme_data = json.load(f)

with open(HOST_FILE) as f:
    host_data = json.load(f)

for record in sme_data:
    record["basic_security_measures"]["https_enabled"] = host_data["https_enabled"]
    record["basic_security_measures"]["encryption_at_rest"] = host_data["encryption_at_rest"]

    record["host_scan_timestamp"] = host_data["host_scan_timestamp"]
    record["extra_security_signals"] = host_data.get("extra_security_signals", {})


with open(OUTPUT_FILE, "w") as f:
    json.dump(sme_data, f, indent=4)

print("Merged SME + host scan data")