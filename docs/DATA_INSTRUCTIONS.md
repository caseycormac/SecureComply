# DATA_INSTRUCTIONS.md

## Overview

This document defines the required input format for SecureComply+.

All input data must:
- Be valid JSON
- Follow the exact structure shown below
- Use only the allowed values defined in this document

If invalid data is provided:
- The record will fail validation
- Clear error messages will be shown in the CLI
- The record will not be processed

---

## File Location

Place your input file inside the `/data` directory.

Example:

```
data/my_input.json
data/sample.json
data/example_upload.json
```

---

## Running the Tool

```bash
python run.py data/my_input.json
```

---

## Input Format (Template)

Copy and modify the template below:

```json
[
  {
    "basic_security_measures": {
      "https_enabled": true,
      "password_storage_method": "bcrypt",
      "regular_security_testing": "quarterly",
      "encryption_at_rest": "full",
      "mfa_enforced": "all_users"
    },
    "transparency_user_rights": {
      "cookie_consent_mechanism": "opt_in",
      "privacy_policy_present": true,
      "privacy_policy_clarity": "clear",
      "lawful_basis": "contract",
      "third_party_sharing_disclosed": "full",
      "dsar_response_time_days": 30,
      "dsar_process": "documented"
    },
    "internal_controls": {
      "data_breach_process_maturity": "tested",
      "breach_notification_hours": 72,
      "data_retention_policy": "legal_only",
      "retention_period_days": 90,
      "record_of_processing": "complete",
      "dpia_process": "documented",
      "has_dpo": "appointed"
    }
  }
]

You may replace any genuinely non-applicable field value with `N/A`.
Example:
- `"https_enabled": "N/A"`
- `"dsar_response_time_days": "N/A"`
```

---
## N/A Values

SecureComply supports **Not Applicable** values for fields that do not apply to a given organisation.

Accepted inputs:
- `N/A`
- `n/a`
- `NA`
- `na`

How N/A is handled:
- During ingestion, all supported N/A variants are normalised to `na`
- N/A values are accepted during validation
- N/A controls are **excluded from scoring**
- Excluded controls do not reduce the final percentage score
- Excluded controls are counted separately in the final report as **N/A Controls Excluded**

Use N/A only where a control is genuinely not applicable to the organisation.
Do not use N/A to avoid answering a relevant control.

* * *

## Allowed Values

### Basic Security Measures

| Field | Allowed Values |
|-------|--------------|
| https_enabled | true / false, "N/A" |
| password_storage_method | argon2, bcrypt, sha256, md5, plaintext, "N/A" |
| regular_security_testing | continuous, quarterly, annual, ad_hoc, none, "N/A" |
| encryption_at_rest | full_with_key_management, full, partial, none, "N/A" |
| mfa_enforced | all_users, privileged_users, admin_only, none, "N/A" |

---

### Transparency & User Rights

| Field | Allowed Values |
|-------|--------------|
| cookie_consent_mechanism | granular, opt_in, implied, none, "N/A" |
| privacy_policy_present | true / false, "N/A" |
| privacy_policy_clarity | clear, partially_clear, unclear, missing, "N/A" |
| lawful_basis | contract, legal_obligation, consent, legitimate_interests, public_task, vital_interests, mixed, "N/A" |
| third_party_sharing_disclosed | full, partial, unclear, none, "N/A" |
| dsar_response_time_days | Integer (e.g. 30), "N/A" |
| dsar_process | automated, documented, partial, informal, missing, "N/A" |

---

### Internal Controls

| Field | Allowed Values |
|-------|--------------|
| data_breach_process_maturity | tested, documented, informal, none, "N/A" |
| breach_notification_hours | Integer (e.g. 72), "N/A" |
| data_retention_policy | legal_only, mixed, operational, indefinite, none, "N/A" |
| retention_period_days | Integer (e.g. 30, 90, 180), "N/A" |
| record_of_processing | automated, complete, partial, none, "N/A" |
| dpia_process | integrated, documented, ad_hoc, none, "N/A" |
| has_dpo | appointed, outsourced, informal_role, none, "N/A" |

---

## Notes

- Field names are case-sensitive
- Values should match the allowed options exactly
- Enum values are normalised to lowercase during ingestion
- Integers should be provided as numbers, not quoted strings where possible
- Boolean values should be `true` or `false`
- `N/A`, `n/a`, `NA`, and `na` are accepted for supported fields
- Blank or missing values may be treated as missing data rather than not applicable

---

## Optional: Host Telemetry Integration

You may enrich input data using host scan results:

```bash
python merge_host_data.py
```

This will:
- Merge host scan data into SME records
- Add fields such as:
  - HTTPS status
  - Encryption at rest
  - Additional security indicators

These fields:
- Do NOT affect scoring
- Are displayed in the final report for context

---

## Common Errors

| Error | Cause |
|------|------|
| Invalid enum value | Value not in allowed list |
| Missing field | Required field not included |
| Wrong data type | String instead of integer/boolean |
| Malformed JSON | Missing brackets, commas, etc. |

---

## Recommendation

Start with the provided template and modify values gradually.

This ensures:
- Correct structure
- Faster testing
- Fewer validation errors

---
