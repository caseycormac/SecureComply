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
      "mfa_enforced": "all_users",
      "patch_management_frequency": "monthly"
    },
    "transparency_user_rights": {
      "cookie_consent_mechanism": "opt_in",
      "privacy_policy_present": true,
      "privacy_policy_clarity": "clear",
      "lawful_basis": "contract",
      "third_party_sharing_disclosed": "full",
      "dsar_response_time_days": 30,
      "dsar_process": "documented",
      "dsar_identity_verification": "strong"
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
```

---

## Allowed Values

### Basic Security Measures

| Field | Allowed Values |
|-------|--------------|
| https_enabled | true / false |
| password_storage_method | argon2, bcrypt, sha256, md5, plaintext |
| regular_security_testing | continuous, quarterly, annual, ad_hoc, none |
| encryption_at_rest | full_with_key_management, full, partial, none |
| mfa_enforced | all_users, privileged_users, admin_only, none |
| patch_management_frequency | weekly, monthly, quarterly, none |

---

### Transparency & User Rights

| Field | Allowed Values |
|-------|--------------|
| cookie_consent_mechanism | granular, opt_in, implied, none |
| privacy_policy_present | true / false |
| privacy_policy_clarity | clear, partially_clear, unclear, missing |
| lawful_basis | contract, legal_obligation, consent, legitimate_interests, public_task, vital_interests, mixed |
| third_party_sharing_disclosed | full, partial, unclear, none |
| dsar_response_time_days | Integer (e.g. 30) |
| dsar_process | automated, documented, partial, informal, missing |
| dsar_identity_verification | strong, weak, none |

---

### Internal Controls

| Field | Allowed Values |
|-------|--------------|
| data_breach_process_maturity | tested, documented, informal, none |
| breach_notification_hours | Integer (e.g. 72) |
| data_retention_policy | legal_only, mixed, operational, indefinite, none |
| retention_period_days | Integer (e.g. 30, 90, 180) |
| record_of_processing | automated, complete, partial, none |
| dpia_process | integrated, documented, ad_hoc, none |
| has_dpo | appointed, outsourced, informal_role, none |

---

## Notes

- Field names are **case-sensitive**
- Values must match exactly (e.g. `"bcrypt"` not `"BCRYPT"`)
- Integers must not be quoted (e.g. `30`, not `"30"`)
- Boolean values must be `true` or `false` (lowercase)

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