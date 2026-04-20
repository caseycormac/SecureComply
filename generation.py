"""
Version_02 - Synthetic GDPR SME Data Generator (Expanded Fields + Options)

Keeps the SAME nested structure as V1:
- basic_security_measures
- transparency_user_rights
- internal_controls

Upgrades:
- more fields
- richer enums (maturity modelling)
- dependency rules to avoid anomalies

Consistency rules:
- If privacy_policy_present == False -> privacy_policy_clarity = "missing"
- If lawful_basis == "consent" -> cookie_consent_mechanism cannot be "none"
- If data_retention_policy == "none" -> retention_period_days = 0
- If data_retention_policy == "indefinite" -> retention_period_days = 365 (max placeholder)
"""

import os
import json
import random
from datetime import datetime, timezone


# -----------------------------
# ENUMS (EXPANDED)
# -----------------------------

PASSWORD_STORAGE_METHODS = [
    "plaintext", "md5", "sha256", "bcrypt", "argon2", "unknown"
]

SECURITY_TESTING_FREQUENCY = [
    "none", "ad_hoc", "annual", "quarterly", "continuous"
]

ENCRYPTION_AT_REST = [
    "none", "partial", "full", "full_with_key_management"
]

MFA_ENFORCED = [
    "none", "admin_only", "privileged_users", "all_users"
]


COOKIE_CONSENT_MECHANISM = [
    "none", "implied", "opt_in", "granular"
]

PRIVACY_POLICY_CLARITY = [
    "clear", "partially_clear", "unclear", "missing"
]

LAWFUL_BASIS = [
    "consent", "contract", "legal_obligation",
    "legitimate_interests", "vital_interests", "public_task", "mixed"
]

THIRD_PARTY_SHARING_DISCLOSED = [
    "none", "partial", "full", "unclear"
]

DSAR_PROCESSES = [
    "missing", "informal", "partial", "documented", "automated"
]

BREACH_PROCESS_MATURITY = [
    "none", "informal", "documented", "tested"
]

DATA_RETENTION_POLICY = [
    "none", "operational", "legal_only", "mixed", "indefinite"
]

RECORD_OF_PROCESSING = [
    "none", "partial", "complete", "automated"
]

DPIA_PROCESS = [
    "none", "ad_hoc", "documented", "integrated"
]

HAS_DPO = [
    "none", "informal_role", "appointed", "outsourced"
]


def generate_sme_gdpr_data_v2() -> dict:
    # --- Dependency: privacy policy drives clarity ---
    privacy_present = random.choice([True, False])
    if privacy_present:
        privacy_clarity = random.choice(["clear", "partially_clear", "unclear"])
    else:
        privacy_clarity = "missing"

    # --- Lawful basis ---
    lawful_basis = random.choice(LAWFUL_BASIS)

    # --- Dependency: if consent is lawful basis, cookie consent cannot be none ---
    if lawful_basis == "consent":
        cookie_mechanism = random.choice(["opt_in", "granular"])
    else:
        cookie_mechanism = random.choice(COOKIE_CONSENT_MECHANISM)

    # --- Retention policy drives retention days ---
    retention_policy = random.choice(DATA_RETENTION_POLICY)
    if retention_policy == "none":
        retention_days = 0
    elif retention_policy == "indefinite":
        retention_days = 365
    else:
        retention_days = random.randint(1, 365)

    # --- Breach notification ability ---
    breach_notification_hours = random.randint(24, 168)  # 1–7 days

    sme_data = {
        "basic_security_measures": {
            "https_enabled": random.choice([True, False]),
            "password_storage_method": random.choice(PASSWORD_STORAGE_METHODS),
            "regular_security_testing": random.choice(SECURITY_TESTING_FREQUENCY),
            "encryption_at_rest": random.choice(ENCRYPTION_AT_REST),
            "mfa_enforced": random.choice(MFA_ENFORCED),
        },

        "transparency_user_rights": {
            "cookie_consent_mechanism": cookie_mechanism,
            "privacy_policy_present": privacy_present,
            "privacy_policy_clarity": privacy_clarity,
            "lawful_basis": lawful_basis,
            "third_party_sharing_disclosed": random.choice(THIRD_PARTY_SHARING_DISCLOSED),
            "dsar_response_time_days": random.randint(1, 99),
            "dsar_process": random.choice(DSAR_PROCESSES),
        },

        "internal_controls": {
            "data_breach_process_maturity": random.choice(BREACH_PROCESS_MATURITY),
            "breach_notification_hours": breach_notification_hours,
            "data_retention_policy": retention_policy,
            "retention_period_days": retention_days,
            "record_of_processing": random.choice(RECORD_OF_PROCESSING),
            "dpia_process": random.choice(DPIA_PROCESS),
            "has_dpo": random.choice(HAS_DPO),
        },

        # Optional metadata (won't be flattened unless you extend ingestion)
        "metadata": {
            "record_generated_timestamp": datetime.now(timezone.utc).isoformat()
        }
    }

    return sme_data


def generate_multiple_smes(count: int = 10) -> list:
    return [generate_sme_gdpr_data_v2() for _ in range(count)]


if __name__ == "__main__":
    SME_COUNT = 1
    OUTPUT_DIR = "data"
    OUTPUT_FILENAME = "synthetic_sme_gdpr_data_v2.json"
    OUTPUT_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    dataset = generate_multiple_smes(SME_COUNT)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(dataset, f, indent=4)

    print("[+] Version_02 dataset generated")
    print(f"[+] Records: {SME_COUNT}")
    print(f"[+] Saved to: {OUTPUT_PATH}")
