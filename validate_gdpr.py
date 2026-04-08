def validate_gdpr_record(record):
    """
    Validates a GDPR record after ingestion.

    DESIGN PRINCIPLES:
    - "empty" values are allowed → treated as missing → score = 0 later
    - Only truly invalid values are rejected
    - Provides clear, user-friendly error messages for CLI output
    """

    errors = []

    # -----------------------------------
    # CONSTANT: placeholder for missing data
    # -----------------------------------
    EMPTY = "empty"

    # -----------------------------------
    # HELPER FUNCTIONS (for clean error messages)
    # -----------------------------------

    def invalid_enum(field, value, allowed):
        """Error for incorrect categorical (enum) values"""
        return f"Invalid value '{value}' for '{field}'. Expected: {', '.join(allowed)}"

    def invalid_range(field, value, min_val, max_val):
        """Error for numeric range violations"""
        return f"Invalid value '{value}' for '{field}'. Expected integer between {min_val}-{max_val} or 'empty'"

    def invalid_bool(field, value):
        """Error for boolean fields"""
        return f"Invalid value '{value}' for '{field}'. Expected True, False or 'empty'"

    # -----------------------------------
    # BASIC SECURITY MEASURES
    # -----------------------------------

    value = record.get("https_enabled")
    if value != EMPTY and not isinstance(value, bool):
        errors.append(invalid_bool("https_enabled", value))

    value = record.get("password_storage_method")
    allowed = ["plaintext", "md5", "sha256", "bcrypt", "argon2", "unknown", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("password_storage_method", value, allowed))

    value = record.get("regular_security_testing")
    allowed = ["none", "ad_hoc", "annual", "quarterly", "continuous", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("regular_security_testing", value, allowed))

    value = record.get("encryption_at_rest")
    allowed = ["none", "partial", "full", "full_with_key_management", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("encryption_at_rest", value, allowed))

    value = record.get("mfa_enforced")
    allowed = ["none", "admin_only", "privileged_users", "all_users", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("mfa_enforced", value, allowed))

    value = record.get("patch_management_frequency")
    allowed = ["ad_hoc", "quarterly", "monthly", "weekly", "automated", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("patch_management_frequency", value, allowed))

    # -----------------------------------
    # TRANSPARENCY & USER RIGHTS
    # -----------------------------------

    value = record.get("privacy_policy_present")
    if value != EMPTY and not isinstance(value, bool):
        errors.append(invalid_bool("privacy_policy_present", value))

    value = record.get("cookie_consent_mechanism")
    allowed = ["none", "implied", "opt_in", "granular", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("cookie_consent_mechanism", value, allowed))

    value = record.get("privacy_policy_clarity")
    allowed = ["clear", "partially_clear", "unclear", "missing", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("privacy_policy_clarity", value, allowed))

    value = record.get("lawful_basis")
    allowed = [
        "consent", "contract", "legal_obligation",
        "legitimate_interests", "vital_interests",
        "public_task", "mixed", EMPTY
    ]
    if value not in allowed:
        errors.append(invalid_enum("lawful_basis", value, allowed))

    value = record.get("third_party_sharing_disclosed")
    allowed = ["none", "partial", "full", "unclear", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("third_party_sharing_disclosed", value, allowed))

    # Numeric validation
    dsar_days = record.get("dsar_response_time_days")
    if dsar_days != EMPTY and (not isinstance(dsar_days, int) or not (1 <= dsar_days <= 99)):
        errors.append(invalid_range("dsar_response_time_days", dsar_days, 1, 99))

    value = record.get("dsar_process")
    allowed = ["missing", "informal", "partial", "documented", "automated", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("dsar_process", value, allowed))

    value = record.get("dsar_identity_verification")
    allowed = ["none", "basic", "strong", "multi_step", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("dsar_identity_verification", value, allowed))

    # -----------------------------------
    # INTERNAL CONTROLS
    # -----------------------------------

    value = record.get("data_breach_process_maturity")
    allowed = ["none", "informal", "documented", "tested", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("data_breach_process_maturity", value, allowed))

    breach_hours = record.get("breach_notification_hours")
    if breach_hours != EMPTY and (not isinstance(breach_hours, int) or not (1 <= breach_hours <= 168)):
        errors.append(invalid_range("breach_notification_hours", breach_hours, 1, 168))

    value = record.get("data_retention_policy")
    allowed = ["none", "operational", "legal_only", "mixed", "indefinite", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("data_retention_policy", value, allowed))

    retention_days = record.get("retention_period_days")
    if retention_days != EMPTY and (not isinstance(retention_days, int) or not (0 <= retention_days <= 365)):
        errors.append(invalid_range("retention_period_days", retention_days, 0, 365))

    value = record.get("record_of_processing")
    allowed = ["none", "partial", "complete", "automated", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("record_of_processing", value, allowed))

    value = record.get("dpia_process")
    allowed = ["none", "ad_hoc", "documented", "integrated", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("dpia_process", value, allowed))

    value = record.get("has_dpo")
    allowed = ["none", "informal_role", "appointed", "outsourced", EMPTY]
    if value not in allowed:
        errors.append(invalid_enum("has_dpo", value, allowed))

    # -----------------------------------
    # CROSS-FIELD VALIDATION (LOGIC RULES)
    # -----------------------------------

    # These enforce GDPR logic relationships (not just format)

    if record.get("privacy_policy_present") is False and record.get("privacy_policy_clarity") not in ["missing", EMPTY]:
        errors.append("privacy_policy_clarity must be 'missing' when privacy_policy_present is False")

    if record.get("lawful_basis") == "consent" and record.get("cookie_consent_mechanism") == "none":
        errors.append("cookie_consent_mechanism cannot be 'none' when lawful_basis is 'consent'")

    if record.get("data_retention_policy") == "none" and record.get("retention_period_days") not in [0, EMPTY]:
        errors.append("retention_period_days must be 0 when data_retention_policy is 'none'")

    return errors