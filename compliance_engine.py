from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
from config import PROJECT_VERSION

SCORING_VERSION = PROJECT_VERSION

BANDS = [
    (85, 100, "Strong"),
    (70, 84, "Moderate"),
    (50, 69, "Weak"),
    (0, 49, "High Risk"),
]

CATEGORY_MAX = {
    "basic_security_measures": 30,
    "transparency_user_rights": 40,
    "internal_controls": 30,
}

@dataclass
class ControlResult:
    control_id: str
    category: str
    input: Any
    score: int
    max: int
    rule: str
    justification: str
    notes: str = ""


def band_for(score: int) -> str:
    for lo, hi, name in BANDS:
        if lo <= score <= hi:
            return name
    return "Unknown"


def score_enum(value: str, mapping: Dict[str, int], default: int = 0) -> int:
    v = (value or "").strip().lower()
    return mapping.get(v, default)


def score_days(value: int, thresholds: List[Tuple[int, int]]) -> int:
    for upper, score in thresholds:
        if value <= upper:
            return score
    return 0

##N/A Helpers 
def is_na(value: Any) -> bool:
    return str(value).lower() == "na"


def na_aware_enum(value: Any, points: int, mapping: Dict[str, int]) -> Tuple[Any, int, int, str]:
    if is_na(value):
        return "na", 0, 0, "Excluded from scoring (not applicable)."
    return value, score_enum(value, mapping), points, ""


def na_aware_days(value: Any, points: int, thresholds: List[Tuple[int, int]], zero_note: str = "") -> Tuple[Any, int, int, str]:
    if is_na(value):
        return "na", 0, 0, "Excluded from scoring (not applicable)."

    ivalue = int(value)

    if ivalue == 0 and zero_note:
        return ivalue, 0, points, zero_note

    return ivalue, score_days(ivalue, thresholds), points, ""

def compute_audit(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    record MUST be the flattened, validated structure (post-ingestion).
    """

    results: List[ControlResult] = []

    # -----------------------------
    # A) Basic Security Measures (30)
    # -----------------------------

    # https_enabled (boolean)
    https_pts = 8
    https_input = record["https_enabled"]

    if str(https_input).lower() == "na":
        https_score = 0
        https_max = 0
        https_notes = "Excluded from scoring (not applicable)."
    else:
        https_score = https_pts if https_input is True else 0
        https_max = https_pts
        https_notes = ""

    results.append(ControlResult(
        "https_enabled", "basic_security_measures", https_input,
        https_score, https_max,
        "True => 8, False => 0",
        "Encryption in transit supports confidentiality and is aligned with GDPR Art. 32.",
        notes=https_notes
    ))


    # password_storage_method (enum)
    pwd_pts = 8
    pwd_input = record["password_storage_method"]

    if str(pwd_input).lower() == "na":
        pwd_score = 0
        pwd_max = 0
        pwd_notes = "Excluded from scoring (not applicable)."
    else:
        pwd_score = score_enum(pwd_input, {
            "argon2": 8, "bcrypt": 7, "sha256": 4, "md5": 1, "plaintext": 0, "unknown": 0
        })
        pwd_max = pwd_pts
        pwd_notes = ""

    results.append(ControlResult(
        "password_storage_method", "basic_security_measures", pwd_input,
        pwd_score, pwd_max,
        "argon2=>8, bcrypt=>7, sha256=>4, md5=>1, plaintext/unknown=>0",
        "Stronger password hashing reduces account compromise risk.",
        notes=pwd_notes
    ))


    # regular_security_testing (enum)
    test_pts = 6
    testing_input = record["regular_security_testing"]

    if str(testing_input).lower() == "na":
        testing_score = 0
        testing_max = 0
        testing_notes = "Excluded from scoring (not applicable)."
    else:
        testing_score = score_enum(testing_input, {
            "continuous": 6, "quarterly": 5, "annual": 3, "ad_hoc": 1, "none": 0
        })
        testing_max = test_pts
        testing_notes = ""

    results.append(ControlResult(
        "regular_security_testing", "basic_security_measures", testing_input,
        testing_score, testing_max,
        "continuous=>6, quarterly=>5, annual=>3, ad_hoc=>1, none=>0",
        "Regular testing indicates proactive security governance.",
        notes=testing_notes
    ))


    # encryption_at_rest (enum)
    rest_pts = 4
    rest_input = record["encryption_at_rest"]

    if str(rest_input).lower() == "na":
        rest_score = 0
        rest_max = 0
        rest_notes = "Excluded from scoring (not applicable)."
    else:
        rest_score = score_enum(rest_input, {
            "full_with_key_management": 4, "full": 3, "partial": 1, "none": 0
        })
        rest_max = rest_pts
        rest_notes = ""

    results.append(ControlResult(
        "encryption_at_rest", "basic_security_measures", rest_input,
        rest_score, rest_max,
        "full+key_mgmt=>4, full=>3, partial=>1, none=>0",
        "Encryption at rest reduces impact of storage compromise.",
        notes=rest_notes
    ))


    # mfa_enforced (enum)
    mfa_pts = 4
    mfa_input = record["mfa_enforced"]

    if str(mfa_input).lower() == "na":
        mfa_score = 0
        mfa_max = 0
        mfa_notes = "Excluded from scoring (not applicable)."
    else:
        mfa_score = score_enum(mfa_input, {
            "all_users": 4, "privileged_users": 3, "admin_only": 2, "none": 0
        })
        mfa_max = mfa_pts
        mfa_notes = ""

    results.append(ControlResult(
        "mfa_enforced", "basic_security_measures", mfa_input,
        mfa_score, mfa_max,
        "all_users=>4, privileged=>3, admin_only=>2, none=>0",
        "MFA reduces credential abuse and account takeover risk.",
        notes=mfa_notes
    ))

    # -----------------------------
    # B) Transparency & User Rights (40)
    # -----------------------------

    # cookie_consent_mechanism (enum)
    cookie_pts = 5
    cookie_input = record["cookie_consent_mechanism"]

    if str(cookie_input).lower() == "na":
        cookie_score = 0
        cookie_max = 0
        cookie_notes = "Excluded from scoring (not applicable)."
    else:
        cookie_score = score_enum(cookie_input, {
            "granular": 5, "opt_in": 4, "implied": 1, "none": 0
        })
        cookie_max = cookie_pts
        cookie_notes = ""

    results.append(ControlResult(
        "cookie_consent_mechanism", "transparency_user_rights", cookie_input,
        cookie_score, cookie_max,
        "granular=>5, opt_in=>4, implied=>1, none=>0",
        "Consent visibility and quality are important transparency signals for web services.",
        notes=cookie_notes
    ))


    # privacy_policy_present (boolean)
    pol_present_pts = 8
    pol_present_input = record["privacy_policy_present"]

    if str(pol_present_input).lower() == "na":
        pol_present_score = 0
        pol_present_max = 0
        pol_present_notes = "Excluded from scoring (not applicable)."
    else:
        pol_present_score = pol_present_pts if pol_present_input is True else 0
        pol_present_max = pol_present_pts
        pol_present_notes = ""

    results.append(ControlResult(
        "privacy_policy_present", "transparency_user_rights", pol_present_input,
        pol_present_score, pol_present_max,
        "True => 8, False => 0",
        "A privacy policy is a core transparency artefact.",
        notes=pol_present_notes
    ))


    # privacy_policy_clarity (enum with dependency)
    clarity_pts = 7
    clarity_input = record["privacy_policy_clarity"]
    policy_present_input = record["privacy_policy_present"]

    if str(clarity_input).lower() == "na":
        clarity_score = 0
        clarity_max = 0
        clarity_notes = "Excluded from scoring (not applicable)."
    elif str(policy_present_input).lower() == "na":
        clarity_score = 0
        clarity_max = 0
        clarity_notes = "Excluded from scoring because privacy_policy_present is not applicable."
    elif policy_present_input is False:
        clarity_score = 0
        clarity_max = clarity_pts
        clarity_notes = "Dependency applied: privacy_policy_present is False, clarity forced to 0."
    else:
        clarity_score = score_enum(clarity_input, {
            "clear": 7, "partially_clear": 4, "unclear": 2, "missing": 0
        })
        clarity_max = clarity_pts
        clarity_notes = ""

    results.append(ControlResult(
        "privacy_policy_clarity", "transparency_user_rights", clarity_input,
        clarity_score, clarity_max,
        "clear=>7, partially_clear=>4, unclear=>2, missing=>0; if policy missing => 0",
        "Clarity reflects how well data usage, sharing and retention are communicated.",
        notes=clarity_notes
    ))


    # lawful_basis (enum)
    lawful_pts = 8
    lawful_input = record["lawful_basis"]

    if str(lawful_input).lower() == "na":
        lawful_score = 0
        lawful_max = 0
        lawful_notes = "Excluded from scoring (not applicable)."
    else:
        lawful_score = score_enum(lawful_input, {
            "contract": 8, "legal_obligation": 8, "public_task": 8,
            "legitimate_interests": 6, "consent": 6, "vital_interests": 6,
            "mixed": 4
        }, default=0)
        lawful_max = lawful_pts
        lawful_notes = ""

    results.append(ControlResult(
        "lawful_basis", "transparency_user_rights", lawful_input,
        lawful_score, lawful_max,
        "recognised basis=>6–8, mixed=>4, missing/unknown=>0",
        "Identifying a lawful basis is a core requirement for lawful processing (GDPR Art. 6).",
        notes=lawful_notes
    ))


    # third_party_sharing_disclosed (enum)
    third_pts = 6
    third_input = record["third_party_sharing_disclosed"]

    if str(third_input).lower() == "na":
        third_score = 0
        third_max = 0
        third_notes = "Excluded from scoring (not applicable)."
    else:
        third_score = score_enum(third_input, {
            "full": 6, "partial": 3, "unclear": 1, "none": 0
        })
        third_max = third_pts
        third_notes = ""

    results.append(ControlResult(
        "third_party_sharing_disclosed", "transparency_user_rights", third_input,
        third_score, third_max,
        "full=>6, partial=>3, unclear=>1, none=>0",
        "Disclosure of processors/third parties supports transparency obligations.",
        notes=third_notes
    ))


    # dsar_response_time_days (integer)
    dsar_time_pts = 4
    dsar_input = record["dsar_response_time_days"]

    if str(dsar_input).lower() == "na":
        dsar_days = "na"
        dsar_time_score = 0
        dsar_time_max = 0
        dsar_time_notes = "Excluded from scoring (not applicable)."
    elif str(dsar_input).lower() == "empty":
        dsar_days = 0
        dsar_time_score = 0
        dsar_time_max = dsar_time_pts
        dsar_time_notes = "dsar_response_time_days is empty (not documented / no defined timeframe)."
    else:
        dsar_days = int(dsar_input)
        dsar_time_score = score_days(dsar_days, [(30, 4), (45, 2), (10**9, 0)])
        dsar_time_max = dsar_time_pts
        dsar_time_notes = ""

    results.append(ControlResult(
        "dsar_response_time_days", "transparency_user_rights", dsar_days,
        dsar_time_score, dsar_time_max,
        "empty=>0; ≤30=>4, 31–45=>2, >45=>0",
        "GDPR statutory DSAR response baseline is 30 days.",
        notes=dsar_time_notes
    ))


    # dsar_process (enum)
    dsar_proc_pts = 2
    dsar_proc_input = record["dsar_process"]

    if str(dsar_proc_input).lower() == "na":
        dsar_proc_score = 0
        dsar_proc_max = 0
        dsar_proc_notes = "Excluded from scoring (not applicable)."
    else:
        dsar_proc_score = score_enum(dsar_proc_input, {
            "automated": 2, "documented": 2, "partial": 1, "informal": 0, "missing": 0
        })
        dsar_proc_max = dsar_proc_pts
        dsar_proc_notes = ""

    results.append(ControlResult(
        "dsar_process", "transparency_user_rights", dsar_proc_input,
        dsar_proc_score, dsar_proc_max,
        "documented/automated=>2, partial=>1, informal/missing=>0",
        "Process maturity indicates operational ability to honour user rights.",
        notes=dsar_proc_notes
    ))
    
    # -----------------------------
    # C) Internal Controls (30)
    # -----------------------------

    # data_breach_process_maturity (enum)
    breach_proc_pts = 8
    breach_proc_input = record["data_breach_process_maturity"]

    if str(breach_proc_input).lower() == "na":
        breach_proc_score = 0
        breach_proc_max = 0
        breach_proc_notes = "Excluded from scoring (not applicable)."
    else:
        breach_proc_score = score_enum(breach_proc_input, {
            "tested": 8, "documented": 5, "informal": 2, "none": 0
        })
        breach_proc_max = breach_proc_pts
        breach_proc_notes = ""

    results.append(ControlResult(
        "data_breach_process_maturity", "internal_controls", breach_proc_input,
        breach_proc_score, breach_proc_max,
        "tested=>8, documented=>5, informal=>2, none=>0",
        "Incident readiness supports accountability and breach management.",
        notes=breach_proc_notes
    ))


    # breach_notification_hours (integer)
    breach_notify_pts = 5
    breach_input = record["breach_notification_hours"]

    if str(breach_input).lower() == "na":
        breach_hours = "na"
        breach_notify_score = 0
        breach_notify_max = 0
        breach_notes = "Excluded from scoring (not applicable)."
    elif str(breach_input).lower() == "empty":
        breach_hours = 0
        breach_notify_score = 0
        breach_notify_max = breach_notify_pts
        breach_notes = "breach_notification_hours is empty (not documented / no defined notification timeframe)."
    else:
        breach_hours = int(breach_input)
        breach_notify_score = score_days(breach_hours, [(72, 5), (96, 2), (10**9, 0)])
        breach_notify_max = breach_notify_pts
        breach_notes = ""

    results.append(ControlResult(
        "breach_notification_hours", "internal_controls", breach_hours,
        breach_notify_score, breach_notify_max,
        "empty=>0; ≤72=>5, 73–96=>2, >96=>0",
        "Ability to notify within 72 hours supports incident response expectations.",
        notes=breach_notes
    ))

    # data_retention_policy (enum)
    ret_pol_pts = 7
    ret_pol_input = record["data_retention_policy"]

    if str(ret_pol_input).lower() == "na":
        ret_pol_score = 0
        ret_pol_max = 0
        ret_pol_notes = "Excluded from scoring (not applicable)."
    else:
        ret_pol_score = score_enum(ret_pol_input, {
            "legal_only": 7, "mixed": 5, "operational": 3, "indefinite": 1, "none": 0
        })
        ret_pol_max = ret_pol_pts
        ret_pol_notes = ""

    results.append(ControlResult(
        "data_retention_policy", "internal_controls", ret_pol_input,
        ret_pol_score, ret_pol_max,
        "legal_only=>7, mixed=>5, operational=>3, indefinite=>1, none=>0",
        "Retention governance supports storage limitation and accountability.",
        notes=ret_pol_notes
    ))


    # retention_period_days (integer)
    ret_days_pts = 3
    ret_input = record["retention_period_days"]

    if str(ret_input).lower() == "na":
        ret_days = "na"
        ret_days_score = 0
        ret_days_max = 0
        ret_days_notes = "Excluded from scoring (not applicable)."
    elif str(ret_input).lower() == "empty":
        ret_days = 0
        ret_days_score = 0
        ret_days_max = ret_days_pts
        ret_days_notes = "retention_period_days is empty (undefined / not documented)."
    else:
        ret_days = int(ret_input)
        if ret_days == 0:
            ret_days_score = 0
            ret_days_max = ret_days_pts
            ret_days_notes = "retention_period_days is 0 (undefined / not documented)."
        else:
            ret_days_score = score_days(ret_days, [(30, 3), (90, 2), (180, 1), (10**9, 0)])
            ret_days_max = ret_days_pts
            ret_days_notes = ""

    results.append(ControlResult(
        "retention_period_days", "internal_controls", ret_days,
        ret_days_score, ret_days_max,
        "empty=>0; 0=>0; else ≤30=>3, ≤90=>2, ≤180=>1, >180=>0",
        "Shorter retention aligns more closely with minimisation/storage limitation.",
        notes=ret_days_notes
    ))


    # record_of_processing (enum)
    ropa_pts = 3
    ropa_input = record["record_of_processing"]

    if str(ropa_input).lower() == "na":
        ropa_score = 0
        ropa_max = 0
        ropa_notes = "Excluded from scoring (not applicable)."
    else:
        ropa_score = score_enum(ropa_input, {
            "automated": 3, "complete": 3, "partial": 1, "none": 0
        })
        ropa_max = ropa_pts
        ropa_notes = ""

    results.append(ControlResult(
        "record_of_processing", "internal_controls", ropa_input,
        ropa_score, ropa_max,
        "complete/automated=>3, partial=>1, none=>0",
        "Records of processing demonstrate accountability and governance maturity.",
        notes=ropa_notes
    ))


    # dpia_process (enum)
    dpia_pts = 2
    dpia_input = record["dpia_process"]

    if str(dpia_input).lower() == "na":
        dpia_score = 0
        dpia_max = 0
        dpia_notes = "Excluded from scoring (not applicable)."
    else:
        dpia_score = score_enum(dpia_input, {
            "integrated": 2, "documented": 2, "ad_hoc": 1, "none": 0
        })
        dpia_max = dpia_pts
        dpia_notes = ""

    results.append(ControlResult(
        "dpia_process", "internal_controls", dpia_input,
        dpia_score, dpia_max,
        "integrated/documented=>2, ad_hoc=>1, none=>0",
        "A DPIA process supports structured risk assessment for high-risk processing.",
        notes=dpia_notes
    ))


    # has_dpo (enum)
    dpo_pts = 2
    dpo_input = record["has_dpo"]

    if str(dpo_input).lower() == "na":
        dpo_score = 0
        dpo_max = 0
        dpo_notes = "Excluded from scoring (not applicable)."
    else:
        dpo_score = score_enum(dpo_input, {
            "appointed": 2, "outsourced": 2, "informal_role": 1, "none": 0
        })
        dpo_max = dpo_pts
        dpo_notes = ""

    results.append(ControlResult(
        "has_dpo", "internal_controls", dpo_input,
        dpo_score, dpo_max,
        "appointed/outsourced=>2, informal=>1, none=>0",
        "Assigning privacy responsibility supports accountability.",
        notes=dpo_notes
    ))
    
    # -----------------------------
    # Aggregate
    # -----------------------------
    # -----------------------------
    # NEW: N/A-AWARE AGGREGATION
    # -----------------------------

    category_scores = {
        k: {"score": 0, "max": 0}
        for k in CATEGORY_MAX.keys()
    }

    overall = 0
    overall_max = 0
    na_count = 0

    for r in results:

        # -----------------------------
        # DETECT N/A INPUT
        # -----------------------------
        if str(r.input).lower() == "na":
            na_count += 1
            r.justification = "Not applicable to this organisation."
            r.notes = "Excluded from scoring."
            continue

        # -----------------------------
        # NORMAL SCORING
        # -----------------------------
        category_scores[r.category]["score"] += r.score
        category_scores[r.category]["max"] += r.max

        overall += r.score
        overall_max += r.max


    # -----------------------------
    # NORMALISE FINAL SCORE
    # -----------------------------
    if overall_max > 0:
        final_score = int((overall / overall_max) * 100)
    else:
        final_score = 0


    # -----------------------------
    # CATEGORY MAX SAFETY
    # -----------------------------
    for cat in category_scores:
        if category_scores[cat]["max"] == 0:
            category_scores[cat]["max"] = 1


    # -----------------------------
    # RECOMMENDATIONS (FIXED INDENT)
    # -----------------------------
    recs = []
    for r in results:
        if str(r.input).lower() == "na":
            continue  #  skip N/A controls

        if r.score < r.max:
            recs.append({
                "control_id": r.control_id,
                "priority_points_lost": (r.max - r.score),
                "recommendation": recommendation_for(r.control_id),
                "current_score": r.score,
                "max_score": r.max
            })

    recs.sort(key=lambda x: x["priority_points_lost"], reverse=True)


    # -----------------------------
    # RETURN (FIXED)
    # -----------------------------
    return {
        "overall": {
            "score": final_score,
            "band": band_for(final_score),
            "applicable_controls": len(results) - na_count,
            "na_controls": na_count
        },
        "category_scores": category_scores,
        "control_results": [asdict(r) for r in results],
        "recommendations": recs[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scoring_version": SCORING_VERSION,
    }

    # Recommendations (points lost)
    recs = []
    for r in results:
        if r.score < r.max:
            recs.append({
                "control_id": r.control_id,
                "priority_points_lost": (r.max - r.score),
                "recommendation": recommendation_for(r.control_id),
                "current_score": r.score,
                "max_score": r.max
            })
    recs.sort(key=lambda x: x["priority_points_lost"], reverse=True)

    return {
        "overall": {
    "score": final_score,
    "band": band_for(final_score),
    "applicable_controls": len(results) - na_count,
    "na_controls": na_count
        },
        "category_scores": category_scores,
        "control_results": [asdict(r) for r in results],
        "recommendations": recs[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scoring_version": SCORING_VERSION,
    }


def recommendation_for(control_id: str) -> str:
    mapping = {
        "https_enabled": "Enforce HTTPS across all services (HSTS recommended).",
        "password_storage_method": "Use bcrypt/Argon2 with per-user salts; avoid plaintext/weak hashes.",
        "regular_security_testing": "Introduce scheduled security testing (quarterly or continuous where possible).",
        "encryption_at_rest": "Encrypt stored personal data and manage keys securely (KMS/HSM where possible).",
        "mfa_enforced": "Enforce MFA for privileged accounts at minimum; ideally for all users.",
        "cookie_consent_mechanism": "Implement opt-in or granular cookie consent controls where cookies are used.",
        "privacy_policy_present": "Publish an accessible privacy policy covering purposes, rights, sharing and retention.",
        "privacy_policy_clarity": "Improve clarity: lawful basis, retention, third parties, DSAR instructions, contact info.",
        "lawful_basis": "Document a lawful basis per processing activity and ensure it is reflected in policy/UX.",
        "third_party_sharing_disclosed": "Clearly disclose processors/third parties and purposes of sharing.",
        "dsar_response_time_days": "Reduce DSAR response times to ≤30 days and track performance.",
        "dsar_process": "Formalise DSAR workflow (intake, verification, fulfilment, logging).",
        "data_breach_process_maturity": "Create and test an incident response plan with roles and notification steps.",
        "breach_notification_hours": "Improve breach triage and escalation to support ≤72-hour notification.",
        "data_retention_policy": "Define retention per data category and triggers for deletion/anonymisation.",
        "retention_period_days": "Reduce retention where possible and document justification.",
        "record_of_processing": "Maintain a Record of Processing Activities (RoPA) and keep it updated.",
        "dpia_process": "Implement a DPIA workflow for high-risk processing and document decisions.",
        "has_dpo": "Assign a privacy lead or assess whether formal DPO appointment is required.",
    }
    return mapping.get(control_id, "Improve this control to better align with GDPR-inspired best practice.")
