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


def compute_audit(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    record MUST be the flattened, validated structure (post-ingestion).
    """

    results: List[ControlResult] = []

    # -----------------------------
    # A) Basic Security Measures (30)
    # -----------------------------
    https_pts = 8
    results.append(ControlResult(
        "https_enabled", "basic_security_measures", record["https_enabled"],
        https_pts if record["https_enabled"] is True else 0, https_pts,
        "True => 8, False => 0",
        "Encryption in transit supports confidentiality and is aligned with GDPR Art. 32."
    ))

    pwd_pts = 8
    pwd_score = score_enum(record["password_storage_method"], {
        "argon2": 8, "bcrypt": 7, "sha256": 4, "md5": 1, "plaintext": 0, "unknown": 0
    })
    results.append(ControlResult(
        "password_storage_method", "basic_security_measures", record["password_storage_method"],
        pwd_score, pwd_pts,
        "argon2=>8, bcrypt=>7, sha256=>4, md5=>1, plaintext/unknown=>0",
        "Stronger password hashing reduces account compromise risk."
    ))

    test_pts = 6
    testing_score = score_enum(record["regular_security_testing"], {
        "continuous": 6, "quarterly": 5, "annual": 3, "ad_hoc": 1, "none": 0
    })
    results.append(ControlResult(
        "regular_security_testing", "basic_security_measures", record["regular_security_testing"],
        testing_score, test_pts,
        "continuous=>6, quarterly=>5, annual=>3, ad_hoc=>1, none=>0",
        "Regular testing indicates proactive security governance."
    ))

    rest_pts = 4
    rest_score = score_enum(record["encryption_at_rest"], {
        "full_with_key_management": 4, "full": 3, "partial": 1, "none": 0
    })
    results.append(ControlResult(
        "encryption_at_rest", "basic_security_measures", record["encryption_at_rest"],
        rest_score, rest_pts,
        "full+key_mgmt=>4, full=>3, partial=>1, none=>0",
        "Encryption at rest reduces impact of storage compromise."
    ))

    mfa_pts = 4
    mfa_score = score_enum(record["mfa_enforced"], {
        "all_users": 4, "privileged_users": 3, "admin_only": 2, "none": 0
    })
    results.append(ControlResult(
        "mfa_enforced", "basic_security_measures", record["mfa_enforced"],
        mfa_score, mfa_pts,
        "all_users=>4, privileged=>3, admin_only=>2, none=>0",
        "MFA reduces credential abuse and account takeover risk."
    ))

    # -----------------------------
    # B) Transparency & User Rights (40)
    # -----------------------------
    cookie_pts = 5
    cookie_score = score_enum(record["cookie_consent_mechanism"], {
        "granular": 5, "opt_in": 4, "implied": 1, "none": 0
    })
    results.append(ControlResult(
        "cookie_consent_mechanism", "transparency_user_rights", record["cookie_consent_mechanism"],
        cookie_score, cookie_pts,
        "granular=>5, opt_in=>4, implied=>1, none=>0",
        "Consent visibility and quality are important transparency signals for web services."
    ))

    pol_present_pts = 8
    results.append(ControlResult(
        "privacy_policy_present", "transparency_user_rights", record["privacy_policy_present"],
        pol_present_pts if record["privacy_policy_present"] is True else 0, pol_present_pts,
        "True => 8, False => 0",
        "A privacy policy is a core transparency artefact."
    ))

    clarity_pts = 7
    if record["privacy_policy_present"] is False:
        clarity_score = 0
        notes = "Dependency applied: privacy_policy_present is False, clarity forced to 0."
    else:
        clarity_score = score_enum(record["privacy_policy_clarity"], {
            "clear": 7, "partially_clear": 4, "unclear": 2, "missing": 0
        })
        notes = ""
    results.append(ControlResult(
        "privacy_policy_clarity", "transparency_user_rights", record["privacy_policy_clarity"],
        clarity_score, clarity_pts,
        "clear=>7, partially_clear=>4, unclear=>2, missing=>0; if policy missing => 0",
        "Clarity reflects how well data usage, sharing and retention are communicated.",
        notes=notes
    ))

    lawful_pts = 8
    lawful_score = score_enum(record["lawful_basis"], {
        "contract": 8, "legal_obligation": 8, "public_task": 8,
        "legitimate_interests": 6, "consent": 6, "vital_interests": 6,
        "mixed": 4
    }, default=0)
    results.append(ControlResult(
        "lawful_basis", "transparency_user_rights", record["lawful_basis"],
        lawful_score, lawful_pts,
        "recognised basis=>6–8, mixed=>4, missing/unknown=>0",
        "Identifying a lawful basis is a core requirement for lawful processing (GDPR Art. 6)."
    ))

    third_pts = 6
    third_score = score_enum(record["third_party_sharing_disclosed"], {
        "full": 6, "partial": 3, "unclear": 1, "none": 0
    })
    results.append(ControlResult(
        "third_party_sharing_disclosed", "transparency_user_rights", record["third_party_sharing_disclosed"],
        third_score, third_pts,
        "full=>6, partial=>3, unclear=>1, none=>0",
        "Disclosure of processors/third parties supports transparency obligations."
    ))

    dsar_time_pts = 4
    dsar_days = int(record["dsar_response_time_days"])
    dsar_time_score = score_days(dsar_days, [(30, 4), (45, 2), (10**9, 0)])
    results.append(ControlResult(
        "dsar_response_time_days", "transparency_user_rights", dsar_days,
        dsar_time_score, dsar_time_pts,
        "≤30=>4, 31–45=>2, >45=>0",
        "GDPR statutory DSAR response baseline is 30 days."
    ))

    dsar_proc_pts = 2
    dsar_proc_score = score_enum(record["dsar_process"], {
        "automated": 2, "documented": 2, "partial": 1, "informal": 0, "missing": 0
    })
    results.append(ControlResult(
        "dsar_process", "transparency_user_rights", record["dsar_process"],
        dsar_proc_score, dsar_proc_pts,
        "documented/automated=>2, partial=>1, informal/missing=>0",
        "Process maturity indicates operational ability to honour user rights."
    ))

    # -----------------------------
    # C) Internal Controls (30)
    # -----------------------------
    breach_proc_pts = 8
    breach_proc_score = score_enum(record["data_breach_process_maturity"], {
        "tested": 8, "documented": 5, "informal": 2, "none": 0
    })
    results.append(ControlResult(
        "data_breach_process_maturity", "internal_controls", record["data_breach_process_maturity"],
        breach_proc_score, breach_proc_pts,
        "tested=>8, documented=>5, informal=>2, none=>0",
        "Incident readiness supports accountability and breach management."
    ))

    breach_notify_pts = 5
    breach_hours = int(record["breach_notification_hours"])
    breach_notify_score = score_days(breach_hours, [(72, 5), (96, 2), (10**9, 0)])
    results.append(ControlResult(
        "breach_notification_hours", "internal_controls", breach_hours,
        breach_notify_score, breach_notify_pts,
        "≤72=>5, 73–96=>2, >96=>0",
        "Ability to notify within 72 hours supports incident response expectations."
    ))

    ret_pol_pts = 7
    ret_pol_score = score_enum(record["data_retention_policy"], {
        "legal_only": 7, "mixed": 5, "operational": 3, "indefinite": 1, "none": 0
    })
    results.append(ControlResult(
        "data_retention_policy", "internal_controls", record["data_retention_policy"],
        ret_pol_score, ret_pol_pts,
        "legal_only=>7, mixed=>5, operational=>3, indefinite=>1, none=>0",
        "Retention governance supports storage limitation and accountability."
    ))

    ret_days_pts = 3
    ret_days = int(record["retention_period_days"])
    # Here, shorter retention earns more points; 0 means undefined
    if ret_days == 0:
        ret_days_score = 0
        notes = "retention_period_days is 0 (undefined / not documented)."
    else:
        ret_days_score = score_days(ret_days, [(30, 3), (90, 2), (180, 1), (10**9, 0)])
        notes = ""
    results.append(ControlResult(
        "retention_period_days", "internal_controls", ret_days,
        ret_days_score, ret_days_pts,
        "0=>0; else ≤30=>3, ≤90=>2, ≤180=>1, >180=>0",
        "Shorter retention aligns more closely with minimisation/storage limitation.",
        notes=notes
    ))

    ropa_pts = 3
    ropa_score = score_enum(record["record_of_processing"], {
        "automated": 3, "complete": 3, "partial": 1, "none": 0
    })
    results.append(ControlResult(
        "record_of_processing", "internal_controls", record["record_of_processing"],
        ropa_score, ropa_pts,
        "complete/automated=>3, partial=>1, none=>0",
        "Records of processing demonstrate accountability and governance maturity."
    ))

    dpia_pts = 2
    dpia_score = score_enum(record["dpia_process"], {
        "integrated": 2, "documented": 2, "ad_hoc": 1, "none": 0
    })
    results.append(ControlResult(
        "dpia_process", "internal_controls", record["dpia_process"],
        dpia_score, dpia_pts,
        "integrated/documented=>2, ad_hoc=>1, none=>0",
        "A DPIA process supports structured risk assessment for high-risk processing."
    ))

    dpo_pts = 2
    dpo_score = score_enum(record["has_dpo"], {
        "appointed": 2, "outsourced": 2, "informal_role": 1, "none": 0
    })
    results.append(ControlResult(
        "has_dpo", "internal_controls", record["has_dpo"],
        dpo_score, dpo_pts,
        "appointed/outsourced=>2, informal=>1, none=>0",
        "Assigning privacy responsibility supports accountability."
    ))

    # -----------------------------
    # Aggregate
    # -----------------------------
    category_scores = {k: {"score": 0, "max": v} for k, v in CATEGORY_MAX.items()}
    overall = 0
    for r in results:
        category_scores[r.category]["score"] += r.score
        overall += r.score

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
        "overall": {"score": overall, "band": band_for(overall)},
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
