# SecureComply Scoring Rationale

## Overview

This document explains the rationale behind the SecureComply scoring model. It is intended to justify **why specific GDPR-related controls are assessed**, **why they are weighted differently**, and **why certain answers receive more or fewer points**.

The model is not a legal determination of compliance. Instead, it is a **risk-based academic scoring framework** designed to approximate an organisation’s GDPR posture using structured inputs. The scoring logic aims to reward stronger evidence of governance, transparency, and security practice, while clearly penalising weak, missing, or high-risk controls.

The scoring engine evaluates 19 controls across three categories:

- **Basic Security Measures** (30 points)
- **Transparency & User Rights** (40 points)
- **Internal Controls** (30 points)

This gives a total baseline of **100 points**, unless some controls are marked **N/A**, in which case those controls are excluded and the final score is normalised against the remaining applicable maximum. This behaviour is implemented directly in the compliance engine. 

---

## Why the Model Uses Weighted Scoring

Not every GDPR-related control has the same importance. Some controls represent core legal and operational requirements, while others reflect supporting maturity indicators.

For that reason, SecureComply uses a **weighted model** rather than assigning every field equal value.

The weighting was designed around three principles:

1. **Controls central to legal compliance receive more weight**  
   Examples include lawful basis, privacy policy presence, and breach readiness.

2. **Controls that materially reduce organisational risk receive more weight**  
   Examples include HTTPS, password storage, and incident response capability.

3. **Controls that indicate maturity rather than absolute compliance receive fewer points**  
   Examples include having a DPO, DPIA maturity, or partial documentation.

This makes the score more meaningful than a simple checklist. A serious weakness in a major control area has a larger effect than a minor weakness in a lower-impact area. The model structure and category allocations are defined in the compliance engine. fileciteturn0file14

---

## Category Rationale

### 1. Basic Security Measures (30 points)

This category represents the organisation’s technical baseline for protecting personal data. It focuses on safeguards aligned with GDPR Article 32, particularly confidentiality, integrity, and resilience of processing systems.

It includes:
- HTTPS enabled
- Password storage method
- Regular security testing
- Encryption at rest
- MFA enforcement

These controls are included because they are concrete, technically observable, and strongly linked to data protection outcomes. The category is capped at 30 points to reflect its major importance, while still leaving room for governance and transparency to influence the overall result. 

#### Why these weights?

- **HTTPS enabled (8 points):** Strong weighting because encryption in transit is a fundamental baseline control for protecting personal data against interception.
- **Password storage method (8 points):** Also heavily weighted because insecure password handling can directly lead to account compromise and personal data exposure.
- **Regular security testing (6 points):** Important because it reflects whether the organisation actively identifies weaknesses instead of waiting for incidents.
- **Encryption at rest (4 points):** Valuable, but slightly lower weighted because not every system stores sensitive data in the same way and its impact can vary by environment.
- **MFA enforced (4 points):** Important for credential abuse prevention, but given a slightly smaller weight than password storage and HTTPS because it is one part of access protection rather than a full security control set.

---

### 2. Transparency & User Rights (40 points)

This is the highest-weighted category because GDPR is not only a security framework. It is primarily a **data protection and accountability regulation**, and transparency obligations are central to lawful processing.

It includes:
- Cookie consent mechanism
- Privacy policy presence
- Privacy policy clarity
- Lawful basis
- Third-party sharing disclosure
- DSAR response time
- DSAR process maturity

This category is worth **40 points**, the largest share of the model, because an organisation may have decent technical security while still failing core GDPR obligations such as lawful processing, transparency, or data subject rights handling. fileciteturn0file14

#### Why these weights?

- **Privacy policy present (8 points):** Highly weighted because the absence of a privacy policy represents a major transparency failure.
- **Lawful basis (8 points):** Highly weighted because identifying a lawful basis is fundamental to lawful processing under GDPR Article 6.
- **Privacy policy clarity (7 points):** Strong weighting because a policy that exists but is unclear still weakens transparency in practice.
- **Third-party sharing disclosure (6 points):** Important because users should know whether their data is shared and for what purpose.
- **Cookie consent mechanism (5 points):** Significant, especially for web-facing services, because it reflects the quality of consent controls.
- **DSAR response time (4 points):** Moderately weighted because timeliness matters, but it is only one part of rights handling.
- **DSAR process maturity (2 points):** Lower weighted because this is more of an operational maturity signal than a standalone legal requirement.

The category therefore balances **legal compliance essentials** with **practical operational capability**.

---

### 3. Internal Controls (30 points)

This category measures governance maturity, incident handling, documentation, and accountability. It reflects whether the organisation can sustain compliance over time rather than merely demonstrating isolated technical controls.

It includes:
- Data breach process maturity
- Breach notification hours
- Data retention policy
- Retention period days
- Record of processing
- DPIA process
- DPO presence

This category is weighted at 30 points because these controls strongly affect the organisation’s ability to respond to incidents, demonstrate accountability, and maintain defensible privacy practices. fileciteturn0file14

#### Why these weights?

- **Data breach process maturity (8 points):** Highly weighted because breach handling is one of the most operationally critical GDPR functions.
- **Data retention policy (7 points):** Strongly weighted because storage limitation is a core GDPR principle and poor retention creates unnecessary risk.
- **Breach notification hours (5 points):** Important because the 72-hour notification concept is central to breach response expectations.
- **Retention period days (3 points):** Lower weighted than the policy itself because the presence of a defensible retention framework matters more than a raw number on its own.
- **Record of processing (3 points):** Moderate value because it supports accountability and auditability.
- **DPIA process (2 points):** Lower weighted because it applies more strongly in specific higher-risk cases, so it indicates maturity rather than universal failure.
- **Has DPO (2 points):** Also lower weighted because not every organisation is required to formally appoint a DPO, although assigning responsibility remains good practice.

---

## Why Some Answers Score Partially

The scoring model uses **graduated scoring** instead of simple yes/no answers wherever possible. This is intentional.

Many compliance controls are not binary in real organisations. For example:
- `bcrypt` is stronger than `sha256`, but weaker than `argon2`
- quarterly testing is better than annual testing
- partial disclosure is better than none
- documented processes are better than informal ones

This allows the tool to reflect **maturity progression**, not just pass/fail outcomes. The scoring engine therefore supports partial marks for intermediate states, which makes results more realistic and more useful for remediation planning. This mapping is defined in the control-by-control scoring logic. fileciteturn0file14

---

## Why Weak Security Choices Are Penalised Heavily

Some options deliberately receive very low scores, such as:
- `plaintext` password storage
- no privacy policy
- no lawful basis
- no retention policy
- no breach process

These are heavily penalised because they represent either:
- a major absence of control,
- a high-risk security weakness,
- or a likely failure of GDPR accountability principles.

The aim is to ensure that serious gaps are visible in the final score and cannot be hidden by doing well in a large number of lower-value areas.

---

## Why Dependency Rules Exist

Some scoring decisions depend on related fields. This is to stop logically inconsistent inputs producing misleading scores.

Examples include:
- If `privacy_policy_present` is `False`, then `privacy_policy_clarity` cannot meaningfully score well.
- If a control is marked `N/A`, it is excluded from scoring.
- Numeric timing fields such as DSAR response days and breach notification hours only score when valid and applicable.

This makes the model more defensible because scores are not assigned in isolation. The validation and scoring code both contain logic to enforce these relationships. fileciteturn0file3 fileciteturn0file14

---

## Why N/A Controls Are Excluded

SecureComply supports **not applicable** values. This was added because some organisations may not process data in ways that make every control relevant.

If an answer is marked `N/A`:
- the control is accepted,
- it is removed from the applicable scoring maximum,
- and the final score is normalised against the remaining relevant controls.

This prevents organisations from being unfairly penalised for controls that genuinely do not apply to their context. The compliance engine tracks both applicable controls and excluded controls in the final result. fileciteturn0file14

---

## Why the Final Score Is Normalised

The final score is expressed as a percentage out of 100, even when some controls are excluded.

The rationale is simple:
- it makes reports easy to interpret,
- it supports comparisons across organisations,
- and it avoids misleading raw totals when the applicable maximum changes.

For example, if several controls are excluded as N/A, the tool does **not** keep the denominator fixed at 100. Instead, it calculates:

**final score = (points earned / applicable maximum) × 100**

This ensures the result remains fair and comparable. That normalisation is explicitly implemented in the scoring engine. fileciteturn0file14

---

## Why Recommendations Are Based on Points Lost

Recommendations are prioritised according to **points lost** rather than simply listing all failed controls equally.

This is important because it gives the output practical value. A control that loses 8 points should normally be addressed before one that loses 1 or 2 points. By sorting recommendations by points lost, the report highlights the most meaningful remediation actions first. That prioritisation is built directly into the audit output. fileciteturn0file14

---

## Why Host Telemetry Does Not Affect the Score

Host telemetry is included in SecureComply as contextual security evidence, but it is intentionally kept **non-scoring**.

Examples include:
- firewall status
- patch management status
- automatic updates
- system logging
- open ports

The rationale for excluding these from the main score is that the core model is designed around **declared GDPR control inputs** rather than environment-specific infrastructure scanning. Keeping host telemetry separate avoids distorting the GDPR score while still giving useful supporting context in the report. This separation is visible in the merge logic and reporting flow. fileciteturn0file0 fileciteturn0file1 fileciteturn0file9

---

## Why the Model Is Suitable for This Project

This scoring approach is appropriate for the SecureComply project because it:

- translates GDPR-related controls into a measurable framework,
- balances legal, technical, and operational factors,
- supports explainability through clear scoring rules,
- produces prioritised remediation guidance,
- and remains flexible through support for missing and N/A values.

For an academic final-year project, this is important because the model is not a black box. Each score can be traced back to an explicit rule, justification, and weighting decision in the compliance engine. fileciteturn0file14

---
