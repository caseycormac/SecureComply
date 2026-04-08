# report_generator.py
# Version_03 - HTML dashboard (NO OpenAI, NO matplotlib)
# Charts are pure HTML/CSS: donut (conic-gradient) + bars
# Works with audit_result_v2.json structure: {"audit_results":[{...}], "invalid_records":[...]}

from __future__ import annotations

import os
import json
import glob
from datetime import datetime
from pydoc import html
from typing import Dict, Any, List, Tuple
#from ai_narrative import generate_ciso_ai
from .ai_narrative import generate_ciso_ai
from config import PROJECT_VERSION


# -----------------------------
# Defaults (you can change these)
# -----------------------------
DEFAULT_REPORTS_DIR = "reports"
DEFAULT_HTML_OUT = os.path.join(DEFAULT_REPORTS_DIR, "audit_report_v3.html")

#test
def load_benchmark():
    """
    Loads precomputed benchmark data.

    WHY:
    - Benchmark is generated offline (not every run)
    - This function safely loads it
    - Returns None if file missing (robust design)
    """
    try:
        with open("benchmark/benchmark.json") as f:
            return json.load(f)
    except:
        return None
#test

# -----------------------------
# File helpers
# -----------------------------
def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _find_latest_audit_json(reports_dir: str) -> str:
    """
    Finds the most recently modified audit_result*.json file in reports_dir.
    """
    pattern = os.path.join(reports_dir, "audit_result*.json")
    candidates = glob.glob(pattern)
    if not candidates:
        raise FileNotFoundError(
            f"No audit files found. Expected something like: {pattern}\n"
            f"Run pipeline.py first, or pass a path explicitly."
        )
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def _load_first_audit(audit_json_path: str) -> dict:
    data = _read_json(audit_json_path)
    audits = data.get("audit_results", [])
    if not audits:
        raise RuntimeError(f"No audit_results found in {audit_json_path}")
    return audits[0]


def _html_escape(s: Any) -> str:
    s = "" if s is None else str(s)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


# -----------------------------
# Audit analysis helpers
# -----------------------------
def _overall_score_and_band(audit: dict) -> Tuple[int, str, str]:
    overall = audit.get("overall", {}) or {}
    score = int(overall.get("score", 0) or 0)
    band = str(overall.get("band", "Unknown") or "Unknown")
    summary = str(overall.get("summary", "") or "")
    return score, band, summary


def _risk_level(score: int) -> str:
    # Simple heuristic labels
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Moderate"
    if score >= 50:
        return "High"
    return "Critical"


def _top_gaps_points_lost(audit: dict, n: int = 5) -> List[dict]:
    """
    Returns top controls by points lost (max-score), descending.
    Each element includes: control_id, category, lost, score, max, justification.
    """
    out = []
    for c in (audit.get("control_results", []) or []):
        try:
            s = int(c.get("score", 0) or 0)
            m = int(c.get("max", 0) or 0)
        except Exception:
            s, m = 0, 0
        lost = max(0, m - s)
        if lost > 0:
            out.append({
                "control_id": c.get("control_id", ""),
                "category": c.get("category", ""),
                "lost": lost,
                "score": s,
                "max": m,
                "justification": c.get("justification", ""),
            })
    out.sort(key=lambda x: x["lost"], reverse=True)
    return out[:n]


def _category_scores(audit: dict) -> Dict[str, Dict[str, int]]:
    """
    Example:
      "category_scores": {
         "basic_security_measures": {"score": 13, "max": 30},
         ...
      }
    """
    return audit.get("category_scores", {}) or {}


def _category_percent(cat_score: dict) -> float:
    s = float(cat_score.get("score", 0) or 0)
    m = float(cat_score.get("max", 0) or 0)
    return 0.0 if m <= 0 else (s / m) * 100.0

#------------------------------
# Additional
#------------------------------

def _render_extra_security(audit: dict) -> str:

    extra = audit.get("extra_security_signals", {})

    if not extra:
        return "<div class='muted'>No host security signals detected.</div>"

    rows = ""

    mapping = {
        "patch_management_status": "Patch Management",
        "firewall_enabled": "Firewall Enabled",
        "automatic_updates": "Automatic Updates",
        "system_logging_enabled": "System Logging",
        "open_port_count": "Open Port Count",
        "open_ports": "Open Ports"
    }

    for key, label in mapping.items():
        value = extra.get(key, "unknown")

        recommendation = {
            "patch_management_status": "Implement automated patch management and vulnerability remediation.",
            "firewall_enabled": "Enable host-based firewall to improve network boundary protection.",
            "automatic_updates": "Enable automatic security updates where possible.",
            "system_logging_enabled": "Ensure system logging is enabled and logs are centrally monitored.",
            "open_port_count": "Reduce exposed services to minimise attack surface.",
            "open_ports": "Review exposed ports and disable unnecessary services."
        }.get(key, "")

        rows += f"""
        <tr>
            <td>{label}</td>
            <td>{value}</td>
            <td>{recommendation}</td>
        </tr>
        """

    return f"""
    <div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th>Security Indicator</th>
                <th>Status</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    </div>
    """

# ------------------------------
# NEW: Remediation Task Plan + Projected Score
# ------------------------------
def _build_task_plan(audit: dict):

    """
    Builds a prioritised remediation plan from:
    - GDPR scoring recommendations (SCORING impact)
    - Host security signals (NON-SCORING)

    Also calculates projected score after fixes.
    """

    tasks = []
    total_gain = 0

    # --- Use existing recommendations (already sorted by impact) ---
    for r in audit.get("recommendations", []):
        lost = int(r.get("priority_points_lost", 0))

        # Priority based on impact
        if lost >= 7:
            priority = "High"
        elif lost >= 4:
            priority = "Medium"
        else:
            priority = "Low"

        # Effort estimation (simple mapping)
        effort_map = {
            "https_enabled": "Medium",
            "privacy_policy_present": "Medium",
            "privacy_policy_clarity": "Medium",
            "data_retention_policy": "Medium",
            "regular_security_testing": "Medium",
            "third_party_sharing_disclosed": "Low",
            "breach_notification_hours": "Medium",
            "encryption_at_rest": "High",
        }

        effort = effort_map.get(r["control_id"], "Medium")

        # Add GDPR scoring task
        tasks.append({
            "task": r["recommendation"],
            "impact": f"+{lost} pts",
            "priority": priority,
            "effort": effort
        })

        total_gain += lost

    # --- Add host-based security tasks (NON-SCORING) ---
    extra = audit.get("extra_security_signals", {})

    if extra.get("firewall_enabled") is False:
        tasks.append({
            "task": "Enable host-based firewall",
            "impact": "Non-scoring",
            "priority": "Low",
            "effort": "Low"
        })

    if extra.get("system_logging_enabled") is False:
        tasks.append({
            "task": "Enable system logging and monitoring",
            "impact": "Non-scoring",
            "priority": "Low",
            "effort": "Low"
        })

    if extra.get("patch_management_status") == "outdated":
        tasks.append({
            "task": "Implement automated patch management",
            "impact": "Non-scoring",
            "priority": "Medium",
            "effort": "Medium"
        })

    # --- Calculate projected score ---
    current_score = audit.get("overall", {}).get("score", 0)

    # Conservative projection (more realistic for grading)
    projected_score = min(100, current_score + int(total_gain * 0.8))

    return tasks, current_score, projected_score

def _render_task_plan(audit: dict) -> str:
    """
    Renders remediation plan as HTML table.
    """

    tasks, current, projected = _build_task_plan(audit)

    rows = ""
    for t in tasks:
        rows += f"""
        <tr>
            <td>{t['priority']}</td>
            <td>{t['task']}</td>
            <td>{t['impact']}</td>
            <td>{t['effort']}</td>
        </tr>
        """

    return f"""
    <div style="margin-bottom:10px;">
        <strong>Projected Score After Fixes:</strong>
        {current} → <span style="color:#16a34a; font-weight:700;">{projected}</span> / 100
    </div>

    <div class="table-wrap">
    <table>
        <thead>
            <tr>
                <th>Priority</th>
                <th>Task</th>
                <th>Impact</th>
                <th>Effort</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    </div>
    """


# -----------------------------
# Deterministic CISO-style statement (NO OpenAI)
# -----------------------------
def _ciso_risk_statement(audit: dict) -> str:
    score, band, summary = _overall_score_and_band(audit)
    risk = _risk_level(score)
    gaps = _top_gaps_points_lost(audit, n=3)
    recs = audit.get("recommendations", []) or []

    if gaps:
        drivers = ", ".join([f"{g['control_id']} ({g['category']})" for g in gaps])
    else:
        drivers = "no material control deficiencies identified by the scoring rules"

    # Pull 1-2 rec titles (short)
    rec_texts = []
    for r in recs[:2]:
        if isinstance(r, dict) and r.get("recommendation"):
            rec_texts.append(str(r.get("recommendation")))
    rec_line = ""
    if rec_texts:
        rec_line = f" Immediate remediation should prioritise: {rec_texts[0]}"
        if len(rec_texts) > 1:
            rec_line += f" Next: {rec_texts[1]}"

    # CISO-style paragraph (board-friendly)
    return (
        f"Based on this audit, the organisation’s GDPR control posture is rated '{band}' "
        f"with an overall score of {score}/100 ({risk} risk). "
        f"The most material risk drivers are: {drivers}. "
        f"If unaddressed, these gaps increase the likelihood of non-compliance outcomes (e.g., insufficient transparency, "
        f"weak security governance, or delayed rights handling), potentially resulting in regulatory scrutiny, "
        f"reputational impact, and operational disruption."
        f"{rec_line} "
        f"Evidence capture and re-audit are recommended to demonstrate measurable improvement and auditability."
        + (f" Context: {summary}" if summary else "")
    )



# -----------------------------
# HTML chart components (pure CSS)
# -----------------------------
def _donut_overall(score: int) -> str:
    score = max(0, min(100, int(score)))
    # conic-gradient: filled then remainder
    return f"""
      <div class="donut" style="--p:{score};">
        <div class="donut-inner">
          <div class="donut-num">{score}</div>
          <div class="donut-sub">/ 100</div>
        </div>
      </div>
    """


def _bar_row(label: str, pct: float, right_text: str) -> str:
    pct = max(0.0, min(100.0, pct))
    return f"""
      <div class="bar-row">
        <div class="bar-label">{_html_escape(label)}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:{pct:.1f}%;"></div>
        </div>
        <div class="bar-val">{_html_escape(right_text)}</div>
      </div>
    """


def _render_category_bars(audit: dict) -> str:
    cats = _category_scores(audit)
    if not cats:
        return "<div class='muted'>No category_scores found.</div>"

    # Sort by lowest % first (shows weaknesses)
    items = []
    for k, v in cats.items():
        pct = _category_percent(v)
        items.append((pct, k, v.get("score", 0), v.get("max", 0)))
    items.sort(key=lambda t: t[0])

    rows = []
    for pct, name, s, m in items:
        rows.append(_bar_row(name, pct, f"{s}/{m} ({pct:.0f}%)"))
    return "<div class='bars'>" + "\n".join(rows) + "</div>"


def _render_top_gaps(audit: dict) -> str:
    gaps = _top_gaps_points_lost(audit, n=6)
    if not gaps:
        return "<div class='muted'>No gaps detected (all controls at max score).</div>"

    # Scale bars relative to biggest gap
    max_lost = max(g["lost"] for g in gaps) or 1
    rows = []
    for g in gaps:
        pct = (g["lost"] / max_lost) * 100.0
        label = f"{g['control_id']}  •  {g['category']}"
        right = f"Lost {g['lost']} pts ({g['score']}/{g['max']})"
        rows.append(_bar_row(label, pct, right))
    return "<div class='bars'>" + "\n".join(rows) + "</div>"


# -----------------------------
# Tables
# -----------------------------
def _render_recommendations_table(audit: dict) -> str:
    recs = audit.get("recommendations", []) or []
    if not recs:
        return "<div class='muted'>No recommendations generated.</div>"

    rows = []
    for r in recs:
        if not isinstance(r, dict):
            continue
        rows.append(f"""
          <tr>
            <td><code>{_html_escape(r.get("control_id",""))}</code></td>
            <td>{_html_escape(r.get("priority_points_lost",""))}</td>
            <td>{_html_escape(r.get("current_score",""))}/{_html_escape(r.get("max_score",""))}</td>
            <td>{_html_escape(r.get("recommendation",""))}</td>
          </tr>
        """)

    return f"""
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Control</th>
              <th>Points Lost</th>
              <th>Current</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    """


def _render_controls_table(audit: dict) -> str:
    controls = audit.get("control_results", []) or []
    if not controls:
        return "<div class='muted'>No control_results found.</div>"

    rows = []
    for c in controls:
        score = int(c.get("score", 0) or 0)
        maxs = int(c.get("max", 0) or 0)
        status = "Pass" if score == maxs else ("Partial" if score > 0 else "Fail")
        status_cls = "pill pass" if status == "Pass" else ("pill partial" if status == "Partial" else "pill fail")

        rows.append(f"""
          <tr>
            <td>{_html_escape(c.get("category",""))}</td>
            <td><code>{_html_escape(c.get("control_id",""))}</code></td>
            <td><span class="{status_cls}">{status}</span></td>
            <td><strong>{score}/{maxs}</strong></td>
            <td><code>{_html_escape(c.get("rule",""))}</code></td>
            <td>{_html_escape(c.get("justification",""))}</td>
            <td class="muted">{_html_escape(c.get("notes",""))}</td>
          </tr>
        """)

    return f"""
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Category</th>
              <th>Control</th>
              <th>Status</th>
              <th>Score</th>
              <th>Rule</th>
              <th>Justification</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    """


# -----------------------------
# HTML page
# -----------------------------
def generate_html(audit: dict, source_json: str, use_ai: bool = True) -> str:
    score, band, summary = _overall_score_and_band(audit)
    #test
    benchmark = load_benchmark()
    #test
    ts = _html_escape(audit.get("timestamp", ""))
    version = _html_escape(audit.get("scoring_version", ""))
    extra_security = _render_extra_security(audit)
    # NEW: Build remediation task plan section
    task_plan = _render_task_plan(audit)

    #ai_text = generate_ciso_ai(audit)

    #  ALWAYS DEFINE ciso + ai_used
    if use_ai:
        ai_text = generate_ciso_ai(audit)

        if ai_text:
            ciso = ai_text
            ai_used = True
        else:
            ciso = _ciso_risk_statement(audit)
            ai_used = False
    else:
        ciso = _ciso_risk_statement(audit)
        ai_used = False

    
        

    donut = _donut_overall(score)
    cat_bars = _render_category_bars(audit)
    top_gaps = _render_top_gaps(audit)
    recs_table = _render_recommendations_table(audit)
    controls_table = _render_controls_table(audit)

# -----------------------------
# Benchmark comparison section
# -----------------------------
    if benchmark:
        benchmark_html = f"""
        <div class="card">
          <div class="card-header">
            <h2>Benchmark Comparison</h2>
            <div class="pill">Synthetic SME baseline</div>
          </div>

          <p><strong>Your Score:</strong> {score}</p>
          <p><strong>SME Average:</strong> {benchmark['average_score']}</p>
          <p><strong>Median:</strong> {benchmark['quartiles']['median']}</p>
          <p><strong>Top Quartile (Q3):</strong> {benchmark['quartiles']['q3']}</p>
        </div>
        """
    else:
        benchmark_html = """
        <div class="card">
          <div class="card-header">
            <h2>Benchmark Comparison</h2>
          </div>
          <p class="muted">Benchmark data not available.</p>
        </div>
        """
#----
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    html =  f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>GDPR Audit Report (V03)</title>
  <style>
    :root {{
      --bg: #f6f7fb;
      --card: #ffffff;
      --text: #111827;
      --muted: #6b7280;
      --border: #e5e7eb;

      --good: #16a34a;
      --warn: #f59e0b;
      --bad: #dc2626;

      --accent: #3b82f6;
      --accent2: #22c55e;
    }}

    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: var(--bg);
      color: var(--text);
    }}

    .container {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 22px 14px 60px;
    }}

    .top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }}

    h1 {{ margin: 0; font-size: 20px; }}
    h2 {{ margin: 0; font-size: 16px; }}
    .muted {{ color: var(--muted); }}
    .tiny {{ font-size: 12px; }}

    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    @media (max-width: 900px) {{
      .grid {{ grid-template-columns: 1fr; }}
    }}

    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px;
      box-shadow: 0 1px 10px rgba(0,0,0,0.04);
    }}
    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
    }}

    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: #f9fafb;
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
    }}
    .pill.pass {{ color: var(--good); border-color: rgba(22,163,74,.25); }}
    .pill.partial {{ color: var(--warn); border-color: rgba(245,158,11,.25); }}
    .pill.fail {{ color: var(--bad); border-color: rgba(220,38,38,.25); }}

    /* Donut chart */
    .donut {{
      width: 140px;
      height: 140px;
      border-radius: 50%;
      background: conic-gradient(var(--accent) calc(var(--p) * 1%), #e5e7eb 0);
      display: grid;
      place-items: center;
      margin-top: 6px;
    }}
    .donut-inner {{
      width: 98px;
      height: 98px;
      border-radius: 50%;
      background: #fff;
      border: 1px solid var(--border);
      display: grid;
      place-items: center;
      text-align: center;
      padding-top: 6px;
    }}
    .donut-num {{ font-size: 24px; font-weight: 800; line-height: 1; }}
    .donut-sub {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}

    /* Bars */
    .bars {{ display: grid; gap: 10px; margin-top: 6px; }}
    .bar-row {{
      display: grid;
      grid-template-columns: 220px 1fr 170px;
      gap: 10px;
      align-items: center;
    }}
    @media (max-width: 900px) {{
      .bar-row {{ grid-template-columns: 1fr; }}
    }}
    .bar-label {{ font-size: 13px; color: #111827; }}
    .bar-track {{
      height: 10px;
      border-radius: 999px;
      background: #eef2ff;
      border: 1px solid var(--border);
      overflow: hidden;
    }}
    .bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, var(--accent), var(--accent2));
    }}
    .bar-val {{ font-size: 12px; color: var(--muted); text-align: right; }}
    @media (max-width: 900px) {{
      .bar-val {{ text-align: left; }}
    }}

    /* Tables */
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 14px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
      background: #fff;
    }}
    th, td {{
      padding: 10px;
      border-bottom: 1px solid #f0f0f0;
      vertical-align: top;
      font-size: 13px;
    }}
    th {{
      position: sticky;
      top: 0;
      background: #fafafa;
      color: var(--muted);
      z-index: 1;
      text-align: left;
    }}
    code {{
      background: #f3f4f6;
      padding: 2px 6px;
      border-radius: 8px;
    }}

    .footer-ciso {{
      border: 1px solid #fed7aa;
      background: linear-gradient(180deg, #fff 0%, #fff7ed 100%);
    }}
  </style>
</head>

<body>
  <div class="container">

    <div class="top">
      <div>
        <h1>GDPR Audit Report ({PROJECT_VERSION})</h1>
        <div class="muted tiny">Generated: {now} • Source: {_html_escape(source_json)}</div>
      </div>
      <div class="muted tiny">Audit timestamp: {ts} • Scoring: {version}</div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-header">
          <h2>Overall Posture</h2>
          <div class="pill">Band: {_html_escape(band)} • Risk: {_html_escape(_risk_level(score))}</div>
        </div>

        <div style="display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
          {donut}
          <div style="min-width:260px;">
            <div class="muted tiny">Overall Score</div>
            <div style="font-size:34px; font-weight:800;">{score}/100</div>
            <div class="muted" style="margin-top:6px; white-space:pre-wrap; line-height:1.5;">
              {_html_escape(summary)}
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h2>Category Score Chart</h2>
          <div class="pill">Lowest categories first</div>
        </div>
        {cat_bars}
      </div>
    </div>
        {benchmark_html}
    <div class="card" style="margin-top:12px;">
      <div class="card-header">
        <h2>Top Gaps (Points Lost)</h2>
        <div class="pill">What to fix first</div>
      </div>
      {top_gaps}
    </div>

    <div class="card" style="margin-top:12px;">
      <div class="card-header">
        <h2>Recommendations</h2>
        <div class="pill">Engine-generated</div>
      </div>
      {recs_table}
    </div>

    <div class="card footer-ciso" style="margin-top:12px;">
      <div class="card-header">
        <h2>CISO Risk Statement</h2>
        <div class="pill">AI / Deterministic</div>
      </div>
      <p style="white-space: normal; line-height: 1.65; margin: 0;">
        {_html_escape(ciso)}
      </p>
    </div>
    <div class="card" style="margin-top:12px;">
      <div class="card-header">
        <h2>Operational Security Indicators</h2>
        <div class="pill">Host telemetry (non-scoring)</div>
      </div>
      {extra_security}
    </div>
  
  <div class="card" style="margin-top:12px;">
  <div class="card-header">
    <h2>Remediation Task Plan</h2>
    <div class="pill">Prioritised improvements</div>
  </div>
  {task_plan}
</div>
    <div class="card" style="margin-top:12px;">
      <div class="card-header">
        <h2>Control Breakdown</h2>
        <div class="pill">Traceability: rule + justification</div>
      </div>
      {controls_table}
    </div>
</body>
</html>
"""

    return html, ai_used
# -----------------------------
# CLI
# -----------------------------
def main() -> None:
    import sys

    # Usage:
    #   python report_generator.py
    #   python report_generator.py reports/audit_result_v2.json
    #   python report_generator.py reports/audit_result_v2.json reports/audit_report_v3.html

    reports_dir = DEFAULT_REPORTS_DIR

    if len(sys.argv) >= 2:
        audit_json = sys.argv[1]
    else:
        audit_json = _find_latest_audit_json(reports_dir)

    if len(sys.argv) >= 3:
        out_html = sys.argv[2]
    else:
        out_html = DEFAULT_HTML_OUT

    audit = _load_first_audit(audit_json)
    html = generate_html(audit, source_json=audit_json, use_ai=False)
    _write_text(out_html, html)

    print(f"[+] HTML report generated → {out_html}")
    print(f"[+] Source audit JSON → {audit_json}")


if __name__ == "__main__":
    main()
