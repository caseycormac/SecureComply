import os
from sys import audit
from openai import OpenAI

# -------------------------
# NEW: Load API key
# -------------------------
def load_api_key():
    """
    Loads OpenAI API key from:
    1. Environment variable
    2. Local file (openai.key)
    """

    # 1. Environment variable
    key = os.getenv("OPENAI_API_KEY")
    if key:
        return key

    # 2. Local file fallback
    try:
        with open("openai.key", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None

api_key = load_api_key()
client = OpenAI(api_key=api_key) if api_key else None

def generate_ciso_ai(audit: dict) -> str:
    if client is None:
        return None
    """
    Generates AI-powered CISO risk statement.
    Falls back if API fails.
    """

    try:
        score = audit["overall"]["score"]
        band = audit["overall"]["band"]

        if score >= 85:
            risk = "Low"
        elif score >= 70:
            risk = "Moderate"
        elif score >= 50:
            risk = "High"
        else:
            risk = "Critical"

        top_gaps = [
            f"{g['control_id']} ({g['category']})"
            for g in audit.get("top_gaps", [])[:3]
        ]

        prompt = f"""
Act as a Chief Information Security Officer preparing an executive GDPR audit risk statement for inclusion in a professional compliance report.

Assessment results:
Organisation score: {score}/100
Risk level: {risk}
Compliance band: {band}
Top risk areas: {", ".join(top_gaps)}

Task:
Write one polished paragraph between 150 and 250 words that interprets these results for a senior business audience.

The paragraph should:
1. Assess the organisation's overall GDPR compliance posture in line with the score, band, and risk level
2. Highlight the most significant weaknesses using the listed top risk areas
3. Explain the likely consequences in terms of regulatory exposure, business disruption, customer trust, and reputational harm
4. State the highest-priority next steps to improve compliance and reduce risk

Rules:
- No bullet points
- No headings
- No placeholders
- No generic filler language
- No overstatement
- Keep the language formal, concise, and credible
- Ensure the narrative changes meaningfully depending on whether the result is Strong, Moderate, Weak, or High Risk
- If the score is 100/100, explicitly state that no material deficiencies were identified in the assessed controls and that the priority is to maintain and periodically review this position

End with this exact line:
This summary was generated with AI support and should be reviewed by a qualified human expert.

"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",  # cheap + fast
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        #print("AI ERROR:", e)
        return None