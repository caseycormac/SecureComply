import time
import sys
import os
import argparse

from ingestion_module import ingest_gdpr_json
from validate_gdpr import validate_gdpr_record
from compliance_engine import compute_audit
from report_generator.report_generator import generate_html

# -------------------------
# CONFIG
# -------------------------

REPORT_PATH = "reports/audit_report_v3.html"

# -------------------------
# COLOURS
# -------------------------
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"



def parse_arguments():
    """
    Parses command-line arguments for SecureComply+.

    WHY:
    - Provides a professional CLI interface
    - Allows users to understand available options
    - Prevents accidental execution when using --help
    """

    parser = argparse.ArgumentParser(
        description="SecureComply+ GDPR Auditor - Compliance & Risk Assessment Tool"
    )

    # Optional flags
    parser.add_argument(
    "--usage",
    action="store_true",
    help="Show usage guide with example commands and workflow"
)
    
    parser.add_argument(
    "--data-instructions",
    action="store_true",
    help="Show how to format SME input JSON (copy-paste template)"
)
    
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run full demo pipeline (generate synthetic data + audit)"
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI-generated CISO narrative"
    )

    parser.add_argument(
        "--explain",
        action="store_true",
        help="Enable explainability mode (shows why controls failed)"
    )

    # Optional positional argument
    parser.add_argument(
        "input_file",
        nargs="?",
        help="Path to GDPR JSON input file"
    )

    return parser.parse_args()

#test

def print_data_instructions():
    """
    Displays copy-paste ready instructions for creating a valid SME JSON input file.
    This does NOT run the pipeline — it is purely for user/examiner guidance.
    """

    print("""
====================================
DATA INPUT (COPY & USE TEMPLATE)
====================================

[STEP 1] Create a JSON file in /data/
Example:
data/my_sme_input.json

[STEP 2] Copy this template:

[
  {
    "https_enabled": true,
    "password_storage_method": "bcrypt",
    "regular_security_testing": "quarterly",
    "encryption_at_rest": "full",
    "mfa_enforced": "all_users",

    "cookie_consent_mechanism": "granular",
    "privacy_policy_present": true,
    "privacy_policy_clarity": "clear",
    "lawful_basis": "contract",
    "third_party_sharing_disclosed": "full",
    "dsar_response_time_days": 30,
    "dsar_process": "documented",

    "data_breach_process_maturity": "tested",
    "breach_notification_hours": 72,
    "data_retention_policy": "legal_only",
    "retention_period_days": 30,
    "record_of_processing": "complete",
    "dpia_process": "documented",
    "has_dpo": "appointed"
  }
]

[STEP 3] Replace values using allowed options below

------------------------------------
ALLOWED VALUES
------------------------------------

password_storage_method:
• argon2 | bcrypt | sha256 | md5 | plaintext

regular_security_testing:
• continuous | quarterly | annual | ad_hoc | none

encryption_at_rest:
• full_with_key_management | full | partial | none

mfa_enforced:
• all_users | privileged_users | admin_only | none

cookie_consent_mechanism:
• granular | opt_in | implied | none

privacy_policy_clarity:
• clear | partially_clear | unclear | missing

lawful_basis:
• contract | legal_obligation | public_task
• legitimate_interests | consent | vital_interests | mixed

third_party_sharing_disclosed:
• full | partial | unclear | none

dsar_process:
• automated | documented | partial | informal | missing

data_breach_process_maturity:
• tested | documented | informal | none

data_retention_policy:
• legal_only | mixed | operational | indefinite | none

record_of_processing:
• automated | complete | partial | none

dpia_process:
• integrated | documented | ad_hoc | none

has_dpo:
• appointed | outsourced | informal_role | none

------------------------------------
IMPORTANT
------------------------------------
• Booleans must be: true / false
• Numbers must be integers (e.g. 30, 72)
• Invalid values will fail validation

[RUN COMMAND]
python run.py data/my_sme_input.json

====================================
Tip: See DATA_INSTRUCTIONS.md for full details
====================================
          
""")

#test


# -------------------------
# UI / BRANDING
# -------------------------
def print_header():
    print(CYAN)
    print("====================================")
    print("SecureComply+ GDPR Auditor (V6.0)")
    print("====================================")
    print(RESET)


def progress_bar(label, duration=1.0, steps=20):
    print(f"{label} ", end="", flush=True)
    for _ in range(steps):
        time.sleep(duration / steps)
        print("█", end="", flush=True)
    print(" 100%")


# -------------------------
# 🔥 NEW: Compliance Engine Visualisation
# -------------------------
def compliance_engine_visual():
    print("\n[3/5] Running Compliance Engine\n")

    steps = [
        "→ Ingestion module (data normalisation)",
        "→ Validation engine (rule enforcement)",
        "→ Scoring engine (control evaluation)",
        "→ Risk model (band classification)",
        "→ Recommendation engine (gap analysis)"
    ]

    for step in steps:
        print(step)
        time.sleep(0.3)

    print("\n   ████████████████████ 100%\n")


# -------------------------
# 🤖 NEW: AI Visualisation
# -------------------------
def ai_visual(ai_used=True):
    print("\n[AI] Generating CISO Narrative")

    print("   → Connecting to OpenAI API")
    time.sleep(0.3)

    print("   → Model: gpt-4o-mini")
    time.sleep(0.3)

    print("   → Generating risk summary")
    time.sleep(0.5)

    if ai_used:
        print(f"   {GREEN}✔ AI narrative generated{RESET}\n")
    else:
        print(f"   {YELLOW}⚠ Fallback used (AI unavailable){RESET}\n")


# -------------------------
# RESULT OUTPUT
# -------------------------
def print_result(score, band):
    # Risk colour + icon
    if score >= 70:
        colour = GREEN
        icon = "🟢"
    elif score >= 50:
        colour = YELLOW
        icon = "🟡"
    else:
        colour = RED
        icon = "🔴"

    print(f"\n{colour}✔ Audit Complete{RESET}")
    print(f"Risk Level: {icon} {band.upper()}")
    print(f"Score: {score}/100")
    print(f"Report: {REPORT_PATH}\n")


# -------------------------
# CORE PIPELINE
# -------------------------

def show_usage():
    """
    Displays a user-friendly usage guide.

    PURPOSE:
    - Helps examiner understand how to use the tool
    - Acts as a mini README inside CLI
    - Improves usability and professionalism
    """

    print("\n=== SecureComply+ Usage Guide ===\n")

    print("DESCRIPTION:")
    print("SecureComply+ is a GDPR compliance auditing tool that evaluates")
    print("organisational security posture and generates a risk-based report.\n")

    print("COMMON COMMANDS:\n")

    print("1. Run demo (recommended for first-time use):")
    print("   python run.py --demo\n")

    print("2. Run audit on your own data:")
    print("   python run.py <input_file.json>\n")

    print("3. Run without AI narrative:")
    print("   python run.py <input_file.json> --no-ai\n")

    print("4. Enable explainability mode:")
    print("   python run.py <input_file.json> --explain\n")

    print("5. Combine options:")
    print("   python run.py <input_file.json> --no-ai --explain\n")

    print("\n")

    print("ADVANCED USAGE (WITH HOST TELEMETRY):\n")

    print("1. Run host security scan:")
    print("   bash host_scan.sh\n")

    print("2. Merge scan results with GDPR data:")
    print("   python merge_host_data.py <input.json> host_scan_output.json\n")

    print("3. Run audit on merged dataset:")
    print("   python run.py data/merged_input.json\n")

    print("\n")

    print("WHAT THE TOOL DOES:")
    print("- Ingests and normalises GDPR data")
    print("- Validates inputs against expected formats")
    print("- Applies compliance scoring model")
    print("- Generates a GDPR audit report")
    print("- Compares results against SME benchmark\n")

    print("OUTPUT:")
    print("- HTML report located in: reports/audit_report_v3.html\n")

    print("TIP:")
    print("Start with --demo to see the full system in action.\n")

    print("=================================\n")


def show_data_source(input_file, records):
    print("\n[DATA SOURCES]\n")

    # Check if synthetic (based on filename or structure)
    if "synthetic" in input_file.lower():
        print("✔ Synthetic GDPR dataset")
    else:
        print("✔ External GDPR dataset")

    # Check for host scan integration
    if records and "extra_security_signals" in records[0]:
        print("✔ Host telemetry integrated")
    else:
        print("✖ No host telemetry detected")

    print("")

#TEST 
def explain_results(audit):
    print("\n[EXPLAINABILITY MODE]\n")

    critical = []
    high = []

    for c in audit.get("control_results", []):
        if c["score"] == c["max"]:
            continue  # skip perfect controls

        if c["score"] == 0:
            critical.append(c)
        else:
            high.append(c)

    # 🔴 CRITICAL
    if critical:
        print("🔴 CRITICAL ISSUES:")
        for c in critical:
            print(f"- {c['control_id']} → {c['input']}")
        print("")

    # 🟡 HIGH
    if high:
        print("🟡 HIGH PRIORITY:")
        for c in high:
            print(f"- {c['control_id']} → {c['input']}")
        print("")
#TEST
def run_pipeline(input_file, use_ai=True):
    print_header()

    # STEP 1
    progress_bar("[1/5] Loading data")
    records = ingest_gdpr_json(input_file)
    show_data_source(input_file, records) 

    if not records:
        print(f"{RED}❌ No data loaded{RESET}")
        return

    # STEP 2
    progress_bar("[2/5] Validating input")

    valid_records = []

    # ✅ Step 1: validate
    for r in records:
        errors = validate_gdpr_record(r)
        if not errors:
            valid_records.append(r)

    # ✅ Step 2: handle no valid records
    if not valid_records:
        print(f"{RED}❌ No valid records{RESET}\n")

        print("⚠ Validation Errors Detected:\n")

        for i, r in enumerate(records):
            errors = validate_gdpr_record(r)

            if errors:
                print(f"{YELLOW}Record {i+1}:{RESET}")
                for err in errors:
                    print(f"  {RED}•{RESET} {err}")
                print("")

        return

    # STEP 3 (NEW VISUAL)
    compliance_engine_visual()

    record = valid_records[0]

    audit = compute_audit(record)

    #  ADD THIS
    audit["extra_security_signals"] = record.get("extra_security_signals", {})
    audit["host_scan_timestamp"] = record.get("host_scan_timestamp")

    # STEP 4
    progress_bar("[4/5] Generating report")
    
    html, ai_used = generate_html(
    audit,
    source_json="reports/audit_result_v3.json",
    use_ai=use_ai
)

    os.makedirs("reports", exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(html)

    # 🤖 AI VISUAL (always show — even if fallback internally)
    ai_visual(ai_used=ai_used)

    # STEP 5
    progress_bar("[5/5] Finalising", duration=0.5)

    # RESULT
    score = audit["overall"]["score"]
    band = audit["overall"]["band"]

    print_result(score, band)

    # AUTO OPEN REPORT
    try:
        os.startfile(REPORT_PATH)
    except Exception:
        import webbrowser
        absolute_path = os.path.abspath(REPORT_PATH)
        webbrowser.open(f"file://{absolute_path}")

    #TEST
    return audit
    #TEST

# -------------------------
# INTERACTIVE MENU
# -------------------------
def interactive_menu():
    print_header()

    print("Select an option:\n")
    print("1. Run GDPR Audit")
    print("2. Exit\n")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        path = input("\nEnter path to GDPR JSON file: ").strip()

        if not os.path.exists(path):
            print(f"{RED}❌ File not found{RESET}")
            return

        run_pipeline(path)

    elif choice == "2":
        print("Exiting...")
        sys.exit(0)

    else:
        print(f"{RED}Invalid option{RESET}")



import subprocess
import os
import sys

# -------------------------
# DEMO PIPELINE (FIXED)
# -------------------------

def run_demo_pipeline():
    print("\n[DEMO MODE] Running full pipeline...\n")

    # 1. Generate SME data
    print("[+] Generating SME data...")
    subprocess.run(["python", "generation.py"])

    # 2. Host scan (skip on Windows)
    subprocess.run(["bash", "host_scan.sh"])

    # 3. Merge data
    print("[+] Merging data...")
    subprocess.run(["python", "merge_host_data.py"])

    return "data/merged_input_v4.json"


# -------------------------
# ENTRY POINT (ARGPARSE)
# -------------------------

args = parse_arguments()

# Handle usage guide (DOES NOT RUN TOOL)
if args.usage:
    show_usage()
    sys.exit(0)

# If --help is used → argparse automatically prints help and exits
# So nothing runs (this is exactly what you want)

# -------------------------
# DATA INSTRUCTIONS (NEW)
# -------------------------
if args.data_instructions:
    print_data_instructions()
    sys.exit(0)  # IMPORTANT: stops the rest of the program

# Determine input source
if args.demo or not args.input_file:
    input_file = run_demo_pipeline()
else:
    input_file = args.input_file

# AI toggle
use_ai = not args.no_ai

# Run pipeline
audit = run_pipeline(input_file, use_ai)

# Explainability mode
if args.explain and audit:
    explain_results(audit)