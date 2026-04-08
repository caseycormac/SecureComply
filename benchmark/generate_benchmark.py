"""
generate_benchmark.py

PURPOSE:
--------
Generates an industry benchmark using synthetic SME GDPR data.

WHY:
----
- Real GDPR datasets are not publicly available
- We simulate realistic SMEs using generation.py
- We run them through the compliance engine
- We compute baseline metrics (average, quartiles, etc.)

OUTPUT:
-------
benchmark/benchmark.json

DESIGN:
-------
- Runs OFFLINE (not part of main pipeline)
- Uses existing modules (no duplication)
- Produces reusable benchmark file
"""

import sys
import os

# FIX: allow imports from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json


# Import your existing modules
from generation import generate_multiple_smes
from ingestion_module import flatten_gdpr_record, fill_empty_fields, normalise_record
from compliance_engine import compute_audit


# -----------------------------
# CONFIG
# -----------------------------

NUM_SAMPLES = 200   # Number of synthetic SMEs (increase for better accuracy)
OUTPUT_FILE = "benchmark/benchmark.json"


# -----------------------------
# MAIN FUNCTION
# -----------------------------

def generate_benchmark():
    """
    Generates benchmark metrics from synthetic SME dataset.
    """

    print("[+] Generating synthetic SME dataset...")

    # Step 1: Generate synthetic data
    dataset = generate_multiple_smes(NUM_SAMPLES)

    scores = []
    category_totals = {}
    category_counts = {}

    print("[+] Running audits on dataset...")

    for record in dataset:

        # -----------------------------
        # Step 2: Flatten + clean record
        # -----------------------------
        flat = flatten_gdpr_record(record)

        # Fill missing values ("empty")
        flat = fill_empty_fields(flat)

        # Normalise data types (booleans, ints, enums)
        flat = normalise_record(flat)

        # -----------------------------
        # Step 3: Run compliance engine
        # -----------------------------
        audit = compute_audit(flat)

        # -----------------------------
        # Step 4: Collect overall score
        # -----------------------------
        score = audit["overall"]["score"]
        scores.append(score)

        # -----------------------------
        # Step 5: Collect category scores
        # -----------------------------
        for category, values in audit["category_scores"].items():

            if category not in category_totals:
                category_totals[category] = 0
                category_counts[category] = 0

            category_totals[category] += values["score"]
            category_counts[category] += 1

    # -----------------------------
    # Step 6: Compute metrics
    # -----------------------------

    print("[+] Calculating benchmark metrics...")

    # Average score
    avg_score = sum(scores) / len(scores)

    # Sort scores for percentile calculations
    scores_sorted = sorted(scores)

    # Quartiles
    q1 = scores_sorted[int(len(scores_sorted) * 0.25)]
    median = scores_sorted[int(len(scores_sorted) * 0.5)]
    q3 = scores_sorted[int(len(scores_sorted) * 0.75)]

    # Category averages
    category_averages = {}

    for category in category_totals:
        category_averages[category] = round(
            category_totals[category] / category_counts[category], 2
        )

    # -----------------------------
    # Step 7: Save benchmark file
    # -----------------------------

    benchmark_data = {
        "num_samples": NUM_SAMPLES,
        "average_score": round(avg_score, 2),
        "quartiles": {
            "q1": q1,
            "median": median,
            "q3": q3
        },
        "category_averages": category_averages
    }

    os.makedirs("benchmark", exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(benchmark_data, f, indent=4)

    print(f"[+] Benchmark generated → {OUTPUT_FILE}")


# -----------------------------
# ENTRY POINT
# -----------------------------

if __name__ == "__main__":
    generate_benchmark()