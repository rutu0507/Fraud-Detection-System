def build_report(entry):
    return {
        "Summary": entry["result"],
        "Confidence": f"{entry['confidence']}%",
        "Input": entry["input"],
        "Recommendation":
            "Report to Cyber Crime Portal"
            if entry["confidence"] >= 60
            else "No action required"
    }
