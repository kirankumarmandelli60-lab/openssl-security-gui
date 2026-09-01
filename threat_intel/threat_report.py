from datetime import datetime


def generate_threat_report(ioc_analysis, risk_analysis):
    """
    Generate a human-readable threat intelligence report.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    indicator = ioc_analysis.get("indicator", "")
    normalized = ioc_analysis.get("normalized", "")
    ioc_type = ioc_analysis.get("type", "Unknown")
    confidence = ioc_analysis.get("confidence", "Low")

    score = risk_analysis.get("score", 0)
    severity = risk_analysis.get("severity", "Unknown")
    reasons = risk_analysis.get("reasons", [])

    recommended_checks = ioc_analysis.get(
        "recommended_checks",
        []
    )

    report = []

    report.append("=" * 60)
    report.append("CYBER THREAT INTELLIGENCE REPORT")
    report.append("=" * 60)

    report.append("")
    report.append(f"Generated: {timestamp}")

    report.append("")
    report.append("INDICATOR")
    report.append("-" * 60)
    report.append(f"Original:   {indicator}")
    report.append(f"Normalized: {normalized}")
    report.append(f"Type:       {ioc_type}")
    report.append(f"Confidence: {confidence}")

    report.append("")
    report.append("RISK ASSESSMENT")
    report.append("-" * 60)
    report.append(f"Risk Score: {score}/100")
    report.append(f"Severity:   {severity}")

    report.append("")
    report.append("RISK FACTORS")
    report.append("-" * 60)

    if reasons:
        for reason in reasons:
            report.append(f"- {reason}")
    else:
        report.append("- No specific risk factors identified")

    report.append("")
    report.append("RECOMMENDED INVESTIGATION")
    report.append("-" * 60)

    if recommended_checks:
        for check in recommended_checks:
            report.append(f"- {check}")
    else:
        report.append("- Manual analyst investigation")

    report.append("")
    report.append("=" * 60)
    report.append("END OF REPORT")
    report.append("=" * 60)

    return "\n".join(report)


def save_threat_report(report, output_path):
    """
    Save a generated threat intelligence report to disk.
    """

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)

    return output_path