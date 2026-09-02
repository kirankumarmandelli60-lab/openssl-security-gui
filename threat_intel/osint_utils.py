from datetime import datetime


def generate_osint_checklist(ioc_analysis):
    """
    Generate an OSINT investigation checklist based on IOC type.

    This function does not perform network requests.
    It provides structured investigation areas for an analyst.
    """

    ioc_type = ioc_analysis["type"]
    indicator = ioc_analysis["normalized"]

    checklist = {
        "indicator": indicator,
        "type": ioc_type,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "checks": []
    }

    if ioc_type == "IPv4":
        checklist["checks"] = [
            "WHOIS / registration information",
            "Reverse DNS",
            "Passive DNS",
            "IP reputation",
            "ASN / hosting information",
            "Related infrastructure",
            "Threat-intelligence correlation",
        ]

    elif ioc_type == "Domain":
        checklist["checks"] = [
            "WHOIS / registration information",
            "DNS records",
            "Passive DNS",
            "Certificate Transparency",
            "Domain reputation",
            "Related IP addresses",
            "Related infrastructure",
            "Threat-intelligence correlation",
        ]

    elif ioc_type == "URL":
        checklist["checks"] = [
            "URL reputation",
            "Domain analysis",
            "Redirect analysis",
            "Certificate information",
            "Web infrastructure",
            "Malware / phishing correlation",
            "Threat-intelligence correlation",
        ]

    elif ioc_type in ("MD5", "SHA1", "SHA256"):
        checklist["checks"] = [
            "Malware reputation",
            "Malware family correlation",
            "First-seen / last-seen information",
            "Related samples",
            "File behavior",
            "Threat-intelligence correlation",
        ]

    elif ioc_type == "Email":
        checklist["checks"] = [
            "Domain reputation",
            "Domain registration",
            "Known breach exposure",
            "Phishing correlation",
            "OSINT correlation",
        ]

    else:
        checklist["checks"] = [
            "Manual validation",
            "OSINT investigation",
            "Threat-intelligence correlation",
        ]

    return checklist


def format_osint_checklist(checklist):
    """
    Convert an OSINT checklist into analyst-readable text.
    """

    lines = []

    lines.append("=" * 60)
    lines.append("OSINT INVESTIGATION CHECKLIST")
    lines.append("=" * 60)
    lines.append("")

    lines.append(f"Indicator: {checklist['indicator']}")
    lines.append(f"Type:      {checklist['type']}")
    lines.append(f"Generated: {checklist['generated']}")
    lines.append("")

    lines.append("INVESTIGATION AREAS")
    lines.append("-" * 60)

    for check in checklist["checks"]:
        lines.append(f"[ ] {check}")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)

def create_investigation_record(ioc_analysis):
    """
    Create a structured OSINT investigation record.

    This function does not perform network requests.
    It initializes investigation findings as pending.
    """

    checklist = generate_osint_checklist(ioc_analysis)

    record = {
        "indicator": checklist["indicator"],
        "type": checklist["type"],
        "generated": checklist["generated"],
        "findings": {}
    }

    for check in checklist["checks"]:
        record["findings"][check] = {
            "status": "Pending",
            "result": None,
            "source": None
        }

    return record
