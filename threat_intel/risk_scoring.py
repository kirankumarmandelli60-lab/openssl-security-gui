def calculate_risk_score(ioc_type, indicators=None):
    """
    Calculate a basic risk score for an IOC.

    Returns a score from 0 to 100 and a severity classification.
    """

    if indicators is None:
        indicators = {}

    score = 0
    reasons = []

    # IOC type baseline
    if ioc_type in ("IPv4", "IPv6"):
        score += 20
        reasons.append("Network indicator identified")

    elif ioc_type == "Domain":
        score += 20
        reasons.append("Domain indicator identified")

    elif ioc_type == "URL":
        score += 25
        reasons.append("URL indicator identified")

    elif ioc_type in ("MD5", "SHA1", "SHA256"):
        score += 30
        reasons.append("File hash identified")

    elif ioc_type == "Email":
        score += 15
        reasons.append("Email indicator identified")

    else:
        score += 5
        reasons.append("Unknown indicator type")

    # Threat-intelligence indicators
    if indicators.get("known_malicious"):
        score += 40
        reasons.append("Known malicious indicator")

    if indicators.get("blacklisted"):
        score += 25
        reasons.append("Indicator appears on a blacklist")

    if indicators.get("suspicious"):
        score += 20
        reasons.append("Suspicious behavior or characteristics")

    if indicators.get("darkweb_reference"):
        score += 20
        reasons.append("Darkweb reference detected")

    if indicators.get("breach_reference"):
        score += 20
        reasons.append("Breach-related reference detected")

    # Prevent score from exceeding 100
    score = min(score, 100)

    # Severity classification
    if score >= 80:
        severity = "Critical"

    elif score >= 60:
        severity = "High"

    elif score >= 30:
        severity = "Medium"

    else:
        severity = "Low"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons,
    }
