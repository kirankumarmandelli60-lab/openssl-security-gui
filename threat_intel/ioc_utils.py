import re
from urllib.parse import urlparse


IOC_TYPES = {
    "IPv4": re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
    ),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "Email": re.compile(
        r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    ),
}


def is_ipv4(value):
    return bool(IOC_TYPES["IPv4"].match(value))


def is_hash(value):
    if IOC_TYPES["SHA256"].match(value):
        return "SHA256"

    if IOC_TYPES["SHA1"].match(value):
        return "SHA1"

    if IOC_TYPES["MD5"].match(value):
        return "MD5"

    return None


def is_email(value):
    return bool(IOC_TYPES["Email"].match(value))


def is_url(value):
    try:
        parsed = urlparse(value)

        return parsed.scheme in ("http", "https") and bool(
            parsed.netloc
        )

    except Exception:
        return False


def is_domain(value):
    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63}$"
    )

    return bool(domain_pattern.match(value))


def identify_ioc(value):
    """
    Identify the most likely IOC type.
    """

    value = value.strip()

    if not value:
        return "Unknown"

    hash_type = is_hash(value)

    if hash_type:
        return hash_type

    if is_ipv4(value):
        return "IPv4"

    if is_email(value):
        return "Email"

    if is_url(value):
        return "URL"

    if is_domain(value):
        return "Domain"

    return "Unknown"


def normalize_ioc(value):
    """
    Normalize an IOC before analysis.
    """

    value = value.strip()

    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)

        return parsed.geturl().lower()

    return value.lower()


def analyze_ioc(value):
    """
    Perform basic static IOC analysis.

    This function intentionally performs no network requests.
    """

    normalized = normalize_ioc(value)
    ioc_type = identify_ioc(normalized)

    analysis = {
        "indicator": value,
        "normalized": normalized,
        "type": ioc_type,
        "confidence": "Low",
        "recommended_checks": [],
    }

    if ioc_type == "IPv4":
        analysis["confidence"] = "High"

        analysis["recommended_checks"] = [
            "WHOIS / registration information",
            "Reverse DNS",
            "Passive DNS",
            "IP reputation",
            "Related infrastructure",
            "Threat-intelligence correlation",
        ]

    elif ioc_type == "Domain":
        analysis["confidence"] = "High"

        analysis["recommended_checks"] = [
            "WHOIS / registration information",
            "DNS records",
            "Passive DNS",
            "Certificate transparency",
            "Domain reputation",
            "Related infrastructure",
        ]

    elif ioc_type == "URL":
        analysis["confidence"] = "High"

        analysis["recommended_checks"] = [
            "URL reputation",
            "Domain analysis",
            "Redirect analysis",
            "Certificate information",
            "Web infrastructure",
            "Malware/phishing correlation",
        ]

    elif ioc_type in ("MD5", "SHA1", "SHA256"):
        analysis["confidence"] = "High"

        analysis["recommended_checks"] = [
            "Malware reputation",
            "Malware family correlation",
            "First-seen / last-seen information",
            "Related samples",
            "Threat-intelligence correlation",
        ]

    elif ioc_type == "Email":
        analysis["confidence"] = "Medium"

        analysis["recommended_checks"] = [
            "Domain reputation",
            "Domain registration",
            "Known breach exposure",
            "Phishing correlation",
            "OSINT correlation",
        ]

    else:
        analysis["recommended_checks"] = [
            "Manual validation",
            "OSINT investigation",
            "Threat-intelligence correlation",
        ]

    return analysis