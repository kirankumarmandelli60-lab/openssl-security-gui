from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime


def generate_self_signed_certificate():
    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Andhra Pradesh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Tadepalligudem"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OpenSSL_GUI_App"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Kiran"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() +
            datetime.timedelta(days=365)
        )
        .sign(private_key, hashes.SHA256())
    )

    with open("certificates/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return "certificates/certificate.pem"


def view_certificate(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data)

    info = f"""
Subject:
{cert.subject}

Issuer:
{cert.issuer}

Serial Number:
{cert.serial_number}

Valid From:
{cert.not_valid_before_utc}

Valid Until:
{cert.not_valid_after_utc}
"""

    return info