import argparse
import datetime
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

parser = argparse.ArgumentParser()
parser.add_argument("--name", help="Name of cert", default="issuer")
parser.add_argument("--out", help="Path where cert will be saved", default="testdata")
args = parser.parse_args()

# Save the private key
private_key = ec.generate_private_key(ec.SECP256R1())
private_key_path = os.path.join(args.out, "{}_private_key.pem".format(args.name))
open(private_key_path, "wb").write(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

# Generate the certificate
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Mountain View"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Digital Credentials"),
        x509.NameAttribute(NameOID.COMMON_NAME, "digitalcredentials.dev"),
    ]
)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(weeks=52 * 10)
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.BasicConstraints(True, None),
        critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

# Save the certificate
cert_path = os.path.join(args.out, "{}_cert.pem".format(args.name))
open(cert_path, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
