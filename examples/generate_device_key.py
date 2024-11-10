import argparse
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

parser = argparse.ArgumentParser()
parser.add_argument("--name", help="Name of key", default="device")
parser.add_argument("--out", help="Path where key will be saved", default="testdata")
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

# save the public key
public_key_path = os.path.join(args.out, "{}_public_key.pem".format(args.name))
open(public_key_path, "wb").write(
    private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)
