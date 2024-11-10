import argparse
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import load_pem_x509_certificates


def get_keys():
    parser = argparse.ArgumentParser()
    parser.add_argument("issuer_cert_chain", help="Path to issuer certificate chain PEM file")
    parser.add_argument("issuer_private_key", help="Path to issuer private key PEM file")
    parser.add_argument("device_public_key", help="Path to device public key PEM file")
    parser.add_argument("device_private_key", help="Path to device private key PEM file")
    args = parser.parse_args()

    # Load the issuer certificate chain and private key
    issuer_cert_chain_file = open(args.issuer_cert_chain, "rb").read()
    issuer_cert_chain = load_pem_x509_certificates(issuer_cert_chain_file)
    issuer_private_key_file = open(args.issuer_private_key, "rb").read()
    issuer_private_key = load_pem_private_key(issuer_private_key_file, None)

    # Load the device public key
    device_public_key_file = open(args.device_public_key, "rb").read()
    device_public_key = load_pem_public_key(device_public_key_file)

    # Load the device private key
    device_private_key_file = open(args.device_private_key, "rb").read()
    device_private_key = load_pem_private_key(device_private_key_file, None)

    return (issuer_cert_chain, issuer_private_key, device_public_key, device_private_key)
