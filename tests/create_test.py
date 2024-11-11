from unittest import TestCase

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import load_pem_x509_certificates

from isomdoc import create_mdoc

issuer_cert = b"""-----BEGIN CERTIFICATE-----
MIICRzCCAe2gAwIBAgIUdK0P/dVwQ5WfFEhbntqgZ9oynsUwCgYIKoZIzj0EAwIw
eTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1v
dW50YWluIFZpZXcxHDAaBgNVBAoME0RpZ2l0YWwgQ3JlZGVudGlhbHMxHzAdBgNV
BAMMFmRpZ2l0YWxjcmVkZW50aWFscy5kZXYwHhcNMjQxMTEwMDEwODAzWhcNMzQx
MDI5MDEwODAzWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW
MBQGA1UEBwwNTW91bnRhaW4gVmlldzEcMBoGA1UECgwTRGlnaXRhbCBDcmVkZW50
aWFsczEfMB0GA1UEAwwWZGlnaXRhbGNyZWRlbnRpYWxzLmRldjBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABOtDqHrSdqvbGCsalMxtFFgsG1bJ+QfDaThDNlzjQSwE
k14On5ZcrPzl0mM2WgKwLsKRvWymKvFB0pU9bLZ5EGmjUzBRMB0GA1UdDgQWBBQL
LHD8AxxsbwunUTBS45pEGTnbsDAfBgNVHSMEGDAWgBQLLHD8AxxsbwunUTBS45pE
GTnbsDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQD8lbryGFFj
P2Xaxy7zJbnnGLvLKrvJweDpqtMfhvvnMwIgbkMANURt0aeiHqvNMpR1cSHYSeyC
MRGTq8fq7bljh8s=
-----END CERTIFICATE-----
"""
issuer_cert = load_pem_x509_certificates(issuer_cert)

issuer_private_key = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKMscCIweVPaM9uoE2hNpW9syu9IkJLev+puy4e5hG9WoAoGCCqGSM49
AwEHoUQDQgAE60OoetJ2q9sYKxqUzG0UWCwbVsn5B8NpOEM2XONBLASTXg6fllys
/OXSYzZaArAuwpG9bKYq8UHSlT1stnkQaQ==
-----END EC PRIVATE KEY-----
"""
issuer_private_key = load_pem_private_key(issuer_private_key, None)


class TestCreate(TestCase):
    def test_create(self):
        mdoc = create_mdoc("doc", issuer_cert, issuer_private_key)
    