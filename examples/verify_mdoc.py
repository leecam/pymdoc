from .device_response import generate_device_response
from .utils import get_keys

from cryptography.hazmat.primitives import hashes
from isomdoc import create_mdoc, verify_device_response

(issuer_cert_chain, issuer_private_key, device_public_key, device_private_key) = get_keys()

# Create the mDL and add some data elements
mdl = create_mdoc("org.iso.18013.5.1.mDL", issuer_cert_chain, issuer_private_key)
mdl.add_data_item("org.iso.18013.5.1", "family_name", "Mustermann")
mdl.add_data_item("org.iso.18013.5.1", "given_name", "Erika")
mdl.add_data_item("org.iso.18013.5.1", "age_over_21", "True")
issuer_signed = mdl.generate_credential(device_public_key)

# Generate a device response, this would normally be created by the device's wallet.
session_transcript = bytes(10)
device_response = generate_device_response(
    "org.iso.18013.5.1.mDL", issuer_signed, device_private_key, session_transcript
)

# Verify the device response
verified_device_response = verify_device_response(device_response, session_transcript)
print("Response is valid")
# print("verified_device_response {}".format(verified_device_response))

# Get the document and print some values
document = verified_device_response.documents[0]
doctype = document.doctype
family_name = document.issuer_signed.get_element_value("org.iso.18013.5.1", "family_name")
print("Doctype: {}".format(doctype))
print("org.iso.18013.5.1/family_name: {}".format(family_name))

# Remember to check the issuer cert
print(document.issuer_signed.mso_certificate_chain)
