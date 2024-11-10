from .device_response import generate_device_response
from .utils import get_keys

from isomdoc import create_mdoc, verify_device_response

(issuer_cert_chain, issuer_private_key, device_public_key, device_private_key) = get_keys()

# Create the mDL and add some data elements
mdl = create_mdoc("org.iso.18013.5.1.mDL", issuer_cert_chain, issuer_private_key)
mdl.add_data_item("org.iso.18013.5.1", "family_name", "Mustermann")
mdl.add_data_item("org.iso.18013.5.1", "given_name", "Erika")
mdl.add_data_item("org.iso.18013.5.1", "age_over_21", "True")
issuer_signed = mdl.generate_credential(device_public_key)

device_response = generate_device_response(
    "org.iso.18013.5.1.mDL", issuer_signed, device_private_key, None, None
)

verified_device_response = verify_device_response(device_response)
print("verified_device_response {}".format(verified_device_response))

document = verified_device_response.documents[0]
