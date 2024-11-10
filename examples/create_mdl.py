from .utils import get_keys

from isomdoc import create_mdoc

(issuer_cert_chain, issuer_private_key, device_public_key, _) = get_keys()

# Create the mDL and add some data elements
mdl = create_mdoc("org.iso.18013.5.1.mDL", issuer_cert_chain, issuer_private_key)
mdl.add_data_item("org.iso.18013.5.1", "family_name", "Mustermann")
mdl.add_data_item("org.iso.18013.5.1", "given_name", "Erika")
mdl.add_data_item("org.iso.18013.5.1", "age_over_21", "True")
issuer_signed = mdl.generate_credential(device_public_key)
print(issuer_signed)
