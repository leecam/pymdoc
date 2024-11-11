import cbor2
import codecs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


# Create a DeviceResponse for exmples.
def generate_device_response(doctype, issuer_signed, device_private_key, session_transcript):
    device_namespaces = {}
    namespace_tag = cbor2.CBORTag(24, cbor2.dumps(device_namespaces))

    device_authentication = [
        "DeviceAuthentication",
        session_transcript,
        doctype,
        cbor2.dumps(namespace_tag),
    ]

    device_authentication_bytes = cbor2.dumps(
        cbor2.CBORTag(24, cbor2.dumps(device_authentication))
    )

    protected = cbor2.dumps({1: -7})
    sig_structure = []
    sig_structure.append("Signature1")
    sig_structure.append(protected)
    sig_structure.append(b"")
    sig_structure.append(device_authentication_bytes)

    signature = device_private_key.sign(cbor2.dumps(sig_structure), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)

    rhex = codecs.decode("{:064x}".format(r), "hex")
    shex = codecs.decode("{:064x}".format(s), "hex")

    device_signature = [protected, {}, None, rhex + shex]

    device_signed = {
        "nameSpaces": namespace_tag,
        "deviceAuth": {"deviceSignature": device_signature},
    }
    document = {
        "docType": doctype,
        "issuerSigned": cbor2.loads(issuer_signed),
        "deviceSigned": device_signed,
    }

    device_response = {"version": "1.0", "documents": [document], "status": 0}

    return cbor2.dumps(device_response)
