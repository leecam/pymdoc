import cbor2


# Create a DeviceResponse for exmples.
def generate_device_response(doctype, issuer_signed, device_private_key, nonce, origin):
    device_namespaces = {}
    device_namespaces_bytes = cbor2.CBORTag(24, cbor2.dumps(device_namespaces))

    device_signature = [cbor2.dumps({1: -7}), {}, None, bytes(64)]

    device_signed = {
        "nameSpaces": device_namespaces_bytes,
        "deviceAuth": {"deviceSignature": device_signature},
    }
    document = {
        "docType": doctype,
        "issuerSigned": cbor2.loads(issuer_signed),
        "deviceSigned": device_signed,
    }

    device_response = {"version": "1.0", "documents": [document], "status": 0}

    return cbor2.dumps(device_response)
