import os
import cbor2
import codecs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from isomdoc.internal import to_cose_public_key, MDocDataTypes
from typing import List, Optional


class MDoc:
    def __init__(
        self,
        doctype: str,
        issuer_cert_chain: List[Certificate],
        issuer_private_key: PrivateKeyTypes,
    ):
        self.doctype = doctype
        # TODO: Check these are valid algos according to 18013-5
        self.issuer_cert_chain = issuer_cert_chain
        self.issuer_private_key = issuer_private_key
        self.namespaces = {}

    def add_data_item(self, namespace: str, identifier: str, value: MDocDataTypes):
        if namespace not in self.namespaces:
            self.namespaces[namespace] = []
        self.namespaces[namespace].append({"identifier": identifier, "value": value})

    def generate_credential(
        self,
        device_public_key: PublicKeyTypes,
        signed_datetime: datetime = datetime.now(timezone.utc),
        valid_from_datetime: datetime = datetime.now(timezone.utc),
        valid_until_datetime: datetime = datetime.now(timezone.utc) + timedelta(weeks=52 * 10),
        expected_update_datetime: Optional[datetime] = None,
    ):
        issuer_signed = {}

        # Create the namespaces
        issuer_namespaces = {}
        value_digests = {}
        for namespace_key, namespace_value in self.namespaces.items():
            # TODO: Randomize the digestId
            digest_id = 0
            namespace_items = []
            namespace_digests = {}
            for item in namespace_value:
                issuer_item = {}
                issuer_item["digestID"] = digest_id
                issuer_item["random"] = os.urandom(16)
                issuer_item["elementIdentifier"] = item["identifier"]
                issuer_item["elementValue"] = item["value"]
                issuer_item_bytes = cbor2.dumps(issuer_item)
                item_tag = cbor2.CBORTag(24, issuer_item_bytes)
                namespace_items.append(item_tag)
                # TODO: Support the other digest algos
                namespace_digests[digest_id] = sha256(cbor2.dumps(item_tag)).digest()

                digest_id = digest_id + 1

            issuer_namespaces[namespace_key] = namespace_items
            value_digests[namespace_key] = namespace_digests
        issuer_signed["nameSpaces"] = issuer_namespaces

        # Create the MSO
        mso = {}
        mso["version"] = "1.0"
        mso["digestAlgorithm"] = "SHA-256"
        mso["docType"] = self.doctype
        mso["valueDigests"] = value_digests
        mso["deviceKeyInfo"] = {"deviceKey": to_cose_public_key(device_public_key)}
        # TODO: Make sure these are all tdate
        validity_info = {}
        validity_info["signed"] = signed_datetime
        validity_info["validFrom"] = valid_from_datetime
        validity_info["validUntil"] = valid_until_datetime
        if expected_update_datetime is not None:
            validity_info["expectedUpdate"] = expected_update_datetime
        mso["validityInfo"] = validity_info

        mso_bytes = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))

        # Create the COSESign1
        protected = cbor2.dumps({1: -7})  # alg is ECDSA SHA256
        unprotected = None
        if len(self.issuer_cert_chain) == 1:
            cert = self.issuer_cert_chain[0]
            unprotected = {33: cert.public_bytes(serialization.Encoding.DER)}  # issuer x509 chain
        else:
            raise RuntimeError("support multi certs")

        sig_structure = []
        sig_structure.append("Signature1")
        sig_structure.append(protected)
        sig_structure.append(b"")
        sig_structure.append(mso_bytes)

        signature_der = self.issuer_private_key.sign(
            cbor2.dumps(sig_structure), ec.ECDSA(hashes.SHA256())
        )

        r, s = decode_dss_signature(signature_der)
        rhex = codecs.decode("{:064x}".format(r), "hex")
        shex = codecs.decode("{:064x}".format(s), "hex")

        issuer_auth = [protected, unprotected, mso_bytes, rhex + shex]

        issuer_signed["issuerAuth"] = issuer_auth
        return cbor2.dumps(issuer_signed)


def create_mdoc(
    doctype: str, issuer_cert_chain: List[Certificate], issuer_private_key: PrivateKeyTypes
) -> MDoc:
    return MDoc(doctype, issuer_cert_chain, issuer_private_key)
