import cbor2
import codecs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import Certificate
from cryptography.x509 import load_der_x509_certificate
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
from isomdoc.internal import (
    DeviceResponseStatusCode,
    MDocDataTypes,
    MSOSignatureAlgorithm,
    from_cose_public_key,
)
from typing import List, Optional


class DeviceSignatureAlgorithm(int, Enum):
    ES256 = -7
    ES384 = -35
    ES512 = -36
    EdDSA = -8


class DigestAlgorithm(str, Enum):
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"

    def to_hash_function(algo):
        funcs = {
            DigestAlgorithm.SHA_256: hashlib.sha256,
            DigestAlgorithm.SHA_384: hashlib.sha384,
            DigestAlgorithm.SHA_512: hashlib.sha512,
        }
        return funcs[algo]


@dataclass
class ValidityInfo:
    signed: datetime
    valid_from: datetime
    valid_until: datetime
    expected_update: Optional[datetime]

    def __init__(self, validity_info: dict):
        if "signed" not in validity_info:
            raise RuntimeError("validity_info missing signed")
        if "validFrom" not in validity_info:
            raise RuntimeError("validity_info missing validFrom")
        if "validUntil" not in validity_info:
            raise RuntimeError("validity_info missing validUntil")

        self.signed = validity_info["signed"]
        self.valid_from = validity_info["validFrom"]
        self.valid_until = validity_info["validUntil"]
        self.expected_update = validity_info.get("expectedUpdate", None)


@dataclass
class IssuerSignedItem:
    digest_id: int
    random: bytes
    element_identifier: str
    element_value: MDocDataTypes

    def __init__(self, item_bytes: bytes, value_digests: dict, element_hash: bytes):
        item = cbor2.loads(item_bytes)
        self.digest_id = item["digestID"]
        self.random = item["random"]
        self.element_identifier = item["elementIdentifier"]
        self.element_value = item["elementValue"]

        if self.digest_id not in value_digests:
            raise RuntimeError("Missing digest")
        digest = value_digests[self.digest_id]
        if digest != element_hash:
            raise RuntimeError("Digest doesn't match")


@dataclass
class IssuerSigned:
    namespaces: dict
    mso_signature_algorithm: MSOSignatureAlgorithm
    mso_certificate_chain: List[Certificate]
    validity_info: ValidityInfo
    digest_algorithm: DigestAlgorithm
    device_key: PublicKeyTypes

    def __init__(self, issuer_signed: dict, doctype: str):
        if "issuerAuth" not in issuer_signed:
            raise RuntimeError("issuerAuth missing from IssuerSigned")
        issuer_auth = issuer_signed["issuerAuth"]

        # issuerAuth is a COSE_Sign1.
        if len(issuer_auth) != 4:
            raise RuntimeError("issuerAuth is not a COSE_Sign1")

        protected = issuer_auth[0]
        unprotected = issuer_auth[1]
        payload = issuer_auth[2]
        signature = issuer_auth[3]

        # Protected is a cbor containing only the alg element
        protected_dict = cbor2.loads(protected)
        if len(protected_dict) != 1:
            raise RuntimeError("issuerAuth COSE_Sign1 protected contains too many elements")
        if 1 not in protected_dict:
            raise RuntimeError("issuerAuth COSE_Sign1 protected does not contain alg element")
        self.mso_signature_algorithm = MSOSignatureAlgorithm(protected_dict[1])

        # Unprotected contains the x509 cert chain, 33
        if 33 not in unprotected:
            raise RuntimeError(
                "issuerAuth COSE_Sign1 unprotected does not contain x5chain element"
            )
        x509_cert_chain = unprotected[33]
        if isinstance(x509_cert_chain, bytes):
            x509_cert_chain = [x509_cert_chain]
        self.mso_certificate_chain = [load_der_x509_certificate(cert) for cert in x509_cert_chain]

        mso_public_key = self.mso_certificate_chain[0].public_key()
        # TODO: Check for allowed curves

        # Now check the signature
        sig_structure = []
        sig_structure.append("Signature1")
        sig_structure.append(protected)
        sig_structure.append(b"")
        sig_structure.append(payload)

        # TODO Support the algos corrected
        r = int(codecs.encode(signature[:32], "hex"), 16)
        s = int(codecs.encode(signature[32:], "hex"), 16)
        der_encoded_signature = encode_dss_signature(r, s)
        mso_public_key.verify(
            der_encoded_signature, cbor2.dumps(sig_structure), ec.ECDSA(hashes.SHA256())
        )
        # If we made it here the COSE_Sign1 was valid

        mso_tag = cbor2.loads(payload)
        if not isinstance(mso_tag, cbor2.CBORTag):
            raise RuntimeError("issuerAuth payload not a CBOR Tag")
        if mso_tag.tag != 24:
            raise RuntimeError("issuerAuth payload not a CBOR Tag 24")
        mso = cbor2.loads(mso_tag.value)

        if "version" not in mso:
            raise RuntimeError("mso missing version")
        if "digestAlgorithm" not in mso:
            raise RuntimeError("mso missing digestAlgorithm")
        if "valueDigests" not in mso:
            raise RuntimeError("mso missing valueDigests")
        if "deviceKeyInfo" not in mso:
            raise RuntimeError("mso missing deviceKeyInfo")
        if "docType" not in mso:
            raise RuntimeError("mso missing docType")
        if "validityInfo" not in mso:
            raise RuntimeError("mso missing validityInfo")

        if mso["version"] != "1.0":
            raise RuntimeError("mso version not supported")
        if doctype != mso["docType"]:
            raise RuntimeError("doctype in mso does not match doctype")
        self.validity_info = ValidityInfo(mso["validityInfo"])
        self.digest_algorithm = DigestAlgorithm(mso["digestAlgorithm"])

        if "deviceKey" not in mso["deviceKeyInfo"]:
            raise RuntimeError("mso deviceKeyInfo missing deviceKey")
        device_key = mso["deviceKeyInfo"]["deviceKey"]
        self.device_key = from_cose_public_key(device_key)

        value_digests = mso["valueDigests"]

        # Parse the namespaces
        self.namespaces = {}
        namespaces = issuer_signed.get("nameSpaces", None)
        if namespaces is not None:
            for namespace, elements in namespaces.items():
                parsed_elements = []
                for element in elements:
                    if not isinstance(element, cbor2.CBORTag):
                        raise RuntimeError("IssuerSignedItemBytes not a cbor tag")
                    if element.tag != 24:
                        raise RuntimeError("IssuerSignedItemBytes not a cbor tag 24")
                    if namespace not in value_digests:
                        raise RuntimeError("namespace missing from valueDigests")
                    element_hash = DigestAlgorithm.to_hash_function(self.digest_algorithm)(
                        cbor2.dumps(element)
                    ).digest()
                    parsed_elements.append(
                        IssuerSignedItem(element.value, value_digests[namespace], element_hash)
                    )
                self.namespaces[namespace] = parsed_elements

    def get_element_value(self, namespace: str, element_identifier: str) -> MDocDataTypes:
        elements = self.namespaces.get(namespace, None)
        if elements is None:
            return None
        for element in elements:
            if element.element_identifier == element_identifier:
                return element.element_value
        return None


@dataclass
class DeviceSigned:
    namespaces: dict
    device_signature_algorithm: DeviceSignatureAlgorithm

    def __init__(
        self,
        device_signed: dict,
        doctype: str,
        device_public_key: PublicKeyTypes,
        session_transcript: bytes,
    ):

        if "nameSpaces" not in device_signed:
            raise RuntimeError("deviceSigned must contain nameSpaces")

        namespace_tag = device_signed["nameSpaces"]
        # TODO: Check the structure of this to make sure it matches the spec
        self.namespaces = cbor2.loads(namespace_tag.value)
        if not isinstance(namespace_tag, cbor2.CBORTag):
            raise RuntimeError("deviceSigned nameSpaces not a cbor tag")
        if namespace_tag.tag != 24:
            raise RuntimeError("deviceSigned nameSpaces not a cbor tag 24")

        if "deviceAuth" not in device_signed:
            raise RuntimeError("deviceSigned must contain deviceAuth")
        device_auth = device_signed["deviceAuth"]
        # TODO support MAC
        if "deviceSignature" not in device_auth:
            raise RuntimeError("deviceAuth must contain deviceSignature")
        device_signature = device_auth["deviceSignature"]

        # device_signature is a COSE_Sign1
        if len(device_signature) != 4:
            raise RuntimeError("deviceSignature is not a COSE_Sign1")

        protected = device_signature[0]
        unprotected = device_signature[1]
        payload = device_signature[2]
        signature = device_signature[3]

        # Protected is a cbor containing only the alg element
        protected_dict = cbor2.loads(protected)
        if len(protected_dict) != 1:
            raise RuntimeError("deviceSignature COSE_Sign1 protected contains too many elements")
        if 1 not in protected_dict:
            raise RuntimeError("deviceSignature COSE_Sign1 protected does not contain alg element")
        self.device_signature_algorithm = DeviceSignatureAlgorithm(protected_dict[1])

        if unprotected != {}:
            raise RuntimeError("deviceSignature COSE_Sign1 unprotected is invalid")

        if payload is not None:
            raise RuntimeError("deviceSignature COSE_Sign1 payload is not null")

        # Check the device signature
        device_authentication = [
            "DeviceAuthentication",
            session_transcript,
            doctype,
            cbor2.dumps(namespace_tag),
        ]

        device_authentication_bytes = cbor2.dumps(
            cbor2.CBORTag(24, cbor2.dumps(device_authentication))
        )

        sig_structure = []
        sig_structure.append("Signature1")
        sig_structure.append(protected)
        sig_structure.append(b"")
        sig_structure.append(device_authentication_bytes)

        # TODO Support the algos corrected
        r = int(codecs.encode(signature[:32], "hex"), 16)
        s = int(codecs.encode(signature[32:], "hex"), 16)
        der_encoded_signature = encode_dss_signature(r, s)
        device_public_key.verify(
            der_encoded_signature, cbor2.dumps(sig_structure), ec.ECDSA(hashes.SHA256())
        )


@dataclass
class Document:
    doctype: str
    issuer_signed: IssuerSigned
    device_signed: DeviceSigned

    def __init__(self, document: dict, session_transcript: bytes):
        if "docType" not in document:
            raise RuntimeError("Document must contain docType")
        self.doctype = document["docType"]
        if "issuerSigned" not in document:
            raise RuntimeError("Document must contain issuerSigned")
        self.issuer_signed = IssuerSigned(document["issuerSigned"], self.doctype)
        if "deviceSigned" not in document:
            raise RuntimeError("Document must contain deviceSigned")
        self.device_signed = DeviceSigned(
            document["deviceSigned"],
            self.doctype,
            self.issuer_signed.device_key,
            session_transcript,
        )


@dataclass
class DeviceResponse:
    documents: Document

    def __init__(self, device_response: bytes, session_transcript: bytes):
        self.documents = []

        device_response_dict = cbor2.loads(device_response)
        if "version" not in device_response_dict:
            raise RuntimeError("Device Response must contain version")

        if device_response_dict["version"] != "1.0":
            raise RuntimeError("Only Device Response v1.0 supported")

        if "status" not in device_response_dict:
            raise RuntimeError("Device Response must contain status")

        if device_response_dict["status"] != DeviceResponseStatusCode.OK:
            raise RuntimeError("Device Response Status not OK")

        if "documents" not in device_response_dict:
            return

        self.documents = [
            Document(doc, session_transcript) for doc in device_response_dict["documents"]
        ]


def verify_device_response(device_response: bytes, session_transcript: bytes) -> DeviceResponse:
    return DeviceResponse(device_response, session_transcript)
