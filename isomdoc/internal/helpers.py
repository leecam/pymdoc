from codecs import decode, encode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


# TODO: Support all the key types.
def to_cose_public_key(public_key: PublicKeyTypes) -> dict:
    public_numbers = public_key.public_numbers()
    cose_public_key = {}
    # key type
    cose_public_key[1] = 2
    # curve p-256
    cose_public_key[-1] = 1
    # x
    cose_public_key[-2] = decode("{:064x}".format(public_numbers.x), "hex")
    # y
    cose_public_key[-3] = decode("{:064x}".format(public_numbers.y), "hex")
    return cose_public_key


def from_cose_public_key(cose_key: dict) -> PublicKeyTypes:
    kty = cose_key.get(1, None)
    if kty == 2:
        # EC Key
        curves = {1: ec.SECP256R1(), 2: ec.SECP384R1(), 3: ec.SECP521R1()}
        crv = cose_key[-1]
        if crv not in curves:
            raise RuntimeError("Unsupported COSE curve")
        x = cose_key[-2]
        y = cose_key[-3]
        x = int(encode(x, "hex"), 16)
        y = int(encode(y, "hex"), 16)
        return ec.EllipticCurvePublicNumbers(x, y, curves[crv]).public_key()
    else:
        raise RuntimeError("Unsupported COSE key type")
