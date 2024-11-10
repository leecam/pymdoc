from datetime import datetime
from enum import Enum
from typing import Union

MDocDataTypes = Union[int, str, bytes, bool, datetime]


class DeviceResponseStatusCode(int, Enum):
    OK = 0
    GENERAL_ERROR = 10
    CBOR_DECODING_ERROR = 11
    CBOR_VALIDATION_ERROR = 12


class MSOSignatureAlgorithm(int, Enum):
    ES256 = -7
    ES384 = -35
    ES512 = -36
    EdDSA = -8
