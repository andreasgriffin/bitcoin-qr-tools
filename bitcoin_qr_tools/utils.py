import logging
from typing import List

from hwilib.descriptor import Descriptor

BITCOIN_BIP21_URI_SCHEME = "bitcoin"
logger = logging.getLogger(__name__)


class InvalidBitcoinURI(Exception):
    pass


def serialized_to_hex(serialized):
    return bytes(serialized).hex()


def hex_to_serialized(hex_string):
    return bytes.fromhex(hex_string)


class DecodingException(Exception):
    pass


class InconsistentDescriptors(Exception):
    pass


class WrongNetwork(Exception):
    pass


def _flatten_descriptors(descriptor: Descriptor) -> List[Descriptor]:
    if descriptor.pubkeys and len(descriptor.subdescriptors) == 0:
        return [descriptor]
    elif len(descriptor.pubkeys) == 0 and len(descriptor.subdescriptors) == 1:
        return [descriptor] + _flatten_descriptors(descriptor.subdescriptors[0])
    else:
        raise Exception(f"The descriptor cannot be flattened")
