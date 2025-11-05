import logging
from typing import List, Optional

import bdkpython as bdk
from hwilib.descriptor import Descriptor, PubkeyProvider, parse_descriptor

logger = logging.getLogger(__name__)


def get_all_pubkey_providers(hwi_descriptor: Descriptor) -> List[PubkeyProvider]:
    pubkey_providers = hwi_descriptor.pubkeys.copy()
    for subdescriptor in hwi_descriptor.subdescriptors:
        pubkey_providers += get_all_pubkey_providers(subdescriptor).copy()
    return pubkey_providers


def get_adapted_hwi_descriptor(descriptor_str: str, new_derivation_path: str) -> Descriptor:
    hwi_descriptor = parse_descriptor(descriptor_str)
    pubkey_providers = get_all_pubkey_providers(hwi_descriptor)
    for pubkey_provider in pubkey_providers:
        pubkey_provider.deriv_path = new_derivation_path
    return hwi_descriptor


def get_equal_derivation_path(descriptor_str: str) -> Optional[str]:
    "Returns the derivation_path is all derivation_paths are equal. Otherwise None"

    hwi_descriptor = parse_descriptor(descriptor_str)
    pubkey_providers = get_all_pubkey_providers(hwi_descriptor=hwi_descriptor)

    # check that all derivation paths are equal
    derivation_paths = [pubkey_provider.deriv_path for pubkey_provider in pubkey_providers]
    all_equal = all(x == derivation_paths[0] for x in derivation_paths)

    if all_equal:
        return pubkey_providers[0].deriv_path
    else:
        return None


def convert_to_bdk_descriptor(descriptor_str: str, network: bdk.Network) -> bdk.Descriptor:
    # sparrow format for root keys
    # here we replace this
    sparrow_root_key_format = "/m]"
    if sparrow_root_key_format in descriptor_str:
        if "#" in descriptor_str:
            descriptor_str = descriptor_str.split("#")[0]
        descriptor_str = descriptor_str.replace(sparrow_root_key_format, "]")

    return bdk.Descriptor(descriptor_str, network)


def convert_to_multipath_descriptor(descriptor_str: str, network: bdk.Network) -> bdk.Descriptor:
    descriptor = convert_to_bdk_descriptor(descriptor_str=descriptor_str, network=network)
    if descriptor.is_multipath():
        return descriptor
    else:
        return convert_to_bdk_descriptor(
            descriptor_str=get_adapted_hwi_descriptor(
                str(descriptor), new_derivation_path="/<0;1>/*"
            ).to_string(),
            network=network,
        )


def is_valid_descriptor(descriptor_str: str, network: bdk.Network) -> bool:
    try:
        convert_to_multipath_descriptor(descriptor_str=descriptor_str, network=network)
    except:
        return False
    return True


def address_descriptor_from_multipath_descriptor(
    descriptor: bdk.Descriptor, kind: bdk.KeychainKind, address_index: int
) -> str:
    assert descriptor.is_multipath()
    external_int = 0 if kind == bdk.KeychainKind.EXTERNAL else 1
    descriptor_str = str(descriptor.to_single_descriptors()[external_int]).split("#")[0]

    new_derivation_path = f"/{external_int}/{address_index}"
    receive_descriptor = get_adapted_hwi_descriptor(descriptor_str, new_derivation_path=new_derivation_path)
    return receive_descriptor.to_string(hardened_char="'")
