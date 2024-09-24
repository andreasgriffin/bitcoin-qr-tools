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


class MultipathDescriptor:
    """
    Will create main+change BDK single and multisig descriptors, no matter if '/<0;1>/*' or '/0/*' or '/1/*' is specified
    It also uses hwi to handle edge cases that bdk doesnt support yet.

    This is only necessary until https://github.com/bitcoindevkit/bdk/issues/1021  is done.
    """

    def __init__(self, bdk_descriptor: bdk.Descriptor, change_descriptor: bdk.Descriptor) -> None:
        self.bdk_descriptors = [bdk_descriptor, change_descriptor]

        for bdk_descriptor in self.bdk_descriptors:
            # check that the self.bdk_descriptors each have equal derivation_paths
            derivation_path = self.get_equal_derivation_path(bdk_descriptor.as_string())
            assert (
                derivation_path
            ), f"Derivation paths in {bdk_descriptor.as_string()} are not all equal. MultipathDescriptor does not  support this."

    @classmethod
    def get_equal_derivation_path(cls, descriptor_str: str) -> Optional[str]:
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

    @classmethod
    def is_valid(cls, descriptor_str: str, network: bdk.Network) -> bool:
        try:
            cls.from_descriptor_str(descriptor_str=descriptor_str, network=network)
        except:
            return False
        return True

    @classmethod
    def from_descriptor_str(cls, descriptor_str: str, network: bdk.Network):
        derivation_path = cls.get_equal_derivation_path(descriptor_str)

        assert (
            derivation_path
        ), f"Derivation paths are not all equal, and from this no MultiPathDescriptor can be created."

        # sparrow qr code misses the change derivation path completely
        assert derivation_path in [
            "",
            "/0/*",
            "/1/*",
            "/<0;1>/*",
        ], f"Unknown derivation path {derivation_path}, and from this no MultiPathDescriptor can be created."

        receive_descriptor = get_adapted_hwi_descriptor(descriptor_str, new_derivation_path="/0/*")
        change_descriptor = get_adapted_hwi_descriptor(descriptor_str, new_derivation_path="/1/*")

        return cls(
            bdk.Descriptor(receive_descriptor.to_string(), network=network),
            bdk.Descriptor(change_descriptor.to_string(), network=network),
        )

    def as_string(self) -> str:
        return self._as_string(only_public=True)

    def as_string_private(self) -> str:
        return self._as_string(only_public=False)

    def _as_string(self, only_public=False) -> str:
        # TODO: Once https://github.com/bitcoindevkit/bdk/issues/1021" solved replace hwi with bdk
        assert len(self.bdk_descriptors) == 2

        receive_descriptor_str = (
            self.bdk_descriptors[0].as_string()
            if only_public
            else self.bdk_descriptors[0].as_string_private()
        )

        receive_descriptor = get_adapted_hwi_descriptor(
            receive_descriptor_str, new_derivation_path="/<0;1>/*"
        )
        return receive_descriptor.to_string(hardened_char="'")

    def address_descriptor(self, kind: bdk.KeychainKind, address_index: int) -> str:
        receive_descriptor_str = self.bdk_descriptors[0].as_string()

        new_derivation_path = f"/{0 if kind == bdk.KeychainKind.EXTERNAL else 1}/{address_index}"
        receive_descriptor = get_adapted_hwi_descriptor(
            receive_descriptor_str, new_derivation_path=new_derivation_path
        )
        return receive_descriptor.to_string(hardened_char="'")
