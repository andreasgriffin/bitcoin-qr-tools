import json
import logging
import re

import bdkpython as bdk
from hwilib.descriptor import (
    Descriptor,
    PubkeyProvider,
    _get_func_expr,
    parse_descriptor,
)

from bitcoin_qr_tools.converter_xpub import ConverterXpub
from bitcoin_qr_tools.utils import WrongNetwork, _flatten_descriptors

logger = logging.getLogger(__name__)


class SignerInfo:
    def __init__(
        self,
        fingerprint: str,
        key_origin: str,
        xpub: str,
        derivation_path: str | None = None,
        name: str | None = None,
        first_address: str | None = None,
    ) -> None:
        """_summary_

        Args:
            fingerprint (str): Root fingerprint
            key_origin (str): _description_
            xpub (str): _description_
            derivation_path (Optional[str], optional): _description_. Defaults to None.
            name (Optional[str], optional): _description_. Defaults to None.
            first_address (Optional[str], optional): _description_. Defaults to None.
        """
        self.fingerprint = fingerprint
        self.key_origin = self.format_key_origin(key_origin)
        self.xpub = xpub
        self.derivation_path = derivation_path
        self.name = name
        self.first_address = first_address

    def format_key_origin(self, value):
        assert value.startswith("m"), "The value must start with m"
        return value.replace("'", "h")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__dict__})"

    def __str__(self) -> str:
        return f"{self.__dict__}"

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    def dict(self) -> dict:
        return self.__dict__

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__

    @classmethod
    def _is_testnet(cls, network: bdk.Network) -> bool:
        return network in [
            bdk.Network.REGTEST,
            bdk.Network.TESTNET,
            bdk.Network.SIGNET,
        ]

    @classmethod
    def _inner_most_pubkey_provider(cls, descriptors: list[Descriptor]) -> tuple[list[str], PubkeyProvider]:
        """
        Deturns the name of the descriptor (also when it was nested) and the single PubkeyProvider found

        If there are more than 1 PubkeyProvider present, it will raise DecodingException

        Args:
            descriptors (List[Descriptor]): _description_

        Raises:
            Exception: _description_

        Returns:
            Tuple[str, PubkeyProvider]: _description_
        """
        if len(descriptors) != 1:
            raise Exception("Only 1 descriptor expected")
        flattened_descriptors = _flatten_descriptors(descriptors[0])

        names = [d.name for d in flattened_descriptors]
        assert len(flattened_descriptors[-1].pubkeys) == 1
        pubkey_provider = flattened_descriptors[-1].pubkeys[0]
        return names, pubkey_provider

    @classmethod
    def hwi_pubkey_provider_to_signer_info(
        cls, hwi_pk_prov: PubkeyProvider, network: bdk.Network, name: str | None = None
    ) -> "SignerInfo":
        if hwi_pk_prov.extkey:
            is_testnet = hwi_pk_prov.extkey.is_testnet
            if is_testnet != cls._is_testnet(network):
                raise WrongNetwork(
                    f"""Expected Network {network}, but got {"Testnet" if is_testnet else "Mainnet"}"""
                )

        return SignerInfo(
            fingerprint=hwi_pk_prov.origin.fingerprint.hex(),
            key_origin=hwi_pk_prov.origin.get_derivation_path(),
            xpub=cls._normalize_xpub_and_validate_network(hwi_pk_prov.pubkey, network),
            derivation_path=hwi_pk_prov.deriv_path,
            name=name,
        )

    @classmethod
    def _get_inner_most_signer_info(cls, expr: str) -> tuple[str, str]:
        funcs = []
        error = False
        while not error:
            try:
                func, expr = _get_func_expr(expr)
                funcs.append(func)
            except Exception:
                error = True
        return "p2" + "-".join([func for func in funcs]), expr

    @classmethod
    def _handle_incomplete_descriptor_bare_p2wsh(
        cls, descriptor_str: str, network: bdk.Network
    ) -> "SignerInfo | None":
        try:
            name, most_inner_expr = cls._get_inner_most_signer_info(descriptor_str)
            signer_info = SignerInfo.from_str(most_inner_expr, network)
            signer_info.name = name
        except Exception:
            return None
        return signer_info

    @classmethod
    def _normalize_xpub_and_validate_network(cls, xpub: str, network: bdk.Network) -> str:
        xpub = ConverterXpub.normalized_to_bip32(xpub)
        ConverterXpub.ensure_xpub_matches_network(xpub, network)
        return xpub

    @classmethod
    def _wrapped_single_key_descriptor_to_signer_info(
        cls, s: str, network: bdk.Network
    ) -> "SignerInfo | None":
        if re.fullmatch(r"[a-z0-9_]+\(.*\)(#.*)?", s, re.IGNORECASE) is None:
            return None
        try:
            return cls.decode_descriptor_as_signer_info(s, network)
        except WrongNetwork:
            raise
        except Exception:
            pass

        try:
            _, most_inner_expr = cls._get_inner_most_signer_info(s.split("#")[0])
            if not most_inner_expr.startswith("["):
                return None
            if most_inner_expr.count("[") != 1 or most_inner_expr.count("]") != 1 or "," in most_inner_expr:
                return None
            return SignerInfo.from_str(most_inner_expr, network)
        except WrongNetwork:
            raise
        except Exception:
            return None

    @classmethod
    def decode_descriptor_as_signer_info(cls, descriptor_str: str, network: bdk.Network) -> "SignerInfo":
        try:
            descriptor = parse_descriptor(desc=descriptor_str)
            names, pubkey_provider = cls._inner_most_pubkey_provider([descriptor])
            return cls.hwi_pubkey_provider_to_signer_info(
                pubkey_provider, network=network, name="-".join(["p2" + name for name in names])
            )
        except ValueError as e:
            if "A matching pair of parentheses cannot be found" in e.args:
                signer_info = cls._handle_incomplete_descriptor_bare_p2wsh(
                    descriptor_str=descriptor_str, network=network
                )
                if signer_info:
                    return signer_info
            raise e

    @classmethod
    def from_str(cls, s: str, network: bdk.Network) -> "SignerInfo":
        """
        Splits 1 keystore,e.g. "[a42c6dd3/84'/1'/0']xpub/0/*"
        into fingerprint, key_origin, xpub, wallet_path

        It also replaces the "'" into "h"

        It overwrites fingerprint, key_origin, xpub  in default_keystore.
        """
        # one could use:
        #     pubkey_provider, _ = parse_pubkey(s)
        #     return SignerInfo(
        #         fingerprint=pubkey_provider.origin.fingerprint.hex(),
        #         key_origin=pubkey_provider.origin.get_derivation_path(),
        #         xpub=pubkey_provider.pubkey,
        #         derivation_path=pubkey_provider.deriv_path,
        #     )
        # however this cannot handle slip-132

        if not s.startswith("["):
            signer_info = cls._wrapped_single_key_descriptor_to_signer_info(s, network)
            if signer_info:
                return signer_info

        def key_origin_contains_valid_characters(s: str) -> bool:
            # Matches strings that consist of 'h', '/', digits, and optionally ends with a single quote
            return re.fullmatch("[mh/0-9']*", s) is not None

        def extract_groups(string: str, pattern):
            match = re.match(pattern, string)
            if match is None:
                raise Exception(f"'{string}' does not match the required pattern!")
            return match.groups()

        groups = extract_groups(s, r"\[(.*?)\/(.*?)\](.*?)(\/.*?)?$")

        key_origin = "m/" + groups[1].replace("'", "h")
        # guard against false positive detections
        assert key_origin_contains_valid_characters(key_origin)

        return SignerInfo(
            fingerprint=groups[0],
            key_origin=key_origin,
            xpub=cls._normalize_xpub_and_validate_network(groups[2], network),
            derivation_path=groups[3],
        )
