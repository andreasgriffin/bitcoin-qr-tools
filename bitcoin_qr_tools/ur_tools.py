import logging
from typing import Any, List, Optional

import bdkpython as bdk
from base58 import b58decode_check
from hwilib.descriptor import MultisigDescriptor, PubkeyProvider, parse_descriptor
from hwilib.key import KeyOriginInfo, parse_path

from bitcoin_qr_tools.data import Data, SignerInfo
from bitcoin_qr_tools.urtypes.crypto import SCRIPT_EXPRESSION_TAG_MAP
from bitcoin_qr_tools.urtypes.crypto import CoinInfo as UR_CoinInfo
from bitcoin_qr_tools.urtypes.crypto import HDKey as UR_HDKey
from bitcoin_qr_tools.urtypes.crypto import Keypath as UR_KeyPath
from bitcoin_qr_tools.urtypes.crypto import MultiKey as UR_MultiKey
from bitcoin_qr_tools.urtypes.crypto import PathComponent as UR_PathComponent
from bitcoin_qr_tools.urtypes.crypto import ScriptExpression as UR_ScriptExpression
from bitcoin_qr_tools.utils import _flatten_descriptors

from .urtypes.crypto import Account as UR_ACCOUNT
from .urtypes.crypto import Output as UR_OUTPUT

logger = logging.getLogger(__name__)


class URComparator:
    @classmethod
    def _compare_path_component(cls, c1: UR_PathComponent, c2: UR_PathComponent, prefix: str = "") -> bool:
        all_same = True
        # Compare index
        if c1.index != c2.index:
            print(f"{prefix}DIFFERENCE in component index: {c1.index} != {c2.index}")
            all_same = False
        # else:
        #     print(f"{prefix}Same component index: {c1.index}")
        # Compare hardened
        if c1.hardened != c2.hardened:
            print(f"{prefix}DIFFERENCE in component hardened: {c1.hardened} != {c2.hardened}")
            all_same = False
        # else:
        #     print(f"{prefix}Same component hardened: {c1.hardened}")
        # Compare wildcard
        if c1.wildcard != c2.wildcard:
            print(f"{prefix}DIFFERENCE in component wildcard: {c1.wildcard} != {c2.wildcard}")
            all_same = False
        # else:
        #     print(f"{prefix}Same component wildcard: {c1.wildcard}")

        return all_same

    @classmethod
    def _compare_keypath(cls, kp1: Optional[UR_KeyPath], kp2: Optional[UR_KeyPath], prefix: str = "") -> bool:
        if kp1 is None and kp2 is None:
            # print(f"{prefix}Both Keypaths are None")
            return True
        elif kp1 is None:
            print(f"{prefix}DIFFERENCE: Keypath is None in first HDKey but not in second")
            return False
        elif kp2 is None:
            print(f"{prefix}DIFFERENCE: Keypath is None in second HDKey but not in first")
            return False

        all_same = True
        # Compare source_fingerprint
        if kp1.source_fingerprint != kp2.source_fingerprint:
            print(
                f"{prefix}DIFFERENCE in source_fingerprint: {kp1.source_fingerprint} != {kp2.source_fingerprint}"
            )
            all_same = False
        # else:
        # print(f"{prefix}Same source_fingerprint: {kp1.source_fingerprint}")
        # Compare depth
        if kp1.depth != kp2.depth:
            print(f"{prefix}DIFFERENCE in depth: {kp1.depth} != {kp2.depth}")
            all_same = False
        # else:
        # print(f"{prefix}Same depth: {kp1.depth}")
        # Compare components length
        if len(kp1.components) != len(kp2.components):
            print(
                f"{prefix}DIFFERENCE in number of components: {len(kp1.components)} != {len(kp2.components)}"
            )
            all_same = False
        else:
            # print(f"{prefix}Same number of components: {len(kp1.components)}")
            # Compare each component
            for i, (c1, c2) in enumerate(zip(kp1.components, kp2.components)):
                print(f"{prefix}Comparing component {i}:")
                if not cls._compare_path_component(c1, c2, prefix=prefix + "  "):
                    all_same = False

        return all_same

    @classmethod
    def _compare_use_info(cls, u1: Any, u2: Any, prefix: str = "") -> bool:
        if u1 is None and u2 is None:
            print(f"{prefix}Both use_info are None")
            return True
        elif u1 is None:
            print(f"{prefix}DIFFERENCE: use_info is None in first HDKey but not in second")
            return False
        elif u2 is None:
            print(f"{prefix}DIFFERENCE: use_info is None in second HDKey but not in first")
            return False

        all_same = True
        # Adjust fields according to your actual use_info structure
        if hasattr(u1, "network") and hasattr(u2, "network"):
            if u1.network != u2.network:
                print(f"{prefix}DIFFERENCE in use_info.network: {u1.network} != {u2.network}")
                all_same = False
            # else:
            #     print(f"{prefix}Same use_info.network: {u1.network}")
        else:
            print(f"{prefix}No 'network' attribute found on use_info. Adjust comparison as needed.")

        return all_same

    @classmethod
    def verbose_compare_hdkeys(cls, hdkey1: UR_HDKey, hdkey2: UR_HDKey) -> None:
        attributes = [
            "master",
            "key",
            "chain_code",
            "private_key",
            "parent_fingerprint",
            "name",
            "note",
        ]

        all_same = True
        # Compare simple attributes
        for attr in attributes:
            if not hasattr(hdkey1, attr) and not hasattr(hdkey2, attr):
                continue
            val1 = getattr(hdkey1, attr)
            val2 = getattr(hdkey2, attr)
            if val1 != val2:
                all_same = False
                print(f"DIFFERENCE in '{attr}':")
                print(f"  hdkey1.{attr} = {val1}")
                print(f"  hdkey2.{attr} = {val2}")
            # else:
            #     print(f"Same '{attr}': {val1}")

        # Compare use_info, origin, children using helpers
        print("\nComparing 'use_info':")
        if hasattr(hdkey1, "use_info") and hasattr(hdkey2, "use_info"):
            if not cls._compare_use_info(hdkey1.use_info, hdkey2.use_info, prefix="  "):
                all_same = False

        print("\nComparing 'origin':")
        if hasattr(hdkey1, "origin") and hasattr(hdkey2, "origin"):
            if not cls._compare_keypath(hdkey1.origin, hdkey2.origin, prefix="  "):
                all_same = False

        print("\nComparing 'children':")
        if hasattr(hdkey1, "children") and hasattr(hdkey2, "children"):
            if not cls._compare_keypath(hdkey1.children, hdkey2.children, prefix="  "):
                all_same = False

        if all_same:
            print("\nThe two UR_HDKey objects are identical.")
        else:
            print("\nDifferences found in the UR_HDKey objects above.")

    @classmethod
    def verbose_compare_output(cls, o1: UR_OUTPUT, o2: UR_OUTPUT) -> None:
        all_same = True

        # Compare script_expressions
        if len(o1.script_expressions) != len(o2.script_expressions):
            print(
                f"DIFFERENCE in number of script_expressions: {len(o1.script_expressions)} != {len(o2.script_expressions)}"
            )
            all_same = False
        else:
            # print(f"Same number of script_expressions: {len(o1.script_expressions)}")
            for i, (se1, se2) in enumerate(zip(o1.script_expressions, o2.script_expressions)):
                print(f"Comparing script_expressions[{i}]:")
                # Compare tag
                if se1.tag != se2.tag:
                    print(f"  DIFFERENCE in tag: {se1.tag} != {se2.tag}")
                    all_same = False
                # else:
                #     print(f"  Same tag: {se1.tag}")

                # Compare expression
                if se1.expression != se2.expression:
                    print(f"  DIFFERENCE in expression: {se1.expression} != {se2.expression}")
                    all_same = False
                # else:
                #     print(f"  Same expression: {se1.expression}")

        # Compare crypto_key
        print("\nComparing crypto_key:")
        if o1.crypto_key is None and o2.crypto_key is None:
            print("Both crypto_key are None")
        elif type(o1.crypto_key) != type(o2.crypto_key):
            print(f"DIFFERENCE: types {type(o1.crypto_key) } != { type(o2.crypto_key)}")
            all_same = False
        elif isinstance(o1.crypto_key, UR_HDKey) and isinstance(o2.crypto_key, UR_HDKey):
            cls.verbose_compare_hdkeys(o1.crypto_key, o2.crypto_key)
        elif isinstance(o1.crypto_key, UR_MultiKey) and isinstance(o2.crypto_key, UR_MultiKey):
            if len(o1.crypto_key.hd_keys) != len(o2.crypto_key.hd_keys):
                print(f"DIFFERENCE: .crypto_key.hd_keys have different length")
            for i, (k1, k2) in enumerate(zip(o1.crypto_key.hd_keys, o2.crypto_key.hd_keys)):
                print(f"Comparing {i}.th  keypair {k1, k2}")
                cls.verbose_compare_hdkeys(k1, k2)

        if all_same:
            print("\nThe two Output objects are identical.")
        else:
            print("\nDifferences found in the Output objects above.")

    @classmethod
    def verbose_compare_accounts(cls, a1: UR_ACCOUNT, a2: UR_ACCOUNT) -> None:
        if a1.master_fingerprint != a2.master_fingerprint:
            print(f"DIFFERENCE: master_fingerprint")

        for i, (o1, o2) in enumerate(zip(a1.output_descriptors, a2.output_descriptors)):
            print(f"Comapring {i}. output_descriptors\n")
            cls.verbose_compare_output(o1, o2)


# class URToolsUnsafe():


#     @classmethod
#     def  _hdkey_is_testnet(cls,  hdkey:UR_HDKey)->bool:
#         path_components = hdkey.origin.components
#         if len(path_components)>2 and path_components[1].index==1:
#             return True
#         return False


#     @classmethod
#     def  _hdkey_matches_network(cls,  hdkey:UR_HDKey, network:bdk.Network)->bool:
#         network_is_testnet            = network in [bdk.Network.REGTEST, bdk.Network.TESTNET, bdk.Network.SIGNET, ]
#         hdkey_is_testnet = cls._hdkey_is_testnet(hdkey)
#         return network_is_testnet == hdkey_is_testnet

#     @classmethod
#     def  _decode_hdkey(cls, hdkey:UR_HDKey, network:bdk.Network)->SignerInfo:
#         """
#         Unfortunately, coininfo.network / use-info.network is not set correctly in keystone
#         https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md#cddl-for-coin-info
#         so we use the https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md#cddl-for-key-path instead
#         """
#         xpub = hdkey.bip32_key(include_derivation_path=False)
#         fingerprint = binascii.hexlify(hdkey.origin.source_fingerprint).decode("utf-8")

#         path = hdkey.origin.path()
#         key_origin = f"m/{path}" if path  else "m"


#         if not cls._hdkey_matches_network(hdkey=hdkey, network=network) :
#             raise WrongNetwork(f"""Expected Network {network}. But {key_origin=} doesnt match.""")

#         return SignerInfo(fingerprint=fingerprint, key_origin=key_origin, xpub=xpub, name=hdkey.name)


#     @classmethod
#     def decode_output_as_signer_info(cls, output:UR_OUTPUT, network:bdk.Network)->SignerInfo:
#         hdkey = output.hd_key()
#         if not hdkey:
#             raise DecodingException(f"No HDKey available. Instead got {type(output.crypto_key)}")

#         data = cls._decode_hdkey(hdkey, network=network)
#         assert isinstance(data, SignerInfo)
#         data.name = f"p2{'-'.join([e.expression for e in output.script_expressions])}"
#         return data


class URTools:
    """
    See UR docs: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md
    """

    @classmethod
    def decode_output_as_descriptor(cls, output: UR_OUTPUT, network: bdk.Network) -> Data:
        return Data.from_str(output.descriptor(), network=network)

    @classmethod
    def decode_account_as_signer_infos(cls, account: UR_ACCOUNT, network: bdk.Network) -> List[SignerInfo]:
        return [
            SignerInfo.decode_descriptor_as_signer_info(output.descriptor(), network=network)
            for output in account.output_descriptors
        ]

    @classmethod
    def _hd_key_to_pubkey_provider(cls, hdkey: UR_HDKey) -> PubkeyProvider:
        key_origin = KeyOriginInfo(
            fingerprint=hdkey.origin.source_fingerprint, path=parse_path(hdkey.origin.path())
        )
        xpub = hdkey.bip32_key(include_derivation_path=False)
        deriv_path = f"/{hdkey.children.path()}"
        return PubkeyProvider(origin=key_origin, pubkey=xpub, deriv_path=deriv_path)

    @classmethod
    def _key_origin_to_keypath(cls, key_origin_info: KeyOriginInfo, fingerprint: bytes = None) -> UR_KeyPath:
        """
        Convert a BIP32 path string into a Keypath object using hwi_parse_path.

        :param path_str: A string representing a BIP32 path (e.g. "m/84'/0'/0'")
        :param fingerprint: Optional 4-byte fingerprint to associate with the Keypath
        :return: A Keypath object populated with PathComponent objects.
        """
        # Use hwi_parse_path to get a list of uint32 integers representing the path
        parts = key_origin_info.path

        # Convert each index into a PathComponent
        components = []
        for part in parts:
            hardened = (part & 0x80000000) != 0
            index = part & ~0x80000000 if hardened else part
            components.append(UR_PathComponent(index=index, hardened=hardened))

        return UR_KeyPath(components=components, source_fingerprint=fingerprint, depth=len(components))

    @classmethod
    def _derivation_path_to_keypath(cls, derivation_path: str) -> UR_KeyPath:

        parts = derivation_path.lstrip("/").split("/")

        components = []
        for part in parts:
            if part == "*":
                # Wildcard component
                component = UR_PathComponent(index=None, hardened=False)
                component.wildcard = True
                components.append(component)
            else:
                # Regular BIP32 index
                integer_idx = int(part)
                hardened = (integer_idx & 0x80000000) != 0
                index = integer_idx & ~0x80000000 if hardened else integer_idx

                component = UR_PathComponent(index=index, hardened=hardened)
                component.wildcard = False
                components.append(component)

        depth = 0  # keystone lets this at 0.  len(components)
        return UR_KeyPath(components=components, source_fingerprint=None, depth=depth)

    @classmethod
    def _use_info(cls, is_testnet: bool) -> UR_CoinInfo:
        return UR_CoinInfo(type=0, network=int(is_testnet))

    @classmethod
    def _pubkey_provider_to_hdkey(cls, pubkey_provider: PubkeyProvider, name: str | None = None) -> UR_HDKey:
        # Decode the extended key (xpub / xprv)
        xpub = pubkey_provider.pubkey
        decoded = b58decode_check(xpub)

        # Extended key structure:
        # version (4 bytes) | depth (1 byte) | parent_fingerprint (4 bytes) |
        # child_number (4 bytes) | chain_code (32 bytes) | key_data (33 bytes)
        version = decoded[0:4]
        decoded[4]
        parent_fingerprint = decoded[5:9]
        child_number = decoded[9:13]
        chain_code = decoded[13:45]
        key_data = decoded[45:]

        # Determine if it's a private key
        if key_data[0] == 0x00:
            # Private key
            private_key = key_data[1:]
            key = private_key
        else:
            # Public key
            private_key = False
            key = key_data

        # Parse the origin path
        origin_keypath = cls._key_origin_to_keypath(
            pubkey_provider.origin, fingerprint=pubkey_provider.origin.fingerprint
        )

        # Parse the children path if provided
        children_keypath = (
            cls._derivation_path_to_keypath(pubkey_provider.deriv_path)
            if pubkey_provider.deriv_path
            else None
        )

        # Build props for UR_HDKey
        props = {
            "key": key,
            "chain_code": chain_code,
            "private_key": private_key,
            "use_info": cls._use_info(pubkey_provider.extkey.is_testnet),
            "origin": origin_keypath,
            "children": children_keypath,
            "parent_fingerprint": parent_fingerprint if parent_fingerprint != b"\x00\x00\x00\x00" else None,
            "name": name,
            "note": None,
        }

        return UR_HDKey(props)

    @classmethod
    def _script_expression_base(cls, name: str) -> UR_ScriptExpression:
        for tag in SCRIPT_EXPRESSION_TAG_MAP.values():
            if tag.expression == name:
                return tag

    @classmethod
    def _script_expressions(cls, name: str) -> List[UR_ScriptExpression]:
        expressions: List[UR_ScriptExpression] = []
        for single_expression in name.split("-"):
            for tag in SCRIPT_EXPRESSION_TAG_MAP.values():
                if tag.expression == single_expression:
                    expressions.append(tag)
        return expressions

    @classmethod
    def encode_ur_output(cls, descriptor_str: str, keystore_name: str | None = None) -> UR_OUTPUT:
        """_summary_

        Args:
            descriptor_str (str): _description_
            keystore_name (str): Name of the keystore.  Not supported for multisig.

        Raises:
            Exception: _description_
            NotImplementedError: _description_

        Returns:
            UR_OUTPUT: _description_
        """
        hwi_descriptor = parse_descriptor(desc=descriptor_str)

        if len(hwi_descriptor.pubkeys) == 1:
            descriptor_names, _ = SignerInfo._inner_most_pubkey_provider([hwi_descriptor])
            crypto_key = cls._pubkey_provider_to_hdkey(hwi_descriptor.pubkeys[0], name=keystore_name)
        elif len(hwi_descriptor.pubkeys) == 0 and hwi_descriptor.subdescriptors:
            # multisig
            flattened_descriptors = _flatten_descriptors(hwi_descriptor)
            descriptor_names = [d.name for d in flattened_descriptors]
            multisig_descriptor = flattened_descriptors[-1]
            if not isinstance(multisig_descriptor, MultisigDescriptor):
                raise Exception(f"descritpor not consistent with a multisig")

            hd_keys = [cls._pubkey_provider_to_hdkey(pubkey) for pubkey in multisig_descriptor.pubkeys]
            crypto_key = UR_MultiKey(threshold=multisig_descriptor.thresh, ec_keys=[], hd_keys=hd_keys)
        else:
            raise NotImplementedError(f"{len(hwi_descriptor.pubkeys)} pubkeys")

        script_expressions = [cls._script_expression_base(name) for name in descriptor_names]
        return UR_OUTPUT(script_expressions=script_expressions, crypto_key=crypto_key)

    @classmethod
    def encode_ur_account(cls, signer_infos: List[SignerInfo], descriptor_names: List[str]) -> UR_ACCOUNT:
        assert signer_infos, "Empty list signer_infos"
        first_info = signer_infos[0]

        output_descriptors = []
        for signer_info, descriptor_name in zip(signer_infos, descriptor_names):
            pubkey_provider = PubkeyProvider(
                origin=KeyOriginInfo.from_string(
                    signer_info.key_origin.replace("m", signer_info.fingerprint)
                ),
                pubkey=signer_info.xpub,
                deriv_path=signer_info.derivation_path,
            )
            crypto_key = cls._pubkey_provider_to_hdkey(pubkey_provider)

            script_expressions = cls._script_expressions(descriptor_name.replace("p2", ""))
            output = UR_OUTPUT(script_expressions=script_expressions, crypto_key=crypto_key)

            output_descriptors.append(output)

        return UR_ACCOUNT(
            master_fingerprint=bytes.fromhex(first_info.fingerprint), output_descriptors=output_descriptors
        )
